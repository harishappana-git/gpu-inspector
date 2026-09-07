package report

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/harishappana/gpu-inspector/internal/model"
)

var (
	gpuIdentifier = regexp.MustCompile(`(?i)\b(?:GPU|MIG)-[a-z0-9][a-z0-9/-]*`)
	pciIdentifier = regexp.MustCompile(`(?i)\b[0-9a-f]{4,8}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]\b`)
	ipv4          = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	absolutePath  = regexp.MustCompile(`(^|[\s"'(=])(?:/[a-zA-Z0-9_.~+-][^\s"'<>),;]*|[a-zA-Z]:\\[^\s"'<>),;]*)`)
	credential    = regexp.MustCompile(`(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|token|authorization|cookie)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)`)
	bearer        = regexp.MustCompile(`(?i)\bBearer\s+[a-z0-9._~+/=-]+`)
	knownToken    = regexp.MustCompile(`\b(?:AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9_-]{12,}|gh[pousr]_[a-zA-Z0-9]{15,}|eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\b`)
	privateKey    = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
	pseudonymous  = regexp.MustCompile(`^redacted-[0-9a-f]{12}$`)
)

type redactor struct {
	salt         string
	replacements map[string]string
	ordered      []string
}

func sensitiveKey(key string) bool {
	key = strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	for _, word := range []string{"password", "passwd", "secret", "token", "credential", "authorization", "cookie", "api_key", "access_key", "private_key", "command_line", "cmdline", "environment", "raw_output", "raw_log"} {
		if strings.Contains(key, word) {
			return true
		}
	}
	return key == "env" || key == "raw" || key == "stdout" || key == "stderr"
}

func identityKey(key string) bool {
	key = strings.ToLower(key)
	return strings.Contains(key, "uuid") || strings.Contains(key, "serial") || strings.Contains(key, "pci_address") || strings.Contains(key, "pci_bus") || strings.Contains(key, "hostname") || strings.Contains(key, "instance_id") || strings.Contains(key, "ip_address")
}

func (red *redactor) pseudonym(value string) string {
	if pseudonymous.MatchString(value) {
		return value
	}
	return "redacted-" + digest([]byte(red.salt + "\x00" + value))[:12]
}

func (red *redactor) collect(value any, key string) {
	switch v := value.(type) {
	case map[string]any:
		for k, child := range v {
			red.collect(child, k)
		}
	case []any:
		for _, child := range v {
			red.collect(child, key)
		}
	case string:
		if len(v) >= 4 && sensitiveKey(key) {
			red.replacements[v] = "[redacted]"
		} else if v != "" && identityKey(key) {
			red.replacements[v] = red.pseudonym(v)
		}
	case json.Number:
		if identityKey(key) {
			red.replacements[v.String()] = red.pseudonym(v.String())
		}
	}
}

func (red *redactor) text(value string) string {
	value = privateKey.ReplaceAllString(value, "[redacted-private-key]")
	for _, raw := range red.ordered {
		value = strings.ReplaceAll(value, raw, red.replacements[raw])
	}
	value = credential.ReplaceAllString(value, "[redacted-credential]")
	value = bearer.ReplaceAllString(value, "[redacted-credential]")
	value = knownToken.ReplaceAllString(value, "[redacted-credential]")
	value = gpuIdentifier.ReplaceAllStringFunc(value, red.pseudonym)
	value = pciIdentifier.ReplaceAllStringFunc(value, red.pseudonym)
	value = ipv4.ReplaceAllStringFunc(value, func(s string) string {
		if net.ParseIP(s) != nil {
			return red.pseudonym(s)
		}
		return s
	})
	// IPv6 contains colons; inspect bounded whitespace-separated tokens instead of
	// a permissive hexadecimal expression that could erase measurements.
	for _, token := range strings.Fields(value) {
		candidate := strings.Trim(token, "[](),;\"'")
		if strings.Contains(candidate, ":") && net.ParseIP(candidate) != nil {
			value = strings.ReplaceAll(value, candidate, red.pseudonym(candidate))
		}
	}
	value = absolutePath.ReplaceAllStringFunc(value, func(s string) string {
		prefix := ""
		if len(s) > 0 && strings.ContainsRune(" \t\r\n\"'(=", rune(s[0])) {
			prefix = s[:1]
		}
		return prefix + "[redacted-path]"
	})
	return plain(value)
}

func (red *redactor) transform(value any, key string) any {
	if sensitiveKey(key) {
		return "[redacted]"
	}
	switch v := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(v))
		for k, child := range v {
			result[red.text(k)] = red.transform(child, k)
		}
		return result
	case []any:
		result := make([]any, len(v))
		for i, child := range v {
			result[i] = red.transform(child, key)
		}
		return result
	case string:
		return red.text(v)
	case json.Number:
		if identityKey(key) {
			return red.pseudonym(v.String())
		}
		// Counts and method conditions remain numeric, with their exact lexical
		// value retained; they must not be mistaken for arbitrary text.
		return v
	default:
		return value
	}
}

// Redact removes sensitive structured fields and identifiers from the normalized
// model, then scrubs known formats from free text. It never includes raw logs.
// Pseudonyms are consistent within a scan; they are not cross-scan host identity.
func Redact(r model.Report) (model.Report, error) {
	var result model.Report
	r.ArtifactHashes = nil
	data, err := json.Marshal(r)
	if err != nil {
		return result, fmt.Errorf("redact report: %w", err)
	}
	var generic any
	if err = decodeJSON(data, &generic); err != nil {
		return result, err
	}
	red := redactor{salt: r.ScanID, replacements: map[string]string{}}
	red.collect(generic, "")
	for raw := range red.replacements {
		red.ordered = append(red.ordered, raw)
	}
	sort.Slice(red.ordered, func(i, j int) bool {
		if len(red.ordered[i]) == len(red.ordered[j]) {
			return red.ordered[i] < red.ordered[j]
		}
		return len(red.ordered[i]) > len(red.ordered[j])
	})
	data, err = json.Marshal(red.transform(generic, ""))
	if err != nil {
		return result, err
	}
	if err = decodeJSON(data, &result); err != nil {
		return result, fmt.Errorf("decode redacted report: %w", err)
	}
	const limitation = "Export redaction removed identifiers, private paths and sensitive fields; pseudonyms apply only within this scan. Review the local draft before sharing."
	found := false
	for _, existing := range result.Limitations {
		if existing == limitation {
			found = true
			break
		}
	}
	if !found {
		result.Limitations = append(result.Limitations, limitation)
	}
	return result, nil
}

// Export verifies the source and regenerates a minimal private bundle from the
// redacted evidence model. It copies no source-directory files or raw journals.
func Export(sourceDir, destDir string) error {
	if err := Verify(sourceDir); err != nil {
		return fmt.Errorf("source verification failed: %w", err)
	}
	if _, err := os.Lstat(destDir); err == nil {
		return fmt.Errorf("export destination already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	r, err := Read(filepath.Join(sourceDir, "report.json"))
	if err != nil {
		return err
	}
	redacted, err := Redact(r)
	if err != nil {
		return err
	}
	if err = privateDir(destDir); err != nil {
		return err
	}
	var evidence strings.Builder
	for _, observation := range redacted.Observations {
		data, err := json.Marshal(observation)
		if err != nil {
			return err
		}
		evidence.Write(data)
		evidence.WriteByte('\n')
	}
	if err = publish(destDir, "evidence.jsonl", []byte(evidence.String())); err != nil {
		return err
	}
	_, err = os.Lstat(filepath.Join(sourceDir, "ticket.md"))
	return WriteWithOptions(destDir, redacted, Options{Ticket: err == nil})
}
