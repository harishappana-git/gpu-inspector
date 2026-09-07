// Package advisory compares retained observations with explicitly trusted signed
// OEM and driver-advisory assertions. No vendor keys or production data ship here.
package advisory

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/harishappana/gpu-inspector/internal/bundle"
	"github.com/harishappana/gpu-inspector/internal/model"
)

const SchemaVersion = "1.0.0"
const MaxEntries = 256
const MaxVBIOSVersions = 32

type Source struct {
	URL         string    `json:"url"`
	Title       string    `json:"title"`
	PublishedAt time.Time `json:"published_at"`
}

type OEMEntry struct {
	ID              string   `json:"id"`
	SKU             string   `json:"sku"`
	BoardPartNumber string   `json:"board_part_number"`
	VBIOSVersions   []string `json:"vbios_versions"`
	Source          Source   `json:"source"`
}

// Selector matches retained structured evidence, never message text. Field and
// Value are paired: either the scalar observation names Field in Conditions, or
// Value is compared with that direct key in an observation's structured value.
type Selector struct {
	CheckID  string       `json:"check_id"`
	MethodID string       `json:"method_id"`
	Status   model.Status `json:"status"`
	Field    string       `json:"field,omitempty"`
	Value    any          `json:"value,omitempty"`
}

type DriverEntry struct {
	ID        string   `json:"id"`
	SKU       string   `json:"sku"`
	DriverMin string   `json:"driver_min"`
	DriverMax string   `json:"driver_max"`
	Symptom   Selector `json:"symptom"`
	Summary   string   `json:"summary"`
	Source    Source   `json:"source"`
}

type Pack struct {
	Kind              string        `json:"kind"`
	SchemaVersion     string        `json:"schema_version"`
	ID                string        `json:"advisory_id"`
	Version           string        `json:"version"`
	Publisher         string        `json:"publisher"`
	IssuedAt          time.Time     `json:"issued_at"`
	ValidUntil        time.Time     `json:"valid_until"`
	OEM               []OEMEntry    `json:"oem"`
	Driver            []DriverEntry `json:"driver_advisories"`
	authenticated     bool
	digest, keyDigest string
	seal              [32]byte
}

var token = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}$`)
var skuPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
var checkPattern = regexp.MustCompile(`^[A-M][0-9]{2}$`)
var versionPart = regexp.MustCompile(`^[0-9]{1,6}$`)
var decimal = regexp.MustCompile(`^-?(?:0|[1-9][0-9]{0,19})(?:\.[0-9]{1,12})?$`)

func Load(path string, key ed25519.PublicKey, now time.Time) (*Pack, error) {
	return LoadContext(context.Background(), path, key, now)
}

func LoadContext(ctx context.Context, path string, key ed25519.PublicKey, now time.Time) (*Pack, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > bundle.MaxDocumentBytes {
		return nil, errors.New("advisory pack must be a bounded regular file")
	}
	data, err := io.ReadAll(cancelReader{ctx, io.LimitReader(f, bundle.MaxDocumentBytes+1)})
	if err != nil {
		return nil, err
	}
	if len(data) > bundle.MaxDocumentBytes {
		return nil, errors.New("advisory pack exceeds document limit")
	}
	payload, err := bundle.Verify(data, key)
	if err != nil {
		return nil, err
	}
	var p Pack
	if err := bundle.Decode(payload, &p); err != nil {
		return nil, err
	}
	if err := p.Validate(now); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sum, keySum := sha256.Sum256(payload), sha256.Sum256(key)
	p.authenticated, p.digest, p.keyDigest = true, hex.EncodeToString(sum[:]), hex.EncodeToString(keySum[:])
	canonical, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	p.seal = sha256.Sum256(canonical)
	return &p, nil
}

type cancelReader struct {
	ctx    context.Context
	source io.Reader
}

func (r cancelReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > 64<<10 {
		p = p[:64<<10]
	}
	n, err := r.source.Read(p)
	if cancelled := r.ctx.Err(); cancelled != nil {
		return 0, cancelled
	}
	return n, err
}

func (p *Pack) Validate(now time.Time) error {
	if p == nil || p.Kind != "gri-advisory" || p.SchemaVersion != SchemaVersion || !token.MatchString(p.ID) || !token.MatchString(p.Version) || !plainText(p.Publisher, 128) {
		return errors.New("invalid versioned advisory pack identity")
	}
	if now.IsZero() || p.IssuedAt.IsZero() || p.IssuedAt.After(now) || !p.ValidUntil.After(now) || !p.ValidUntil.After(p.IssuedAt) {
		return errors.New("advisory pack is expired or has invalid dates")
	}
	if len(p.OEM)+len(p.Driver) == 0 || len(p.OEM)+len(p.Driver) > MaxEntries {
		return errors.New("advisory pack must contain 1 to 256 entries")
	}
	seen, boards := map[string]bool{}, map[string]bool{}
	entry := func(id, sku string, s Source) error {
		if !token.MatchString(id) || seen[id] || len(sku) > 96 || !skuPattern.MatchString(sku) || sku == "unknown" {
			return errors.New("invalid or duplicate advisory entry identity or normalized SKU")
		}
		seen[id] = true
		return s.validate(p.IssuedAt)
	}
	for _, o := range p.OEM {
		if err := entry(o.ID, o.SKU, o.Source); err != nil {
			return err
		}
		if !hardwareToken(o.BoardPartNumber) || len(o.VBIOSVersions) == 0 || len(o.VBIOSVersions) > MaxVBIOSVersions {
			return errors.New("OEM entry requires exact board part number and bounded known VBIOS versions")
		}
		key := o.SKU + "\x00" + normalizeHardware(o.BoardPartNumber)
		if boards[key] {
			return errors.New("duplicate OEM SKU/board entry")
		}
		boards[key] = true
		versions := map[string]bool{}
		for _, v := range o.VBIOSVersions {
			n := normalizeHardware(v)
			if !hardwareToken(v) || versions[n] {
				return errors.New("invalid or duplicate known VBIOS version")
			}
			versions[n] = true
		}
	}
	for _, d := range p.Driver {
		if err := entry(d.ID, d.SKU, d.Source); err != nil {
			return err
		}
		lo, lerr := parseDriver(d.DriverMin)
		hi, herr := parseDriver(d.DriverMax)
		if lerr != nil || herr != nil || compareDriver(lo, hi) > 0 || !plainText(d.Summary, 512) {
			return errors.New("driver advisory needs an ordered numeric driver range and summary")
		}
		if !checkPattern.MatchString(d.Symptom.CheckID) || !token.MatchString(d.Symptom.MethodID) || (d.Symptom.Status != model.Fail && d.Symptom.Status != model.Warning) {
			return errors.New("driver advisory requires an explicit FAIL/WARNING observation selector")
		}
		if (d.Symptom.Field == "") != (d.Symptom.Value == nil) {
			return errors.New("symptom field and primitive value must be supplied together")
		}
		if d.Symptom.Field != "" {
			if !token.MatchString(d.Symptom.Field) {
				return errors.New("invalid symptom field")
			}
			if _, ok := primitive(d.Symptom.Value); !ok {
				return errors.New("symptom value must be a bounded string, bool or exact decimal")
			}
		}
	}
	return nil
}

func (s Source) validate(issued time.Time) error {
	u, err := url.Parse(s.URL)
	if err != nil || len(s.URL) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || !plainText(s.Title, 256) || s.PublishedAt.IsZero() || s.PublishedAt.After(issued) {
		return errors.New("entry requires a dated HTTPS source without credentials or query parameters")
	}
	return nil
}

func plainText(s string, max int) bool {
	if s == "" || len(s) > max || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func normalizeHardware(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }
func hardwareToken(s string) bool {
	if !plainText(s, 96) || !token.MatchString(s) {
		return false
	}
	switch normalizeHardware(s) {
	case "UNKNOWN", "N/A", "NA", "NONE", "UNSUPPORTED":
		return false
	}
	return true
}

func parseDriver(s string) ([4]uint64, error) {
	var result [4]uint64
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return result, errors.New("driver version must have 2 to 4 numeric components")
	}
	for i, p := range parts {
		if !versionPart.MatchString(p) {
			return result, errors.New("invalid driver version component")
		}
		result[i], _ = strconv.ParseUint(p, 10, 64)
	}
	return result, nil
}
func compareDriver(a, b [4]uint64) int {
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// Numeric comparisons use exact bounded decimal rationals; uint64 evidence never
// passes through float64. Exponents, null, arrays and objects are not selectors.
func primitive(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		if !plainText(x, 128) {
			return "", false
		}
		return "s:" + x, true
	case bool:
		return fmt.Sprintf("b:%t", x), true
	default:
		data, err := json.Marshal(v)
		if err != nil || !decimal.Match(data) {
			return "", false
		}
		n, ok := new(big.Rat).SetString(string(data))
		if !ok {
			return "", false
		}
		return "n:" + n.RatString(), true
	}
}
