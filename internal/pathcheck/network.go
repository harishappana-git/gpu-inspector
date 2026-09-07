package pathcheck

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
)

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func newHTTPClient(limit time.Duration) *http.Client {
	transport := &http.Transport{
		Proxy:               nil, // Do not route an opted-in object through inherited proxy settings.
		DialContext:         (&net.Dialer{Timeout: minDuration(limit, 5*time.Second), KeepAlive: 0}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: minDuration(limit, 5*time.Second), ResponseHeaderTimeout: minDuration(limit, 10*time.Second),
		MaxResponseHeaderBytes: 16 << 10, DisableCompression: true, DisableKeepAlives: true,
		MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, ForceAttemptHTTP2: false,
	}
	return &http.Client{Transport: transport, Timeout: limit, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func validateEndpoint(raw string) (*url.URL, error) {
	if len(raw) > 4096 {
		return nil, errors.New("URL exceeds the allowed length")
	}
	u, e := url.Parse(raw)
	if e != nil {
		return nil, errors.New("invalid endpoint URL")
	}
	if u.Scheme != "https" || u.Hostname() == "" || u.Opaque != "" {
		return nil, errors.New("endpoint must be an explicit HTTPS URL")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("endpoint userinfo, query strings and fragments are not accepted")
	}
	if strings.ContainsAny(u.Host, "\r\n\t ") {
		return nil, errors.New("invalid endpoint host")
	}
	return u, nil
}
func endpointConditions(opts Options, limit int64) map[string]any {
	digest := sha256.Sum256([]byte(opts.URL))
	return map[string]any{"opt_in": true, "endpoint_sha256": hex.EncodeToString(digest[:]), "endpoint_source": "explicit user-selected object; no implicit license/download permission inferred", "protocol": "HTTPS", "method": "GET", "payload_byte_budget": limit, "budget_scope": "response-body bytes consumed by this process; DNS/TLS/HTTP overhead and transport buffering are additional", "redirects_followed": false, "proxy_from_environment": false, "tls_verification": true, "compression_requested": "identity", "authentication": "none", "content_exported": false, "filesystem_artifacts": false, "connection_count": 1}
}
func networkMissing(status model.Status, start time.Time, message string, conditions map[string]any) []model.Observation {
	return []model.Observation{
		evidence("G02", "pathcheck.https.reachability", "selected-endpoint", status, nil, 0, start, message, conditions),
		evidence("G03", "pathcheck.https.download", "selected-endpoint", status, nil, 0, start, message, conditions),
		evidence("G04", "pathcheck.https.estimate", "selected-endpoint", model.NotTested, nil, 0, start, "No representative full-object transfer estimate is established by this single bounded sample.", conditions),
	}
}

func runNetwork(ctx context.Context, opts Options, client httpDoer) []model.Observation {
	start := time.Now()
	limit := opts.DownloadBytes
	if limit == 0 {
		limit = DefaultDownloadBytes
	}
	conditions := endpointConditions(opts, limit)
	if ctx.Err() != nil {
		return networkMissing(model.TimeBudgetExhausted, start, "Endpoint test did not start because its time budget/cancellation was reached.", conditions)
	}
	if limit <= 0 || limit > MaxDownloadBytes {
		return networkMissing(model.ToolError, start, "Download payload budget must be positive and no greater than 64 MiB.", conditions)
	}
	endpoint, err := validateEndpoint(opts.URL)
	if err != nil {
		return networkMissing(model.ToolError, start, err.Error(), conditions)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return networkMissing(model.ToolError, start, "Could not construct the explicitly requested endpoint test.", conditions)
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", limit-1))
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "GPU-Rental-Inspector/"+model.ToolVersion)
	resp, err := client.Do(req)
	headerElapsed := time.Since(start)
	if err != nil {
		status, message := networkError(ctx, err)
		return networkMissing(status, start, message, conditions)
	}
	defer resp.Body.Close()
	conditions["http_status"] = resp.StatusCode
	conditions["http_protocol"] = resp.Proto
	encoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
	switch encoding {
	case "", "identity", "gzip", "deflate", "br", "zstd":
		conditions["response_content_encoding"] = encoding
	default:
		conditions["response_content_encoding"] = "other"
	}
	conditions["range_honored"] = resp.StatusCode == http.StatusPartialContent
	if resp.ContentLength >= 0 {
		conditions["reported_response_content_length"] = resp.ContentLength
	}
	reachability := evidence("G02", "pathcheck.https.reachability", "selected-endpoint", model.Pass, map[string]any{"http_status": resp.StatusCode, "response_headers_ms": float64(headerElapsed.Nanoseconds()) / 1e6}, 1, start, "The explicitly selected endpoint completed a TLS-verified HTTP exchange; this does not establish arbitrary Internet reachability or object availability.", conditions)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := "The endpoint responded with a non-success HTTP status; no object body was downloaded."
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			message = "The endpoint returned a redirect. It was not followed because only the explicit endpoint was authorized."
		}
		return []model.Observation{reachability, evidence("G03", "pathcheck.https.download", "selected-endpoint", model.Fail, nil, 0, start, message, conditions), evidence("G04", "pathcheck.https.estimate", "selected-endpoint", model.NotTested, nil, 0, start, "No successful object transfer is available for an estimate.", conditions)}
	}
	readStart := time.Now()
	buf := make([]byte, 32<<10)
	remaining := limit
	var count int64
	complete := false
	readErr := error(nil)
	reads := 0
	for remaining > 0 {
		if e := ctx.Err(); e != nil {
			readErr = e
			break
		}
		size := len(buf)
		if int64(size) > remaining {
			size = int(remaining)
		}
		n, e := resp.Body.Read(buf[:size])
		if n > 0 {
			count += int64(n)
			remaining -= int64(n)
			reads++
		}
		if e == io.EOF {
			complete = true
			break
		}
		if e != nil {
			readErr = e
			break
		}
		if n == 0 {
			readErr = io.ErrNoProgress
			break
		}
	}
	bodyElapsed := time.Since(readStart)
	status := model.Pass
	message := "Measured body bytes from one explicit object request; endpoint, cache and network conditions apply. Content authenticity, license and full-download speed are not established."
	if readErr != nil {
		status, message = networkError(ctx, readErr)
		message = "Object transfer ended before its requested sample completed: " + message
	}
	if count == 0 && status == model.Pass {
		status = model.Warning
		message = "The endpoint returned no object body; reachability was observed, but there is no positive-size throughput sample."
	}
	value := map[string]any{"downloaded_body_bytes": count, "body_read_ms": float64(bodyElapsed.Nanoseconds()) / 1e6, "total_request_ms": float64(time.Since(start).Nanoseconds()) / 1e6, "payload_cap_reached": remaining == 0, "observed_eof": complete, "http_status": resp.StatusCode}
	if count > 0 && bodyElapsed > 0 {
		value["body_read_mib_s"] = float64(count) / (1 << 20) / bodyElapsed.Seconds()
		value["end_to_end_mib_s"] = float64(count) / (1 << 20) / time.Since(start).Seconds()
	}
	return []model.Observation{reachability, evidence("G03", "pathcheck.https.download", "selected-endpoint", status, value, reads, start, message, conditions), evidence("G04", "pathcheck.https.estimate", "selected-endpoint", model.NotTested, nil, 0, start, "A single capped request is not a representative full-object transfer rate; no speculative completion-time estimate was generated.", conditions)}
}

func networkError(ctx context.Context, err error) (model.Status, string) {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return model.TimeBudgetExhausted, "The endpoint request reached its deadline or was cancelled."
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return model.TimeBudgetExhausted, "The endpoint request timed out."
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return model.Fail, "DNS resolution failed for the explicitly selected endpoint."
	}
	var cert x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &cert) || errors.As(err, &hostname) || errors.As(err, &invalid) {
		return model.Fail, "TLS certificate verification failed; verification was not disabled."
	}
	return model.ToolError, "The selected endpoint exchange failed; raw errors, URLs and response content are excluded from exported evidence."
}
