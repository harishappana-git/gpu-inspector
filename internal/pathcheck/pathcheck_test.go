package pathcheck

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
)

func byCheck(t *testing.T, obs []model.Observation, id string) model.Observation {
	t.Helper()
	for _, o := range obs {
		if o.CheckID == id {
			return o
		}
	}
	t.Fatalf("missing check %s", id)
	return model.Observation{}
}

func TestNoPathTestsWithoutOptIn(t *testing.T) {
	if obs := Run(context.Background(), Options{Workspace: t.TempDir()}); len(obs) != 0 {
		t.Fatal("default invocation performed active tests")
	}
}
func TestDiskUsesOwnedUnnamedFileAndPreservesWorkspace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "user-data")
	original := []byte("private user content must not be read or modified")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	obs := Run(context.Background(), Options{Workspace: dir, DiskBytes: DefaultDiskBytes, Timeout: 5 * time.Second})
	if o := byCheck(t, obs, "F07"); o.Status != model.Pass || o.Value.(map[string]any)["tested_bytes"] != DefaultDiskBytes {
		t.Fatalf("integrity failed: %+v", o)
	}
	if o := byCheck(t, obs, "F05"); o.Status != model.Pass || o.Value.(map[string]any)["write"].(map[string]any)["p95_ms"] == nil {
		t.Fatalf("default budget should provide qualified sample count: %+v", o)
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 1 || entries[0].Name() != "user-data" {
		t.Fatalf("test left named artifacts: %v %v", entries, e)
	}
	current, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(current, original) {
		t.Fatal("user file changed")
	}
	encoded, _ := json.Marshal(obs)
	if strings.Contains(string(encoded), dir) || strings.Contains(string(encoded), string(original)) {
		t.Fatal("workspace path or user content exported")
	}
}
func TestDiskPartialCancellationCleansOwnedScratch(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { time.Sleep(time.Millisecond); cancel() }()
	obs := Run(ctx, Options{Workspace: dir, DiskBytes: MaxDiskBytes, Timeout: time.Second})
	if o := byCheck(t, obs, "F07"); o.Status != model.TimeBudgetExhausted {
		t.Fatalf("cancelled test claimed integrity: %+v", o)
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 0 {
		t.Fatalf("cancellation left scratch files: %v %v", entries, e)
	}
}
func TestDiskValidationAndSmallSampleLimits(t *testing.T) {
	for _, opts := range []Options{{DiskBytes: 1}, {Workspace: t.TempDir(), DiskBytes: MaxDiskBytes + 1}, {Workspace: t.TempDir(), DiskBytes: -1}} {
		obs := Run(context.Background(), opts)
		if byCheck(t, obs, "F03").Status == model.Pass {
			t.Fatal("invalid disk budget/workspace accepted")
		}
	}
	obs := Run(context.Background(), Options{Workspace: t.TempDir(), DiskBytes: 1 << 20})
	o := byCheck(t, obs, "F05")
	if o.Status != model.Warning {
		t.Fatal("tiny tail sample passed")
	}
	summary := o.Value.(map[string]any)["write"].(map[string]any)
	if _, exists := summary["p95_ms"]; exists {
		t.Fatal("p95 emitted from insufficient operation count")
	}
}

type corruptOnSync struct{ *os.File }

func (f corruptOnSync) Sync() error {
	if _, err := f.WriteAt([]byte{0xff}, 0); err != nil {
		return err
	}
	return f.File.Sync()
}
func TestReadbackDetectsActualCorruption(t *testing.T) {
	f, e := os.CreateTemp(t.TempDir(), "owned-*")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	m, e := exerciseFile(context.Background(), corruptOnSync{f}, blockBytes+17)
	if e != nil || !m.Complete || m.Expected == m.Actual {
		t.Fatalf("corrupt readback escaped detection: %+v %v", m, e)
	}
}

func TestEndpointValidationDoesNotAcceptCredentialURLs(t *testing.T) {
	for _, raw := range []string{"http://example.invalid/object", "https://user:secret@example.invalid/object", "https://example.invalid/object?token=secret", "https://example.invalid/object?", "https://example.invalid/object#secret", "https:///object"} {
		if _, err := validateEndpoint(raw); err == nil {
			t.Fatalf("unsafe URL accepted: %s", raw)
		}
	}
	if _, err := validateEndpoint("https://example.invalid:443/public/model.bin"); err != nil {
		t.Fatal(err)
	}
}
func tlsFixture(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *http.Client) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	client := newHTTPClient(time.Second)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client.Transport.(*http.Transport).TLSClientConfig.RootCAs = roots
	t.Cleanup(client.CloseIdleConnections)
	return server, client
}

func TestDownloadCapsPayloadAndExportsNoURLOrBody(t *testing.T) {
	var requests atomic.Int32
	server, client := tlsFixture(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "" || r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("Range") != "bytes=0-1023" {
			t.Errorf("unexpected request headers: %+v", r.Header)
		}
		_, _ = io.WriteString(w, strings.Repeat("PRIVATE-RESPONSE-CONTENT", 1024))
	})
	opts := Options{URL: server.URL + "/private-name", DownloadBytes: 1024}
	obs := runNetwork(context.Background(), opts, client)
	o := byCheck(t, obs, "G03")
	if o.Status != model.Pass || o.Value.(map[string]any)["downloaded_body_bytes"] != int64(1024) || requests.Load() != 1 {
		t.Fatalf("download cap/request count failed: %+v", o)
	}
	encoded, _ := json.Marshal(obs)
	if strings.Contains(string(encoded), "PRIVATE-RESPONSE-CONTENT") || strings.Contains(string(encoded), "private-name") || strings.Contains(string(encoded), server.URL) {
		t.Fatal("endpoint/body leaked into evidence")
	}
}
func TestRedirectIsNotFollowed(t *testing.T) {
	var follow atomic.Int32
	server, client := tlsFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/next" {
			follow.Add(1)
			w.WriteHeader(200)
			return
		}
		w.Header().Set("Location", "/next")
		w.WriteHeader(http.StatusFound)
	})
	obs := runNetwork(context.Background(), Options{URL: server.URL + "/first", DownloadBytes: 1024}, client)
	if follow.Load() != 0 || byCheck(t, obs, "G02").Status != model.Pass || byCheck(t, obs, "G03").Status != model.Fail {
		t.Fatalf("redirect was followed or misclassified: %+v", obs)
	}
}
func TestTLSVerificationRemainsRequired(t *testing.T) {
	server, _ := tlsFixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "not-reached") })
	client := newHTTPClient(time.Second)
	defer client.CloseIdleConnections()
	obs := runNetwork(context.Background(), Options{URL: server.URL, DownloadBytes: 1024}, client)
	if o := byCheck(t, obs, "G02"); o.Status != model.Fail || !strings.Contains(o.Message, "TLS certificate") {
		t.Fatalf("untrusted certificate was not rejected: %+v", o)
	}
}
func TestTransportDoesNotUseEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "https://secret-proxy.invalid")
	client := newHTTPClient(time.Second)
	defer client.CloseIdleConnections()
	transport := client.Transport.(*http.Transport)
	if transport.Proxy != nil || transport.TLSClientConfig.InsecureSkipVerify || !transport.DisableCompression {
		t.Fatal("transport weakened trust/privacy defaults")
	}
}
func TestDownloadCancellationAndHTTPFailure(t *testing.T) {
	server, client := tlsFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		<-r.Context().Done()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	obs := runNetwork(ctx, Options{URL: server.URL + "/slow", DownloadBytes: 1024}, client)
	if byCheck(t, obs, "G03").Status != model.TimeBudgetExhausted {
		t.Fatal("network deadline lost")
	}
	obs = runNetwork(context.Background(), Options{URL: server.URL + "/missing", DownloadBytes: 1024}, client)
	if byCheck(t, obs, "G02").Status != model.Pass || byCheck(t, obs, "G03").Status != model.Fail {
		t.Fatal("HTTP reachability and object failure conflated")
	}
}
