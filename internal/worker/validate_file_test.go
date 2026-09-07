package worker

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func parseRequestFixtureBytes(t *testing.T, r Result) []byte {
	t.Helper()
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseRequestAdmitsAllMethodContractsAndRetainsPendingQualification(t *testing.T) {
	for _, method := range []string{"memory_integrity", "fp32_gemm", "bf16_gemm", "tf32_gemm", "hbm_copy", "h2d", "d2h", "working_set", "dispatch_latency", "int8_gemm", "fp8_gemm", "numa_transfer"} {
		t.Run(method, func(t *testing.T) {
			r := protocolFixture(method, "quick")
			if method == "int8_gemm" || method == "fp8_gemm" {
				r = lowPrecisionFixture(method)
			}
			if method == "numa_transfer" {
				r = numaFixture()
			}
			got, err := ParseRequest(parseRequestFixtureBytes(t, r), request(method, "quick"), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != "ok" || got.Method != method || got.DeviceUUID != testUUID || got.Conditions["worker_qualification"] != "pending_real_gpu_acceptance" || len(got.Limitations) == 0 {
				t.Fatalf("protocol admission lost request/provenance boundaries: %+v", got)
			}
		})
	}
	r := protocolFixture("memory_integrity", "standard")
	if _, err := ParseRequest(parseRequestFixtureBytes(t, r), request("memory_integrity", "standard"), time.Second); err != nil {
		t.Fatal("complete eight-pass Standard result rejected: ", err)
	}
}

func TestParseRequestRejectsValidResultFromDifferentInvocation(t *testing.T) {
	data := parseRequestFixtureBytes(t, protocolFixture("h2d", "quick"))
	// The recorded output is independently valid. Rejection must come from the
	// public request boundary, not malformed result conditions.
	if _, err := Parse(data, testUUID, "h2d", time.Second); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Request)
	}{
		{"seed", func(q *Request) { q.Seed++ }},
		{"memory cap", func(q *Request) { q.MemoryMiB *= 2 }},
		{"budget", func(q *Request) { q.Budget *= 2 }},
		{"tier", func(q *Request) { q.Tier = "standard" }},
		{"method", func(q *Request) { q.Method = "d2h" }},
		{"selected UUID", func(q *Request) { q.Device.UUID = "GPU-11111111-2222-3333-4444-555555555555" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := request("h2d", "quick")
			tc.change(&q)
			if _, err := ParseRequest(data, q, time.Second); err == nil {
				t.Fatal("different retained invocation accepted")
			}
		})
	}
	if _, err := ParseRequest(data, request("h2d", "quick"), 50*time.Millisecond); err == nil {
		t.Fatal("reported worker lifetime exceeded actual parent duration")
	}
}

func TestParseRequestPreservesUnavailableAndMismatchStatuses(t *testing.T) {
	for _, status := range []string{"unsupported", "blocked", "test_error", "budget_exhausted", "mismatch"} {
		t.Run(status, func(t *testing.T) {
			r := protocolFixture("h2d", "quick")
			r.Status = status
			r.Metric = nil
			if status == "mismatch" {
				r.Correctness.MismatchCount = 1
				r.Correctness.MismatchLowerBound = 1
				r.Correctness.CountIsLowerBound = true
				r.Correctness.Examples = []map[string]any{{"logical_index": 0, "expected": 1, "observed": 2}}
			} else {
				// Initialization can fail before an invocation echo or samples exist.
				r.Conditions = nil
				r.Samples = nil
				r.SampleCount = 0
				r.Correctness = Correctness{}
				r.Timings = Timings{WallMS: 1}
				r.Spread.Median = nil
				r.Spread.MAD = nil
			}
			r.Errors = []map[string]any{{"code": "synthetic_fixture_only"}}
			got, err := ParseRequest(parseRequestFixtureBytes(t, r), request("h2d", "quick"), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != status || got.Metric != nil || len(got.Errors) != 1 {
				t.Fatal("data admission promoted a nonpassing worker result")
			}
		})
	}
}

func TestParseRequestRetainsStrictParserAndNumericalGates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Result)
	}{
		{"unchecked", func(r *Result) { r.Correctness.Checked = false }},
		{"synthetic", func(r *Result) { r.Correctness.Synthetic = true }},
		{"bad arithmetic", func(r *Result) { r.Conditions["transfer_bytes"] = float64(32 << 20) }},
		{"non-rechecked UUID", func(r *Result) { r.Conditions["selected_uuid_rechecked"] = false }},
		{"mismatch without evidence", func(r *Result) { r.Status = "mismatch"; r.Metric = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := protocolFixture("h2d", "quick")
			tc.change(&r)
			if _, err := ParseRequest(parseRequestFixtureBytes(t, r), request("h2d", "quick"), time.Second); err == nil {
				t.Fatal("public wrapper bypassed protocol validation")
			}
		})
	}
	data := parseRequestFixtureBytes(t, protocolFixture("h2d", "quick"))
	for _, bad := range [][]byte{append(append([]byte(nil), data...), []byte("\n{}")...), []byte(strings.Replace(string(data), `"status":"ok"`, `"status":"ok","status":"ok"`, 1)), []byte(strings.Replace(string(data), `"status":"ok"`, `"status":"ok","unknown":true`, 1))} {
		if _, err := ParseRequest(bad, request("h2d", "quick"), time.Second); err == nil {
			t.Fatal("ambiguous worker document accepted")
		}
	}
}
