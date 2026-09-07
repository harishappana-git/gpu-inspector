package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
	"github.com/harishappana/gpu-inspector/internal/secureexec"
)

const selectedUUID = "GPU-01234567-89ab-cdef-0123-456789abcdef"

func selectedDevice() model.Device {
	return model.Device{UUID: selectedUUID, PCIAddress: "00000000:03:00.0", Index: 0, Name: "NVIDIA H100 PCIe", SKU: "h100-pcie-80gb", MIGMode: "disabled", VirtualizationMode: "none"}
}

var intervalStart = time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)

func journalRow(timestamp time.Time, message, transport string) string {
	b, _ := json.Marshal(map[string]any{"__REALTIME_TIMESTAMP": strconv.FormatInt(timestamp.UnixMicro(), 10), "_TRANSPORT": transport, "MESSAGE": message, "_HOSTNAME": "PRIVATE-HOST"})
	return string(b) + "\n"
}

func TestXidRestrictsPCIIntervalAndExportsOnlyCodes(t *testing.T) {
	data := journalRow(intervalStart.Add(time.Second), "NVRM: Xid (PCI:0000:03:00): 31, pid=PRIVATE-PID name=SECRET-WORKLOAD", "kernel") +
		journalRow(intervalStart.Add(time.Second), "NVRM: Xid (PCI:0000:03:00): 31, duplicate delivery", "kernel") +
		journalRow(intervalStart.Add(2*time.Second), "NVRM: Xid (0000:03:00): 79, PRIVATE-ADDRESS", "kernel") +
		journalRow(intervalStart.Add(time.Second), "NVRM: Xid (PCI:0000:04:00): 48, OTHER-GPU", "kernel") +
		journalRow(intervalStart.Add(-time.Second), "NVRM: Xid (PCI:0000:03:00): 43, OLD-EVENT", "kernel") +
		journalRow(intervalStart.Add(time.Second), "NVRM: Xid (PCI:0000:03:00): 94, USER-INJECTION", "stdout")
	opts := Options{Runner: func(ctx context.Context, tool string, args []string, env map[string]string, limit int) secureexec.Result {
		if tool != "journalctl" || limit != 1<<20 || len(env) != 0 {
			t.Fatal("unexpected log scope")
		}
		joined := strings.Join(args, " ")
		for _, required := range []string{"--kernel", "--boot=0", "--system", "--since=@", "--until=@", "--no-pager", "--output=json"} {
			if !strings.Contains(joined, required) {
				t.Fatalf("unbounded journal command: %s", joined)
			}
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("journal execution has no deadline")
		}
		return secureexec.Result{Stdout: []byte(data)}
	}}
	o := xid(context.Background(), selectedDevice(), intervalStart, intervalStart.Add(5*time.Second), opts)
	if o.Status != model.Warning || o.ResourceID != selectedUUID || o.SampleCount != 2 {
		t.Fatalf("wrong scoped Xid evidence: %+v", o)
	}
	encoded, _ := json.Marshal(o)
	for _, private := range []string{"PRIVATE-", "SECRET-", "OTHER-GPU", "OLD-EVENT", "USER-INJECTION", "pid="} {
		if strings.Contains(string(encoded), private) {
			t.Fatalf("private/raw event payload exported: %s", private)
		}
	}
	if o.Conditions["complete_event_history"] != false || o.Conditions["physical_defect_attribution"] != false {
		t.Fatal("Xid event became a universal hardware diagnosis")
	}
	value := o.Value.(map[string]any)
	if value["xid_31_observed"] != true || value["xid_79_observed"] != true || value["xid_48_observed"] != nil || value["xid_43_observed"] != nil || value["xid_94_observed"] != nil {
		t.Fatal("advisory selector was missing or escaped selected PCI/time/kernel scope")
	}
}

func TestXidMissingDeniedEmptyAndPartialEvidence(t *testing.T) {
	cases := []struct {
		name   string
		result secureexec.Result
		status model.Status
		value  bool
	}{
		{"missing", secureexec.Result{Err: os.ErrNotExist, ExitCode: -1}, model.DependencyMissing, false},
		{"denied", secureexec.Result{Stderr: []byte("Hint: You are currently not seeing messages from other users. PRIVATE"), ExitCode: 1, Err: errors.New("private raw error")}, model.PermissionDenied, false},
		{"empty", secureexec.Result{ExitCode: 1, Err: errors.New("exit status 1")}, model.Pass, true},
		{"empty marker", secureexec.Result{Stdout: []byte("-- No entries --\n"), ExitCode: 1, Err: errors.New("exit status 1")}, model.Pass, true},
		{"empty but denied", secureexec.Result{Err: os.ErrPermission, ExitCode: 1}, model.PermissionDenied, false},
		{"malformed", secureexec.Result{Stdout: []byte("not json SECRET")}, model.ToolError, false},
		{"partial", secureexec.Result{Stdout: []byte(journalRow(intervalStart, "NVRM: Xid (PCI:0000:03:00): 31, SECRET", "kernel") + "truncated"), Truncated: true}, model.Warning, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := xid(context.Background(), selectedDevice(), intervalStart, intervalStart.Add(time.Second), Options{Runner: func(context.Context, string, []string, map[string]string, int) secureexec.Result { return tc.result }})
			if o.Status != tc.status || (o.Value != nil) != tc.value {
				t.Fatalf("absence/partial status lost: %+v", o)
			}
			data, _ := json.Marshal(o)
			if strings.Contains(string(data), "SECRET") || strings.Contains(string(data), "PRIVATE") {
				t.Fatal("raw tool error exported")
			}
		})
	}
}

func TestXidInvalidTargetAndCancellationPreventExecution(t *testing.T) {
	calls := 0
	opts := Options{Runner: func(context.Context, string, []string, map[string]string, int) secureexec.Result {
		calls++
		return secureexec.Result{}
	}}
	d := selectedDevice()
	d.UUID = "GPU-prefix"
	if o := xid(context.Background(), d, intervalStart, intervalStart, opts); o.Status != model.Contaminated || calls != 0 {
		t.Fatal("partial UUID permitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if o := xid(ctx, selectedDevice(), intervalStart, intervalStart, opts); o.Status != model.TimeBudgetExhausted || calls != 0 {
		t.Fatal("cancelled collector executed")
	}
}

func discoveryFixture(uuid, pci string) string {
	return fmt.Sprintf("1 GPU found (Active).\n| GPU ID | Device Information |\n| 7 | Name: NVIDIA H100 PCIe |\n| | PCI Bus ID: %s |\n| | Device UUID: %s |\n0 NvSwitches found.\n| Switch ID | |\n", pci, uuid)
}
func attributeFixture(uuid, pci string) string {
	return fmt.Sprintf("| GPU ID: 7 | Device Information |\n| UUID | %s |\n| PCI Bus ID | %s |\n| Serial Number | PRIVATE-SERIAL |\n", uuid, pci)
}
func diagnosticFixture(status string, id int) []byte {
	return []byte(fmt.Sprintf(`{"metadata":{"version":"4.6.0","Driver Version Detected":"570.00"},"entity_groups":[{"entity_group_id":1,"entity_group":"GPU","entities":[{"entity_id":%d,"device_id":"2330","serial_num":"PRIVATE-SERIAL"}]}],"DCGM Diagnostic":{"test_categories":[{"category":"Deployment","tests":[{"name":"software","results":[{"entity_group_id":1,"entity_group":"GPU","entity_id":%d,"status":%q,"info":["SECRET-INFO"],"warnings":[]}],"test_summary":{"status":%q}}]}]}}`, id, id, status, status))
}

type dcgmFixtureRunner struct {
	t               *testing.T
	calls           int
	diagnosticCalls int
	list            string
	version         string
	engineVersion   string
	output          []byte
	exit            int
	cancel          bool
	postMismatch    bool
}

func (f *dcgmFixtureRunner) run(ctx context.Context, tool string, args []string, env map[string]string, limit int) secureexec.Result {
	f.calls++
	if tool != "dcgmi" || len(env) != 0 || limit > 1<<20 {
		f.t.Fatal("unexpected vendor execution")
	}
	if _, ok := ctx.Deadline(); !ok {
		f.t.Fatal("vendor command is unbounded")
	}
	if len(args) == 1 && args[0] == "--version" {
		version := f.version
		if version == "" {
			version = "4.6.0"
		}
		return secureexec.Result{Stdout: []byte("dcgmi version: " + version + "\n")}
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--host "+localDCGMHost) {
		f.t.Fatal("vendor command can autostart or contact another host")
	}
	if args[0] == "--vv" {
		version := f.engineVersion
		if version == "" {
			version = "4.6.0"
		}
		return secureexec.Result{Stdout: []byte("Local build info:\nVersion : 4.6.0\nBuild ID : PRIVATE-BUILD\nHostengine build info:\nVersion : " + version + "\nCommit ID : PRIVATE-COMMIT\n")}
	}
	if args[0] == "discovery" && args[1] == "--list" {
		data := f.list
		if data == "" {
			data = discoveryFixture(selectedUUID, "00000000:03:00.0")
		}
		return secureexec.Result{Stdout: []byte(data)}
	}
	if args[0] == "discovery" {
		if !strings.Contains(joined, "--gpuid 7") {
			f.t.Fatal("NVML index was substituted for DCGM identity")
		}
		uuid := selectedUUID
		if f.postMismatch && f.diagnosticCalls > 0 {
			uuid = "GPU-ffffffff-ffff-ffff-ffff-ffffffffffff"
		}
		return secureexec.Result{Stdout: []byte(attributeFixture(uuid, "00000000:03:00.0"))}
	}
	if args[0] != "diag" {
		f.t.Fatal("unexpected mutation command")
	}
	f.diagnosticCalls++
	for _, required := range []string{"--run 1", "--entity-id gpu:7", "--timeout ", "--enable-heartbeat", "--debugLevel NONE", "--json"} {
		if !strings.Contains(joined, required) {
			f.t.Fatalf("unsafe or unbounded diagnostic command: %s", joined)
		}
	}
	for _, forbidden := range []string{"--group", "--gpuList", "gpu:*", "cpu:", "--train", "--ignoreErrorCodes"} {
		if strings.Contains(joined, forbidden) {
			f.t.Fatalf("scope expansion: %s", joined)
		}
	}
	if f.cancel {
		return secureexec.Result{Err: context.DeadlineExceeded, ExitCode: -1}
	}
	output := f.output
	if output == nil {
		output = diagnosticFixture("Pass", 7)
	}
	var err error
	if f.exit != 0 {
		err = errors.New("PRIVATE-RAW-ERROR")
	}
	return secureexec.Result{Stdout: output, ExitCode: f.exit, Err: err}
}

func TestDCGMDispatchVerifiesNonmatchingManagementIndexAndContinuity(t *testing.T) {
	f := &dcgmFixtureRunner{t: t}
	o := dcgm(context.Background(), selectedDevice(), Options{DCGMEnabled: true, Timeout: 40 * time.Second, Runner: f.run})
	if o.Status != model.Pass || f.calls != 6 || f.diagnosticCalls != 1 || o.Conditions["stop_active"] != false || o.Conditions["daemon_completion_known"] != true {
		t.Fatalf("vendor workflow incomplete: %+v calls=%d", o, f.calls)
	}
	data, _ := json.Marshal(o)
	if strings.Contains(string(data), "PRIVATE-") || strings.Contains(string(data), "SECRET-") {
		t.Fatal("vendor raw serial/log content exported")
	}
}

func TestDCGMRefusesUnverifiedScopeAndUnsupportedVersions(t *testing.T) {
	for _, tc := range []struct {
		name, list, version string
		status              model.Status
	}{
		{"mismatched PCI", discoveryFixture(selectedUUID, "00000000:04:00.0"), "", model.Contaminated},
		{"duplicate mapping", discoveryFixture(selectedUUID, "00000000:03:00.0") + discoveryFixture(selectedUUID, "00000000:03:00.0"), "", model.Contaminated},
		{"unvalidated release", "", "3.3.9", model.Unsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &dcgmFixtureRunner{t: t, list: tc.list, version: tc.version}
			o := dcgm(context.Background(), selectedDevice(), Options{DCGMEnabled: true, Runner: f.run})
			if o.Status != tc.status || f.diagnosticCalls != 0 || o.Value != nil {
				t.Fatalf("unverified vendor dispatch: %+v", o)
			}
		})
	}
}

func TestDCGMFailureSkipTimeoutAndPostIdentityLossStopFurtherWork(t *testing.T) {
	for _, tc := range []struct {
		name   string
		f      dcgmFixtureRunner
		status model.Status
	}{
		{"vendor failure", dcgmFixtureRunner{output: diagnosticFixture("Fail", 7), exit: 226}, model.Warning},
		{"skipped", dcgmFixtureRunner{output: diagnosticFixture("Skip", 7)}, model.Warning},
		{"timeout", dcgmFixtureRunner{cancel: true}, model.TimeBudgetExhausted},
		{"native timeout", dcgmFixtureRunner{exit: 245}, model.TimeBudgetExhausted},
		{"wrong result entity", dcgmFixtureRunner{output: diagnosticFixture("Pass", 0)}, model.Contaminated},
		{"identity lost after result", dcgmFixtureRunner{postMismatch: true}, model.Contaminated},
		{"malformed", dcgmFixtureRunner{output: []byte(`{"SECRET":"PRIVATE"}`)}, model.ToolError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.f
			f.t = t
			o := dcgm(context.Background(), selectedDevice(), Options{DCGMEnabled: true, Runner: f.run})
			if o.Status != tc.status || o.Conditions["stop_active"] != true {
				t.Fatalf("vendor status did not stop active work: %+v", o)
			}
			if tc.status == model.TimeBudgetExhausted && o.Conditions["daemon_completion_known"] != false {
				t.Fatal("client kill claimed daemon termination")
			}
		})
	}
}

func TestDCGMOptInAndMinimumBudget(t *testing.T) {
	f := &dcgmFixtureRunner{t: t}
	o := dcgm(context.Background(), selectedDevice(), Options{Runner: f.run})
	if o.Status != model.NotTested || f.calls != 0 {
		t.Fatal("vendor diagnostics ran without opt-in")
	}
	o = dcgm(context.Background(), selectedDevice(), Options{DCGMEnabled: true, Timeout: time.Second, Runner: f.run})
	if o.Status != model.TimeBudgetExhausted || f.calls != 0 {
		t.Fatal("vendor diagnostics launched without native timeout budget")
	}
}

func TestDCGMValidatesHostVersionBeforeDispatch(t *testing.T) {
	for _, version := range []string{"4.5.0", "4.6.0-dev", "4.6.0\nVersion : 4.6.0"} {
		f := &dcgmFixtureRunner{t: t, engineVersion: version}
		o := dcgm(context.Background(), selectedDevice(), Options{DCGMEnabled: true, Runner: f.run})
		if o.Status != model.Unsupported || f.diagnosticCalls != 0 {
			t.Fatalf("unvalidated daemon version was dispatched: %+v", o)
		}
	}
}

func TestDCGMStructuredWarningsAndUnknownTestsNeverPass(t *testing.T) {
	warning := `"warnings":[{"error_id":42,"error_category":11,"error_severity":22,"warning":"PRIVATE-WARNING"}]`
	for _, tc := range []struct {
		name, from, to string
		status         model.Status
	}{
		{"numeric warning retained", `"warnings":[]`, warning, model.Warning},
		{"unknown warning schema", `"warnings":[]`, `"warnings":[{"warning":"PRIVATE-WARNING"}]`, model.ToolError},
		{"unknown subcheck", `"name":"software"`, `"name":"PRIVATE-UNKNOWN-TEST"`, model.Warning},
		{"wider suite", `"category":"Deployment"`, `"category":"Hardware"`, model.Contaminated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &dcgmFixtureRunner{t: t, output: []byte(strings.ReplaceAll(string(diagnosticFixture("Pass", 7)), tc.from, tc.to))}
			o := dcgm(context.Background(), selectedDevice(), Options{DCGMEnabled: true, Runner: f.run})
			if o.Status != tc.status || o.Conditions["stop_active"] != true {
				t.Fatalf("unrecognized/warning content became a pass: %+v", o)
			}
			data, _ := json.Marshal(o)
			if strings.Contains(string(data), "PRIVATE-") {
				t.Fatal("raw warning or name exported")
			}
			if tc.name == "numeric warning retained" && !strings.Contains(string(data), `"error_codes":[42]`) {
				t.Fatal("numeric vendor warning was discarded")
			}
		})
	}
}

func TestInjectedRunnerOutputIsCapped(t *testing.T) {
	r := runTool(context.Background(), Options{Runner: func(context.Context, string, []string, map[string]string, int) secureexec.Result {
		return secureexec.Result{Stdout: []byte(strings.Repeat("x", 4096)), Stderr: []byte(strings.Repeat("y", 4096))}
	}}, "dcgmi", []string{"--version"}, 1024)
	if !r.Truncated || len(r.Stdout) != 1024 || len(r.Stderr) != 1024 {
		t.Fatal("injected runner exceeded parser memory bound")
	}
}

func TestNonLinuxDiagnosticsAreExplicitlyUnsupported(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("non-Linux platform behavior")
	}
	called := false
	opts := Options{DCGMEnabled: true, Runner: func(context.Context, string, []string, map[string]string, int) secureexec.Result {
		called = true
		return secureexec.Result{}
	}}
	if Xid(context.Background(), selectedDevice(), intervalStart, intervalStart, opts).Status != model.Unsupported || DCGM(context.Background(), selectedDevice(), opts).Status != model.Unsupported || called {
		t.Fatal("Linux adapters attempted execution on a different OS")
	}
}
