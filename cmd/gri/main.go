// Command gri performs local, bounded inspection of one selected rented GPU.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/harishappana/gpu-inspector/internal/bundle"
	"github.com/harishappana/gpu-inspector/internal/catalog"
	"github.com/harishappana/gpu-inspector/internal/collect"
	"github.com/harishappana/gpu-inspector/internal/model"
	"github.com/harishappana/gpu-inspector/internal/reference"
	"github.com/harishappana/gpu-inspector/internal/report"
	"github.com/harishappana/gpu-inspector/internal/rules"
	"github.com/harishappana/gpu-inspector/internal/scan"
	"github.com/harishappana/gpu-inspector/internal/worker"
	"io"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	if collect.HandleInternalCommand(os.Args[1:]) || scan.HandleInternalCommand(os.Args[1:]) {
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
func flags(name string, stderr io.Writer) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(stderr)
	return f
}
func parse(f *flag.FlagSet, args []string) error {
	if err := f.Parse(args); err != nil {
		return err
	}
	if len(f.Args()) != 0 {
		return fmt.Errorf("unexpected argument %q", f.Args()[0])
	}
	return nil
}
func run(ctx context.Context, args []string, out, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(out, usage)
		return 0
	}
	var err error
	switch args[0] {
	case "version", "--version":
		fmt.Fprintf(out, "gri %s | schema %s | methods %s | development, unqualified\n", model.ToolVersion, model.SchemaVersion, model.MethodVersion)
	case "scan":
		return scanCommand(ctx, args[1:], out, stderr)
	case "demo":
		err = demoCommand(args[1:], out, stderr)
	case "catalog":
		err = catalogCommand(args[1:], out, stderr)
	case "explain":
		err = explainCommand(args[1:], out, stderr)
	case "ticket":
		err = ticketCommand(args[1:], out, stderr)
	case "verify":
		err = verifyCommand(args[1:], out, stderr)
	case "export":
		err = exportCommand(args[1:], out, stderr)
	case "cleanup":
		err = cleanupCommand(args[1:], out, stderr)
	case "replay":
		err = replayCommand(args[1:], out, stderr)
	case "keys":
		err = keysCommand(args[1:], out, stderr)
	case "sign":
		err = signCommand(args[1:], out, stderr)
	case "manifest":
		err = manifestCommand(args[1:], out, stderr)
	default:
		err = fmt.Errorf("unknown command %q; run gri help", args[0])
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "gri:", err)
		return 1
	}
	return 0
}

func scanCommand(ctx context.Context, args []string, out, stderr io.Writer) int {
	f := flags("scan", stderr)
	var o scan.Options
	f.StringVar(&o.Device, "device", "", "full permitted GPU UUID; mandatory when multiple GPUs are visible")
	f.StringVar(&o.ExpectedSKU, "expected-sku", "", "user-declared expected exact SKU")
	f.StringVar(&o.Tier, "tier", "quick", "quick or standard")
	f.StringVar(&o.Profile, "profile", "general", "general, inference, training or rendering; priorities only")
	f.StringVar(&o.Output, "output", "", "new private output directory (default reports/<UTC>)")
	f.StringVar(&o.Workspace, "workspace", "", "selected path for capacity context and opted-in scratch tests")
	budget := f.Float64("budget-seconds", 0, "scan cap in seconds; default Quick90/Standard300")
	f.IntVar(&o.MemoryMiB, "memory-mib", 0, "owned CUDA allocation cap; default Quick256/Standard1024 MiB")
	f.Uint64Var(&o.Seed, "seed", 1, "reproducible unsigned 32-bit seed")
	f.StringVar(&o.WorkerPath, "worker", "", "signed CUDA worker executable")
	f.StringVar(&o.WorkerManifest, "worker-manifest", "", "signed worker manifest envelope")
	f.StringVar(&o.WorkerPublicKey, "worker-public-key", "", "explicitly trusted Ed25519 PEM key")
	f.BoolVar(&o.AllowUnqualifiedWorker, "allow-unqualified-worker", false, "allow development acceptance work; readiness remains unqualified")
	f.StringVar(&o.ReferencePath, "reference", "", "signed qualified reference envelope")
	f.StringVar(&o.ReferencePublicKey, "reference-public-key", "", "trusted reference Ed25519 PEM public key")
	price := f.Float64("price-per-hour", 0, "optional user-declared rental price per hour")
	currency := f.String("currency", "USD", "three-letter currency for the declared price")
	f.Float64Var(&o.MaxTemperatureC, "max-temperature-c", 0, "optional user-selected active-test stop ceiling")
	f.Int64Var(&o.DiskBytes, "disk-test-bytes", 0, "Standard only: opt in to test-owned scratch bytes (max64MiB)")
	f.StringVar(&o.Endpoint, "endpoint", "", "Standard only: explicitly authorized HTTPS object URL, no credentials/query/redirects")
	f.Int64Var(&o.DownloadBytes, "download-bytes", 0, "explicit endpoint response-body cap; default8MiB, max64MiB")
	if err := parse(f, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	visited := map[string]bool{}
	f.Visit(func(v *flag.Flag) { visited[v.Name] = true })
	if !visited["budget-seconds"] {
		*budget = 90
		if o.Tier == "standard" {
			*budget = 300
		}
	}
	if math.IsNaN(*budget) || math.IsInf(*budget, 0) || *budget < 1 || *budget > 900 {
		fmt.Fprintln(stderr, "gri: budget-seconds must be finite and between 1 and 900")
		return 1
	}
	o.Budget = time.Duration(*budget * float64(time.Second))
	if !visited["memory-mib"] {
		o.MemoryMiB = 256
		if o.Tier == "standard" {
			o.MemoryMiB = 1024
		}
	}
	if o.Output == "" {
		o.Output = filepath.Join("reports", time.Now().UTC().Format("20060102T150405.000000000Z"))
	}
	if visited["price-per-hour"] {
		o.Price = &model.Price{PerHour: *price, Currency: strings.ToUpper(*currency), Source: "user-declared"}
	}
	if visited["download-bytes"] && o.Endpoint == "" {
		fmt.Fprintln(stderr, "gri: download-bytes requires an explicit endpoint")
		return 1
	}
	if visited["worker"] || visited["worker-manifest"] || visited["worker-public-key"] {
		if o.WorkerPath == "" || o.WorkerManifest == "" || o.WorkerPublicKey == "" {
			fmt.Fprintln(stderr, "gri: worker, worker-manifest and worker-public-key must be supplied together")
			return 1
		}
	}
	if (o.ReferencePath == "") != (o.ReferencePublicKey == "") {
		fmt.Fprintln(stderr, "gri: reference and reference-public-key must be supplied together")
		return 1
	}
	o.Progress = func(s string) { fmt.Fprintln(stderr, "gri:", s) }
	r, err := scan.Run(ctx, o)
	if err != nil {
		fmt.Fprintln(stderr, "gri:", err)
		return 1
	}
	fmt.Fprint(out, report.Terminal(r))
	fmt.Fprintf(out, "Artifacts: %s\n", o.Output)
	if r.Cancelled {
		return 130
	}
	switch r.Verdict {
	case model.DoNotStart:
		return 2
	case model.Inconclusive:
		return 3
	}
	return 0
}

func catalogCommand(args []string, out, stderr io.Writer) error {
	f := flags("catalog", stderr)
	asJSON := f.Bool("json", false, "emit versioned catalog JSON")
	if err := parse(f, args); err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(out).Encode(catalog.All())
	}
	fmt.Fprintln(out, "147 design checks. Q=Quick, S=Standard, O=opt-in extension, F=future. Catalog presence is not implementation or coverage.")
	for _, c := range catalog.All() {
		fmt.Fprintf(out, "%s [%s] %s\n", c.ID, c.Stage, c.Name)
	}
	return nil
}

func loadVerified(path string) (model.Report, error) {
	if filepath.Base(path) != "report.json" {
		return model.Report{}, errors.New("expected the report.json inside a verified evidence directory")
	}
	if err := report.Verify(filepath.Dir(path)); err != nil {
		return model.Report{}, err
	}
	return report.Read(path)
}
func explainCommand(args []string, out, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: gri explain FINDING --report DIR/report.json")
	}
	id := args[0]
	f := flags("explain", stderr)
	path := f.String("report", "", "retained report JSON")
	if err := parse(f, args[1:]); err != nil {
		return err
	}
	r, err := loadVerified(*path)
	if err != nil {
		return err
	}
	text, err := report.Explain(r, id)
	if err == nil {
		fmt.Fprint(out, text)
	}
	return err
}
func ticketCommand(args []string, out, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "draft" {
		return errors.New("only local 'ticket draft' is supported")
	}
	f := flags("ticket draft", stderr)
	path := f.String("report", "", "retained report JSON")
	provider := f.String("provider", "generic", "generic local draft; no submission integration")
	output := f.String("output", "", "optional new local Markdown file")
	if err := parse(f, args[1:]); err != nil {
		return err
	}
	if *provider != "generic" {
		return errors.New("only provider generic is implemented; no policy or refund entitlement is inferred")
	}
	r, err := loadVerified(*path)
	if err != nil {
		return err
	}
	data := []byte(report.TicketDraft(r))
	if *output != "" {
		if err = bundle.WriteNew(*output, data, 0600); err != nil {
			return err
		}
		fmt.Fprintf(out, "Local redacted ticket draft: %s\n", *output)
	} else {
		_, err = out.Write(data)
	}
	return err
}
func verifyCommand(args []string, out, stderr io.Writer) error {
	f := flags("verify", stderr)
	dir := f.String("report-dir", "", "private evidence directory")
	if err := parse(f, args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("report-dir is required")
	}
	if err := report.Verify(*dir); err != nil {
		return err
	}
	fmt.Fprintln(out, "Verified listed artifact bytes and private permissions. Hash integrity is not host authentication.")
	return nil
}
func exportCommand(args []string, out, stderr io.Writer) error {
	f := flags("export", stderr)
	dir := f.String("report-dir", "", "source evidence directory")
	dest := f.String("output", "", "new redacted output directory")
	if err := parse(f, args); err != nil {
		return err
	}
	if *dir == "" || *dest == "" {
		return errors.New("report-dir and output are required")
	}
	if err := report.Export(*dir, *dest); err != nil {
		return err
	}
	fmt.Fprintf(out, "Verified redacted export: %s\n", *dest)
	return nil
}
func cleanupCommand(args []string, out, stderr io.Writer) error {
	f := flags("cleanup", stderr)
	dir := f.String("report-dir", "", "verified GRI evidence directory to remove")
	if err := parse(f, args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("report-dir is required")
	}
	if err := report.Verify(*dir); err != nil {
		return fmt.Errorf("cleanup refused without a valid owned artifact index: %w", err)
	}
	entries, err := os.ReadDir(*dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err = os.Remove(filepath.Join(*dir, entry.Name())); err != nil {
			return err
		}
	}
	if err = os.Remove(*dir); err != nil {
		return err
	}
	fmt.Fprintln(out, "Removed only the verified GRI report artifacts and their directory.")
	return nil
}

func keysCommand(args []string, out, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "generate" {
		return errors.New("usage: gri keys generate --output NEW_DIR")
	}
	f := flags("keys generate", stderr)
	dir := f.String("output", "", "new private key directory on trusted build host")
	if err := parse(f, args[1:]); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("output is required")
	}
	if err := bundle.GenerateKeys(*dir); err != nil {
		return err
	}
	fmt.Fprintln(out, "Generated local development Ed25519 keys. This key is not a product release trust root; keep private.pem on the trusted build host.")
	return nil
}
func signCommand(args []string, out, stderr io.Writer) error {
	f := flags("sign", stderr)
	path := f.String("input", "", "manifest/reference payload file")
	keyPath := f.String("key", "", "private PEM key file (never key material in arguments)")
	dest := f.String("output", "", "new signed envelope file")
	if err := parse(f, args); err != nil {
		return err
	}
	if *path == "" || *keyPath == "" || *dest == "" {
		return errors.New("input, key and output are required")
	}
	data, err := bundle.ReadLimited(*path, 2<<20)
	if err != nil {
		return err
	}
	key, err := bundle.LoadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	signed, err := bundle.Sign(data, key)
	if err != nil {
		return err
	}
	if err = bundle.WriteNew(*dest, append(signed, '\n'), 0600); err != nil {
		return err
	}
	fmt.Fprintln(out, "Signed exact payload bytes. Qualification is a separate evidence requirement.")
	return nil
}
func manifestCommand(args []string, out, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "worker" {
		return errors.New("usage: gri manifest worker --binary FILE --output FILE")
	}
	f := flags("manifest worker", stderr)
	binary := f.String("binary", "", "Linux amd64 CUDA worker executable")
	dest := f.String("output", "", "new unsigned manifest file")
	if err := parse(f, args[1:]); err != nil {
		return err
	}
	if *binary == "" || *dest == "" {
		return errors.New("binary and output are required")
	}
	data, err := bundle.ReadLimited(*binary, 128<<20)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	m := worker.Manifest{Kind: "gri-worker", Version: model.ToolVersion, MethodVersion: model.MethodVersion, Platform: "linux-amd64", File: filepath.Base(*binary), SHA256: hex.EncodeToString(digest[:]), Qualified: false, QualificationEvidence: []string{}}
	contents, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err = bundle.WriteNew(*dest, append(contents, '\n'), 0600); err != nil {
		return err
	}
	fmt.Fprintln(out, "Created an unsigned, unqualified manifest. It does not assert executable architecture, CUDA compatibility or numerical qualification.")
	return nil
}

func replayCommand(args []string, out, stderr io.Writer) error {
	f := flags("replay", stderr)
	path := f.String("report", "", "original retained report.json")
	dest := f.String("output", "", "new reevaluated evidence directory")
	refPath := f.String("reference", "", "optional signed qualified reference")
	refKey := f.String("reference-public-key", "", "explicit trusted reference key")
	if err := parse(f, args); err != nil {
		return err
	}
	if *dest == "" {
		return errors.New("output is required")
	}
	if (*refPath == "") != (*refKey == "") {
		return errors.New("reference and reference-public-key must be supplied together")
	}
	r, err := loadVerified(*path)
	if err != nil {
		return err
	}
	var p *reference.Pack
	if *refPath != "" {
		key, e := bundle.LoadPublicKey(*refKey)
		if e != nil {
			return e
		}
		p, e = reference.Load(*refPath, key, time.Now().UTC())
		if e != nil {
			return e
		}
	}
	r.OriginalScanID = r.ScanID
	r.ScanID = r.ScanID + "-replay-" + time.Now().UTC().Format("150405.000000000")
	r.ArtifactHashes = map[string]string{}
	r.Limitations = append(r.Limitations, "Reevaluated retained observations with rule "+model.RuleVersion+" at "+time.Now().UTC().Format(time.RFC3339)+". No new hardware work was performed; the original observation interval is preserved.")
	rules.Evaluate(&r, p)
	if err = report.Write(*dest, r); err != nil {
		return err
	}
	fmt.Fprint(out, report.Terminal(r))
	fmt.Fprintf(out, "Reevaluated artifact: %s\n", *dest)
	return nil
}

const usage = `GPU Rental Inspector (gri) — development implementation

  gri scan --tier quick [--device GPU-<full-uuid>] [--output DIR]
  gri scan --tier standard --budget-seconds 300 --expected-sku h100-pcie-80gb
  gri demo --scenario clean|ecc-error|missing --output DIR
  gri catalog [--json]
  gri explain FINDING --report DIR/report.json
  gri ticket draft --report DIR/report.json --provider generic [--output FILE]
  gri verify --report-dir DIR
  gri export --report-dir DIR --output NEW_DIR
  gri replay --report DIR/report.json --output NEW_DIR
  gri cleanup --report-dir DIR
  gri keys generate --output NEW_DIR
  gri manifest worker --binary FILE --output FILE
  gri sign --input FILE --key PRIVATE_PEM --output FILE
  gri version

Run a command with --help for its flags. Quick and Standard are local and free.
No qualified worker or healthy reference ships with this development source.
Missing dependencies/calibration produce an explicit INCONCLUSIVE report.
Active workers require Linux x86-64 and a signed, explicitly trusted artifact.

Scan exit codes: 0 keep/keep-with-caveats; 1 operational/usage error;
2 do-not-start; 3 inconclusive; 130 cancellation with partial report.
Demo/replay commands return 0 when their report workflow succeeds.
`
