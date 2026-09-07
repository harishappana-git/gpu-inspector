# GPU Rental Inspector

To test a real H100 server from Windows with automatic setup, execution, report retrieval and recovery, follow the [automated H100 setup guide](docs/H100_AUTOMATED_SETUP.md). After supplying the server connection once, run `./scripts/test-h100-server.cmd -Config ./h100-server.json`.

Local Windows/RTX 5080 implementation results, measured scope and rerun commands are recorded in [Windows RTX 5080 validation](docs/WINDOWS_RTX5080_VALIDATION.md).

The [H100 single-node guide and remaining checklist](docs/H100_SINGLE_NODE.md) cover the Linux build/run scripts, twelve Standard worker methods, selected-device Xid/DCGM diagnostics and signed OEM/driver advisory inputs.

GPU Rental Inspector (`gri`) is a local development CLI for examining **one selected NVIDIA GPU allocation** and its visible execution environment. It implements the Phase 1 source workflow in [Design v2.0](GPU_Rental_Inspector_Design_v2_0.md): bounded collection, isolated CUDA-worker integration, explicit missing-data states, deterministic assessment, private local reports and support drafts. Optional bounded workspace and HTTPS-object checks cover the Phase 1B extension.

**Current release state: development implementation, not qualified for production GPU acceptance.** No real H100 rental measurement, healthy-reference pack, production signing key or signed production worker is included. The development CUDA worker is explicitly unqualified. Reports with missing methods or calibration remain `INCONCLUSIVE` / `UNCALIBRATED`, with a null score. Passing software fixtures is not GPU qualification. Remaining work is tracked in [Implementation status](docs/IMPLEMENTATION_STATUS.md) and [Acceptance runbook](docs/ACCEPTANCE.md).

## Build and try the local workflow

The Go module requires Go 1.24 or later. The development and CI reproduction pin is **Go 1.24.5**, matching the initial development host; this pin is not a statement about current security support. The CLI uses the Go standard library and pinned `golang.org/x/sys` Windows APIs. CMake 3.24+, a C++17 compiler and CUDA/cuBLAS are separate worker-build dependencies.

```sh
make build
./bin/gri version
./bin/gri catalog
./bin/gri demo --scenario clean --output ./reports/demo-clean
./bin/gri verify --report-dir ./reports/demo-clean
```

`clean`, `ecc-error` and `missing` are **synthetic demonstration scenarios**. Even `clean` is an uncalibrated fixture, not a healthy GPU measurement. Use a new report directory for each run; retained reports are not overwritten. Open `reports/demo-clean/report.html` in a browser to inspect linked evidence, methods and limitations.

For a local observation on an authorized Linux NVIDIA allocation:

```sh
./bin/gri scan --tier quick --output ./reports/quick-001
```

The scanner auto-selects only when permitted visibility resolves to one unambiguous full GPU. With several visible GPUs, explicitly select the full UUID:

```sh
./bin/gri scan \
  --device GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee \
  --expected-sku h100-pcie-80gb \
  --tier quick --profile general \
  --budget-seconds 120 --memory-mib 256 \
  --output ./reports/quick-002
```

The UUID is a placeholder for the intended allocation. Numeric CUDA visibility masks are resolved through runtime enumeration rather than treated as management indices. Ambiguous mappings, MIG partitions, target changes and unsupported execution remain explicit limitations. macOS supports development, fixtures and degraded-mode reports; it is not the CUDA measurement target.

### Native Windows and RTX 5080

Windows x64 supports the existing CLI workflow: discovery and telemetry, bounded Quick/Standard scans, signed worker admission, eleven CUDA numerical methods including FP8/INT8, cancellation, reports, verification, replay, export, local tickets, signing, cleanup and opted-in disk/HTTPS checks. Standard also schedules a NUMA comparison that is explicitly unsupported on native Windows. The RTX 5080 worker targets SM120 and uses the card's reported capacity and cache size. Linux H100 builds retain SM90 and their separate qualification requirements. RTX results and references cannot stand in for H100 results.

Build and try the CLI in PowerShell with Go on `PATH`:

```powershell
go build -trimpath -o ./bin/gri.exe ./cmd/gri
./bin/gri.exe version
./bin/gri.exe demo --scenario clean --output ./reports/windows-demo-001
./bin/gri.exe verify --report-dir ./reports/windows-demo-001
./bin/gri.exe scan --tier quick --expected-sku rtx-5080-16gb --output ./reports/windows-quick-001
```

GPU methods additionally need Visual Studio 2022 C++ tools/Windows SDK, CMake and **CUDA Toolkit 12.8+ including cuBLAS**, using a compiler supported by that toolkit. In an x64 developer PowerShell, run `./scripts/build-windows.ps1 -CudaRoot $env:CUDA_PATH`; `-CPUOnly` builds the CLI and CPU harness without CUDA. See the [Windows build script](scripts/build-windows.ps1), [worker dependency instructions](worker/README.md) and [local acceptance procedure](docs/ACCEPTANCE.md). Sign the worker and its required adjacent CUDA runtime DLLs using repeated `manifest worker --dependency PATH` options, then supply `--worker`, `--worker-manifest`, `--worker-public-key` and `--allow-unqualified-worker` to a controlled scan. The manifest's platform defaults to the current OS/architecture; `--platform linux-amd64` or `--platform windows-amd64` declares a cross-built worker.

Windows process control uses owned Job Objects and per-device exclusion. Private evidence and keys use protected current-user-only Windows DACLs; verification rejects public permissions and junction/reparse redirects. Disk scratch uses an exclusive delete-on-close handle, including cleanup after process termination. File data is flushed before publication; Windows does not claim POSIX directory-fsync power-loss durability.

Hardware and OS capabilities remain explicit: the RTX 5080 has no MIG partitions, and unavailable ECC/remap fields are unsupported. Linux cgroups, PSI, `/dev/shm` and POSIX limits do not apply to Windows; native Windows memory, CPU, storage and interface context are collected where available. WDDM desktop processes can block the idle guard. Operators explicitly accepting desktop contention for development testing can use `--allow-busy`; primary performance evidence is marked `CONTAMINATED` while separate correctness observations remain available. Tests never change TDR, clocks, power limits or driver mode. Existing diagnostic gaps listed below remain gaps on both platforms. Reports stay uncalibrated until actual worker qualification and independently acquired matching healthy references are available.

Without an explicitly supplied signed worker, a scan collects available management/OS context and records active CUDA methods as unavailable. Supplying a worker enables bounded GPU work, which consumes rental time. The scanner owns target checks, deadlines, stop conditions and evidence; the [worker package](worker/README.md) defines numerical and memory-coverage boundaries.

An inconclusive scan deliberately exits **3** after saving its report. Scan exit codes are `0` for keep/keep-with-caveats, `1` for an operational or usage error, `2` for do-not-start, `3` for inconclusive, and `130` for cancellation with a partial report. Check the reported artifact path and run `gri verify`; a nonzero decision code does not itself mean report generation failed. Demo and replay commands return `0` when their artifact workflow succeeds, independently of the displayed verdict.

## Commands and options

Run a command with `--help` for its current argument contract.

| Command | Purpose |
| --- | --- |
| `gri scan` | Observe one selected allocation, run available bounded methods and write local evidence. |
| `gri demo --scenario clean\|ecc-error\|missing --output DIR` | Exercise the workflow using explicitly synthetic evidence. |
| `gri catalog [--json]` | Show all design checks, including future, optional and currently unsupported checks. Catalog membership does not mean implementation or execution. |
| `gri checklist --report DIR/report.json [--json] [--all]` | Verify an existing report and list remaining Phase 1 checks plus separate release gates. Synthetic and skipped Standard evidence cannot close acceptance work. |
| `gri explain FINDING --report DIR/report.json` | Explain a finding and its action/verification guidance. |
| `gri ticket draft --report DIR/report.json --provider generic` | Print a redacted local support draft; `--output FILE` writes a new file. No message is submitted. |
| `gri verify --report-dir DIR` | Verify hashes, private permissions and the allowed evidence-file set. |
| `gri import --archive FILE --output NEW_DIR [--json]` | Validate a bounded H100 campaign archive and regenerate a private local report index without executing downloaded content. |
| `gri worker-validate --input FILE --device UUID --method METHOD --elapsed-ms N` | Validate retained worker JSON against the expected request; command success admits the protocol, not the GPU result. |
| `gri export --report-dir DIR --output NEW_DIR` | Verify and regenerate a minimal redacted report/evidence bundle. |
| `gri replay --report DIR/report.json --output NEW_DIR` | Verify retained evidence and reevaluate it with current rules into a linked new report, preserving the original interval. No new hardware work occurs. Optional `--reference` and `--reference-public-key` must be supplied together. |
| `gri cleanup --report-dir DIR` | Verify ownership/integrity and remove known report artifacts. This does not terminate a rental or delete arbitrary directory contents. |
| `gri keys generate --output NEW_DIR` | Generate a local Ed25519 signing key pair for trusted development use. |
| `gri manifest worker --binary FILE --output FILE` | Create an unsigned, unqualified manifest for the executable bytes; optional `--platform` declares the target and repeated `--dependency FILE` binds adjacent Windows runtime DLLs. |
| `gri sign --input FILE --key PRIVATE_PEM --output FILE` | Sign a payload into a local envelope. A signature does not establish qualification. |
| `gri version` | Print the development tool version. |

| Scan option | Meaning |
| --- | --- |
| `--device`, `--expected-sku` | Full selected UUID and optional user-declared expected variant. |
| `--tier quick\|standard` | Bounded scan depth; both are free-software workflows. Standard is not a long-term stability certificate. |
| `--profile general\|inference\|training\|rendering` | Assessment context, without workload-throughput claims or invented workload weights. |
| `--budget-seconds`, `--memory-mib`, `--seed` | Scan budget, owned worker-allocation cap and recorded numerical seed. A host driver wait may remain uninterruptible. |
| `--output`, `--workspace` | New private evidence directory and explicit workspace for capacity/context or opted-in scratch testing. |
| `--worker`, `--worker-manifest`, `--worker-public-key` | CUDA executable, signed manifest envelope and independently trusted Ed25519 public key. |
| `--allow-unqualified-worker` | Development acceptance-test opt-in. It does not enable calibrated acceptance or promote the development worker to qualified status. |
| `--allow-busy` | Explicit development opt-in to test a contended device, such as a WDDM desktop; primary performance evidence is contaminated and cannot support calibrated scoring. |
| `--reference`, `--reference-public-key` | Signed healthy-reference envelope and trusted public key. No healthy pack is bundled. |
| `--advisory`, `--advisory-public-key` | Standard only: local signed dated OEM/driver pack and explicit trust key; unknown or unmatched versions abstain. |
| `--dcgm`, `--dcgm-budget-seconds` | Standard only: opt in to the selected-H100 DCGM 4.6.0 level-1 software suite on an existing local hostengine; default 40 seconds, range 5–60, inside the scan budget. |
| `--price-per-hour`, `--currency` | Optional user-declared price context; no market feed or refund guarantee. |
| `--max-temperature-c` | Optional user-selected safety ceiling, not a universal device-defect threshold. |
| `--disk-test-bytes` | Standard-tier scratch-test opt-in requiring `--workspace`; cap 64 MiB. Zero disables it. |
| `--endpoint`, `--download-bytes` | Standard-tier HTTPS-object test opt-in and response-body cap, at most 64 MiB. No endpoint means no active network test. |

## Evidence and decisions

Runs preserve states including `PASS`, `FAIL`, `NOT_TESTED`, `UNSUPPORTED`, `PERMISSION_DENIED`, `DEPENDENCY_MISSING`, `TIME_BUDGET_EXHAUSTED`, `CONTAMINATED` and `TOOL_ERROR`. Unavailable fields do not become zero or pass.

The resulting action is `KEEP`, `KEEP WITH CAVEATS`, `DO NOT START / REQUEST FIX OR REPLACEMENT`, or `INCONCLUSIVE`. Required correctness/resource gates override scores. A score needs all five eligible exact-method measurements and a qualified matching reference; missing weights are not renormalized. Unconfirmed failures, historical counters, disclosed power caps and exposure observations retain distinct meanings. Brief guest-visible measurements do not certify device authenticity, future lifetime, workload fit or a cluster.

Reports contain `report.html`, `report.json`, `guide.md`, `evidence-index.json`, and the normalized `evidence.jsonl` journal. A blocker or explicit request creates `ticket.md`. HTML uses no remote scripts, fonts or tracking. Hashes detect changed bytes; they do not authenticate the host or replace signatures. POSIX files use `0600` permissions in a `0700` directory; Windows uses protected owner-only DACLs. Interrupted runs retain available observations and mark unfinished work explicitly.

```sh
./bin/gri export --report-dir ./reports/quick-001 --output ./reports/quick-001-share
./bin/gri verify --report-dir ./reports/quick-001-share
./bin/gri ticket draft --report ./reports/quick-001/report.json --provider generic
```

Exports regenerate normalized evidence, pseudonymize identifiers and remove private paths, IP addresses and sensitive fields. Review a redacted draft before sharing. Default collection does not upload measurements, request account tokens, read user file content, export process command lines or capture traffic payloads. No provider submission, reset, firmware change, power-policy change, container replacement or rental termination occurs.

Optional disk testing uses generated bytes in one owned scratch descriptor without opening existing workspace files. Results describe a short buffered write/sync/reread and disclose cache effects. Optional endpoint testing performs one bounded HTTPS request with verified TLS, no credentials, no redirects and no inherited proxy configuration. Selecting an endpoint discloses the request to that service; body limits exclude DNS/TLS/header/transport overhead. See [optional path checks](internal/pathcheck/README.md).

## Development and release work

```sh
make test
make test-race
make vet
make worker-cpu
make build-linux
```

`make build-linux` produces a Linux amd64 **cgo-free fallback** binary. Native Linux `CGO_ENABLED=1` builds compile the dynamic NVML adapter; runtime NVIDIA libraries are still needed. `make worker-cuda CUDA_ROOT=/path/to/pinned/cuda` defaults to the Linux SM90 H100 qualification target. Windows builds use MSVC and default to SM120; explicit CMake architecture settings can build both. Real-device numerical qualification, sanitizer runs, reference acquisition and rental acceptance remain separate gates for each declared GPU/platform configuration.

`make release-check` runs local software checks and builds only. It does not sign, publish, deploy, provision a GPU, acquire a reference or approve a release. CI is configured for Linux/macOS and native Windows Go tests, race detection, vet, CLI builds and CPU harnesses without GPU hardware; a configured workflow is not evidence of a passed remote run. Windows race detection needs a compatible GCC C toolchain in addition to Go; the MSVC CPU harness is a separate check.

The six previously absent adapters now have bounded development implementations: DCGM software diagnostics (`B11`), scan-interval kernel-journal Xid evidence (`B06`), FP8/INT8 workers (`C04`), controlled Linux NUMA transfers (`D10`), signed driver advisories (`H04`) and signed OEM/VBIOS matching (`A10`). Native Linux/H100 validation and trusted reference/advisory data remain necessary. Complete Xid history, live NVML event subscription, long vendor stress and production qualification are not claimed. See [H100 setup and remaining checklist](docs/H100_SINGLE_NODE.md).

| Area | Source |
| --- | --- |
| CLI and scheduler | `cmd/gri`, `internal/scan` |
| Evidence model and catalog | `internal/model`, `internal/catalog` |
| Read-only NVIDIA/host adapters | `internal/collect` |
| Selected Linux diagnostics and signed vendor assertions | `internal/diagnostics`, `internal/advisory` |
| Process isolation and worker protocol | `internal/secureexec`, `internal/worker`, `worker` |
| Signatures and reference matching | `internal/bundle`, `internal/reference` |
| Assessment and local reports | `internal/rules`, `internal/report`, `internal/privatefs` |
| Explicit path extensions | `internal/pathcheck` |

Read [Implementation status](docs/IMPLEMENTATION_STATUS.md) before making a product claim and [Acceptance runbook](docs/ACCEPTANCE.md) before real-H100 qualification.
