# GPU Rental Inspector

GPU Rental Inspector (`gri`) is a local development CLI for examining **one selected NVIDIA GPU allocation** and its visible execution environment. It implements the Phase 1 source workflow in [Design v2.0](GPU_Rental_Inspector_Design_v2_0.md): bounded collection, isolated CUDA-worker integration, explicit missing-data states, deterministic assessment, private local reports and support drafts. Optional bounded workspace and HTTPS-object checks cover the Phase 1B extension.

**Current release state: development implementation, not qualified for production GPU acceptance.** No real H100 rental measurement, healthy-reference pack, production signing key or signed production worker is included. The development CUDA worker is explicitly unqualified. Reports with missing methods or calibration remain `INCONCLUSIVE` / `UNCALIBRATED`, with a null score. Passing software fixtures is not GPU qualification. Remaining work is tracked in [Implementation status](docs/IMPLEMENTATION_STATUS.md) and [Acceptance runbook](docs/ACCEPTANCE.md).

## Build and try the local workflow

The Go module requires Go 1.24 or later. The development and CI reproduction pin is **Go 1.24.5**, matching the initial development host; this pin is not a statement about current security support. The CLI uses the Go standard library. CMake 3.24+, a C++17 compiler and an explicitly qualified CUDA installation are separate worker-build dependencies.

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

Without an explicitly supplied signed worker, a scan collects available management/OS context and records active CUDA methods as unavailable. Supplying a worker enables bounded GPU work, which consumes rental time. The scanner owns target checks, deadlines, stop conditions and evidence; the [worker package](worker/README.md) defines numerical and memory-coverage boundaries.

An inconclusive scan deliberately exits **3** after saving its report. Scan exit codes are `0` for keep/keep-with-caveats, `1` for an operational or usage error, `2` for do-not-start, `3` for inconclusive, and `130` for cancellation with a partial report. Check the reported artifact path and run `gri verify`; a nonzero decision code does not itself mean report generation failed. Demo and replay commands return `0` when their artifact workflow succeeds, independently of the displayed verdict.

## Commands and options

Run a command with `--help` for its current argument contract.

| Command | Purpose |
| --- | --- |
| `gri scan` | Observe one selected allocation, run available bounded methods and write local evidence. |
| `gri demo --scenario clean\|ecc-error\|missing --output DIR` | Exercise the workflow using explicitly synthetic evidence. |
| `gri catalog [--json]` | Show all design checks, including future, optional and currently unsupported checks. Catalog membership does not mean implementation or execution. |
| `gri explain FINDING --report DIR/report.json` | Explain a finding and its action/verification guidance. |
| `gri ticket draft --report DIR/report.json --provider generic` | Print a redacted local support draft; `--output FILE` writes a new file. No message is submitted. |
| `gri verify --report-dir DIR` | Verify hashes, private permissions and the allowed evidence-file set. |
| `gri export --report-dir DIR --output NEW_DIR` | Verify and regenerate a minimal redacted report/evidence bundle. |
| `gri replay --report DIR/report.json --output NEW_DIR` | Verify retained evidence and reevaluate it with current rules into a linked new report, preserving the original interval. No new hardware work occurs. Optional `--reference` and `--reference-public-key` must be supplied together. |
| `gri cleanup --report-dir DIR` | Verify ownership/integrity and remove known report artifacts. This does not terminate a rental or delete arbitrary directory contents. |
| `gri keys generate --output NEW_DIR` | Generate a local Ed25519 signing key pair for trusted development use. |
| `gri manifest worker --binary FILE --output FILE` | Create an unsigned, unqualified manifest for the executable bytes. |
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
| `--reference`, `--reference-public-key` | Signed healthy-reference envelope and trusted public key. No healthy pack is bundled. |
| `--price-per-hour`, `--currency` | Optional user-declared price context; no market feed or refund guarantee. |
| `--max-temperature-c` | Optional user-selected safety ceiling, not a universal device-defect threshold. |
| `--disk-test-bytes` | Standard-tier scratch-test opt-in requiring `--workspace`; cap 64 MiB. Zero disables it. |
| `--endpoint`, `--download-bytes` | Standard-tier HTTPS-object test opt-in and response-body cap, at most 64 MiB. No endpoint means no active network test. |

## Evidence and decisions

Runs preserve states including `PASS`, `FAIL`, `NOT_TESTED`, `UNSUPPORTED`, `PERMISSION_DENIED`, `DEPENDENCY_MISSING`, `TIME_BUDGET_EXHAUSTED`, `CONTAMINATED` and `TOOL_ERROR`. Unavailable fields do not become zero or pass.

The resulting action is `KEEP`, `KEEP WITH CAVEATS`, `DO NOT START / REQUEST FIX OR REPLACEMENT`, or `INCONCLUSIVE`. Required correctness/resource gates override scores. A score needs all five eligible exact-method measurements and a qualified matching reference; missing weights are not renormalized. Unconfirmed failures, historical counters, disclosed power caps and exposure observations retain distinct meanings. Brief guest-visible measurements do not certify device authenticity, future lifetime, workload fit or a cluster.

Reports contain `report.html`, `report.json`, `guide.md`, `evidence-index.json`, and the normalized `evidence.jsonl` journal. A blocker or explicit request creates `ticket.md`. HTML uses no remote scripts, fonts or tracking. Hashes detect changed bytes; they do not authenticate the host or replace signatures. Files use `0600` permissions in a `0700` directory. Interrupted runs retain available observations and mark unfinished work explicitly.

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

`make build-linux` produces a Linux amd64 **cgo-free fallback** binary. Native Linux `CGO_ENABLED=1` builds compile the dynamic NVML adapter; runtime NVIDIA libraries are still needed. `make worker-cuda CUDA_ROOT=/path/to/pinned/cuda` targets an authorized Linux x86-64 H100 qualification environment. CUDA compilation, numerical validation, sanitizer runs, reference acquisition and real-rental acceptance remain open gates.

`make release-check` runs local software checks and builds only. It does not sign, publish, deploy, provision a GPU, acquire a reference or approve a release. CI runs development checks on Linux/macOS without GPU hardware; a configured workflow is not evidence of a passed remote run.

Some diagnostics remain absent beyond the unqualified CUDA implementation: no DCGM execution (`B11`), complete Xid-history collector (`B06`), FP8/INT8 worker (`C04`), controlled NUMA-transfer experiment (`D10`), versioned driver-advisory matcher (`H04`) or signed OEM/VBIOS comparison (`A10`) is implemented. Reported VBIOS text remains metadata, not a consistency pass. See the explicit gaps in [Implementation status](docs/IMPLEMENTATION_STATUS.md).

| Area | Source |
| --- | --- |
| CLI and scheduler | `cmd/gri`, `internal/scan` |
| Evidence model and catalog | `internal/model`, `internal/catalog` |
| Read-only NVIDIA/host adapters | `internal/collect` |
| Process isolation and worker protocol | `internal/secureexec`, `internal/worker`, `worker` |
| Signatures and reference matching | `internal/bundle`, `internal/reference` |
| Assessment and local reports | `internal/rules`, `internal/report` |
| Explicit path extensions | `internal/pathcheck` |

Read [Implementation status](docs/IMPLEMENTATION_STATUS.md) before making a product claim and [Acceptance runbook](docs/ACCEPTANCE.md) before real-H100 qualification.
