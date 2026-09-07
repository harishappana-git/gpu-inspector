# Phase 1 acceptance and qualification runbook

This is a procedure for **future authorized qualification**, not a record that it occurred. Follow [Implementation status](IMPLEMENTATION_STATUS.md) and the [worker qualification ledger](../worker/QUALIFICATION.md). The current development version has no qualified worker, healthy pack, production key or real-rental acceptance evidence.

The [H100 single-node setup and remaining checklist](H100_SINGLE_NODE.md) provides `scripts/build-linux-h100.sh`, `scripts/run-h100.sh`, the twelve-method Standard scope, opt-in DCGM and signed advisory inputs. `gri checklist --report DIR/report.json` produces a checklist from verified retained evidence; it does not close the campaign gates described here.

## 1. Define and retain the exact scope

Use an operator-controlled or explicitly authorized Linux x86-64 H100 PCIe allocation for H100 qualification. Native Windows x64 / RTX 5080 validation can exercise the same implemented workflow first; retain it as a separate hardware/platform campaign. Record the exact full GPU UUID, observed PCI identity, form factor/memory SKU, MIG/virtualization state, visible-device mapping, driver/runtime/cuBLAS/toolkit/compiler versions, host/container limits and method version. Windows runs additionally record WDDM/TCC mode and desktop contention. Keep raw identifiers in private local evidence; share reviewed redacted exports. Do not label RTX, SXM, NVL, a MIG slice or a different driver/method stack as an exact H100 PCIe reference match.

Pre-register the checks, budget, memory cap, workspace, expected conditions and stop criteria. Define who may approve provider maintenance. Protect existing workload data and record its persistence separately. No test should reset a GPU, clear counters, alter firmware/power/link policy, stress an unselected device, drop global caches, read another tenant's data or terminate the rental.

Prepare a new private artifact location for each attempt:

```sh
umask 077
mkdir -m 700 ./acceptance
```

Retain the source revision, command configuration, installation/build interval, scan interval, actual rental cost assumptions, failures and partial results. A rerun creates new evidence rather than erasing the first attempt.

On Windows, let `gri` create each new evidence/key directory with a protected current-user-only DACL. `New-Item` or numeric mode bits do not establish Windows privacy. Keep the local parent directory under the operator's control, and retain logs privately with the evidence.

## 2. Reproduce software checks on the trusted build host

```sh
go version
make test
make test-race
make vet
make worker-cpu
make build
make build-linux
```

Capture command output and return codes in the private qualification record. `build-linux` is a cgo-free CLI fallback build. On native Linux, also build the dynamic NVML adapter:

```sh
CGO_ENABLED=1 go test ./internal/collect
CGO_ENABLED=1 go build -trimpath -o ./bin/gri-linux-native ./cmd/gri
```

No NVML headers or GPU are needed to compile this adapter, so compilation alone does not test its actual runtime ABI. Repeat collector tests against the pinned NVIDIA runtime on the qualification machine. Test the same final binary and image that will be distributed.

Build the Linux worker on the pinned Linux CUDA environment:

```sh
make worker-cuda CUDA_ROOT=/path/to/pinned/cuda
```

CMake requests CUDA Toolkit 12.0+ for SM90 and CUDA Toolkit 12.8+ for SM120, links CUDA runtime and cuBLAS, and uses a C++17 source contract. These are build requirements, not a validated compatibility matrix. Record actual dependency versions and license/redistribution review. On Linux the launcher snapshots the executable, not adjacent shared libraries; qualify system-loader or absolute-RPATH resolution after relocation. On Windows it snapshots explicitly signed, allowlisted adjacent runtime DLLs as well. Do not assume a build-tree binary and an installed binary load the same dependencies.

For native Windows, run these commands in an x64 Visual Studio developer PowerShell with Go, CMake and a toolkit-supported compiler available:

```powershell
go version
go test ./...
go vet ./...
./scripts/build-windows.ps1 -CPUOnly
./scripts/build-windows.ps1 -CudaRoot $env:CUDA_PATH
```

The script builds `bin/gri.exe`, configures a Release worker build under `build/worker-windows`, runs the CPU known-answer harness, and builds the SM120 worker unless `-CPUOnly` is selected. `-Architectures '90-real;120-real;120-virtual'` requests a dual-architecture build with a supporting toolkit. Windows `go test -race ./...` additionally requires a compatible GCC C toolchain and `CGO_ENABLED=1`; MSVC is used for the C++/CUDA harness, not as Go's GCC substitute. Retain actual command results; a missing race toolchain leaves that check incomplete.

## 3. Sign development artifacts without implying qualification

Generate development keys **on the trusted build machine**. Keep the private key there; the rental needs only the executable, signed manifest and independently verified public key. No production signing key or official public trust root exists in this repository.

```sh
./bin/gri keys generate --output ./acceptance/development-signing-keys
./bin/gri manifest worker \
  --binary ./build/worker-cuda/gri-cuda-worker \
  --output ./acceptance/worker-manifest.json
./bin/gri sign \
  --input ./acceptance/worker-manifest.json \
  --key ./acceptance/development-signing-keys/private.pem \
  --output ./acceptance/worker-envelope.json
```

These commands create an **unqualified development** manifest and signature over actual bytes. A self-generated key tests the signing workflow; it is not an official release endorsement. Verify the public key through a trusted channel before transferring artifacts. No provider account credential is needed by the scanner, and no private key should be passed as a CLI argument value or installed on an untrusted rental.

For Windows, use `gri.exe` and include each staged CUDA runtime dependency. The following assumes CUDA 12 DLL names; use the exact names and bytes required by the selected toolkit, staged next to the executable before manifest generation:

```powershell
./bin/gri.exe keys generate --output ./acceptance/windows-development-keys
./bin/gri.exe manifest worker `
  --platform windows-amd64 `
  --binary ./build/worker-windows/gri-cuda-worker.exe `
  --dependency ./build/worker-windows/cudart64_12.dll `
  --dependency ./build/worker-windows/cublas64_12.dll `
  --dependency ./build/worker-windows/cublasLt64_12.dll `
  --output ./acceptance/windows-worker-manifest.json
./bin/gri.exe sign `
  --input ./acceptance/windows-worker-manifest.json `
  --key ./acceptance/windows-development-keys/private.pem `
  --output ./acceptance/windows-worker-envelope.json
```

The platform defaults to the current host; set `--platform` explicitly for a cross-built artifact. Do not include GPU-driver or arbitrary user DLLs in the signed dependency list. Test missing, renamed and modified dependencies and verify admission fails before any GPU work. Dependency authenticity does not independently qualify the worker's methods.

Do not edit `qualified` to make the development build pass admission. The current loader explicitly refuses promoting this development version through a manifest flag. Qualification requires reviewed evidence and the corresponding supported release process, including final executable/dependency validation and key custody.

## 4. Establish honest degraded-mode behavior

Before active tests, exercise missing/denied/unsupported paths and confirm that the CLI still produces a useful private report. Synthetic demonstrations are available on the development machine:

```sh
./bin/gri demo --scenario clean --output ./acceptance/demo-clean
./bin/gri demo --scenario ecc-error --output ./acceptance/demo-ecc-error
./bin/gri demo --scenario missing --output ./acceptance/demo-missing
./bin/gri verify --report-dir ./acceptance/demo-clean
./bin/gri verify --report-dir ./acceptance/demo-ecc-error
./bin/gri verify --report-dir ./acceptance/demo-missing
```

Expect synthetic labels in every demo. `clean` and missing calibration remain inconclusive with no readiness score; the deliberate ECC-error fixture tests blocker/report logic only. It does not measure an actual failure or its real-world frequency. An unavailable driver, a worker that cannot load, a denied field or a timed-out child must retain a named status and next action.

On the authorized rental, run a scan without a worker to confirm target discovery and passive context. Verify that no unselected GPU receives a workload. If target ownership is ambiguous, resolve it before enabling active work.

## 5. Run the unqualified worker in controlled acceptance mode

The UUID and paths below are placeholders. Use the verified allocation and actual signed artifact files. Quick is shown first with explicit limits:

```sh
./bin/gri scan \
  --device GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee \
  --expected-sku h100-pcie-80gb --profile general --tier quick \
  --budget-seconds 120 --memory-mib 256 --seed 42 \
  --worker ./gri-cuda-worker \
  --worker-manifest ./worker-envelope.json \
  --worker-public-key ./development-public.pem \
  --allow-unqualified-worker \
  --output ./acceptance/h100-quick-001
```

This explicitly permits development measurements while preserving unqualified status. No calibrated acceptance score should result, even if a numerical method passes. Retain exact checked bytes, passes, shapes, math modes, direction, units, sample timing/spread, mismatch counts and limitations. A first numerical mismatch is an observed method failure, not a reproduced physical defect. Stop active work, preserve evidence and use only the provider-supported confirmation procedure.

The Windows RTX equivalent uses the local development artifacts and exact RTX SKU:

```powershell
./bin/gri.exe scan `
  --device GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee `
  --expected-sku rtx-5080-16gb --profile general --tier quick `
  --budget-seconds 120 --memory-mib 256 --seed 42 `
  --worker ./build/worker-windows/gri-cuda-worker.exe `
  --worker-manifest ./acceptance/windows-worker-envelope.json `
  --worker-public-key ./acceptance/windows-development-keys/public.pem `
  --allow-unqualified-worker `
  --output ./acceptance/rtx-quick-001
```

Replace the placeholder UUID with the selected card. Busy WDDM desktop processes can prevent the idle guard from admitting active work. An operator explicitly accepting desktop contention may add `--allow-busy` for local development validation; resulting primary performance evidence is `CONTAMINATED`, with separate correctness evidence retained. This does not establish idle performance or permit calibrated scoring. Do not alter Windows TDR, power limits, clocks or driver mode to obtain a passing result. Repeat with `--tier standard` and an appropriate budget to exercise every existing method; verify completed method IDs instead of inferring execution from the tier name.

Expect scan exit code **3** while the report is inconclusive. Codes `0`, `2`, `3` and `130` respectively represent keep/caveats, do-not-start, inconclusive and cancellation with partial evidence; `1` is an operational/usage error. Record both the code and successful `gri verify` result. Do not suppress every nonzero code in an automated acceptance script. Demo/replay return `0` when report generation succeeds and do not encode their verdict in the exit status.

After reviewing Quick evidence and confirming safe conditions, repeat with `--tier standard`, a pre-registered budget such as `--budget-seconds 600`, and a new output directory. Actual completed methods and duration determine coverage. Standard does not establish multi-day stability, thermal-aging behavior or remaining life.

Run all nine methods and the sanitizer campaign in [worker/QUALIFICATION.md](../worker/QUALIFICATION.md). Compare independent CPU answers and selected-device readbacks. Synthetic corruption stays in the CPU harness; do not inject physical ECC errors on a rental. Account for sanitizer overhead separately from scored timings.

## 6. Exercise isolation, failure and false-positive cases

| Case | Required observation |
| --- | --- |
| One visible full GPU | Exact selected UUID throughout; no implicit peer workload. |
| Multiple visible GPUs / remapped CUDA ordinals | Explicit selection; management indices never replace runtime mapping. |
| MIG mask or partition allocation | Explicit unsupported/refused result; never silently test its parent. |
| Disappearing or changed selected device | Stop later active tests and retain contaminated/missing evidence. |
| Existing unrelated workload | Do not terminate it; detect contamination/idle-gate limitations and preserve scope. |
| Missing worker/library/driver or denied sensor | Distinct absent-state report; no empty-to-zero or unavailable-to-pass conversion. |
| Hung/oversized/malformed worker | Bounded parent timeout/output; partial evidence survives; no false hardware-defect conclusion. |
| Cancellation during collection and each active phase | Stop scheduling; retain completed evidence; mark unfinished methods; remove only owned scratch resources. |
| Uninterruptible driver wait | Document the host limitation and provider escalation; do not promise successful userspace termination. |
| Historical corrected/uncorrected totals | Preserve historical context separately from new interval deltas and reset uncertainty. |
| New errors or current remap/retirement maintenance | Preserve event evidence and request supported investigation; do not clear counters to obtain a pass. |
| Disclosed power cap, idle link downshift, passive cooling, quota or small shared memory | Specific caveat/context; no universal defect, overselling, cooling failure or training-penalty claim. |
| Application/library failure | Distinguish compatibility/test-method behavior from active hardware evidence. |
| Conflicting method samples, wrong UUID/version/unit/conditions or stale times | Exclude affected evidence from calibrated scoring; no first-passing-sample cherry-picking. |
| Missing mandatory check, incomplete metric set or unqualified worker/reference | Null readiness score and honest abstention. |
| Identical evidence re-evaluation | Deterministic findings, fixed-weight scoring and stable evidence links. |

Use approved reversible limits only on controlled systems. Do not deliberately disrupt a shared rental to manufacture a failure. For every case, retain the expected result, actual evidence, discrepancy and reviewer disposition. A passed source fixture does not close its corresponding actual-device isolation or operational gate.

## 7. Verify optional Phase 1B paths separately

Disk testing requires both a selected workspace and an explicit positive byte budget:

```sh
./bin/gri scan --tier standard \
  --workspace /path/to/authorized/scratch \
  --disk-test-bytes 16777216 \
  --output ./acceptance/workspace-001
```

Confirm existing files are unchanged, the owned descriptor is cleaned up after completion/cancellation, requested/actual bytes are recorded and readback matches. This is a short buffered path check; cold cache, burst exhaustion, steady-state media speed, storage persistence and production p99 remain untested.

For a network-path check, select an authorized HTTPS object yourself:

```sh
./bin/gri scan --tier standard \
  --endpoint https://your-authorized-endpoint.example/object \
  --download-bytes 8388608 \
  --output ./acceptance/endpoint-001
```

The example is not a real endpoint. Use an object you may access without credentials. Verify TLS validation, disabled redirects/proxies, body-byte bounds and omitted URL/body/private metadata. A request discloses itself to the selected service; total transport cost exceeds consumed payload bytes. Do not turn this into endpoint discovery or a general bandwidth claim. Re-run core scans with both opt-ins absent and verify no external request occurs.

## 8. Acquire and qualify healthy references

Use independently tracked allocations selected for health and known configuration, not merely high speed. The provisional policy requires at least five allocations across two hosts with distinct retained provenance and explicit approval; it is not a statistical guarantee. Repeat sessions do not count as independent hosts. Exclude or quarantine impossible/replayed/inconsistent runs and preserve the reasons.

The pack must bind exact SKU, modes, driver, worker digest, method version, complete conditions hashes, metric units/direction, measured healthy ranges/reference values, acquisition/expiration dates and reviewed provenance. All five score metrics are required. A specification ceiling, copied benchmark, synthetic number or single fast allocation is not a healthy pack. Fleet percentiles and host-reputation claims remain out of scope.

Only after worker and reference qualification may a supported release use `--reference` and `--reference-public-key`. Record the signed envelope and independent public-key verification. Test rejection of wrong SKU/modes/methods/units/conditions, expired dates, altered signatures and insufficient provenance. Retain the underlying uncapped ratios; the 0–100 convention is not a health probability or an application-speed prediction.

## 9. Verify evidence, privacy and cleanup

```sh
./bin/gri verify --report-dir ./acceptance/h100-quick-001
./bin/gri export \
  --report-dir ./acceptance/h100-quick-001 \
  --output ./acceptance/h100-quick-001-share
./bin/gri verify --report-dir ./acceptance/h100-quick-001-share
./bin/gri ticket draft \
  --report ./acceptance/h100-quick-001/report.json \
  --provider generic \
  --output ./acceptance/provider-draft.md
```

Inspect every exported artifact for seeded test secrets, UUID/PCI/serial identifiers, private paths, IP addresses, environment/command-line content and raw dumps. Confirm pseudonyms remain consistent within the scan. Check restrictive permissions, hash tamper detection, rejection of symlinks/unindexed files and all evidence links. HTML must work offline without remote requests. Ticket text must preserve uncertainty, contain no refund entitlement and remain unsubmitted.

Reevaluate retained evidence into a new linked report when reviewing rule changes:

```sh
./bin/gri replay \
  --report ./acceptance/h100-quick-001/report.json \
  --output ./acceptance/h100-quick-001-replayed
./bin/gri verify --report-dir ./acceptance/h100-quick-001-replayed
```

Verify the original bytes remain unchanged, the replay records its original scan ID and original observation interval, and large uint64 counters retain exact values. Replay is rule evaluation of saved evidence, not a retest or a new GPU measurement. Complete an actual browser layout review as a separate reporting gate; automated HTML checks do not establish visual QA.

Cleanup is an explicit deletion action for known verified report files. First retain the qualification archive under the chosen retention policy, then test cleanup on a disposable verified demo directory:

```sh
./bin/gri cleanup --report-dir ./acceptance/demo-missing
```

Confirm unrelated directories/files remain intact. Cleanup is not secure erasure of backups, cloud replicas or filesystem snapshots; those require their own retention controls. Do not use it to erase a failed acceptance attempt before the reviewed archive is retained.

## 10. Make the release decision from durable evidence

For each WP1–WP7 gate, record source revision, exact build/runtime versions, hardware scope, evidence/artifact hashes, test command/result, expected behavior, remaining limitation and reviewer approval. Also retain false-positive/negative findings by environment, abstention rate, real Quick/Standard latency and testing cost. An improvement claim needs controlled before/after workload evidence; a changed score alone is insufficient.

Release only when every gate applicable to the declared supported/uncalibrated scope is closed. Verify the final distributed executable and dependencies, production signatures, installation/readback and trusted public-key delivery. Preserve unresolved cases explicitly. Neither `make release-check`, green CPU-only CI, a signed development artifact nor a synthetic clean report closes the real-rental gates.
