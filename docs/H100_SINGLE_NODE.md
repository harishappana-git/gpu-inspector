# H100 single-node development run and remaining checklist

Status: 2026-09-07. This implements the design's Phase 1 scope: **one explicitly selected full H100 on one Linux x86-64 node**. Other visible GPUs are not loaded. A multi-GPU node is supported as a selection environment; NVLink/NCCL, peer stress, multi-node and real application benchmarks remain later phases.

This is a development acceptance workflow. Local RTX results, signed development binaries and successful software tests do not qualify an H100 or create a healthy reference. The expected verdict without qualified evidence is `INCONCLUSIVE`, exit 3, with retained reports.

For automatic setup, SSH execution, sanitizer attempts, report download and recovery from Windows, start with the [automated H100 setup guide](H100_AUTOMATED_SETUP.md). The steps below also support a separately prepared Linux bundle.

## Prepare on a trusted Linux build host

Use existing Go 1.24+, CMake 3.24+, a supported C/C++ compiler, and CUDA Toolkit 12.0+ with cuBLAS/cuBLASLt. Use the exact pinned toolkit/compiler/driver combination being evaluated; minimum versions are build requirements, not a qualified compatibility matrix. The Windows reproduction used CUDA 12.8.1, MSVC 19.38 and Go 1.24.5. The build script uses existing dependencies. The separate automated setup can install explicitly enabled Ubuntu build prerequisites; it keeps the existing driver.

```bash
bash scripts/build-linux-h100.sh \
  --cuda-root /usr/local/cuda \
  --output ./dist/h100-development-001
```

The script runs Go tests, race detection and vet; builds the native Linux NVML CLI and SM90 worker; runs the CPU known-answer harness; checks shared-library resolution; and stages a signed development bundle with SHA-256 inventory. It creates a fresh private build directory and keeps failures. Build logs and an automatically generated development private key stay in that build directory. The distribution contains only the public key. Existing keys can instead be selected with `--signing-key` and `--public-key`; their pairing is verified before the signature is published.

Build before starting paid rental time when possible. A separately prepared bundle can be copied using your established transfer method. Alternatively, the automated controller uploads source and builds on one explicitly configured SSH node; it uses existing SSH access and obtains no provider credentials. Independently compare the `worker-public.pem` fingerprint before trusting a separately transferred bundle. An editable checksum list by itself is not a distribution signature or trust root.

The worker uses system shared libraries and an absolute RPATH to the selected CUDA `lib64`. **CUDA libraries are not bundled or authenticated by the Linux worker manifest.** The runtime needs that pinned library location and a compatible driver/glibc. Test the relocated final package and record actual loaded dependencies on the H100; a successful build-host `ldd` is insufficient for that release gate. Do not copy the build directory/private signing key to an untrusted rental.

## Run and retain the result

Obtain the full UUID of the authorized allocation through its existing management view, for example `nvidia-smi --query-gpu=uuid,name --format=csv,noheader`. This inventories visible devices; it does not start peer workloads. Substitute the actual UUID below.

```bash
bash ./dist/h100-development-001/scripts/run-h100.sh \
  --device GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee \
  --expected-sku h100-pcie-80gb \
  --tier quick --budget-seconds 120 --memory-mib 256 \
  --output ./h100-quick-001

bash ./dist/h100-development-001/scripts/run-h100.sh \
  --device GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee \
  --expected-sku h100-pcie-80gb \
  --tier standard --budget-seconds 300 --memory-mib 1024 \
  --output ./h100-standard-001
```

Use `h100-sxm-80gb` or `h100-nvl-94gb` for those actual variants. Their reference cohorts remain separate. Full GPU mode, permitted visibility, idle conditions, stable UUID/PCI identity, allocation headroom and safety telemetry are checked before work. MIG and ambiguous mappings are refused. The runner never enables the busy-GPU override. Each attempt requires a new output directory.

The runner streams progress and saves:

| Artifact | Meaning |
| --- | --- |
| `terminal.log` | CLI progress, result and retained limitations. |
| `evidence/report.html`, `report.json`, `evidence.jsonl` | Private measurements and all catalog states with integrity index. |
| `verification.log` | Actual report hash/permission verification result. |
| `remaining-checklist.txt`, `checklist.json` | Current Phase 1 measurement gaps and the seven remaining release gates. |
| `run-status.json` | Scan, logging, verification and checklist exit codes. |

Exit 3 means inconclusive; exit 2 is the report's do-not-start decision. The runner preserves those codes when artifacts verify. An operational, logging, verification or checklist failure returns 1. Ctrl+C permits the scanner's partial-report path; inspect the retained status before another run.

Generate the same checklist for any existing verified report, including Windows results:

```bash
./bin/gri checklist --report ./reports/example/report.json
./bin/gri checklist --report ./reports/example/report.json --json
```

Redirect a checklist outside the indexed `evidence` directory. Adding unindexed files there intentionally prevents cleanup/verification from treating the directory as wholly owned evidence. A synthetic report cannot mark actual hardware acceptance work complete. A Quick report leaves Standard checks pending. Checklist command success means successful generation, not acceptance.

## Added single-GPU diagnostic coverage

| Check | Implemented behavior | Remaining runtime/data boundary |
| --- | --- | --- |
| A10 | Signed OEM tuple comparison using exact SKU, board part and VBIOS metadata. Unknown tuples abstain. | Requires an explicitly trusted, dated source pack and exposed board/VBIOS metadata; no vendor corpus or attestation is bundled. |
| B06 | Current-boot Linux kernel-journal query, scoped to the verified UUID/PCI scan interval, with numeric Xid codes and timestamps only. | Journal permission/retention/latency can hide events. No complete history or live NVML event subscription is claimed; no universal code-to-hardware-fault rule. |
| B11 | Opt-in DCGM **4.6.0** level-1 software/deployment suite; verify client/hostengine versions, UUID/PCI-to-entity mapping, scope and result. | Requires an existing local hostengine and supported privileges. No service installation/start, long vendor stress/RMA suite or peer diagnostic. |
| C04 | Separate INT8 and FP8 numerical GEMMs with explicit formats and scale conventions. | Development methods require SM90 qualification; unsupported/nonperformed paths remain missing capability, not a failed GPU. |
| D10 | Linux pinned H2D comparison between permitted GPU-local and remote NUMA memory, fixed submitting CPU, verified owned-page placement and full content checks. | Requires two permitted nodes and page-placement/query access. One-node hosts, restricted containers and native Windows abstain. |
| H04 | Signed dated driver advisory matching exact SKU, numeric driver range and a retained explicit symptom. | No production advisory corpus is bundled; a matched issue is a possible explanation, not proof of cause. |

Standard schedules twelve worker methods: `memory_integrity`, `fp32_gemm`, `bf16_gemm`, `hbm_copy`, `h2d`, `d2h`, `tf32_gemm`, `working_set`, `dispatch_latency`, `int8_gemm`, `fp8_gemm`, `numa_transfer`. Quick keeps the original six. The legacy `hbm_copy` ID describes device-memory copy; RTX GDDR results are not labeled measured HBM. FP8 uses E4M3 operands, FP32 accumulation/output, tensor scales 1 and a documented TN layout; INT8 uses signed integer operands, INT32 accumulation/output and unit scale/zero point. These test numerical paths and dense throughput, not model quantization quality.

To include the short vendor software suite, add `--dcgm --dcgm-budget-seconds 40` to a Standard run. Its 5–60 second allowance is **inside** the global scan budget and is reserved from CUDA scheduling. All connected vendor calls target `127.0.0.1` and one verified GPU entity. The scanner sets native timeout/heartbeat controls and stops later active paths after an incomplete vendor result. Killing the client does not prove immediate daemon completion; inspect `daemon_completion_known` before retesting. See [diagnostic contracts](../internal/diagnostics/README.md).

To enable A10/H04, add `--advisory /path/to/signed-pack.json --advisory-public-key /path/to/trusted-public.pem` to Standard. See the [strict signed pack schema](../internal/advisory/README.md). Packs are local inputs; source links are not fetched during scans. No example vendor assertions should be promoted from a test fixture into production data.

## Remaining acceptance checklist

- [x] Implement the six source adapters above and integrate explicit coverage, deadlines, selected-device guards and evidence.
- [x] Add Linux development build/staging and bounded run scripts, signature-key pairing checks and report-derived checklists.
- [x] Run local Windows software tests and real RTX FP8/INT8 numerical tests; compile SM90+SM120 device targets.
- [ ] Build and execute the complete final CUDA worker on native Linux H100, including the Linux NUMA branch. Windows fat-binary compilation is not a Linux host build.
- [ ] Validate all twelve methods on each claimed H100 variant and pinned runtime, including numerical checks, headroom, deadline/cancellation and selected-device isolation.
- [ ] Execute all four Compute Sanitizer tools with retained results; the earlier Windows instrumentation attempts were blocked, not passes.
- [ ] Exercise DCGM 4.6.0 and kernel-journal real output, permission denial, timeout/daemon completion and UUID mapping on the actual host/container.
- [ ] Verify local/remote NUMA page placement and transfer comparison on a multi-socket permitted allocation; retain honest unsupported results on other topology/permission configurations.
- [ ] Obtain and review applicable dated OEM/advisory data; validate trusted signer provenance independently. Complete event history remains unavailable where the host does not expose it.
- [ ] Acquire independent healthy H100 allocations/hosts and raw runs, review exclusions and sign exact-configuration reference packs. No scores or percentiles are fabricated while this is pending.
- [ ] Complete the WP1–WP7 release gates: native ABI/isolation, method/sanitizer qualification, labeled outcome review, dependency/license/privacy review, relocated runtime validation, production key/distribution process and actual rental acceptance.

These unchecked items require hardware, external evidence or explicit release review. The full procedures and scope restrictions remain in [ACCEPTANCE.md](ACCEPTANCE.md), [implementation status](IMPLEMENTATION_STATUS.md) and the [worker qualification ledger](../worker/QUALIFICATION.md).

## Local evidence for this extension

On 2026-09-07 the integrated Standard run on Windows 10 / RTX 5080 / driver 610.88 used a 512 MiB allocation cap and a 300-second budget. It completed in **48.675 seconds**: all eleven numerical CUDA methods had separate validation `PASS`, zero mismatches, and observed GPU temperatures 35–51°C; NUMA returned `UNSUPPORTED` on Windows. Report verification and JSON checklist generation both returned 0. The scan returned 3 because the development worker/reference were unqualified and the WDDM desktop run explicitly permitted busy-GPU overlap.

Retained local files: `build/h100-extension-validation/run-status.json`, `standard-live.log`, `checklist.json`, and `reports/h100-extension-rtx5080-standard-20260907T1403397534504Z`. Independent FP8/INT8 Quick/Standard worker logs are under `build/windows-validation/low-precision-quick` and `low-precision-standard`. These ignored local artifacts remain on this development machine; they are not committed H100 campaign evidence.

The final repeated Standard run completed in **48.553 seconds**, again with eleven numerical validation passes and zero mismatches, NUMA `UNSUPPORTED`, and observed temperatures **36–50°C**. Its optional-method projection preserves missing NUMA coverage without treating a nonperformed optional method as unavailable mandatory GPU usability. The report is `reports/h100-extension-rtx5080-final-20260907T1418279930033Z`; verification and checklist both passed, and scan exit 3 remains expected. The corresponding `final-run-status.json`, `final-gpu-summary.json`, `final-standard.log` and `final-checklist.json` are under `build/h100-extension-validation`.

Software verification completed here: **219 top-level Go tests passed** (217 ordinary tests plus two separately enabled real NVIDIA read-only integration tests), zero failed; the Windows file-symlink privilege fixture remains narrowly skipped. Full race detection and vet passed; the CPU known-answer/corruption CTest passed 1/1. Eight hermetic Bash runner scenarios passed under Git Bash, including scan decision codes and artifact/logging failures. Linux amd64 cgo-free CLI and test binaries, macOS arm64 CLI, and the Windows SM90+SM120 worker compiled. Linux NUMA host code passed cross-target Clang syntax with real Debian/Linux headers; this is not full Linux CUDA compilation or execution. Logs and summaries are retained in the same validation directory and `build/windows-validation/linux-syntax`.
