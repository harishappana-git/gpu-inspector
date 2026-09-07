# Worker qualification ledger

Current state: **NOT QUALIFIED — development implementation**.

Qualification is per OS, architecture, driver and toolkit combination. Windows
x64 RTX 5080 (SM120/CUDA 12.8+) is now an implementation target in addition to
Linux x86-64 H100 (SM90/CUDA 12.0+). A local RTX success never qualifies an H100,
and neither product uses the other's performance reference. Retain exact local
build/test logs independently of this ledger; the gates below still require
their stated evidence before production qualification.

| Gate | Current evidence | Required next evidence |
| --- | --- | --- |
| CPU known answers | C++17 harness compiled and CTest passed on Windows with MSVC 19.38.33145 (2026-09-07) and earlier macOS with AppleClang 21.0.0; all eight patterns, varied seeds/offsets, fixed matrix answer, BF16/TF32 exact-representation checks, synthetic memory/GEMM corruption, NaN/Inf rejection; added exact FP8 E4M3 small-integer byte encodings and bounded NUMA CPU-list parsing; earlier macOS ASan+UBSan build passed | Retain compiler version and test log in release artifact |
| CUDA compile/link | Windows executable built with SM90 machine code plus SM120 machine code/PTX using NVCC 12.8.93 / MSVC 19.38.33145, shared CUDA runtime/cuBLAS/cuBLASLt and static host CRT (2026-09-07); latest build `build/worker-lowprecision` includes all twelve method dispatches | Clean Linux SM90 host/device build and relocated Windows/Linux signed dependency manifests; a Windows executable containing SM90 kernels is not a Linux build |
| Numerical CUDA methods | Windows RTX 5080 Quick completed six original methods and Standard completed all nine original methods with zero checked-output mismatches (2026-09-07); Standard used a 512 MiB device allocation cap, eight integrity patterns and 4096-square GEMMs; local reports `reports/rtx5080-quick-002` and `reports/rtx5080-standard-001`. Additional actual FP8 and INT8 Quick/Standard runs both passed exact checked outputs; details below | Independent small-matrix reference challenge, complete per-platform acceptance and all twelve applicable methods on Linux H100; local busy-WDDM results remain unqualified and performance-contaminated |
| Controlled NUMA comparison | Linux source implements permitted-node selection, fixed permitted local CPU, owned-page MPOL_BIND, query-only full page placement checks, bounded local/remote H2D and full content checks. CPU parsing and strict Go protocol tests pass; Windows intentionally returns unsupported. Actual Linux NUMA branch and shared host helpers passed Clang 23.1.0 syntax checking targeting x86_64-linux-gnu with real Debian glibc/kernel/libstdc++ and CUDA headers; evidence `build/windows-validation/linux-syntax` | Real Linux CUDA compile/link and two-node runtime proof including page-query permission denial, placement failure, affinity restoration and content failure; syntax checking ran on Windows and no measured Linux NUMA result is claimed |
| CUDA sanitizer | Compute Sanitizer 2025.1.0.0 / CUDA 12.8.1 attempted on Windows RTX 5080 (2026-09-07): nine memcheck methods plus memory/dispatch racecheck, initcheck and synccheck. All instrumentation attempts blocked by disabled WDDM debugger interface; logs `build/windows-validation/sanitizer`; no clean sanitizer pass claimed | Authorized OS debugger-interface setup or suitable Linux target, followed by actual memcheck, initcheck, racecheck and synccheck instrumentation; retain logs |
| Stable selection | Source enforces full UUID, exact visibility and double runtime UUID check | Remapped ordinal, multi-GPU host, hidden GPU, MIG, changed/disappeared GPU fixtures and actual-device checks |
| Allocation ownership/headroom | Source owns all buffers and reserves headroom | Concurrent-memory-pressure tests, allocation failures, pointer/range review, proof of no peer contexts/access |
| Cancellation/driver loss | Cooperative worker budget; parent hard timeout required | Kill/cancel during each phase, failed driver/device disappearance, bounded output and partial-report recovery |
| Timings and repetitions | Event and wall arrays implemented with validity checks | Event/wall consistency, actual Quick/Standard wall budgets, power/thermal curves, repeated runs on separate allocations |
| Correctness interpretation | First mismatch stops load; reports unconfirmed mismatch | Independent reproducibility investigation workflow and false-positive challenge; no device-fault claim from a worker-only failure |
| Calibration | No healthy baseline included | Separate vetted H100 PCIe and RTX 5080 reference acquisition, independent allocations, matching OS/driver model, exact-key qualification and signed approvals |
| Packaging | Source/CMake and signed Windows runtime DLL snapshot support | Actual Windows/Linux binary/dependency qualification, license review, verified release signatures and relocated install/readback test |
| Windows display scheduling | Driver model and kernel timeout state retained; no TDR changes. Local numerical methods completed under explicit busy-GPU opt-in, with performance observations marked contaminated. Sanitizer attempts retained 37–40 C selected-device temperature before/after each bounded call | WDDM desktop responsiveness, cancellation during each method and actual sanitizer access; signed DLL snapshot/tamper and native subprocess tests pass locally |

Additional C04 hardware evidence on 2026-09-07 used the selected local RTX 5080,
CUDA 12.8.1 and the same WDDM environment. Both methods completed eight Quick
samples at 2048 square and 64 Standard samples at 4096 square. Independent host
INT64 reference dot products checked 1,024 output positions per Quick method and
8,192 per Standard method, with zero mismatches. Every returned output also
passed finite/range checks. FP8 used E4M3 with unit tensor-wide scales and FP32
accumulation/output; INT8 used exact INT32 pedantic accumulation/output. Actual
JSON passed the Go worker protocol validator. Retained logs are
`build/windows-validation/low-precision-quick` and
`build/windows-validation/low-precision-standard`; selected-device temperature
stayed 36–42 C. These known-answer checks do not establish arbitrary-input
quantization accuracy, calibrated throughput, clean sanitizer instrumentation,
or Linux/H100 acceptance. The twelve-method source scope comprises eleven
portable methods and the Linux-only controlled NUMA comparison.

Suggested sanitizer invocation pattern after authorization and target guard:

```sh
CUDA_VISIBLE_DEVICES=GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee compute-sanitizer --tool memcheck \
  ./build/worker-cuda/gri-cuda-worker --device GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee \
  --method memory_integrity --budget-ms 30000 --memory-mib 128 --seed 42 --tier quick
```

The example UUID is documentation notation, not an allocation identifier.
Replace it with the authorized full UUID. Run analogous checks for
each method and other sanitizer tools with their overhead accounted for in the
budget. Do not interpret a clean sanitizer run as a physical-memory certificate.

Do not change the ledger to qualified until durable logs and the actual signed
release artifacts have been reviewed. Synthetic harness success is never a
substitute for real GPU acceptance evidence.
