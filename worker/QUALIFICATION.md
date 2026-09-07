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
| CPU known answers | C++17 harness compiled and CTest passed on Windows with MSVC 19.38.33145 (2026-09-07) and earlier macOS with AppleClang 21.0.0; all eight patterns, varied seeds/offsets, fixed matrix answer, BF16/TF32 exact-representation checks, synthetic memory/GEMM corruption, NaN/Inf rejection; earlier macOS ASan+UBSan build passed | Retain compiler version and test log in release artifact |
| CUDA compile/link | Windows SM120 build completed with NVCC 12.8.93 / MSVC 19.38.33145, shared CUDA runtime/cuBLAS and static host CRT (2026-09-07) | Clean Linux SM90 build and relocated Windows/Linux signed dependency manifests |
| Numerical CUDA methods | Windows RTX 5080 Quick completed six methods and Standard completed all nine with zero checked-output mismatches (2026-09-07); Standard used a 512 MiB device allocation cap, eight integrity patterns and 4096-square GEMMs; local reports `reports/rtx5080-quick-002` and `reports/rtx5080-standard-001` | Independent small-matrix reference challenge, complete per-platform acceptance and all nine methods on Linux H100; local busy-WDDM results remain unqualified and performance-contaminated |
| CUDA sanitizer | Compute Sanitizer 2025.1.0.0 / CUDA 12.8.1 attempted on Windows RTX 5080 (2026-09-07): nine memcheck methods plus memory/dispatch racecheck, initcheck and synccheck. All instrumentation attempts blocked by disabled WDDM debugger interface; logs `build/windows-validation/sanitizer`; no clean sanitizer pass claimed | Authorized OS debugger-interface setup or suitable Linux target, followed by actual memcheck, initcheck, racecheck and synccheck instrumentation; retain logs |
| Stable selection | Source enforces full UUID, exact visibility and double runtime UUID check | Remapped ordinal, multi-GPU host, hidden GPU, MIG, changed/disappeared GPU fixtures and actual-device checks |
| Allocation ownership/headroom | Source owns all buffers and reserves headroom | Concurrent-memory-pressure tests, allocation failures, pointer/range review, proof of no peer contexts/access |
| Cancellation/driver loss | Cooperative worker budget; parent hard timeout required | Kill/cancel during each phase, failed driver/device disappearance, bounded output and partial-report recovery |
| Timings and repetitions | Event and wall arrays implemented with validity checks | Event/wall consistency, actual Quick/Standard wall budgets, power/thermal curves, repeated runs on separate allocations |
| Correctness interpretation | First mismatch stops load; reports unconfirmed mismatch | Independent reproducibility investigation workflow and false-positive challenge; no device-fault claim from a worker-only failure |
| Calibration | No healthy baseline included | Separate vetted H100 PCIe and RTX 5080 reference acquisition, independent allocations, matching OS/driver model, exact-key qualification and signed approvals |
| Packaging | Source/CMake and signed Windows runtime DLL snapshot support | Actual Windows/Linux binary/dependency qualification, license review, verified release signatures and relocated install/readback test |
| Windows display scheduling | Driver model and kernel timeout state retained; no TDR changes. Local numerical methods completed under explicit busy-GPU opt-in, with performance observations marked contaminated. Sanitizer attempts retained 37–40 C selected-device temperature before/after each bounded call | WDDM desktop responsiveness, cancellation during each method and actual sanitizer access; signed DLL snapshot/tamper and native subprocess tests pass locally |

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
