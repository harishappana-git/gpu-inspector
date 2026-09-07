# Worker qualification ledger

Current state: **NOT QUALIFIED — development implementation**.

| Gate | Current evidence | Required next evidence |
| --- | --- | --- |
| CPU known answers | C++17 harness compiled and CTest passed on macOS with AppleClang 21.0.0; all eight patterns, varied seeds/offsets, fixed matrix answer, BF16/TF32 exact-representation checks, synthetic memory/GEMM corruption, NaN/Inf rejection; a separate ASan+UBSan build also passed | Retain compiler version and test log in release artifact |
| CUDA compile/link | Not run; NVCC unavailable on development machine | Clean Linux SM90 build with pinned toolkit/cuBLAS and dependency manifest |
| Numerical CUDA methods | Not measured | All nine methods on authorized H100 PCIe allocation; compare CPU answers, independent small-matrix reference and checked transfers |
| CUDA sanitizer | Not run | Compute Sanitizer memcheck, initcheck, racecheck and synccheck on each custom kernel and relevant library path; retain logs |
| Stable selection | Source enforces full UUID, exact visibility and double runtime UUID check | Remapped ordinal, multi-GPU host, hidden GPU, MIG, changed/disappeared GPU fixtures and actual-device checks |
| Allocation ownership/headroom | Source owns all buffers and reserves headroom | Concurrent-memory-pressure tests, allocation failures, pointer/range review, proof of no peer contexts/access |
| Cancellation/driver loss | Cooperative worker budget; parent hard timeout required | Kill/cancel during each phase, failed driver/device disappearance, bounded output and partial-report recovery |
| Timings and repetitions | Event and wall arrays implemented with validity checks | Event/wall consistency, actual Quick/Standard wall budgets, power/thermal curves, repeated runs on separate allocations |
| Correctness interpretation | First mismatch stops load; reports unconfirmed mismatch | Independent reproducibility investigation workflow and false-positive challenge; no device-fault claim from a worker-only failure |
| Calibration | No healthy baseline included | Vetted H100 PCIe reference acquisition, independent allocations, exact-key qualification and signed approvals |
| Packaging | Source and CMake only | Actual Linux binary/dependency qualification, license review, verified release signatures and install/readback test |

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
