# CUDA worker development package

This directory implements the isolated CUDA methods for Phase 1A. The current
version is **0.1.0-dev**, with method version **1.0.0**. The portable methods target
Linux x86-64 H100 (SM90) and Windows x64 RTX 5080 (SM120). It remains an
unqualified development build: compilation and local checks do not establish
Compute Sanitizer qualification, H100 measurement, rental isolation, performance
calibration, or a signed production release. See the qualification ledger and
retained local validation logs for the exact checks that have actually run.

The parent CLI owns capability discovery, selected-resource ownership and idle
checks, telemetry safety stops, subprocess timeouts, signature verification,
redaction, and assessment. The worker performs one allowlisted method on one
full physical GPU UUID, emits one JSON line, and exits. It never resets a GPU,
changes clocks/power, creates a context on an unselected device, or accesses
memory belonging to another process. It has no network or credential interface.

## Build and qualification

CPU-only checks work with CMake 3.24+, C++17, and a C++ compiler:

```sh
cmake -S worker -B build/worker-cpu -DGRI_BUILD_CUDA=OFF
cmake --build build/worker-cpu
ctest --test-dir build/worker-cpu --output-on-failure
```

On a **Linux x86-64 H100 qualification machine**, build using an explicitly pinned
CUDA Toolkit 12.0 or later. Linux defaults to SM90 machine code and SM90 PTX;
runtime checks accept compute capability 9.0 and 12.0. Toolkit compatibility is a
build minimum, not a validated compatibility matrix.

```sh
cmake -S worker -B build/worker-cuda -DGRI_BUILD_CUDA=ON \
  -DCMAKE_BUILD_TYPE=Release -DCUDAToolkit_ROOT=/usr/local/cuda
cmake --build build/worker-cuda --parallel 2
ctest --test-dir build/worker-cuda --output-on-failure
```

For **Windows x64 RTX 5080**, use Visual Studio 2022 C++ build tools and Windows
SDK, CMake 3.24+, and **CUDA Toolkit 12.8 or later including cuBLAS**. CUDA 12.8
introduced SM120 compiler/library support. Use the compiler version supported by
the selected toolkit; the local portable toolchain pins MSVC 14.38 and CUDA
12.8.1. In an x64 developer PowerShell:

```powershell
cmake -S worker -B build/worker-windows -DGRI_BUILD_CUDA=ON `
  -DGRI_CUDA_ARCHITECTURES="120-real;120-virtual"
cmake --build build/worker-windows --config Release --parallel 2
ctest --test-dir build/worker-windows -C Release --output-on-failure
```

MSVC warning flags and static host C++ runtime linkage are selected on Windows.
CPU-only CTest uses the same commands with `-DGRI_BUILD_CUDA=OFF`. Multi-config
generators need `--config Release` and `ctest -C Release`. Single-config builds
default to Release so host readback validation fits the method budgets. For a
dual-architecture CUDA 12.8+ build, set
`-DGRI_CUDA_ARCHITECTURES="90-real;120-real;120-virtual"`.

The RTX worker uses the GPU's reported memory capacity and L2 size at runtime;
it does not substitute H100 capacities or baselines. Every existing method is
available on both architectures, subject to runtime allocation, cuBLAS and
driver checks. Unsupported operations retain structured unsupported results.
Windows driver model (WDDM/TCC), kernel timeout state, architecture and OS are
recorded. WDDM desktop scheduling can affect timings. The worker does not change
Windows TDR settings, power limits, clocks, or driver mode.

The executable links CUDA runtime and cuBLAS. It is not a fully static,
driver-independent artifact. Pin the compiler, toolkit, runtime, cuBLAS, glibc,
and driver versions in the release manifest; review their redistribution terms
before bundling libraries. Never build on the renter's machine as the default
installation path. The release packaging layer must sign the actual executable
and its qualified dependencies before a production installer uses it.

The Go launcher snapshots the signed executable into an owner-private
directory and clears inherited loader environment variables. On Windows the
signed manifest may bind up to 12 allowlisted adjacent runtime DLLs using
`dependencies: [{"file":"cudart64_12.dll","sha256":"..."}]`. It authenticates
and snapshots each dependency before starting the process. Each DLL is limited
to 1 GiB, with an aggregate limit of 2 GiB; streaming avoids loading cuBLAS into
the parent CLI's memory. Stage `cudart64_12.dll`, `cublas64_12.dll`, and
`cublasLt64_12.dll` from the pinned toolkit beside the worker, then include each
using `gri manifest worker --dependency PATH`. Needed allowlisted MSVC runtime
DLLs can also be signed; GPU driver and Windows system DLLs remain system-owned.
No ambient CUDA or user PATH is trusted. A manifest must match the actual host
platform (`windows-amd64` or `linux-amd64`).

On Linux the development launcher does not copy adjacent shared libraries.
Consequently, `$ORIGIN` or sibling
library layouts and `LD_LIBRARY_PATH`-dependent installs are not supported by
this development packaging path. A compatible system CUDA/cuBLAS installation
must be resolvable by its system loader configuration or an explicitly qualified
absolute RPATH. CMake's build-tree RPATH commonly names the build machine's
toolkit location; `cmake --install` can remove it. Qualify the *relocated final
executable* on the target image. No portable bundled-library release is claimed.

Before any supported-configuration claim, complete every item in
[QUALIFICATION.md](QUALIFICATION.md). A successful build is not numerical or
hardware qualification.

## Invocation and output

The parent must provide an already-authorized full UUID and an environment that
restricts visibility to that exact UUID:

```sh
CUDA_VISIBLE_DEVICES=GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee \
  build/worker-cuda/gri-cuda-worker \
  --device GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee \
  --method memory_integrity --budget-ms 10000 --memory-mib 256 \
  --seed 12345 --tier quick
```

The UUID above is an illustrative placeholder, not an allocation identifier.
`--device` and `--method` are required. Defaults are `--budget-ms 5000`,
`--memory-mib 256`, `--seed 1`, and `--tier quick`. Numeric values are unsigned;
budget is 100–300000 milliseconds, memory is 1–8192 MiB, and seed is uint32.
Unknown/repeated flags and abbreviated, numeric, MIG, or malformed device IDs
are rejected. A preexisting `CUDA_VISIBLE_DEVICES` different from the exact UUID
is rejected; the worker does not broaden a caller's device visibility. The
parent must preserve container/allocation restrictions when resolving targets.

Exit status 0 means a completed method; status 2 means a structured failure or
incomplete method. Stdout is exactly one bounded JSON object followed by a
newline. Stderr is unused. CUDA/cuBLAS errors expose fixed operation identifiers
and numeric native codes, never arbitrary driver text. All numerical JSON values
are finite or `null`.

| Field | Contract |
| --- | --- |
| `schema_version`, `worker_version`, `method_version` | `"1.0.0"`, `"0.1.0-dev"`, `"1.0.0"` |
| `device_uuid`, `method` | Requested full UUID and allowlisted method |
| `status` | `ok`, `unsupported`, `blocked`, `test_error`, `mismatch`, `budget_exhausted` |
| `metric` | `{name,value,unit}` using the sample median; `null` on any incomplete/failure status |
| `samples`, `sample_count` | Array of scalar doubles in the metric unit and its length |
| `timings` | `cold_start_ms`, `warmup_ms`, total `wall_ms`, paired arrays `event_samples_ms`, `wall_samples_ms`, and `sample_verified_offsets_ms` |
| `spread` | Median, median absolute deviation (`mad`), `independent_allocations: 1` |
| `conditions` | Seed, tier, cap, exact math/input/copy conditions, runtime versions, UUID recheck, scope |
| `coverage` | Method-specific logical bytes, passes, output checks, or working-set windows |
| `correctness` | `checked`, `checked_values`, bounded mismatch examples/count, confirmation and reproducibility fields |
| `errors` | Array of fixed `{code,native_code}` records |
| `limitations` | Explicit constraints on interpretation and current qualification |

`correctness.checked` is false until a host validation actually runs. The
mismatch count is a **lower bound** when wrong output is found, because bounded
examples stop at eight per validation chunk and active load stops immediately.
`confirmation_count` is zero and `reproducible` is false: a single worker
mismatch is an observed method failure, not a reproduced physical GPU fault.
`synthetic` is always false for this executable. Deliberate corruption exists
only in the CPU harness. The parent must keep synthetic fixture reports separate
from observations made by this executable.

Failures and exhausted budgets retain completed samples, checked-value counts,
and bounded error evidence; the main metric becomes null so partial observations
cannot silently enter a performance score. An incomplete integrity pass is not
counted as a completed pass or full allocation coverage.

## Methods

| Method | Checked operation and units |
| --- | --- |
| `memory_integrity` | Test-owned allocation with 3 Quick or 8 Standard patterns; every returned uint32 checked on host in 1 MiB chunks; logical allocation/pass coverage. Pattern fill GB/s is diagnostic context, not an HBM score. |
| `fp32_gemm` | Dense column-major cuBLAS GEMM, FP32 operands/output/accumulator, `CUBLAS_COMPUTE_32F_PEDANTIC` and pedantic math; TFLOP/s counts exactly `2MNK`. |
| `bf16_gemm` | BF16 operands and FP32 output/accumulator; `CUBLAS_COMPUTE_32F`; reduced-precision reduction disallowed. Tensor-core eligibility is distinct from independently proving generated instructions. |
| `tf32_gemm` | FP32 operands/output, explicit `CUBLAS_COMPUTE_32F_FAST_TF32`, reduced-precision reduction disallowed. Integer known answers do not measure arbitrary-input TF32 accuracy. |
| `hbm_copy` | Legacy method ID for owned device-memory copy on both architectures; each buffer at least twice reported L2. Effective GB/s counts reads + writes (`2 * bytes`). SM90 retains `hbm_effective_copy_bandwidth`; SM120 reports `device_memory_effective_copy_bandwidth` (RTX 5080 is GDDR7). All returned output words checked. |
| `working_set` | Cache-scale and above-L2 buffer sizes with strides 1/17; per-window size/stride/value retained. Mixed aggregate is ineligible for HBM reference scoring. |
| `h2d`, `d2h` | Distinct pinned-host `cudaMemcpyAsync` paths; one-direction payload GB/s. Every transferred word is checked in each measured sample. NUMA binding is uncontrolled and disclosed. |
| `dispatch_latency` | 128 separately synchronized one-thread increments; every result checked. Wall microseconds include event/synchronization overhead; event timings retained. |

GEMM uses seeded integers in [-3,3], all exactly representable by FP32, BF16, and
TF32. Independent host int64 dot products validate 128 output positions per
sample, including first/last positions, and every returned output is checked
for nonfinite values. Quick starts at M=N=K=2048; Standard at 4096; shape shrinks
to fit the explicit cap. Two GEMMs warm the library, then 8 or 64 samples each
time eight identical-input GEMMs. The last output of each batch is checked;
overwritten intermediate results are not independently validated. This is a
specified known-answer subset, not a universal floating-point accuracy suite.

The input generator, seeds, and canonical logical-input FNV-1a checksum are
recorded. Memory/transfer checks retain checksums of verified readbacks or
expected input. FNV-1a is a noncryptographic reproducibility checksum, not an
artifact signature or a trust proof. Reference packs must match the complete
method conditions and library version. No healthy reference is supplied here.

Timing separates CUDA initialization from method warm-up. CUDA events bracket
the operation, and event synchronization completes it before host elapsed time
is read. Sample verification offsets retain the measured sequence within the
worker's monotonic timeline, including host validation gaps. A nonpositive/nonfinite event duration or event time exceeding wall
time by more than 2 ms invalidates the measurement. Repetitions are correlated
samples on one allocation. Standard's observed interval is not a heat soak.

The worker leaves at least max(512 MiB, 10% of device memory) free at its initial
headroom check. Its own device buffers use the smaller of remaining free memory
and the explicit cap; cuBLAS/context overhead uses reserve. Concurrent external
allocations can still cause a subsequent allocation failure, which is reported
as blocked. Pinned host memory is capped at 64 MiB Quick / 256 MiB Standard.

The internal monotonic budget is checked between bounded operations and
readback chunks. It is cooperative: CUDA initialization, allocation, a kernel,
or a driver call cannot be interrupted by this check. The parent must enforce
a wall-clock process timeout and stop scheduling active tests after a timeout
or mismatch. An uninterruptible driver wait may survive userspace termination;
neither layer promises to repair the host.

## Primary method references

- NVIDIA [cuBLAS documentation](https://docs.nvidia.com/cuda/cublas/index.html): compute types, math modes, GEMM semantics, library version sensitivity.
- NVIDIA [CUDA C++ Best Practices Guide](https://docs.nvidia.com/cuda/cuda-c-best-practices-guide/): event timing, effective bandwidth accounting, numerical validation and pinned-memory limits.
- NVIDIA [CUDA environment variables](https://docs.nvidia.com/cuda/cuda-programming-guide/05-appendices/environment-variables.html): UUID selection and visible-device enumeration.
- NVIDIA [Compute Sanitizer](https://docs.nvidia.com/compute-sanitizer/ComputeSanitizer/index.html): development checks for memory/race/init/synchronization errors.

These references informed the source implementation. They do not qualify this
worker or establish a healthy H100 or RTX 5080 performance envelope.

- NVIDIA [CUDA 12.8 release notes](https://docs.nvidia.com/cuda/archive/12.8.0/cuda-toolkit-release-notes/index.html): Blackwell compiler/library support.
- NVIDIA [Windows installation guide](https://docs.nvidia.com/cuda/archive/12.8.1/cuda-installation-guide-microsoft-windows/index.html): supported Windows/compiler toolchains.
- NVIDIA [CUDA GPU capabilities](https://developer.nvidia.com/cuda/gpus): RTX 5080 compute capability 12.0.
