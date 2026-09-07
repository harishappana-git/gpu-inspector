# Windows RTX 5080 implementation and local validation

Later FP8/INT8 and twelve-method Standard scheduling work is recorded in the [H100 extension validation](H100_SINGLE_NODE.md#local-evidence-for-this-extension), including the final eleven-method RTX numerical pass and explicit Windows NUMA limitation. The measurements below retain their original earlier scope.

Validated on 2026-09-07, starting from revision `bce2c28021aca717e9950bfcf203f97af819ca85` with the Windows/RTX support changes in the working tree. This records actual local execution; it is not a production qualification or an H100 result.

## Machine and toolchains

- Windows 10 Pro x64, build 19045; NVIDIA GeForce RTX 5080, reported 16,303 MiB VRAM, driver 610.88, WDDM.
- Go 1.24.5; CMake 3.31.8; MSVC 19.38.33145; CUDA Toolkit 12.8.1 / NVCC 12.8.93; cuBLAS 12.8.4.1.
- The Go race detector used the portable LLVM MinGW 20260826 x64 toolchain.
- Toolchains were extracted under `build/.toolchains`; no persistent PATH, GPU power, clock, TDR or debugger settings were changed.

## Implemented scope

Native Windows discovery uses trusted installed NVIDIA paths, dynamically loaded NVML and CUDA UUID enumeration. Native Windows host APIs supply CPU, memory, capacity and interface context. Reports, verification, export, replay, support drafts, development signing, per-GPU locking and bounded process cancellation now work on Windows. Private evidence and signing keys use actual protected owner-only DACLs; disk scratch uses an exclusive delete-on-close descriptor.

The CUDA worker supports SM120 alongside SM90 and uses measured device capacity/cache attributes. All nine existing GPU methods are available on the RTX 5080. Signed Windows DLL digests are checked before private snapshot execution and included in reference-matching conditions. Large artifact copies now observe scan cancellation between bounded reads.

`--allow-busy` is an explicit development-testing option for a desktop GPU with visible activity. Identity, mode, headroom and temperature guards still apply. Primary performance observations are retained as `CONTAMINATED`; separate numerical-validation evidence remains available.

This is support for the existing feature set. It does not implement previously absent catalog diagnostics, fabricate unsupported ECC/MIG sensors, or make Linux-only cgroup/PSI measurements on Windows.

## Executed checks

| Check | Actual result |
| --- | --- |
| Full Go suite, fresh run with installed-driver integration enabled | 171 top-level tests passed; no failures |
| Privilege-dependent file-symlink subtest | One narrowly skipped subtest; native junction rejection tested and passed |
| Full Go race suite | Passed |
| Go vet | Passed |
| Windows CLI and CUDA build | Passed |
| CPU C++ known-answer/corruption harness | CTest 1/1 passed |
| SM120 and combined SM90+SM120 Windows worker builds | Passed |
| Tracked `scripts/build-windows.ps1` | Built CLI/worker, passed CTest and staged required DLLs |
| Native NVML, CUDA UUID mapping and forced `nvidia-smi` fallback | Passed on installed RTX 5080 |
| Synthetic clean, ECC-error and missing scenarios | Expected verdicts, valid artifacts |
| Report verification, redacted export, replay, explain, ticket draft and owned cleanup | Passed |
| Optional 8 MiB disk write/readback | Passed; existing workspace fixture preserved; scratch cleaned |
| Optional HTTPS request, 64 KiB response-body cap | TLS/reachability and bounded download passed |
| Windows child cancellation and descendant cleanup | Passed, including parent normal exit and cancellation before start |
| Linux amd64 cgo-free and macOS arm64 builds/test binaries | Cross-compiled; not executed on those OSes |

The final full Go suite used `GRI_WINDOWS_GPU_TEST=1`. Test counts exclude nested subtests to avoid counting both parent and child results. Logs are under `build/windows-validation`, including `go-test.jsonl`, `go-race.log`, `go-vet.log`, `summary.json` and executable hashes.

## Actual GPU run

Standard run `reports/rtx5080-standard-001` lasted **41.239 seconds**, with a **512 MiB device-allocation cap**. The 45 retained temperature samples ranged from **36 to 50 C**. WDDM reported desktop GPU processes; the run explicitly used `--allow-busy`. All nine method-validation records passed with zero observed mismatches:

| Method | Retained samples |
| --- | ---: |
| Owned memory integrity, eight patterns | 8 |
| FP32 GEMM | 64 |
| BF16 GEMM | 64 |
| Device-memory copy (`hbm_copy` legacy protocol ID; GDDR on this card) | 12 |
| Pinned host-to-device transfer | 20 |
| Pinned device-to-host transfer | 20 |
| TF32 GEMM | 64 |
| Working-set sweep | 48 |
| Dispatch latency | 128 |

The memory test checked its owned allocation across patterns; it did not cover all 16 GiB. GEMM validation combines exact output spot checks with full-output nonfinite checks; this does not prove arbitrary-input numerical correctness. Quick scans also completed all six Quick methods, including a final run after the environment and cancellable-loader fixes.

`reports/rtx5080-standard-final/report.html` is a verified replay of the retained Standard evidence using the final report/catalog code. It preserves the original measurement interval and explicitly records that replay did no new hardware work.

## Remaining qualification gates

Compute Sanitizer 2025.1.0.0 was attempted for all nine methods under memcheck and for memory/dispatch under racecheck, initcheck and synccheck. All 15 attempts were blocked at instrumentation initialization because the WDDM debugger interface requires administrator setup. The worker outputs still completed, but **none of these attempts is a sanitizer pass**. Errors, temperatures and outputs are retained under `build/windows-validation/sanitizer`. Debugger/registry settings were not changed.

Linux H100 execution, enabled sanitizer instrumentation, independent qualification/reference acquisition, multi-device cases, full acceptance and release packaging remain outstanding. All reports correctly retain `INCONCLUSIVE` / `UNCALIBRATED` with no health score. Successful local correctness samples do not establish an idle performance baseline, full-VRAM integrity, long-term stability or H100 readiness.

## Run again on this prepared machine

From the repository directory:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build\windows-validation\run-standard.ps1
```

This local helper uses the retained development worker/signature, runs all nine methods with a 512 MiB cap and explicit busy-desktop consent, chooses a new report directory and verifies it. It performs no optional outbound or disk test. Add `-Tier quick -MemoryMiB 256 -BudgetSeconds 90` for the shorter six-method run. Exit code **3** means the saved report is inconclusive/uncalibrated, not that execution failed. The command changes PowerShell execution policy only for that process.

For a fresh build environment, use the tracked [Windows build script](../scripts/build-windows.ps1), [worker instructions](../worker/README.md) and [acceptance runbook](ACCEPTANCE.md). Rebuilds that change worker/DLL bytes require a new development manifest and signature.
