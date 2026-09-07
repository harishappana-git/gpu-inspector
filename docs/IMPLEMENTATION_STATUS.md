# Phase 1 implementation and release status

Status date: **2026-09-07**. Design basis: [GPU Rental Inspector Design v2.0](../GPU_Rental_Inspector_Design_v2_0.md), especially sections 29–31.

The repository contains a **development source implementation of the Phase 1 local workflow** and the bounded Phase 1B path extension, including native Windows x64 / RTX 5080 support alongside Linux x86-64 / H100. It is not a qualified GPU acceptance product release. Source, automated tests, synthetic demonstrations and compilation results are different evidence classes from real GPU measurements, healthy-reference acquisition, production packaging and rental acceptance.

The initial development host was macOS/arm64 with Go 1.24.5 and no NVIDIA GPU or NVCC. Windows implementation and local validation use an RTX 5080 workstation. Local Windows results belong to that exact hardware, driver and toolchain; they do not close Linux H100 acceptance gates. No completed H100 rental campaign, qualified healthy reference, production release key or production binary signature is represented here. See retained validation output and the worker ledger for the exact compilation and device checks completed; software checks alone never establish GPU qualification.

## Work-package gates

| Design work package | Development source delivered | Release evidence still required |
| --- | --- | --- |
| **WP1 — schema, target ownership, CLI** | Versioned observations/checks/findings/reports; exact UUID selection and guard states; bounded scheduler/process interfaces; incremental local journal; scan/report/signing commands. | Actual-device target isolation across remapped ordinals, multiple GPUs, disappearing devices and restricted tenancy; CLI acceptance on qualified Linux images. |
| **WP2 — NVML/OS collectors and degraded modes** | Dynamic Linux and Windows NVML adapters, version-discovered nvidia-smi fallback, read-only CUDA visibility enumeration, allowlisted host/cgroup/capacity/context collectors, native Windows host APIs, explicit blocked/unsupported states and fixtures. | Native ABI/runtime validation against each declared NVIDIA driver stack; host/container/permission matrix; supported MIG/vGPU policy and real failure/history visibility limits. |
| **WP3 — signed CUDA workers and method verification** | Nine CUDA methods for SM90 and SM120; owned allocations, readback/known-answer checks and bounded protocol; platform-bound signature/digest admission and Windows DLL snapshots; independent CPU answer/corruption harness with MSVC support. Development worker remains explicitly unqualified. | Pinned Linux SM90 and Windows SM120 CUDA/cuBLAS qualification, numerical GPU verification, all sanitizer gates, selected-device cancellation/headroom tests and relocated-binary/dependency qualification. See [worker qualification](../worker/QUALIFICATION.md). |
| **WP4 — healthy reference acquisition/calibration** | Ed25519 envelope verification; exact SKU/mode/driver/worker/method/conditions matching; acquisition/expiration/provenance gates; fixed five-metric scoring with abstention. | Real independently tracked healthy allocations, host diversity, retained raw runs, reviewed exclusions/approvals and signed reference packs. No healthy measurements are bundled. |
| **WP5 — deterministic rules, reports and playbooks** | Explicit verdicts; mandatory-check gates; historical/current-event distinctions; linked highlights; private HTML/JSON; integrity indexes; redacted exports; local ticket/guide drafts; false-positive and report/privacy tests. | False-positive/negative review against independently labeled real outcomes, workload impact validation where claimed, and user review of provider-facing drafts. |
| **WP6 — packaging, privacy and dependencies** | Go standard library plus pinned `golang.org/x/sys`, development Make/PowerShell builds, Linux/macOS/Windows CI configuration, signature utilities, POSIX private modes and protected Windows ACLs, export/deletion behavior and privacy tests. | Supported-toolchain review, dependency/license inventory, final executable/library relocation tests, production key custody/rotation, reproducible signed distribution, installer verification and independent privacy review. No official trust root or hosted installer is supplied. |
| **WP7 — real-rental acceptance/release** | [Acceptance runbook](ACCEPTANCE.md), synthetic scenarios and automated boundary tests. | Execute and retain the complete authorized rental campaign; review mandatory gate failures, latency/cost, isolation, cleanup, abstention and outcome evidence. No rental acceptance campaign has been completed. |

All seven work packages have remaining release gates. The presence of their source code does not close those gates. An initial release can use the design's explicit uncalibrated mode only after its applicable safety, packaging and reporting gates pass; uncalibrated mode is not permission to skip real-device method qualification.

## Implemented source scope

Native Windows supports the same existing command/report/signing and optional-path workflows. The extension adds Windows NVML/CUDA discovery, CPU/memory/storage/interface context, per-device exclusion and owned Job Object process control. Worker builds target SM120 with CUDA 12.8+ and MSVC, and signed manifests bind the actual platform plus explicitly staged runtime DLLs. All nine existing methods remain available subject to hardware, driver and allocation checks. This adds source support; it does not remove the diagnostic gaps below or qualify the methods.

The Go module now includes pinned `golang.org/x/sys` for Windows APIs. Evidence and keys use protected current-user-only DACLs; POSIX retains private file modes. Windows privacy checks reject public ACLs and reparse traversal. Windows scratch has exclusive delete-on-close ownership, including process-exit cleanup. File data is flushed before publication, without claiming POSIX directory-fsync power-loss durability on Windows.

Linux cgroups, PSI, `/dev/shm` and POSIX resource limits remain unsupported on native Windows. Native APIs provide bounded context, while nested Windows job constraints and hidden host limits can remain unknown. RTX 5080 has no MIG capability; unavailable ECC/remap/retirement sensors remain unsupported. WDDM desktop scheduling and explicitly permitted busy runs cannot establish uncontaminated idle performance. No score is available until a qualified exact worker/reference pair is provided; RTX references cannot qualify H100.

| Area | Current behavior | Explicit boundary |
| --- | --- | --- |
| Local target | One selected full NVIDIA GPU UUID; permitted visibility intersection; runtime mapping; rechecks and stop conditions. | No peer load, cluster health assessment, fleet controller or attestation certificate. MIG is refused rather than replaced with its parent. |
| GPU telemetry | Reported identity/memory/modes; supported ECC/remap/retirement fields; temperature/thresholds; power/clocks/PCIe/utilization; count-only process context. | Supported and denied fields vary. NVML and nvidia-smi share the host/driver trust domain. No complete Xid history or assured reset epoch. |
| Host context | Process-visible cgroups/ancestor limits, CPU and memory context, shared memory, pressure/events, workspace capacity/mount type and local network context. | Hidden ancestors, quotas, storage persistence and host-wide truth may remain unresolved. No user files, process command lines or private hierarchy dump. |
| CUDA workers | Memory patterns, FP32/BF16/TF32 GEMM, above-cache copy, working-set sweep, H2D, D2H and dispatch latency source. | Unqualified development methods; no measured H100 performance or universal numerical correctness claim. Controlled buffers and exact sample coverage only. |
| Reference/score | Signature and exact-configuration gates, reference expiration, all five fixed weights and no missing-weight renormalization. | No current qualified pack. User profiles do not supply validated application weights or throughput projections. |
| Outputs | Private local evidence and reports, at most five evidence-linked highlights, deterministic findings, safe static guides and redacted local tickets/exports. | Hash integrity is not host authenticity. Tickets are drafts and never submitted. |
| **Phase 1B optional paths** | Explicit workspace-only generated-byte test and single selected HTTPS-object request, with payload/deadline bounds, cleanup and metadata privacy. | No disk cache drops, direct-I/O/steady-state claims, arbitrary endpoint discovery, redirect following, credentials, content archive or production-tail inference. |

`gri catalog` preserves the entire design catalog. Rows marked Quick/Standard describe intended checks and can still be unsupported, blocked or not tested in a particular scan. Future and disabled optional rows stay explicit. Do not describe the catalog's row count as the number of fully implemented or successfully executed diagnostics.

### Diagnostic implementation gaps

| Check | Current limitation |
| --- | --- |
| `A10` VBIOS/OEM consistency | Raw version metadata can be retained. No qualified signed OEM-comparison adapter is implemented, so the consistency check remains not tested. |
| `B06` Xid evidence | No complete device/time-scoped kernel-event history collector or versioned Xid interpretation database is implemented. |
| `B11` vendor diagnostics | No target-restricted DCGM execution adapter is implemented. Installing DCGM alone does not create evidence. |
| `C04` FP8/INT8 capability | No qualified FP8/INT8 numerical worker exists. Architecture claims do not count as measured capability. |
| `D10` NUMA-sensitive transfer | Pinned transfers disclose placement context; a controlled NUMA-binding comparison is not implemented. |
| `H04` documented driver issue | No curated, dated, exact-version/SKU advisory matcher is implemented. An old version alone is not a failure finding. |

These gaps are visible missing checks, not silently passing placeholders. Other unsupported sensors and future catalog rows remain subject to their own stated scope boundaries.

`H10` now has bounded local build evidence: the inspector executable's SHA-256, Go/platform and tool/schema/rule/method versions, plus allowlisted VCS revision/modified state when available. Paths, environment, dependency inventories and arbitrary build flags are omitted. This records local provenance; it does not establish a reproducible build, an authenticated host or qualified CUDA dependencies.

## Evidence available from this development environment

The repository contains automated tests for parsing/visibility/cgroups, cancellation and process-output limits, signed artifacts, worker protocol admission, numerical known answers and synthetic corruption, reference/rule behavior, report hashes/escaping/permissions, export/privacy and optional path cleanup/TLS/body limits. A test is evidence for its stated software behavior only. Consult actual command output when reporting a pass; test-file presence and configured CI are not execution evidence.

The CPU harness and CUDA worker have their own [qualification ledger](../worker/QUALIFICATION.md). Consult that ledger and retained logs for build, numerical and sanitizer results instead of inferring them from source support. Windows private-filesystem, report, bundle and optional-path scoped Go tests and vet passed locally on 2026-09-07. They include real ACL rejection, native junction rejection, key signing roundtrips, report verification/export, disk corruption detection, and scratch cleanup after forced process termination. Linux test binaries for these packages cross-compiled; that is not Linux execution. A Windows file-symlink fixture requires an unavailable privilege and is narrowly skipped on this host; native directory-junction rejection is exercised directly.

The GitHub workflow now configures Windows Go/race/vet/build checks and an MSVC CPU harness in addition to Linux/macOS. It remains source configuration until a remote run is observed and retained. It allocates no GPU and cannot establish CUDA or GPU-health acceptance. `make release-check` runs local development checks; its name does not change the release decision.

Report QA currently includes automated HTML escaping, external-resource exclusion, evidence-link, JSON, permission, integrity and privacy checks. A completed visual browser layout review is not claimed. Large integer counters are retained as exact JSON numbers across readback, replay and redacted export rather than rounded through binary floating point.

## Release decision

**Continue development and controlled qualification; do not publish a qualified healthy-H100 or production-acceptance claim.** Keep reports explicitly uncalibrated until a qualified worker and reference satisfy all applicable gates. Preserve failed and incomplete attempts. Record final approval only against a durable artifact set containing the exact source revision, toolchain/dependencies, hardware scope, test logs, report hashes, reference provenance and release signatures.

CI actions are pinned to commits resolved from the official [actions/checkout repository](https://github.com/actions/checkout) and [actions/setup-go repository](https://github.com/actions/setup-go) on 2026-09-06. Windows runner prerequisites are documented in the official [Windows Server 2022 runner inventory](https://github.com/actions/runner-images/blob/main/images/windows/Windows2022-Readme.md). This documents workflow dependency provenance, not a completed dependency-security audit.
