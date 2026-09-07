# Phase 1 implementation and release status

Status date: **2026-09-06**. Design basis: [GPU Rental Inspector Design v2.0](../GPU_Rental_Inspector_Design_v2_0.md), especially sections 29–31.

The repository contains a **development source implementation of the Phase 1 local workflow** and the bounded Phase 1B path extension. It is not a qualified H100 product release. Source, automated tests, synthetic demonstrations and compilation results are different evidence classes from real GPU measurements, healthy-reference acquisition, production packaging and rental acceptance.

The initial development host is macOS/arm64 with Go 1.24.5. It has no NVIDIA GPU or NVCC available for this work. No real H100 run, CUDA compile/link validation, Compute Sanitizer campaign, qualified healthy reference, production release key or production binary signature is represented here. These gaps remain open regardless of software test results.

## Work-package gates

| Design work package | Development source delivered | Release evidence still required |
| --- | --- | --- |
| **WP1 — schema, target ownership, CLI** | Versioned observations/checks/findings/reports; exact UUID selection and guard states; bounded scheduler/process interfaces; incremental local journal; scan/report/signing commands. | Actual-device target isolation across remapped ordinals, multiple GPUs, disappearing devices and restricted tenancy; CLI acceptance on qualified Linux images. |
| **WP2 — NVML/OS collectors and degraded modes** | Dynamic Linux NVML adapter, version-discovered nvidia-smi fallback, read-only CUDA visibility enumeration, allowlisted host/cgroup/capacity/context collectors, explicit blocked/unsupported states and fixtures. | Native ABI/runtime validation against the exact NVIDIA driver stack; host/container/permission matrix; supported MIG/vGPU policy and real failure/history visibility limits. |
| **WP3 — signed CUDA workers and method verification** | Nine CUDA method implementations; owned allocations, readback/known-answer checks and bounded protocol; signature/digest admission; independent CPU answer/corruption harness. Development worker remains explicitly unqualified. | Pinned Linux SM90 CUDA/cuBLAS build, numerical GPU verification, all sanitizer gates, selected-device cancellation/headroom tests and relocated-binary/dependency qualification. See [worker qualification](../worker/QUALIFICATION.md). |
| **WP4 — healthy reference acquisition/calibration** | Ed25519 envelope verification; exact SKU/mode/driver/worker/method/conditions matching; acquisition/expiration/provenance gates; fixed five-metric scoring with abstention. | Real independently tracked healthy allocations, host diversity, retained raw runs, reviewed exclusions/approvals and signed reference packs. No healthy measurements are bundled. |
| **WP5 — deterministic rules, reports and playbooks** | Explicit verdicts; mandatory-check gates; historical/current-event distinctions; linked highlights; private HTML/JSON; integrity indexes; redacted exports; local ticket/guide drafts; false-positive and report/privacy tests. | False-positive/negative review against independently labeled real outcomes, workload impact validation where claimed, and user review of provider-facing drafts. |
| **WP6 — packaging, privacy and dependencies** | Standard-library Go build, development Make targets, CI configuration, signature utilities, restricted artifacts, export/deletion behavior and privacy tests. | Supported-toolchain review, dependency/license inventory, final executable/library relocation tests, production key custody/rotation, reproducible signed distribution, installer verification and independent privacy review. No official trust root or hosted installer is supplied. |
| **WP7 — real-rental acceptance/release** | [Acceptance runbook](ACCEPTANCE.md), synthetic scenarios and automated boundary tests. | Execute and retain the complete authorized rental campaign; review mandatory gate failures, latency/cost, isolation, cleanup, abstention and outcome evidence. No rental acceptance campaign has been completed. |

All seven work packages have remaining release gates. The presence of their source code does not close those gates. An initial release can use the design's explicit uncalibrated mode only after its applicable safety, packaging and reporting gates pass; uncalibrated mode is not permission to skip real-device method qualification.

## Implemented source scope

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

The CPU harness has its own [qualification ledger](../worker/QUALIFICATION.md). CUDA compilation and real numerical/sanitizer runs remain absent. The GitHub workflow is source configuration until a remote run is observed and retained. `make release-check` runs local development checks; its name does not change the release decision.

Report QA currently includes automated HTML escaping, external-resource exclusion, evidence-link, JSON, permission, integrity and privacy checks. A completed visual browser layout review is not claimed. Large integer counters are retained as exact JSON numbers across readback, replay and redacted export rather than rounded through binary floating point.

## Release decision

**Continue development and controlled qualification; do not publish a qualified healthy-H100 or production-acceptance claim.** Keep reports explicitly uncalibrated until a qualified worker and reference satisfy all applicable gates. Preserve failed and incomplete attempts. Record final approval only against a durable artifact set containing the exact source revision, toolchain/dependencies, hardware scope, test logs, report hashes, reference provenance and release signatures.

CI actions are pinned to commits resolved from the official [actions/checkout repository](https://github.com/actions/checkout) and [actions/setup-go repository](https://github.com/actions/setup-go) on the status date. This documents provenance of the workflow dependencies, not a completed dependency-security audit.
