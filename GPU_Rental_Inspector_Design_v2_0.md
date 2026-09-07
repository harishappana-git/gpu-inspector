# GPU Rental Inspector — Design v2.0

**Date:** 6 September 2026  |  **Status:** design specification, not implementation  |  **Catalog:** 147 planned checks


---

## GPU Rental Inspector

UPDATED PRODUCT & TECHNICAL DESIGN • VERSION 2.0 • 6 SEPTEMBER 2026

A verdict-first inspection of one rented NVIDIA GPU and its visible execution environment, designed to grow into node, cluster and data-center assurance.

> PRODUCT PROMISE
> Run a bounded local inspection. Learn whether to keep the allocation, keep it with conditions, stop and request remediation/replacement, or collect missing evidence. Every conclusion links to facts, a reference and the limits of what was observed.

### Release decision

| Now | Designed for later |
| --- | --- |
| Free, CLI-first; one selected GPU on one Linux node. | Multiple GPUs, multiple nodes, other vendors and data centers. |
| H100 first. Initial calibration target: H100 PCIe 80 GB. | Separate validated packs for SXM/NVL, other NVIDIA SKUs, then other vendors. |
| Quick and Standard scans; no account or API token. | Deep scans, workload dry-runs, fleet service, controller and Guardian. |
| Local terminal, self-contained HTML, JSON and ticket draft. | Approved provider ticket submission and managed fleet workflows. |


This specification adds a concrete collection pipeline, 147 catalog checks, missing-data fallbacks, custom-kernel responsibilities, reference qualification, score eligibility, safe remediation and provider evidence. It retains the renter experience but removes claims the software cannot establish.

A fast result is a scoped assessment, not proof of authenticity, full physical-memory coverage, remaining lifetime or a guaranteed refund. The fastest observed card is not the minimum acceptable healthy card.

### Document status

Design only. No probe has been implemented, no H100 has been tested for this document, and no healthy measured baseline or fleet percentile is supplied. Numeric scan budgets and release gates below are proposed engineering policies, not validated product performance.

Working name: GPU Rental Inspector. Proposed command: gri. Neither a published package nor an installer domain is represented as available. Sources [S01]–[S44] were consulted for this design; pin their applicable versions before release.

### Reading map

Scope and decision engine: pages 2–8. Full staged catalog: pages 9–21. Missing-data and measurement plans: pages 22–24. Tools, actions and delivery: pages 25–31. Schemas and claim rules: pages 32–33. Clickable primary sources: pages 34–37.


---

## 01 / Scope and claim boundaries

One selected GPU does not mean permission to inspect or stress every device on the host.

| Area | Phase 1 decision | Boundary |
| --- | --- | --- |
| GPU target | H100 PCIe 80 GB is the first qualified reference cohort. | SXM, NVL, MIG and other cards are detected, not compared to the PCIe pack. |
| Device selection | Auto-select only when one permitted device is visible. | Multiple visible devices require an explicit stable target; no peer tests. |
| Operating environment | Linux x86-64; supported NVIDIA driver; bare metal, VM or container. | Unprivileged by default. Windows, WSL and ARM need later qualification. |
| Memory | GPU memory health, accessible capacity and bandwidth now. | Deep host-RAM/whole-node physical-memory diagnostics later. |
| Host, disk and Internet | Read-only context now; small opt-in Standard path tests. | Full storage, software, network and workload diagnosis remain later phases. |
| Workload intent | General default; profile changes priorities and caveat wording. | No token/s, training-time or model-fit promises without a representative dry-run. |
| Price | Optional user-declared rental price; exact-scope value math only. | Live market feeds and paid subscriptions are not Phase 1 dependencies. |
| Existing or new cards | Identical correctness gates and SKU-specific expectations. | No age penalty, prior-mining inference or lifetime estimate from appearance. |
| Remediation | Reviewed guides and scripts generated for user approval. | No silent power changes, firmware flashing, GPU resets or process termination. |
| Provider support | Local ticket-message and evidence files. | Submission requires a verified integration and explicit send permission. |

### Three claim levels

Observed: a measurement or exposed counter. Interpreted: a comparison or hypothesis supported by that evidence. Proven within scope: only a narrowly specified test property, such as a repeated output mismatch. A hardware-defect allegation requires stronger corroboration than a slow benchmark.

H100 is a family with different exposed configurations; maintain separate capability and reference records. NVIDIA documents multiple H100 variants and MIG support. [S11, S12]

> Do not promise “trusts nothing and measures everything.” Use: “Does not rely on listings or one telemetry source; independently exercises accessible resources, cross-checks evidence, and reports what the environment cannot verify.”


---

## 02 / Architecture and collection flow

Measurements are produced on the rented machine; verdicts are reproducible from a versioned evidence bundle.

```text
User intent + expected allocation + test budget
                        |
                 local CLI orchestrator
                        |
      capability discovery + device ownership guard
                        |
   NVML / OS collectors + isolated CUDA/test workers
                        |
       timestamped evidence + test-result journal
                        |
   reference matcher -> deterministic finding engine
                        |
       verdict + highlights + guide + ticket draft
                        |
    terminal / local HTML / JSON / private evidence

Future, opt-in: controller <-> agents <-> fleet service
```

| Component | Implementation decision |
| --- | --- |
| CLI / scheduler | Go entry point; typed plugins; target lock; deadlines; cancellation; local progress stream. |
| CUDA worker | Signed C++/CUDA executable(s), precompiled for supported architectures; driver API and qualified math-library pack. |
| Collectors | Direct NVML where available; nvidia-smi fallback; allowlisted /proc, /sys, cgroup and runtime queries. |
| Evidence store | Append-only local records with scan IDs, test versions, monotonic times and data-source trust labels. |
| Reference engine | Bundled signed SKU and calibrated-method packs; updates explicit; offline assessment supported. |
| Rules and reports | Deterministic rule IDs and templates. No LLM needed for pass/fail or remediation generation. |
| Future coordinator | Per-node agents, scoped resource graph, authenticated transport and workload/rank-aware aggregation. |

A single entry point is practical; a fully static, dependency-free CUDA tool is not the promise. The host NVIDIA driver remains required. Optional cuBLAS/DCGM components have their own compatibility and redistribution requirements. The quick path must not compile code or install a large framework on the rental. [S13, S15]


---

## 03 / How data is obtained from each machine

Collect supported, decision-relevant fields—not an indiscriminate inventory of the user’s files or secrets.

| Layer | Collection method | Treatment |
| --- | --- | --- |
| Declared | User input; later provider API inventory. | Expectation only. Store source, timestamp and whether it was independently checked. |
| Reported | NVML, nvidia-smi, CUDA attributes, sysfs, cgroup, selected logs. | Host/driver-mediated evidence. Preserve unsupported and permission-denied states. |
| Measured | Our signed CUDA workers; qualified vendor/community tools. | Record inputs, checked outputs, duration, repetitions and exact accessible scope. |
| Corroborated | Agreement across IDs, execution behavior, performance and relevant logs. | Raise evidence strength, but do not count shared backends as independent witnesses. |
| Attested, later | Supported device/CPU TEE evidence verified outside the rental trust boundary. | Separate certificate/firmware claims from performance and physical-health claims. |

### Collection contract

Each collector declares required permissions, supported GPUs, read/write effects, estimated cost, output schema, cancellation behavior and fallback. Enumerate safely, map CUDA and NVML handles to the chosen device, then recheck identity before every active test. A changing or ambiguous mapping invalidates the affected result.

Take pre-scan and post-scan error snapshots. During active tests, sample a small telemetry set at a proposed 1 Hz, with source resolution recorded; event subscriptions supplement polling where supported. Treat counters that reset, wrap, become unavailable or change scope as discontinuities—not improvements.

Use monotonic time for durations and UTC for correlation. Record cold-start and warm results separately. A log event must match the selected device and observation window before it is attributed to the scan. Record wall-clock uncertainty and the oldest available log, not an assumed complete history.

### Isolation and trust

NVML and nvidia-smi are not independent proofs: NVIDIA provides nvidia-smi on top of its management-library capabilities. Direct API calls avoid simple text-wrapper substitutions but remain within the host/driver trust boundary. [S01–S03]

Launch tools with argument arrays, timeouts and an allowlisted environment; cap stdout/stderr and redact before export. Do not weaken a security control to obtain a metric. Optional host-privileged collection is a separately approved helper, not a default requirement.


---

## 04 / Direct setup, scan tiers and progress

All Phase 1 scans are free software. Rental time, storage and authorized network traffic can still cost money.

### One-command experience

After a signed release exists, publish one installer-and-scan command that runs without sudo, installs into a private user directory and verifies the release manifest and executable signatures. Also offer an offline signed archive and an inspect-before-run installation path. Do not advertise a placeholder domain as a working command.

```text
# Proposed CLI contract; not an installed product today.
gri scan --tier quick

gri scan --device GPU-<uuid> --expected-sku h100-pcie-80gb \
  --tier standard --profile general --budget-seconds 300

gri explain <finding-id> --report ./report.json
gri ticket draft --report ./report.json --provider generic
```

| Tier | Budget and intended evidence | Not claimed |
| --- | --- | --- |
| Quick / free | Target 60–90 seconds after installation; identity, health deltas, sampled integrity, brief compute/memory/PCIe tests. | No heat-soak guarantee, complete memory sweep or workload throughput projection. |
| Standard / free | Default proposed 300-second cap, configurable; more repetitions and memory coverage; selected supported diagnostics. | No automatic right to overrun the budget because DCGM is slow or unavailable. |
| Deep / later | User-budgeted soak and broader patterns; add workload rehearsal when supported. | Not “full hardware certification”; still constrained by accessible memory and permissions. |

### Quick scheduling target

0–18 s: discover, guard the target, capture baseline and initialize CUDA. 18–38 s: bounded memory/correctness samples. 38–65 s: compute and memory movement. 65–80 s: host transfer. Remaining time: targeted repeat, final deltas and report. This is a proposed schedule to validate on real rentals, not measured timing.

Run heavy tests serially so they do not contaminate each other; lightweight telemetry may overlap. Emit an early stop warning on an active correctness failure or critical device event. Write partial results continuously. Cancellation, missing dependencies and exhausted budgets still produce a report with explicit incomplete coverage.

> Track both installation-to-report time and test time. Slow installation is part of the renter experience; it must not be hidden to make a 90-second claim look better.


---

## 05 / Healthy reference design

“Measured versus expected” is useful only when expected means the right thing.

| Reference layer | Meaning | May support |
| --- | --- | --- |
| Manufacturer ceiling | Published specification for the exact SKU and mode. | Identity sanity and theoretical context; not a mandatory application speed. |
| Healthy operating envelope | Repeated measurements on vetted, correctly configured comparable allocations. | Normal-range judgments and underperformance flags. |
| Best-known healthy reference | Repeatable strong performance from a qualified setup, with its conditions. | Optimization opportunity and reference-equivalent cost; not a defect cutoff. |
| Independent fleet sample | Opt-in results grouped by comparable configuration and deduplicated as far as evidence allows. | Sample percentile, with population bias and sample size disclosed. |
| User requirement | The declared memory, latency, throughput or completion constraint. | Fit/no-fit for that job, even where peer data is missing. |

### Exact reference key

Vendor; product and form factor; memory variant; MIG/vGPU/CC mode; relevant power configuration; driver and worker/method versions; numeric format and math mode; matrix/input shapes; transfer method and direction; topology and host class where relevant; thermal state; test duration; correctness criteria. [S11–S16]

For CPU, disk and Internet tests, a GPU SKU is not a sufficient reference. Use the effective host allocation, selected path and user requirement. Compare an Internet path to the same endpoint/protocol conditions—not to a card specification.

### Two simultaneous comparisons

Compare against the configuration actually exposed, and separately against what was declared. A disclosed lower-power configuration may be healthy at its setting. An undisclosed limitation may justify a replacement request even when it is not a physical defect. Do not normalize a misleading allocation into an unconditional pass.

### Cold-start rule

There are no healthy H100 measurements in this document. Before calibration, report specifications and measurements separately and mark performance judgment UNCALIBRATED. Never fill a healthy table with theoretical TFLOPS, online anecdotes, another H100 variant or guessed values.

> Not “below the top score = defective.” Use “outside a qualified healthy range, repeated under comparable conditions, with confounders checked.” A critical correctness failure can stand on verified test evidence even without a performance baseline.


---

## 06 / Reference qualification and scoring

Reference quality is a release dependency, not an optional analytics feature.

### Build the reference pack

Use operator-controlled or cooperatively validated allocations with known configurations. Run vendor diagnostics where supported, correctness tests and a longer stability assessment; verify no competing job was intentionally active. Repeat the same test pack over independent sessions. Select healthy systems by health and configuration—not merely because they were fast.

Proposed initial policy: at least five independently tracked allocations across at least two host systems for a provisional SKU pack. Publish its limitations. A useful fleet percentile needs a broader cohort; initially suppress it below 30 deduplicated allocations and show population composition. These counts are product gates to evaluate, not statistical guarantees.

Store raw-run provenance, pack version, calibration date, reference interval, sample count and approval history. Separate repeat runs from independent allocations. Quarantine impossible, replayed or inconsistent results. New software/method versions require requalification or an explicit compatibility study.

### Eligibility before scoring

First decide whether the tests and reference match. Second apply correctness and resource gates. Only then compute a score from eligible measured performance. Missing checks reduce coverage and can make the overall result INCONCLUSIVE; they must not vanish through automatic weight renormalization.

```text
Higher-is-better metric ratio = measured / healthy reference
Lower-is-better metric ratio  = healthy reference / measured
Normalized metric score      = 100 * min(1, ratio)
Coverage                     = tested eligible weight / required weight
Reference-equivalent $/hour   = listed $/hour / workload ratio
```

These formulas define a transparent scoring convention, not a biological-health probability. If an overall 0–100 score is shown, label it “measured readiness score,” show coverage beside it and suppress it when a mandatory check is missing. The underlying ratio may exceed 100%; never hide that in the evidence.

Profiles weight measured bottlenecks, not stereotypes. Inference may be compute-, memory- or latency-limited depending on batch, context and serving constraints. Phase 1 profiles change priorities and wording only; later calibrated dry-runs justify numeric workload weights.

Proposed General performance weights: BF16 GEMM 30%, FP32 GEMM 10%, HBM streaming 40%, pinned H2D 10% and D2H 10%. The weighted arithmetic mean uses that fixed denominator only when all five qualified measurements are present. This is a transparent initial product convention to validate, not a claim about every application’s bottlenecks; health and missing-evidence gates still override it.

### Grades and blockers

Use A–F only for eligible quantitative categories under a published scale; use PASS / WARNING / FAIL / UNKNOWN for identity and health, and OBSERVED EXPOSURES / NOT ASSESSED for trust. “Reliability A” or “Security A” would imply evidence a brief guest-level scan does not possess.


---

## 07 / Verdict, highlights and evidence

Three renter actions plus one essential abstention state.

| Verdict | Meaning and action |
| --- | --- |
| KEEP | Required checks passed within the stated scope. Start only the workload/configuration actually covered. |
| KEEP WITH CAVEATS | A specific limitation is understood and acceptable for the selected scope. Show the condition and retest trigger. |
| DO NOT START / REQUEST FIX OR REPLACEMENT | A required check failed or evidence supports an unacceptable allocation. This is not automatically a physical-defect finding. |
| INCONCLUSIVE | Important checks were blocked, uncalibrated, contaminated or unfinished. Name the next useful test. |

### Illustrative first screen — no actual measurement

```text
VERDICT: INCONCLUSIVE — REFERENCE REQUIRED
Scope: one selected H100 allocation | Standard | general
Measured readiness score: withheld — no qualified reference

PASS: selected CUDA device executed checked test operations.
PASS: no mismatches in the memory regions this test exercised.
CONCERN: host-to-GPU results varied across repeated runs.
NEXT: repeat the transfer test on an idle allocation.

Coverage: completed checks and missing checks shown explicitly.
Identity: consistent with reported SKU; not authenticated.
Health: no fault observed in tested scope, not future-life proof.
Evidence: method IDs, timestamps, memory coverage and raw results.
```

The production card shows at most five highlights total, including blockers. A details layer may separate up to three strengths and three concerns. Do not fill empty slots. The card contains the selected scope, observation period, fit statement, evidence limitations and a single next action.

Each concern contains measured value, relevant reference/range, delta where meaningful, consequence, evidence strength and recommendation. When impact is not quantifiable, say “impact not quantified; run this workload check.” Do not invent an 8–12% training penalty from a power-limit reading alone.

### Finding contract

Finding ID; severity; observed fact; subject and time window; source/method; reference ID and applicability; uncertainty; interpretation and alternative explanations; measured or estimated impact; safe next action; verification steps; supporting evidence IDs. Keep observation confidence separate from root-cause confidence.


---

## 08 / Catalog A — identity and allocation

Cross-check consistency; never claim that seven host-mediated checks prove authenticity.

Stage key: Q = Quick; S = Standard; O = optional bounded Phase 1 extension; F = future. All are planned checks, not implemented features. Foundation: [S01–S03, S11–S16, S33–S35].

| ID / stage | Check | How evidence is obtained | Decision-relevant output |
| --- | --- | --- | --- |
| A01 Q | Claimed vs visible SKU | Compare user expectation with NVML, CUDA and available PCI attributes. | Match, mismatch or unresolved expectation. |
| A02 Q | Exact variant | Form factor, memory size, part/subsystem identifiers where exposed. | Do not apply PCIe expectations to SXM/NVL. |
| A03 Q | CUDA capability | Architecture, multiprocessor count, cache and supported attributes. | Attribute consistency, not a die-authenticity certificate. |
| A04 Q | Usable device | Initialize chosen device and execute checked work. | Management visibility differs from application access. |
| A05 Q | Memory allocation shape | Reported capacity, free bytes and successful bounded allocation. | Accessible capacity mismatch; physical type not proven. |
| A06 Q | MIG / vGPU mode | Supported partition queries and runtime-visible resource shape. | Slice or full-device expectation; unknown remains unknown. |
| A07 Q | Stable target mapping | Map UUID/PCI/runtime handle; recheck before each worker. | Stop if the selected resource changes or is ambiguous. |
| A08 Q | Visible count / uniqueness | Enumerate permitted devices without stressing peers. | Expected visibility mismatch; no hidden-host inventory claim. |
| A09 S | Performance signature | Compute/memory/transfer pattern against same-method references. | Identity inconsistency hypothesis, not specific counterfeit ID. |
| A10 S | VBIOS / OEM consistency | Exposed version against signed vendor/OEM references when available. | Unrecognized version is unknown, not automatically modified. |
| A11 Q | Virtualization context | Allowlisted cgroup, namespace, DMI/CPU signals where available. | Observed execution context; not isolation proof. |
| A12 F | Hardware-rooted attestation | Supported device and CPU-TEE evidence with independent verifier. | Precisely scoped verified claims, not a health/performance pass. |


---

## 09 / Catalog B — health and integrity

New and old GPUs receive the same correctness gates; history and age are not inferred.

Stage key: Q = Quick; S = Standard; O = optional bounded Phase 1 extension; F = future. All are planned checks, not implemented features. Foundation: [S03–S09, S18, S19, S31].

| ID / stage | Check | How evidence is obtained | Decision-relevant output |
| --- | --- | --- | --- |
| B01 Q | ECC availability/state | Capability-aware ECC queries and error status. | Enabled, disabled, unsupported or blocked; never “zero” for N/A. |
| B02 Q | Corrected-error delta | Pre/post counters with reset/epoch detection. | New events during the scan; historical total kept separately. |
| B03 Q | Uncorrectable-error delta | Device-scoped events, counter deltas and recovery state. | Stop active testing when a current critical condition is detected. |
| B04 Q | Row-remap state | Pending, failure, available reserve and supported remap fields. | Maintenance required versus historical repaired condition. |
| B05 Q | Retired memory pages | Supported page-retirement state and pending action. | Contextual health signal; no universal lifetime threshold. |
| B06 Q | Xid evidence | NVML events and readable kernel logs, mapped to GPU/time. | Hardware/software/application possibilities remain distinct. |
| B07 Q | Sampled memory patterns | Known patterns in test-owned allocations; verified readback. | Exact bytes/patterns/passes tested and mismatch count. |
| B08 S | Broader accessible-memory sweep | Bounded chunks, varied patterns and headroom protection. | Larger logical coverage; never all physical VRAM claimed. |
| B09 Q | Compute correctness | Known-answer operations; independent host checks where practical. | Reproducible wrong output is a blocker; investigate cause. |
| B10 S | Errors across repeated load | Compare early/late error deltas and successful operations. | Observed stability interval, not multi-day survival probability. |
| B11 S | Vendor diagnostics | Selected target-restricted DCGM tests within approved budget. | Retain individual pass/fail/skip results and plugin versions. |
| B12 Q | Context/device loss | Worker status, timeout, CUDA errors and device reappearance. | Distinguish test failure, software failure and device loss. |


---

## 10 / Catalog C — measured GPU performance

Identical SKU is necessary but not sufficient: method, format and execution conditions must also match.

Stage key: Q = Quick; S = Standard; O = optional bounded Phase 1 extension; F = future. All are planned checks, not implemented features. Foundation: [S13–S16, S18, S20, S31, S32].

| ID / stage | Check | How evidence is obtained | Decision-relevant output |
| --- | --- | --- | --- |
| C01 Q | FP32 compute | Qualified GEMM shapes, timings and checked results. | Measured dense throughput vs eligible same-method reference. |
| C02 Q | BF16/FP16 tensor compute | Explicit operand/accumulator type and supported library path. | Relevant accelerator path, no sparse/dense confusion. |
| C03 S | TF32 precision behavior | Explicit math mode and verification tolerance. | Avoid comparing TF32 and full-FP32 results as equivalent. |
| C04 S | FP8/INT8 capability | Only qualified supported kernels and scale conventions. | Not tested rather than failed when the test path is absent. |
| C05 Q | HBM bandwidth | Large-buffer streaming or qualified copy test exceeding cache scale. | Effective bandwidth with exact read/write byte definition. |
| C06 S | Cache / working-set sweep | Vary working set and strides within owned memory. | Separate cache effects from sustained device-memory behavior. |
| C07 Q | Pinned H2D / D2H | Separate transfer directions with checksum and host placement. | Transfer result, host-memory context and tested size. |
| C08 S | Launch/dispatch latency | Repeated small operations with warm-up and explicit synchronization. | Jitter symptom; not proof of time-sharing. |
| C09 S | Sustained compute curve | Non-overlapping early/late windows, clocks and event timeline. | Measured degradation over this interval only. |
| C10 S | Repeatability | Robust spread, outliers and sample count across windows. | Unstable measurement or allocation; cause may be unresolved. |
| C11 F | Real application proxy | Pinned inference/training/rendering test with representative inputs. | Proxy result explicitly separated from the user’s real job. |
| C12 S | Timing/data validity | CUDA errors, returned result checks, wall/event time consistency. | Invalidate implausible or incomplete measurements. |


---

## 11 / Catalog D — power, cooling and PCIe

Lower clock or lower power alone is not a defect; a slow link matters according to the workload.

Stage key: Q = Quick; S = Standard; O = optional bounded Phase 1 extension; F = future. All are planned checks, not implemented features. Foundation: [S02–S04, S10, S16, S27].

| ID / stage | Check | How evidence is obtained | Decision-relevant output |
| --- | --- | --- | --- |
| D01 Q | Power configuration | Supported configured/default/allowed limits and declared profile. | Disclosed setting versus possible allocation mismatch. |
| D02 S | Power/performance relationship | Align telemetry with measured work windows. | Quantify observed performance gap, not a universal cap penalty. |
| D03 Q | Clock-event reasons | Supported reason masks/counters and sampling intervals. | Power limiting, thermal slowing and idle are distinguished. |
| D04 Q | Core temperature | Available sensor and device-specific thresholds. | Operating observation; no generic one-temperature verdict. |
| D05 S | Memory temperature | Read only if exposed; otherwise record missing. | Do not infer junction temperature from core temperature. |
| D06 S | Cooling stability | Temperature/performance trend under bounded load. | Short-duration correlation, not thermal-paste or mining history. |
| D07 S | Fan/chassis signals | Supported fan data; server cooling only with host access. | Passive GPU without fan metric is not a failed fan. |
| D08 Q | PCIe negotiated link | Width/generation at idle and during transfer; endpoint capabilities. | Persistent narrow/slow path versus idle power management. |
| D09 S | PCIe error deltas | Supported replay counters and available AER evidence. | Rate/context of errors; no hardware cause from total alone. |
| D10 S | NUMA-sensitive transfer | Repeat on permitted host placement when safe and meaningful. | Placement-sensitive bottleneck and verified retest direction. |
| D11 F | GPU energy per work | Supported energy or integrated telemetry with scope labels. | GPU-only estimate, not whole-node electricity or billed spend. |
| D12 F | Power/cooling root cause | Correlate BMC/PSU/inlet telemetry with GPU behavior. | Provider-side investigation, not guest-side PSU diagnosis. |


---

## 12 / Catalog E — host and execution resources

The useful question is how much CPU/RAM the job can actually use.

Stage key: Q = Quick; S = Standard; O = optional bounded Phase 1 extension; F = future. All are planned checks, not implemented features. Foundation: [S24–S27]; optional system tools must be version-qualified.

| ID / stage | Check | How evidence is obtained | Decision-relevant output |
| --- | --- | --- | --- |
| E01 Q | Effective CPU allocation | Allowed CPUs, affinity, quota and cgroup hierarchy visibility. | Visible CPUs are not necessarily usable CPU entitlement. |
| E02 Q | CPU quota throttling | cpu.stat deltas where exposed. | Time lost to quota enforcement, not proof of host overselling. |
| E03 S | Reported steal time | /proc/stat interval with virtualization context. | Hypervisor-reported unavailable CPU time; cause unproven. |
| E04 O | CPU throughput | Short bounded sysbench/stress-ng or own test, run separately. | Only compare equivalent effective host allocations. |
| E05 Q | RAM limit/headroom | Process/cgroup limits, current usage and available host context. | Job-visible memory ceiling and current headroom. |
| E06 Q | OOM/reclaim events | cgroup memory.events and readable relevant logs. | Observed resource event; historical scope disclosed. |
| E07 Q | Swap and pressure | Available swap activity and PSI windows. | Resource-waiting symptoms affecting the job. |
| E08 Q | Shared-memory capacity | /dev/shm capacity/use and intended runtime needs. | Small capacity is a caveat, not guaranteed DataLoader failure. |
| E09 Q | Pinned-memory/process limits | Relevant ulimits, pids and resource restrictions. | Explain the specific operation a limit may block. |
| E10 Q | NUMA / affinity map | Available CPU/memory locality relative to selected GPU. | Placement context; do not assume cross-NUMA is always fatal. |
| E11 F | Host-RAM health/performance | Owned-buffer tests; EDAC/RAS evidence only with authorization. | No guest test certifies all installed physical RAM. |
| E12 F | Input-pipeline waiting | Profile data loading, CPU preparation and transfer under real job. | GPU waiting on host, with measured critical-path effect. |


---

## 13 / Catalog F — storage and checkpoints

Phase 1 performs capacity/context checks; active disk testing is small, optional and restricted to test-owned files.

Stage key: Q = Quick; S = Standard; O = optional bounded Phase 1 extension; F = future. All are planned checks, not implemented features. Foundation: [S28]; full workload diagnosis is future scope.

| ID / stage | Check | How evidence is obtained | Decision-relevant output |
| --- | --- | --- | --- |
| F01 Q | Free space and quota | Selected workspace filesystem, writable access and visible limits. | Capacity available to this job, not entire-host disk size. |
| F02 Q | Mount/persistence context | Exposed filesystem/mount data plus provider/user declaration. | Measured access separated from declared persistence. |
| F03 O | Sequential read/write | Bounded fio scratch-file workload with cache method stated. | Measured path throughput, not NVMe/SATA hardware identity. |
| F04 F | Random/small-file access | Representative I/O size, depth and file distribution. | Whether this dataset layout is a limiting factor. |
| F05 O | Slow I/O operations | Latency distribution with enough samples and test conditions. | Tail measurements without overclaiming from tiny samples. |
| F06 O | Cache and burst effects | Record warm/cold method, file size and sustained window. | Cached burst is not advertised as device steady-state speed. |
| F07 O | Test-file integrity | Known test content and readback/checksum verification. | Only test-owned data verified; failure needs corroboration. |
| F08 F | Checkpoint save/load | Application-defined save, read and resume validation. | Recovery actually works within the tested contract. |
| F09 F | Checkpoint cost | Measured save/pause/upload time and retained capacity. | Progress-protection trade-off for the user’s job. |
| F10 F | Storage health telemetry | smartctl/nvme-cli/BMC only with authorized host access. | Device-scoped wear/error signals; guest visibility may be absent. |


---

## 14 / Catalog G — network and data logistics

No default Internet speed sweep. Every active path test needs an authorized endpoint and byte/time budget.

Stage key: Q = Quick; S = Standard; O = optional bounded Phase 1 extension; F = future. All are planned checks, not implemented features. Foundation: [S29, S30]; controller/provider metadata is declared context, not measurement.

| ID / stage | Check | How evidence is obtained | Decision-relevant output |
| --- | --- | --- | --- |
| G01 Q | Visible route/interface context | Read-only selected route/interface information. | Connectivity context without scanning neighbors. |
| G02 O | Required endpoint reachability | User-authorized DNS/TLS/HTTP request with deadline. | This endpoint is reachable or failed for a named reason. |
| G03 O | Real artifact pull | Fixed-revision, licensed public object or user-selected object; bounded bytes. | Measured endpoint transfer, including authentication/cache context. |
| G04 O | Download duration estimate | Known object byte size divided by representative measured rate. | Assumption-labeled range; parameter count alone is insufficient. |
| G05 F | Upload/checkpoint path | Authorized write to a designated test object and cleanup. | Actual destination throughput, not generic upload speed. |
| G06 F | TCP throughput/latency | Controlled iperf3 peer, direction, streams and settings. | Peer- and path-specific result with repeatability. |
| G07 F | Loss/retransmit evidence | Available transport counters; bounded UDP only with permission. | Transport symptom, not an automatic provider fault. |
| G08 F | Serving reachability | Controlled client connecting to the user’s explicit test endpoint. | No arbitrary port scanning or assertion of universal reachability. |
| G09 F | Location/IP context | Optional provider declaration and consensual external lookup. | Approximate network context; no physical-location or trust proof. |
| G10 F | Network costs/limits | Declared tariffs, transferred bytes and explicit provider data. | Egress/transfer costs and potential limit context. |
| G11 F | Inter-node fabric | Authorized RDMA/NCCL measurements between selected allocations. | No single-GPU test can establish cluster-fabric quality. |


---

## 15 / Catalog H — software readiness

Test in the user’s intended environment; the probe working does not prove the application works.

Stage key: Q = Quick; S = Standard; O = optional bounded Phase 1 extension; F = future. All are planned checks, not implemented features. Foundation: [S02, S13, S15, S31, S32].

| ID / stage | Check | How evidence is obtained | Decision-relevant output |
| --- | --- | --- | --- |
| H01 Q | Driver/runtime versions | Loaded driver/runtime/library versions, not only smi heading. | Actual compatibility context; CUDA driver support differs from installed toolkit. |
| H02 Q | Library usability | Load required libraries; execute bounded initialization/smoke operation. | Missing dependency vs incompatible runtime vs GPU failure. |
| H03 Q | Probe compatibility | Worker architecture and pinned library/runtime requirements. | Unsupported worker is a test limitation, not a bad card. |
| H04 S | Documented driver issue | Curated vendor advisory with exact range, SKU, symptom and date. | Applicable known issue; no broad “old driver = broken” rule. |
| H05 F | Framework import/operation | Explicit PyTorch/other stack smoke test in selected environment. | One real supported operation, not an import-only pass. |
| H06 F | Required extension | User-selected attention/render/quantization extension and test. | Feature works in the requested stack or remains unverified. |
| H07 Q | Container resource setup | Relevant shm, memlock, pids and device accessibility. | Specific configuration caveat without changing security controls. |
| H08 F | Application numerical checks | Customer validation contract plus appropriate precision tolerances. | Outputs meet tested criteria; not a model-quality certificate. |
| H09 F | Application sanitizer run | Optional Compute Sanitizer outside timed performance path. | Diagnose program errors, not certify physical VRAM. |
| H10 S | Reproducible environment | Build IDs, test-pack digest and relevant image/library identifiers. | Result can be reproduced or its limitations are visible. |
| H11 F | Time-to-useful-result | Installer/startup/model-load/first-success phases separately timed. | Instance-start timing requires trustworthy start-time evidence. |
| H12 F | Dataset/license readiness | Verify requested model/data availability and user-authorized access. | No automatic gated-model pull or execution of untrusted model code. |


---

## 16 / Catalog I — trust and idle-resource exposure

This is a defensive configuration assessment of the authorized rental, not a penetration test or malware-clean certificate.

Stage key: Q = Quick; S = Standard; O = optional bounded Phase 1 extension; F = future. All are planned checks, not implemented features. Foundation: [S24, S25, S33–S35].

| ID / stage | Check | How evidence is obtained | Decision-relevant output |
| --- | --- | --- | --- |
| I01 Q | Idle GPU consumption | Supported utilization/memory/process evidence in visible scope. | Unexplained consumption; reserve driver/framework memory considered. |
| I02 O | Visible competing processes | Minimal process metadata for permitted scope; optional known indicators. | A process name is not proof of a miner or malware. |
| I03 Q | Dangerous container exposure | Observe capabilities, privileged indicators and mounted control sockets. | Report exposure and least-privilege advice; never exploit it. |
| I04 O | Tool integrity signals | Verify our artifacts; compare system packages to authentic references if available. | Modified or unverified tool, not proof the entire host is clean. |
| I05 O | Loader/tampering indicators | Relevant allowlisted loader settings; do not collect full environment. | Potential influence on the test; legitimate instrumentation may explain it. |
| I06 F | Unexpected connections | Optional metadata-only snapshot within authorized process scope. | Investigate unexplained egress; no payload capture by default. |
| I07 F | Prior-tenant residue | Explicit workspace-only metadata check with user permission. | Potential provisioning hygiene issue; do not open others’ files. |
| I08 F | SSH key continuity | Controller-held known-host record and independent confirmation. | Changed key needs verification; rebuilds may legitimately change keys. |
| I09 Q | Data-exposure guidance | Observed isolation and attestation status plus trust assumptions. | No datacenter/community label is a security certification. |
| I10 F | External attestation verification | Fresh challenge, issuer/signature/revocation checks and CPU/GPU scope. | Attested properties only; report verification gaps separately. |


---

## 17 / Catalog J — stability, history and operational risk

A brief successful test cannot answer whether a machine will survive a three-day run.

Stage key: Q = Quick; S = Standard; O = optional bounded Phase 1 extension; F = future. All are planned checks, not implemented features. Foundation: [S04, S06–S10, S23]; forecasting below is a proposed future research program.

| ID / stage | Check | How evidence is obtained | Decision-relevant output |
| --- | --- | --- | --- |
| J01 S | Observed stability interval | Successful checked operations, errors and elapsed time. | No failure observed for the actual tested duration. |
| J02 S | Transient slow windows | Repeated same-method windows with robust spread. | Measured variability, not “confirmed noisy neighbor.” |
| J03 S | Warm-up vs deterioration | Timeline separating initialization, settling and later changes. | Do not extrapolate heat-soak failure from a short temperature slope. |
| J04 Q | History visibility | Uptime/reset epoch and oldest accessible event timestamp. | Host uptime is not the rental’s reliability history. |
| J05 Q | Clock sanity | Wall/monotonic consistency; exposed synchronization status. | Correlation uncertainty; no intrusive time reconfiguration. |
| J06 F | Interruption model | User/provider-declared spot or interruptible contract. | Operational preparedness, not a predicted eviction time. |
| J07 F | Host/allocation history | Consent-based controller-linked observations with identity uncertainty. | History of this identifiable allocation, not guaranteed permanent machine ID. |
| J08 F | Guardian drift | Low-overhead passive monitoring; approved idle-time active retests. | Observed new event or change relative to the accepted baseline. |
| J09 F | Failure-risk model | Labeled longitudinal outcomes, censoring, calibration and false-alarm evaluation. | No probability or checkpoint countdown until validated. |
| J10 F | Checkpoint advice | User recovery-point goal plus measured checkpoint cost; explicit assumptions. | Protect progress without inventing a failure hazard. |


---

## 18 / Catalog K — workload dry-run and straggler analysis

Intent selection is available first; detailed execution-based projections arrive only with validated workload packs.

Stage key: Q = Quick; S = Standard; O = optional bounded Phase 1 extension; F = future. All are planned checks, not implemented features. Foundation: [S14, S17, S20, S32].

| ID / stage | Check | How evidence is obtained | Decision-relevant output |
| --- | --- | --- | --- |
| K01 F | Reproducible workload contract | Model/revision, precision, batch, shapes, concurrency and software digest. | Exactly what the assessment covers. |
| K02 F | Inference behavior | Cold load, warm prefill/decode and latency/throughput with cache controls. | Useful output rate under the stated latency requirement. |
| K03 F | Fine-tuning/training step | Representative forward/backward/optimizer work and token count. | Step speed and memory peak for this exact configuration. |
| K04 F | Image generation | Fixed model, resolution, scheduler/steps and execution settings. | Images per time for tested settings; not quality ranking. |
| K05 F | Rendering | Fixed scene/renderer/backend and correctness contract. | Rendering fit without assuming a data-center GPU supports every graphics feature. |
| K06 F | Operating-range sweep | Bounded batches/context/concurrency and successful result checks. | Tested safe range; outside it remains unverified. |
| K07 F | Critical-path profile | Compute, data-loader, transfer, storage and communication timelines. | The part actually delaying completed useful work. |
| K08 F | Within-node imbalance | Compare same-stage devices/ranks with equal work and topology context. | Potential limiting device/path; unequal work is a confounder. |
| K09 F | Cross-node stragglers | Rank-aware synchronized traces and comparable per-rank work. | Victim waiting at a collective is not automatically the cause. |
| K10 F | Retry/resume rehearsal | Known failure boundary in an authorized test job and application resume. | Recovery behavior is measured, not inferred from a saved file. |
| K11 F | Projection validity | Only interpolate calibrated tested configurations; show uncertainty. | No 13B/70B throughput estimate from generic GEMM alone. |


---

## 19 / Catalog L — multi-GPU, cluster and data center

Preserve the single-GPU evidence model; expand the resource graph instead of averaging away bad ranks.

Stage key: Q = Quick; S = Standard; O = optional bounded Phase 1 extension; F = future. All are planned checks, not implemented features. Foundation: [S17, S21–S23, S27, S30].

| ID / stage | Check | How evidence is obtained | Decision-relevant output |
| --- | --- | --- | --- |
| L01 F | Resource graph | Cluster/node/device/partition/NIC/storage-path relationships. | Scope of every observation remains explicit. |
| L02 F | GPU pair paths | P2P access, measured bandwidth/latency and errors. | One weak pair distinguished from the node average. |
| L03 F | NVLink/NVSwitch | Supported link/fabric state, counters and real transfers. | Exposed topology plus measured behavior. |
| L04 F | Collectives | Correctness and performance by operation, size, ranks and transport. | Do not mix algorithm bandwidth with bus bandwidth. |
| L05 F | Fabric transport | Actual NCCL/RDMA path, NIC affinity and supported GPUDirect tests. | Fallback transport vs intended high-performance path. |
| L06 F | NIC/switch health | Authorized endpoint and operator-side error/congestion telemetry. | Guest symptoms distinguished from fabric root cause. |
| L07 F | Clock/trace alignment | Measured clock uncertainty and monotonic local timing. | Trustworthy stage/rank correlation without false causal order. |
| L08 F | Controlled scale ladder | Test available scales and jobs before extrapolating. | Eight GPUs tested does not certify a thousand-GPU cluster. |
| L09 F | Scheduler readiness | Slurm/Kubernetes lifecycle and optional GCM/GPUd integration. | Do not run diagnostics concurrently with unapproved tenant work. |
| L10 F | BMC/PSU/cooling | Read-only operator-authorized management-plane sensors. | Rack/environment limitations considered separately from GPU defects. |
| L11 F | Cluster/storage services | Authorized throughput, checkpoints, metadata services and recovery tests. | Bottlenecks and fault domains across the actual workflow. |
| L12 F | Controlled maintenance actions | Drain/cordon/ticket actions behind explicit approvals and rollback plans. | No autonomous cross-cluster resets or destructive repair. |


---

## 20 / Catalog M — value and decision economics

Use work completed correctly at equivalent requirements; a microbenchmark ratio is not universal application value.

Stage key: Q = Quick; S = Standard; O = optional bounded Phase 1 extension; F = future. All are planned checks, not implemented features. Provider-policy context: [S38, S39, S44].

| ID / stage | Check | How evidence is obtained | Decision-relevant output |
| --- | --- | --- | --- |
| M01 Q | Declared rental price | Optional user input with currency and billing unit. | Price supplied by user, not independently validated. |
| M02 S | Reference-equivalent price | Price divided by eligible same-workload performance ratio. | Label equivalence scope; hide when reference is missing. |
| M03 F | Cost per useful unit | Successful output plus latency/error constraints and relevant charges. | $/million tokens, image or step under tested conditions. |
| M04 O | Scan cost | Measured runtime plus declared price; bytes and storage stated. | Software is free; testing still uses paid rental resources. |
| M05 F | Hidden charges | Documented storage, egress, minimum increments and stop-state costs. | Declared vs observed charges remain separate. |
| M06 F | Live alternatives | Timestamped authorized feeds with comparable availability/configuration. | Same SKU name alone is not a fair market comparison. |
| M07 F | Keep/fix/switch decision | Expected work remaining, retest/downtime/data-transfer costs. | Performance improvement must exceed switching cost. |
| M08 Q | Evidence-backed ticket | Facts, reproduction, relevant reference and requested action. | Ask for investigation/replacement; do not allege fraud from a score. |
| M09 F | Outcome verification | Post-fix/replacement retest with controlled configuration. | Did the proposed action actually improve useful work? |
| M10 F | Fairness/audit | Reference and rule versions, provider conflict disclosures. | Payment never changes health gates or reference admission. |
| M11 F | Return-policy applicability | Current official policy, purchase type and source date. | No guaranteed refund or universal dispute countdown. |


---

## 21 / Missing data: fallback plan

Every missing check has an explicit status, fallback and unresolved limit.

| Missing/blocked | Permitted fallback | What remains unverified |
| --- | --- | --- |
| nvidia-smi | Direct NVML and CUDA driver queries; safe sysfs context. | Host honesty; both APIs still use the host/driver. |
| NVML library/field | Qualified CLI field or worker observation if available. | Hidden sensors, privileged fields and unsupported features. |
| DCGM absent | Our bounded correctness/transfer tests plus supported telemetry. | No DCGM pass is claimed; no automatic privileged install. |
| Kernel logs unreadable | Supported event subscription and before/after error counters. | Historical Xids and events outside the observed interval. |
| ECC unsupported | Known-pattern checks in owned memory. | No ECC history, no proof all errors are detected. |
| Memory-junction temperature | Core sensor and measured performance trend if exposed. | Actual memory temperature and thermal-root-cause claim. |
| SM/cache attributes absent | Capability tests and observed execution signature. | Exact internal topology or physical die authentication. |
| PCIe width hidden | Pinned transfer test with CPU/NUMA/copy-method context. | Exact lane count; slow transfer alone cannot prove x4. |
| Power limit hidden | Measured throughput, exposed clock reasons and time series. | Exact watts or the reason performance is lower. |
| Host processes hidden | Visible idle use, own-job measurements and repeated intervals. | Presence/absence of a miner or another tenant. |
| CPU steal unavailable | Own process CPU time, quota statistics and PSI if accessible. | Hypervisor allocation and physical-host oversubscription. |

Status values: PASS, FAIL, WARNING, NOT_TESTED, UNSUPPORTED, PERMISSION_DENIED, DEPENDENCY_MISSING, TIME_BUDGET_EXHAUSTED, CONTAMINATED, TOOL_ERROR and NOT_APPLICABLE. Zero and empty output must never be used as substitutes for these states.

> Missing telemetry is a product requirement, not a reason to bypass isolation. Custom CUDA kernels measure accessible behavior; they cannot recover absent physical sensors, historical counters or hidden host state.


---

## 22 / Missing data: OS and diagnostic extensions

Build user-space tests first. Do not add a custom kernel driver merely to make the coverage table look complete.

| Missing/blocked | Permitted fallback | Limit / next step |
| --- | --- | --- |
| DMI / hardware serial | Session-local allocation fingerprint and explicit user/provider ID. | No stable cross-user physical-host identity established. |
| SMART / NVMe health | Bounded I/O on designated scratch files. | Physical media type, wear and host disk health unknown. |
| Cold-cache control | Record cache state; safe file-size/method choice where possible. | Never drop host-wide caches or mislabel cached speed. |
| Internet peer | Use user-authorized endpoint; otherwise skip throughput. | No Internet-speed score without an actual test path. |
| Second GPU/node | Mark P2P/NCCL/RDMA tests not applicable to this scan. | No inferred cluster quality. |
| CUDA runtime unusable | Static software/identity report and minimal driver diagnostics. | Active GPU health/performance inconclusive. |
| BMC/PSU/inlet data | Read-only provider export in later operator mode. | No diagnosis of faulty cooling pads, dust or PSU from guest data alone. |
| Trusted host evidence | Later independent supported attestation and controller-held records. | No complete host-authenticity proof from local hashing. |

### What we develop below vendor telemetry

CUDA: known-answer arithmetic, address-dependent patterns in owned buffers, bandwidth/working-set sweeps, transfer checksums, bounded allocation tests and scheduling-jitter measurements. OS: effective-resource discovery, pressure timelines, owned-process timing and safe path tests. Provider mode later: existing EDAC/RAS, AER, eBPF/perf or BMC collectors only after permission and overhead qualification.

Do not introduce GPU disturbance/Rowhammer tests, firmware probes, host escapes, privileged register writes or reads of other tenants’ memory. The objective is inspection of the rented allocation, not circumvention of provider controls.

### Kernel and method qualification

Maintain CPU known-answer tests, architecture-specific CUDA builds and sanitizer checks for the workers themselves. Use multiple reference implementations where practical. A bug in our worker can create a false hardware-failure report, so every mismatch must include reproducibility evidence and its method version. Compute Sanitizer helps debug program errors; it is not a physical-memory health certificate. [S31]


---

## 23 / Measurement methodology

A benchmark is valid only when its unit, scope, numerical behavior and timing are explicit.

| Test family | Required implementation contract |
| --- | --- |
| GEMM | Record M/N/K, batch count, input/accumulator types, math mode, library algorithm, warm-up and checked output. Count 2MNK operations per dense multiply; do not compare sparse advertising numbers to dense results. |
| Memory bandwidth | Use buffers large enough to distinguish cache from HBM. State read/write traffic accounting: a copy can count both reads and writes. Do not compare different effective-bandwidth conventions. |
| Memory integrity | Generate known/address-dependent patterns only in owned allocations. Check returned data and errors. Record unique logical bytes, number of patterns/passes and allocation success; never label this full physical-chip coverage. |
| Transfers | Pin host buffers within safe limits; separate H2D and D2H. State bytes, direction, synchronization, NUMA placement and copy engine/method. Verify transferred content. |
| Time | Separate cold start from warm execution. Synchronize asynchronous work before reporting completion. Compare event and host elapsed times as a consistency check, not a trusted-host bypass. |
| Repetitions | Use time windows and robust summaries. Account for correlated samples; repeated iterations on one device are not independent machines. Publish uncertainty, spread and sample count. |
| Interference | Do not overlap heavy CPU/disk/network tests with GPU transfer/compute measurements unless deliberately testing contention. Flag contaminated windows rather than selectively deleting poor results. |
| Safety | Check headroom, ownership and idle state. Quick sampling defaults must leave reserve memory; larger tests need an explicit cap. Do not touch other visible GPUs or raise power limits. |
| Reproducibility | Store seeds, input hashes, test/configuration versions and limitations. Randomized order/patterns are reproducible from a recorded seed; privacy-sensitive inputs are never uploaded. |

NVIDIA’s best-practices guide covers numerical verification, timing and bandwidth interpretation. CUDA samples are useful references but explicitly are not a comprehensive validation suite; they require our own qualification before becoming customer-facing diagnostics. [S14, S15]

### Stop and escalation policy

On a reproducible mismatch, new critical device event or configured safety limit, stop active load, preserve bounded evidence and recommend investigation. A worker timeout produces a test-error/possible-device-failure finding with uncertainty; the scanner must not keep hammering an unresponsive driver.


---

## 24 / Existing tools versus our engineering

Integrate qualified pieces. Do not run every available suite in one short scan.

| Tool / source | Use | Integration boundary |
| --- | --- | --- |
| NVML + nvidia-smi [S01–S03] | Identity and telemetry. | One common trust domain; version-aware fields. |
| DCGM [S04, S05] | Supported vendor diagnostics. | Selected GPU/plugins; not RMA certification. |
| nvbandwidth [S16] | Transfer benchmarks. | Pin method, settings and numerical meaning. |
| gpu-burn [S18] | Optional sustained stress. | Not Quick default; isolate one selected device. |
| cuda_memtest [S19] | Pattern-test prior art. | Build/support validation before optional reuse. |
| CUDA samples [S15] | Reference/smoke-test code. | Not an official complete benchmark standard. |
| nccl-tests [S17] | Future collectives. | Do not run on one GPU as evidence of fabric quality. |
| fio / iperf3 [S28, S29] | Opt-in path tests. | Own scratch files and authorized peers only. |
| sysbench / stress-ng | Optional CPU/resource tests. | Qualify exact upstream version and safe profile before enabling. |
| OS tools / interfaces [S24–S27] | Resource limits and exposed errors. | Read-only allowlist; missing permissions explicit. |
| SuperBench [S20] | Validation and benchmark prior art. | Reuse modules/methodology after license/version review. |
| Meta GCM [S21, S22] | Health-check/monitoring adapters. | Includes network/storage/software checks; no need to recreate all. |
| GPUd [S23] | Monitoring and diagnosis prior art. | Evaluate for later Guardian/operator integration. |
| llama.cpp / HF / vLLM [S32] | Later workload packs. | Pin model/license/runtime; no large hidden downloads. |
| SiliconMark / ClusterMAX [S36, S37] | Competitor and methodology comparison. | No assumed redistribution, public CLI or integration license. |

The user’s “gcm” is mapped to Meta GPU Cluster Monitoring. “cmax” is treated here as a likely reference to ClusterMAX, not a verified tool called cmax. Do not create an adapter until an exact product/API and permitted use are established.


---

## 25 / Product differentiators to validate

These are hypotheses for customer value—not claims that nothing comparable exists.

| Capability | Our product work | Honest positioning |
| --- | --- | --- |
| Verdict-first review | Selection of a few actionable findings with reproducible evidence. | Packaging and decision quality must outperform existing tools. |
| Healthy reference packs | Curated comparable baselines, method versions and acceptance ranges. | A useful asset; not a guaranteed network effect. |
| Fleet percentiles | Opt-in normalization, admission checks and population-bias disclosure. | Percentile within our sample, not all GPUs worldwide. |
| Identity consistency | Cross-signal checks, contradiction detection and optional attestation. | Detects inconsistencies; cannot promise counterfeit detection on a malicious host. |
| Undisclosed limitation analysis | Declared-vs-actual profile plus measured effect. | Do not equate every power cap with deception or a defect. |
| Resource variability | Repeated windows and symptom localization. | Call it variability, not a proven noisy-neighbor index. |
| Fix-or-replace workflow | Guides, safe scripts, evidence tickets and outcome retests. | Measurable reduction in diagnosis and decision time. |
| Workload operating range | Actual bounded workload sweeps and requirements evaluation. | Only tested or properly calibrated projections. |
| Host history | Consent-based identity linkage and configuration-change tracking. | Pseudonymous, uncertain and appealable; avoid public accusations. |
| Guardian | Passive change alerts and approved idle retests. | Retention depends on useful alerts and measured low overhead. |
| Risk forecasting | Longitudinal labeled outcomes and calibration. | Research-gated; not an MVP sales promise. |
| Effective economics | Equivalent-work comparison and switching-cost calculation. | Not a universal “effective price” based on one synthetic score. |

SiliconMark explicitly addresses rented cloud GPUs and includes GPU, cluster, LLM and inventory assessments. ClusterMAX evaluates cloud providers. GCM, SuperBench and GPUd provide substantial existing infrastructure capabilities. Therefore “nobody packaged this for renters” and “these features do not exist anywhere” must be removed from positioning. [S20–S23, S36, S37]


---

## 26 / Remediation: guides, commands and scripts

Generate a reviewed action plan. Do not let a model invent privileged commands from free-text symptoms.

| Action class | Examples | Phase 1 behavior |
| --- | --- | --- |
| Read-only verification | Inspect a selected device; check limits; collect bounded evidence. | Generate exact version-aware commands and expected observations. |
| User-space change | Adjust own application batch/worker count or selected scratch path. | Explain effect, trade-off, undo step and retest; user executes. |
| Container replacement | Change shm/resource settings or use a compatible pinned image. | Show data-loss/resource implications; never recreate automatically. |
| Provider maintenance | Power policy, persistent link fault, remap failure, reset/reboot or firmware. | Produce provider request; do not override the host. |
| Stop/replacement | Active correctness failure or unacceptable allocation. | Save evidence first; preserve user data; no automatic termination. |

### Every generated guide contains

Applicable finding/rule version; prerequisites and permissions; rationale; exact commands; variables to fill; expected outputs; decision branches; rollback or “not reversible”; retest command; provider escalation. Scripts default to dry-run where changes are possible, validate inputs and touch only explicitly selected resources.

### Example: user-visible HBM error

Stop the test’s load. Save its mismatches, current error deltas and selected-device identity. Run only the supported confirmation check allowed by the environment. Do not clear counters or reset the GPU to make it pass. Request provider investigation/replacement. A successful later retest does not erase the recorded event.

### Example: limited shared memory

Report the measured capacity and the actual workload symptom, if tested. Offer a user-space reduction in data-loader workers as a diagnostic experiment, or a provider/container configuration request. Do not promise that 64 MB always crashes every PyTorch job.

### Example: weak PCIe transfer

Retest with correct pinned buffers on an idle allocation and permitted CPU placement. Check exposed link width/generation during load. If performance remains outside a matched reference, attach evidence and ask the provider to investigate the path. Do not issue commands to alter link registers.

Application stack mismatches go to compatibility guidance; hardware-looking events go to device-specific vendor guidance. Xid meaning and action must be taken from the applicable catalog, not an unversioned universal number-to-defect table. [S06, S07, S13]


---

## 27 / Provider ticket output

Phase 1 creates a message and redacted evidence locally; it does not submit a ticket.

### Automatic local artifacts

report.html; report.json; ticket.md; evidence-index.json; optional redacted evidence archive. Ticket generation is triggered by a blocker or a user request. Deduplicate the same issue within a scan and retain later retest updates.

```text
Subject: Request investigation/replacement — GPU allocation <id>

Allocation: <provider instance ID supplied by user>
Observed device: <exact variant, selected ID redacted as agreed>
Scan: <UTC interval> | <tool/build> | <test-pack version>
Scope: one selected GPU; <guest/container/host visibility>

Observed issue:
<fact, test outcome, number of repetitions, relevant error delta>

Comparison, when available:
<reference ID, exact configuration, range, measured value,
 difference and why this reference is applicable>

User impact:
<measured workload consequence or “impact not yet quantified”>

Checks performed:
<short reproduction and controls; no raw output dump>

Limitations:
<blocked logs/sensors, memory coverage, missing calibration>

Requested action:
Please investigate this allocation and advise on a supported fix
or replacement. Please review any billing adjustment under the
applicable policy. No entitlement to a refund is asserted.

Attachments: report + minimal redacted evidence bundle.
```

### Later submission contract

A controller connector must verify the provider, recipient/endpoint, supported ticket operation and authentication scope. Show the exact message and attachments before a user-approved send. Return the real ticket ID only after the provider confirms creation; retry safely using an idempotency key.

### Policy and data protection

Store policy source, revision/retrieval date and product/purchase applicability. The “refund-window” concept becomes an early-cost-decision workflow: Vast.ai and Runpod publish refund restrictions, so a universal 60/90-minute or other guaranteed refund window must not be displayed. [S38, S39]

Do not terminate a rental to “return it” automatically. Check storage persistence and paid stopped-state resources; the user must protect data and approve lifecycle actions. [S44]


---

## 28 / Privacy, trust and anti-gaming

Anti-gaming improves resistance; it does not make a hostile machine a trusted measuring instrument.

### Local-first data policy

No measurement upload, account or provider token is required in Phase 1. After installation, default scans work offline with bundled references. External path tests, reference downloads and attestation services require explicit network choices; document the metadata disclosed by each. HTML reports use no CDN, external fonts, tracking pixels or remote scripts.

Do not upload user files, prompt content, model weights, process command lines, environment variables, private paths, raw serials, IP addresses or credentials by default. Local evidence uses restrictive permissions, size limits and a retention/cleanup command. No secrets in CLI arguments or shell history for later authentication.

### Fleet and host-history consent

Anonymous metrics and longitudinal host reputation conflict: stable linkage can make records identifiable. Use separate consent for aggregate contribution and cross-scan linkage. Store pseudonymous IDs with provenance and retention limits; raw hardware IDs stay local unless specifically authorized. Support deletion, correction and appeal before public reputation features.

### Anti-gaming controls

| Control | What it provides / does not provide |
| --- | --- |
| Signed release and reference packs | Protects artifact provenance when verified through a trusted channel; host-controlled verification alone can be subverted. |
| Seeded varied test patterns | Reduces simple canned-result matching; seed recorded for reproducibility. No stealth or unapproved workload injection. |
| Controller-held challenge, later | Helps detect stale/replayed reports; does not certify exclusive scheduling or every claimed hardware attribute. |
| Accepted-baseline comparison | Detects observed degradation after acceptance; causal attribution remains separate. |
| Fleet admission controls | Reject obvious impossible/replayed reports; cap contributor/host dominance and retain uncertainty. |
| Attestation, supported systems | Verifies defined device/firmware/TEE claims with fresh evidence; not future health or benchmark-score authenticity by itself. |

A malicious kernel/hypervisor can mediate the readings, timing and execution seen by a normal local process. H100 confidential-computing and supported composite CPU/GPU attestation offer stronger, explicitly scoped evidence; their presence must be checked and independently verified, not assumed on every rental. [S33–S35, S43]


---

## 29 / Phased delivery and work packages

Do not make the single-GPU release depend on a fleet database, cloud account, controller or AI service.

| Phase | Deliverables | Exit condition |
| --- | --- | --- |
| 1A — core free CLI | Target guard; capability discovery; local evidence; Q/S tests; fallback states; HTML/JSON; deterministic verdict; ticket/guide drafts. | Qualified H100 PCIe pack or explicit uncalibrated mode; all safety and reporting gates pass. |
| 1B — broader single-GPU coverage | Separate H100 SXM/NVL packs; opt-in small path tests; more NVIDIA SKUs; improved supportability. | No reference leakage between variants; real-machine validation for each claimed configuration. |
| 2 — workload and node | Deep scan; dry-run packs; calibrated fit/value; consented fleet; multi-GPU/NVLink/NCCL. | Verified workload outcomes and per-device diagnosis; no fabricated percentiles. |
| 3 — cluster and controller | Instance discovery, approved SSH deployment, Guardian, multi-node tests, rank-aware straggler analysis. | Measured scale/overhead limits; safe ownership and credential handling. |
| 4 — vendor and data center | Other vendor adapters, scheduler/BMC/fabric/storage integrations and operator maintenance workflows. | Vendor-specific conformance and operator approval model; no NVIDIA-only schema assumptions. |

### Phase 1 work packages

WP1: evidence schema, target ownership and CLI contracts. WP2: NVML/OS collectors plus degraded-mode fixtures. WP3: signed CUDA workers and method verification. WP4: healthy-reference acquisition and calibration. WP5: rules, report templates and safe playbooks. WP6: packaging, privacy review and dependency qualification. WP7: real-rental acceptance testing and release readiness.

### Future controller mode

Read-only API discovery first; let the user select a current instance; verify SSH host identity; deploy a pinned probe using scoped credentials; stream progress and retrieve redacted outputs. Never forward a broad provider API key onto an untrusted rental. A provider may not expose SSH or ticket APIs; keep capability-specific paths. Vast.ai and Runpod expose instance-management interfaces, but exact API versions/permissions must be pinned during implementation. [S41, S42]

### Commercial tiers

Quick and Standard are free now. Keep scan-depth names separate from future subscription entitlements; do not build token or payment requirements into the local core. Paid fleet services, if introduced later, must not change correctness gates, baseline eligibility or ticket facts.


---

## 30 / Verification and release gates

The scanner must be tested for false accusations, missed problems and honest abstention—not only benchmark speed.

| Gate | Acceptance requirement |
| --- | --- |
| Target isolation | Never stress or modify an unselected GPU. Test remapped indices, multiple visible GPUs, MIG and device disappearance. |
| Fault interpretation | Reproducible method failures, historical counters, new errors and application bugs produce distinct findings. |
| Unavailable data | Every denied/unsupported/missing/timed-out check appears explicitly; no empty field becomes a pass. |
| Reference correctness | Reject wrong SKU/mode/math/transfer-method packs. Healthy-range verdict withheld without qualified data. |
| Quick budget | On supported environments, complete or emit an honest partial report within the selected budget; include installation time separately. |
| Safety/cleanup | No global cache drops, firmware writes, GPU resets or unrelated process/file changes. Scratch ownership and cancellation verified. |
| Numerical validity | Worker outputs validated with known answers; deliberate test-buffer corruption detected in the harness and clearly labeled synthetic. |
| False-positive challenge | Disclosed power caps, cold PCIe states, quota limits, passive cooling and legitimate background services not falsely labeled defective. |
| Blocked/hung tools | Bounded calls and output; report can survive a failed worker. Document cases where the host cannot terminate a driver wait. |
| Privacy | No default outbound telemetry; artifacts free of seeded secrets. Export/redaction and deletion tests pass. |
| Report integrity | Every highlight points to evidence and a method; every quantified consequence is measured or assumption-labeled. |
| Outcome validation | A recommendation’s claimed improvement is supported by controlled before/after tests, not a changed score alone. |

### Evaluation dataset

Use known-good real rentals, agreed reversible resource limits on controlled systems, simulated API/log fixtures, unavailable-permission cases and representative application errors. Synthetic buffer faults validate the detector, not the real-world frequency of bad GPUs. Historical GPU failures require consented evidence and independently reviewed labels.

Publish false-positive/negative results by finding type, environment and confidence; include abstention rate, report latency and testing cost. A failure-risk model or public host leaderboard must not ship merely because the basic scanner works.


---

## 31 / Data schema and extensibility

One evidence model from one GPU to a heterogeneous cluster.

```text
Resource: {resource_id, kind, vendor, parent_id,
  observed_identity, declared_identity, identity_assurance}

Measurement: {measurement_id, resource_id, method_id, version,
  start_utc, duration_monotonic, scope, status,
  value, unit, sample_count, spread, conditions,
  source_kind, visibility, evidence_refs}

Reference: {reference_id, exact_match_key, source_kind,
  qualified_status, range, independent_sample_count,
  method_version, acquired_at, valid_until, signature}

Finding: {finding_id, rule_version, severity,
  observation, interpretation, alternative_causes,
  observation_strength, cause_strength,
  reference_id, impact, impact_basis,
  action_id, retest_id, evidence_refs}

Report: {schema_version, scan_id, resource_scope, profile,
  tier, budget, actual_duration, verdict, verdict_scope,
  score_or_null, coverage, blockers, highlights,
  missing_checks, finding_refs, artifact_hashes}
```

### Plugin contract

Discover capabilities; validate scope; estimate cost; plan; execute with cancellation; normalize observations; redact; evaluate against an applicable reference. Required dependencies and privilege levels are explicit. A vendor adapter implements capabilities, not fake NVIDIA-equivalent fields for unsupported hardware.

### Forward-compatible resource graph

Kinds include node, GPU, partition, CPU pool, memory pool, NIC, interconnect, storage path, workload and rank. Future aggregate results preserve each member’s state and uncertainty. A critical fault on one selected rank cannot be averaged into a healthy cluster score.

### Audit trail

A report retains tool, worker, rule, reference and policy versions. Re-evaluating old evidence with new rules produces a new report linked to the original; it does not silently rewrite history. Reference expiration or device/configuration changes trigger a freshness warning.


---

## 32 / Corrections that protect product credibility

These wording rules are part of the specification, not optional disclaimers.

| Do not say | Say instead |
| --- | --- |
| Genuine GPU, 7/7 checks passed. | Identity signals are consistent; hardware authentication not performed. |
| 100% / all physical VRAM tested. | These logical bytes, patterns and passes were tested in accessible allocations. |
| Below advertised bandwidth = defective. | Measured effective bandwidth compared with the same-method healthy envelope. |
| Below the fastest card = bad. | Gap to best-known reference; normality judged against a qualified healthy range. |
| Row-remap failure means end of life. | Current maintenance/health concern; provider diagnosis required. |
| Hot memory means an ex-mining card. | Observed thermal behavior; prior usage and physical cause not established. |
| Power cap causes exactly 10% slower training. | Measured gap for this test; application impact requires a workload run. |
| CPU steal proves oversubscription. | Reported scheduling unavailability; host policy/cause not proven. |
| Variance proves noisy neighbors. | Repeated performance variability; several possible causes. |
| Disk score proves NVMe / SATA / HDD. | Measured storage-path behavior; physical medium not authenticated. |
| Residential IP means unreliable host. | Approximate network context only; no performance or trust conclusion from IP class. |
| No foreign processes means malware-free. | No relevant process observed in the available namespace and permissions. |
| This machine will survive three days. | No failures observed during the completed assessment interval. |
| Guaranteed return/refund window. | Current provider policy and a support request; no guarantee. |
| Nobody offers this for renters. | Existing competition; our proposed value is a better evidence-to-decision workflow. |

Source context for these distinctions: NVML/DCGM/Xid and memory guidance [S01–S10]; Linux resource visibility [S24–S27]; conditional attestation [S33–S35]; existing renter benchmarking [S36]; provider restrictions [S38, S39].

> Build the inspection and evidence system first. The trustworthy result is sometimes “do not start,” sometimes “healthy for this scope,” and sometimes “we cannot verify enough here.” All three are valuable when the facts are exact.


---

## 33 / Source register — 1 of 4

Primary documentation and project sources • checked for this design on 6 September 2026

Sources support existing capabilities and constraints. Product policies, stage assignments, budgets and proposed algorithms are our design choices. Live documentation can change; release artifacts must record applicable versions and pinned source revisions.

**[S01] NVIDIA — NVML management library.** Management API foundation; nvidia-smi is an NVML-based interface.  
Source: https://developer.nvidia.com/management-library-nvml

**[S02] NVIDIA — nvidia-smi manual.** Supported identity, memory, clock, PCIe, process and error fields; version-dependent output.  
Source: https://docs.nvidia.com/deploy/nvidia-smi/index.html

**[S03] NVIDIA — NVML device-query API.** Typed queries, device handles and feature-dependent telemetry.  
Source: https://docs.nvidia.com/deploy/nvml-api/group__nvmlDeviceQueries.html

**[S04] NVIDIA — DCGM diagnostics.** Run levels, plugins, permissions and limitations; not a substitute for field diagnostics or RMA.  
Source: https://docs.nvidia.com/datacenter/dcgm/latest/user-guide/dcgm-diagnostics.html

**[S05] NVIDIA — DCGM feature overview.** Hardware and environment coverage; capability-specific diagnostics.  
Source: https://docs.nvidia.com/datacenter/dcgm/latest/user-guide/feature-overview.html

**[S06] NVIDIA — Xid introduction and interpretation.** Xids can arise from application, software or hardware problems.  
Source: https://docs.nvidia.com/deploy/xid-errors/introduction.html

**[S07] NVIDIA — Xid catalog.** Version- and architecture-specific event meanings and recommended actions.  
Source: https://docs.nvidia.com/deploy/xid-errors/analyzing-xid-catalog.html

**[S08] NVIDIA — GPU memory row remapping.** Remapping is a repair mechanism; pending and failed states need separate treatment.  
Source: https://docs.nvidia.com/deploy/a100-gpu-mem-error-mgmt/row-remapping.html

**[S09] NVIDIA — response to contained uncorrectable ECC errors.** Containment, application impact and recovery context.  
Source: https://docs.nvidia.com/deploy/a100-gpu-mem-error-mgmt/response-to-uncorrectable-contained-ecc-errors.html

**[S10] NVIDIA — clock-event reasons.** Power limiting, thermal slowing and related reasons are distinct.  
Source: https://docs.nvidia.com/deploy/nvml-api/group__nvmlClocksEventReasons.html

**[S11] NVIDIA — MIG supported GPUs.** H100 variants and partition-capable hardware; do not merge variants.  
Source: https://docs.nvidia.com/datacenter/tesla/mig-user-guide/supported-gpus.html


---

## 34 / Source register — 2 of 4

Primary documentation and project sources • checked for this design on 6 September 2026

Sources support existing capabilities and constraints. Product policies, stage assignments, budgets and proposed algorithms are our design choices. Live documentation can change; release artifacts must record applicable versions and pinned source revisions.

**[S12] NVIDIA — H100 product specifications.** Specification context, form factors and advertised performance ceilings.  
Source: https://www.nvidia.com/en-in/data-center/h100/

**[S13] NVIDIA — CUDA compatibility.** Driver/runtime compatibility is conditional, not a simple version-name match.  
Source: https://docs.nvidia.com/deploy/cuda-compatibility/latest/index.html

**[S14] NVIDIA — CUDA C++ best practices.** Timing, effective bandwidth, numerical verification and workload-sensitive optimization.  
Source: https://docs.nvidia.com/cuda/cuda-c-best-practices-guide/

**[S15] NVIDIA — CUDA samples repository.** Sample code and utilities; explicitly not a comprehensive validation/benchmark suite.  
Source: https://github.com/NVIDIA/cuda-samples

**[S16] NVIDIA — nvbandwidth.** GPU/host bandwidth testing and methodology; pin the selected implementation.  
Source: https://github.com/NVIDIA/nvbandwidth

**[S17] NVIDIA — nccl-tests.** Collective correctness and performance; future multi-GPU and multi-node scope.  
Source: https://github.com/NVIDIA/nccl-tests

**[S18] gpu-burn — project repository.** CUDA stress testing; optional, isolated and target-restricted integration.  
Source: https://github.com/wilicc/gpu-burn

**[S19] cuda_memtest — project repository.** Memory-test patterns; qualification required before reuse on a supported device.  
Source: https://github.com/ComputationalRadiationPhysics/cuda_memtest

**[S20] Microsoft — SuperBench.** Infrastructure validation/profiling framework; useful baseline and test prior art.  
Source: https://github.com/microsoft/superbenchmark

**[S21] Meta — GCM getting started.** Monitoring, health checks and telemetry correlation components.  
Source: https://facebookresearch.github.io/gcm/docs/getting_started/

**[S22] Meta — GCM health checks.** Hardware, software, network, storage and service checks; selected adapters only.  
Source: https://facebookresearch.github.io/gcm/docs/GCM_Health_Checks/getting_started/


---

## 35 / Source register — 3 of 4

Primary documentation and project sources • checked for this design on 6 September 2026

Sources support existing capabilities and constraints. Product policies, stage assignments, budgets and proposed algorithms are our design choices. Live documentation can change; release artifacts must record applicable versions and pinned source revisions.

**[S23] GPUd — project repository.** Existing monitoring, diagnostics and issue-identification capabilities.  
Source: https://github.com/leptonai/gpud

**[S24] Linux — cgroup v2 documentation.** Effective resource limits, memory events and CPU throttling counters.  
Source: https://docs.kernel.org/admin-guide/cgroup-v2.html

**[S25] Linux — /proc filesystem documentation.** Process-visible and system counters, including reported steal accounting.  
Source: https://docs.kernel.org/filesystems/proc.html

**[S26] Linux — pressure-stall information.** CPU, memory and I/O waiting-pressure measurements.  
Source: https://docs.kernel.org/accounting/psi.html

**[S27] Linux — PCIe Advanced Error Reporting.** Available PCIe error evidence and driver/firmware ownership limitations.  
Source: https://docs.kernel.org/PCI/pcieaer-howto.html

**[S28] fio — official documentation.** Bounded storage workloads, verification, caching and latency reporting.  
Source: https://fio.readthedocs.io/en/latest/fio_doc.html

**[S29] ESnet — iperf3 documentation.** Authorized peer-to-peer network measurement; directional and protocol settings.  
Source: https://software.es.net/iperf/invoking.html

**[S30] Linux RDMA — perftest.** Future RDMA bandwidth/latency tests; supported peer and GPU-memory modes.  
Source: https://github.com/linux-rdma/perftest

**[S31] NVIDIA — Compute Sanitizer.** Application memory/race/synchronization debugging; not a physical VRAM certificate.  
Source: https://docs.nvidia.com/compute-sanitizer/ComputeSanitizer/index.html

**[S32] vLLM — benchmark CLI.** Workload benchmarking and prefix-cache contamination warning.  
Source: https://docs.vllm.ai/en/latest/benchmarking/cli/

**[S33] NVIDIA — H100 confidential computing.** Device attestation and confidential-computing trust context.  
Source: https://developer.nvidia.com/blog/confidential-computing-on-h100-gpus-for-secure-and-trustworthy-ai/


---

## 36 / Source register — 4 of 4

Primary documentation and project sources • checked for this design on 6 September 2026

Sources support existing capabilities and constraints. Product policies, stage assignments, budgets and proposed algorithms are our design choices. Live documentation can change; release artifacts must record applicable versions and pinned source revisions.

**[S34] NVIDIA — current attestation SDK.** C++ SDK, CLI and bindings; qualify current interfaces rather than old examples.  
Source: https://github.com/NVIDIA/attestation-sdk

**[S35] Intel — composite GPU attestation.** Combined CPU TEE and NVIDIA GPU attestation architecture.  
Source: https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-gpu-attestation.html

**[S36] Silicon Data — SiliconMark.** Direct prior art: rented-GPU, cluster, LLM and inventory benchmarking.  
Source: https://www.silicondata.com/products/silicon-mark

**[S37] SemiAnalysis — ClusterMAX methodology.** Provider-level evaluation, not an assumed redistributable diagnostic CLI.  
Source: https://www.clustermax.ai/overview

**[S38] Vast.ai — billing documentation.** Refund restrictions; no universal refundable inspection window.  
Source: https://docs.vast.ai/guides/reference/billing

**[S39] Runpod — billing documentation.** Credit/refund conditions; verify policy at action time.  
Source: https://docs.runpod.io/accounts-billing/billing

**[S40] Vast.ai — host self-test.** Host-side verification prior art; not a renter-only permission assumption.  
Source: https://docs.vast.ai/host/how-to-self-test

**[S41] Runpod — list Pods API.** Future controller inventory integration; version-pin before implementation.  
Source: https://docs.runpod.io/api-reference/pods/GET/pods

**[S42] Vast.ai — CLI overview.** Future instance discovery/lifecycle integration; API keys remain on controller.  
Source: https://docs.vast.ai/cli/hello-world

**[S43] NVIDIA — attestation CLI examples.** Current entry points; cryptographic verification is separate from benchmarking.  
Source: https://docs.nvidia.com/attestation/quick-start-guide/latest/attestation-examples/cli_examples.html

**[S44] Runpod — Pod pricing and storage lifecycle.** Stopped resources can retain storage costs; protect data before lifecycle actions.  
Source: https://docs.runpod.io/pods/pricing
