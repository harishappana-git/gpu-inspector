# Read-only collection adapters

`Discover`, `GPU`, `Telemetry`, and `Host` return versioned, normalized observations. `Contracts` declares permissions, effects, cost estimates, cancellation and fallback. The production entry point must call `HandleInternalCommand` before normal CLI parsing, so management and OS reads execute in bounded child processes. Collector helpers receive only locale, a fixed executable search path and GPU visibility variables. They use process groups, an output cap, and cancellation; raw stderr is classified and discarded.

On Linux builds with cgo, the NVIDIA helper loads `libnvidia-ml.so.1` at runtime. No CUDA toolkit/NVML headers are required to build it. Stable public ABI types and individually discovered symbols are used. Unavailable NVML fields can fall back to fields explicitly advertised by the installed `nvidia-smi --help-query-gpu`; selected-device values are requested in one CSV batch. NVML and nvidia-smi remain one host/driver trust domain. A cgo-free Linux build uses the CLI fallback. Other operating systems produce explicit degraded-mode observations.

The CUDA driver is loaded only for read-only enumeration of runtime-visible UUIDs. Numeric CUDA visibility masks are never interpreted as management indices. Masks are intersected with management visibility. MIG-specific masks are rejected as unsupported instead of substituting a physical parent. Full partition enumeration and vGPU qualification remain release gaps. Management visibility does not establish application usability.

GPU snapshots include identity, reported memory, supported ECC counters/state, row remapping, retired-page counts, core temperature and device-provided temperature thresholds, power, clock reasons, PCIe telemetry, utilization, and a count-only compute-process query. No PIDs or process names are exported. Lightweight telemetry uses ten fields. Field statuses preserve unavailable/denied/unsupported values, and a changed UUID contaminates the snapshot. No complete Xid/event history or reliable reset epoch is claimed; a nondecreasing error counter cannot exclude an intervening reset.

Host collection reads only selected proc/sys metadata. Cgroup membership is resolved through the current process mountinfo and membership paths, including cgroup v1/v2 mount roots and readable ancestors. CPU quota and memory ceilings use the tightest readable ancestor, with hidden ancestors, incomplete reads, and sibling consumption stated as limitations. Private hierarchy paths, process identities, mount source/credentials, IP/MAC addresses, environment and raw logs are omitted. Workspace capacity and mount type are read without creating test files; statfs does not establish quota or storage persistence. Network collection reads only local IPv4 route/interface context and sends no traffic.

Validation includes malformed/absent/denied scalar parsing, observed-zero preservation, numeric CUDA remapping, partition refusal, current cgroup and ancestor-limit fixtures, traversal rejection, private-data exclusion, mismatched-UUID contamination, child cancellation, output limits and environment allowlisting. macOS tests and Linux cgo-free cross-compilation are development checks. They do not qualify the native ABI against real NVIDIA hardware or establish performance/health.

Primary API references consulted 2026-09-06:

- [NVIDIA NVML device queries](https://docs.nvidia.com/deploy/nvml-api/group__nvmlDeviceQueries.html), reference page reporting vR610, updated May 26, 2026.
- [NVIDIA NVML enums and temperature thresholds](https://docs.nvidia.com/deploy/nvml-api/group__nvmlDeviceEnumvs.html).
- [NVIDIA nvidia-smi documentation](https://docs.nvidia.com/deploy/nvidia-smi/index.html).
- [Linux cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html).

Release qualification must retain exact driver, library, OS, worker, device configuration, and hardware acceptance evidence. Dynamic symbol presence and successful compilation alone are not qualification.
