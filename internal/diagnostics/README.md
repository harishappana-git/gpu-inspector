# Selected-device Linux diagnostics

This package adds normalized B06 Xid evidence and an explicitly enabled B11
DCGM software check. Both public entry points return `UNSUPPORTED` on Windows;
the RTX 5080 validation cannot qualify these Linux/H100 adapters.

`Xid(ctx, device, scanStart, scanEnd, options)` requires a complete physical GPU
UUID and PCI address whose continuity the caller has verified across the scan.
It reads the accessible current-boot system kernel journal only within that
interval, filters exact PCI identity, and exports timestamps and numeric Xid
codes. It never exports message text, process identifiers, workload names,
hostnames or arbitrary tool errors. Observed events produce `WARNING` symptoms,
without assigning a universal hardware-failure meaning to a code. An empty
accessible query means only that no matching event was observed.

Each retained code also adds a bounded primitive selector, for example
`value.xid_79_observed = true`, for exact advisory matching on this selected
resource. An absent selector is not evidence that a code never occurred.

Journal retention, permissions, driver delivery latency and wall-clock changes
can hide events. `complete_event_history` is always false. Missing tooling,
denied access, exhausted time, malformed data and truncated partial evidence
retain explicit statuses. Defaults are two seconds, at most five seconds and
one MiB of output; at most 1,024 selected events are exported. No root escalation
or historical `dmesg` fallback is attempted.

`DCGM(ctx, device, options)` does nothing unless `DCGMEnabled` is true. It accepts
a full physical H100, disabled MIG, and a known non-vGPU mode. This adapter is
pinned to **DCGM 4.6.0 only**, including the local client, existing hostengine and
returned result metadata. Other versions need a separately reviewed adapter and
fixtures because NVIDIA does not promise a stable `dcgmi` JSON schema.

The bounded sequence is:

1. Resolve the already installed `dcgmi` from fixed system installation
   directories, read its version, and query both build versions using `--vv`.
2. Read discovery and map the exact selected UUID and PCI to one DCGM entity ID.
   The management/NVML index is never substituted for the DCGM ID.
3. Immediately query that entity's UUID/PCI attributes again.
4. Request level 1 with `--entity-id gpu:<verified-ID>`, a native timeout,
   heartbeat, disabled diagnostic debug logging and JSON output.
5. Accept only the pinned software/deployment result schema with exactly the
   selected GPU entity; then revalidate its UUID/PCI attributes.

All connected commands specify `--host 127.0.0.1`. An explicit host argument
prevents `dcgmi diag` from starting its fallback embedded hostengine. The package
does not install or start services, reset/configure devices, run group/all-device
suites, request remote hosts, or issue global stop commands. The existing daemon
may create its own configured local diagnostic artifacts; these are not read or
included in the report. A client visibility environment does not restrict a
separate daemon, so selection is enforced through the verified entity argument.

The default total DCGM allowance is 40 seconds and the package caps it at 60.
The CLI accepts 5–60 seconds; short allocations may expire during discovery and
must not be treated as passes. A two-second margin is reserved below the outer
deadline for return and identity checking. Killing the local client cannot prove
that its existing daemon has completed the request. On interruption,
`daemon_completion_known=false` and `stop_active=true`; callers must stop later
active tests. Every opted-in outcome except a completely parsed, revalidated
all-pass result retains `stop_active=true`.

The exported result keeps allowlisted test names, vendor statuses and numeric
error codes. Raw warning/info text, build details and serial numbers are omitted.
Skipped checks and unknown subchecks are incomplete coverage. Vendor failures
are warnings requiring interpretation, not a physical GPU verdict. Level 1
checks deployment/software readiness; it does not establish H100 stress,
performance, HBM, NVLink or multi-node qualification.

Tests use source-derived fixtures, including selected/nonselected PCI and time,
limited journal access, different DCGM and management indices, version mismatch,
entity mismatch, cancellation, output bounds, warning privacy and identity loss.
These tests and a Linux cross-build are not captured H100 execution. Native Linux
4.6.0/H100 verification of selection, return format, permissions, deadline and
daemon cleanup remains required before claiming hardware qualification.

Primary references used to define the adapter:

- [NVIDIA Xid workflow](https://docs.nvidia.com/deploy/xid-errors/working-with-xid-errors.html)
- [systemd journalctl implementation](https://github.com/systemd/systemd/blob/main/src/journal/journalctl-show.c)
- [DCGM 4.6.0 CLI parsing and flags](https://github.com/NVIDIA/DCGM/blob/v4.6.0/dcgmi/CommandLineParser.cpp)
- [DCGM 4.6.0 discovery](https://github.com/NVIDIA/DCGM/blob/v4.6.0/dcgmi/Query.cpp)
- [DCGM 4.6.0 version query](https://github.com/NVIDIA/DCGM/blob/v4.6.0/dcgmi/Version.cpp)
- [DCGM 4.6.0 diagnostic scope, timeout, heartbeat and JSON implementation](https://github.com/NVIDIA/DCGM/blob/v4.6.0/dcgmi/Diag.cpp)
- [DCGM 4.6.0 result schema](https://github.com/NVIDIA/DCGM/blob/v4.6.0/testing/python3/dcgm_diag_schema.json)
- [NVIDIA diagnostic CLI reference](https://docs.nvidia.com/datacenter/dcgm/latest/reference/command-line-reference/dcgmi/dcgmi-diag.html)
