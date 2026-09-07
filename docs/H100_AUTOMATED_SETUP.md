# Automated H100 server test from Windows

This workflow prepares one server, builds the Linux SM90 worker, runs Quick and Standard scans, attempts all four Compute Sanitizer tools, retrieves the evidence, verifies it locally and opens a local report index. Progress and recovery state are saved automatically. It tests one selected full H100; it does not start workloads on peer GPUs.

**Status: development automation, 2026-09-07.** Windows software tests and RTX measurements cannot validate Linux H100 execution. A completed campaign still has `release_qualified: false`; missing healthy references, vendor data and review gates remain listed in its checklist.

## 1. Supply the server connection once

Provision an authorized **Ubuntu 22.04 or 24.04, Linux x86-64** server with an H100, a working NVIDIA driver and a home/SSH account you can access. The automation uses the existing driver. Allow approximately **12 GiB of free disk**, outbound HTTPS for official toolchains and configured Ubuntu packages, and an idle GPU. Restricted containers can leave journal, DCGM or NUMA checks unavailable.

On this Windows checkout, copy the example and edit its connection fields:

```powershell
Copy-Item .\h100-server.example.json .\h100-server.json
notepad .\h100-server.json
```

```json
{
  "host": "your-server.example.com",
  "user": "ubuntu",
  "port": 22,
  "identity_file": "C:/Users/Harish/.ssh/id_ed25519",
  "known_hosts_file": "",
  "host_key_sha256": "",
  "device": "",
  "expected_sku": "",
  "install_system_deps": true,
  "sanitizer": true,
  "dcgm": true,
  "setup_budget_seconds": 1800,
  "campaign_budget_seconds": 3600,
  "cuda_root": "",
  "open_report": true
}
```

Replace the host and key path. `host` can also be an existing SSH alias; use a DNS name or IPv4 address for direct connections. Leave `identity_file` empty to use existing SSH keys or an agent. The client runs in batch mode, so authentication must already work without password/passphrase prompts. Install the Windows OpenSSH Client beforehand if `ssh` and `scp` are unavailable.

The server must already be trusted in your SSH `known_hosts`, or `host_key_sha256` must contain the **SHA256 fingerprint obtained independently from your provider or server administrator**. With a fingerprint, the controller matches a scanned public host key before login. An unverified `ssh-keyscan` result does not establish trust. A custom `known_hosts_file` can be supplied. Unknown or changed keys stop the workflow; it never disables host verification. See [OpenSSH host checking](https://man.openbsd.org/ssh_config#StrictHostKeyChecking) and [ssh-keyscan trust limitations](https://man.openbsd.org/ssh-keyscan).

Leave `device` empty only if exactly one permitted full GPU is visible. Otherwise enter the exact allocated `GPU-…` UUID from the provider's allocation details. Optional `expected_sku` is `h100-pcie-80gb`, `h100-sxm-80gb` or `h100-nvl-94gb`. Ambiguous selection, MIG and busy devices stop active tests; there is no busy override in this workflow.

`install_system_deps: true` permits noninteractive installation of Python/build prerequisites from existing Ubuntu repositories, using root or passwordless `sudo -n`. Set it to false when dependencies are already installed or system package changes are prohibited. Driver installation, service configuration, GPU resets, reboots and clock/power changes are outside this setup.

The connection file is ignored by Git. Store key **paths**, never private-key contents or passwords. Creating the rental, supplying its connection details and establishing trust are the necessary one-time inputs; subsequent setup, execution and report retrieval require no interactive server commands under these prerequisites.

## 2. Run one command

From the repository in PowerShell:

```powershell
.\scripts\test-h100-server.cmd -Config .\h100-server.json
```

The entry point reuses or downloads a checksum-verified portable Python 3.13.12 without changing system PATH. The controller builds a local Go report verifier, packages allowlisted source files and connects to the configured host. It creates a private `/tmp/gri-h100-<unique-id>` job directory and starts a detached bounded campaign. It does not upload local reports, SSH keys, signing keys or the connection configuration.

The `.cmd` entry point runs this checkout's PowerShell script with a **process-only** execution-policy setting, so the workstation's default restriction on `.ps1` files needs no persistent change. Organizational Group Policy still takes precedence. Use a reviewed checkout; the launch setting permits that script to execute. See [Microsoft's execution-policy scopes](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.6).

The server setup reuses validated Go/CMake versions or downloads pinned toolchains. It assembles a private **CUDA 12.8.1** toolkit with cuBLAS/cuBLASLt and Compute Sanitizer from checksum-pinned official NVIDIA archives, approximately 1.03 GB compressed. `cuda_root` can select an existing complete matching toolkit; an incompatible partial toolkit is refused. Setup compiles a probe without executing GPU work. Full dependency versions, pins and setup limits are in [SETUP_H100.md](../scripts/SETUP_H100.md).

The campaign then:

1. Builds the native Linux CLI and SM90 worker; runs Go tests, race detection, vet and the CPU known-answer harness; checks runtime library resolution.
2. Creates a fresh development signing key on the server and admits the exact development worker. The private key stays in the server build directory and is excluded from retrieved evidence.
3. Runs a 120-second Quick scan and a 300-second Standard scan, with report verification and report-derived checklists. Standard schedules twelve methods, including FP8, INT8 and Linux NUMA comparison.
4. If requested, attempts `memcheck`, `racecheck`, `initcheck` and `synccheck` across the campaign's applicable worker matrix. Each result must include valid worker output and sanitizer instrumentation evidence; exit code zero alone is insufficient. The tool's error-exit option and summaries are described in [NVIDIA's Compute Sanitizer guide](https://docs.nvidia.com/compute-sanitizer/ComputeSanitizer/index.html).
5. Saves campaign status, unresolved checks, logs and an indexed ZIP, then downloads and verifies them locally. It generates a fresh local HTML review index and opens that index when `open_report` is true.

DCGM requests use the existing supported **4.6.0** client and loopback hostengine. Setup records absent/incompatible DCGM; it does not install or start a hostengine. NUMA needs two permitted nodes and page-placement access. These missing capabilities produce explicit pending states. No signed production advisory or healthy-reference corpus is invented or fetched automatically.

Defaults allow up to 30 minutes for setup and 60 minutes for the campaign, plus bounded transfer/packaging overhead and up to roughly four minutes if Python must first be installed. These are ceilings, not a runtime estimate or cost guarantee. The campaign stops later GPU work after critical safety events, timeout or uncertain completion. Sanitizer findings and numerical failures remain failed evidence even when report retrieval succeeds.

Linux/macOS controllers with Python 3.9+ can use the same configuration:

```bash
python3 scripts/h100-remote.py --config h100-server.json
```

## 3. Find the reports

The terminal prints a path such as `build/h100-remote-<timestamp>-<id>`. This private local directory contains:

| File/directory | Purpose |
| --- | --- |
| `state.json` | Exact job identity, source/verifier hashes, connection paths and recovery state. |
| `last-progress.txt`, `local-build.log`, `transfer.log` | Saved progress and local build/upload diagnostics. |
| `campaign.zip.download`, `campaign.zip.sha256.download` | Received evidence archive and checked SHA256 sidecar. |
| `imported-<id>/index.html` | Locally generated overview linking reviewed reports, status and checklists. |
| `imported-<id>/…` | Verified campaign data, per-scan evidence, method/sanitizer results and pending work. |
| `controller-error.json` | Failure/recovery information, when the controller did not finish. |

The importer enforces archive/path/content bounds, manifest hashes and report integrity before publishing its private output. It opens freshly rendered local HTML; downloaded HTML is retained as evidence but never automatically opened. Hash verification detects transfer/content inconsistency; it does not prove that a remote host is trustworthy or its measurements are true.

Controller exit **0** means retrieval and local import completed. Read the campaign status and scan decisions to assess the GPU: an unqualified development scan normally remains **INCONCLUSIVE**, with no calibrated score. Failed setup/build attempts can also be retrieved successfully as explicit incomplete campaigns. Controller exit **1** means setup of the controller, connection, transfer or import did not complete; inspect the saved error and progress.

## 4. Recover a disconnected run

Use the exact recovery directory printed by the first command:

```powershell
.\scripts\test-h100-server.cmd -Resume .\build\h100-remote-<timestamp>-<id>
```

The same bounded job continues on the server when SSH drops. Resume checks the remote launch marker and retrieves that job; it does not automatically rerun GPU tests. Even when the original launch acknowledgement was lost, it avoids overwriting a launched job. Keep the local state and remote job directory until import succeeds. Server destruction or `/tmp` eviction can make recovery impossible.

To validate local preparation before rental time or any SSH connection:

```powershell
.\scripts\test-h100-server.cmd -Config .\h100-server.json -PrepareOnly
```

This builds and packages locally. Resume that printed directory when ready. It does not validate server authentication, dependencies or hardware. If configuration must change, prepare a new run; do not reuse another server's job state.

Both local and remote attempts are retained for investigation. Provider billing continues until you stop the rental through your provider. The tool neither obtains provider credentials nor terminates rentals. Review the retained files before deleting the exact job directory; build directories can contain development private keys and reports contain machine identifiers.

## Remaining H100 acceptance work

The generated checklists cover missing Phase 1 evidence and seven separate release gates. The first real campaign must still establish native Linux behavior, numerical method results, sanitizer coverage, selected-device isolation and applicable NUMA/DCGM/journal behavior on the actual allocation. Restricted or unsupported checks cannot be marked passed by automation.

Independent healthy H100 reference acquisition, dated OEM/driver advisory review, labeled real outcome review, production signing/distribution and final release approval require external evidence. Multi-GPU NVLink/NCCL, multi-node tests and real application benchmarks are later design phases. See the [detailed H100 checklist](H100_SINGLE_NODE.md#remaining-acceptance-checklist) and [acceptance runbook](ACCEPTANCE.md).

## Validation on this Windows machine

On 2026-09-07, 237 top-level Go tests passed; two opt-in NVIDIA tests were skipped in that suite. Race detection and vet passed, and Windows/native and Linux/cgo-free CLI builds succeeded. Python ran 40 controller/campaign tests: 39 passed and the Linux-only `flock` test was skipped. Setup fixtures, eight runner scenarios and seven detached-job wrapper scenarios passed through Git Bash. These are software and mocked orchestration results, not native Linux execution.

The actual cold Windows bootstrap downloaded the pinned Python archive, verified its SHA256, extracted Python 3.13.12 and forwarded arguments successfully in 7.421 seconds. The real Windows launcher then built/prepared locally and resumed preparation without SSH. Producer/import integration verified a failed-setup archive and a 414-entry synthetic campaign containing two verified report directories and all 48 sanitizer result cells. The fixture matrix tests packaging; it contains no actual sanitizer measurements.

Retained results are under `build/h100-automation-validation`, including `SUMMARY.json`, individual test logs, cold-bootstrap evidence and producer/import results. No actual H100 SSH campaign has been run from this machine. Native Linux package installation, driver integration, sanitizer execution and GPU acceptance remain pending the server connection and real run.

Budgets bound owned user-space work; they cannot prove immediate completion of an uninterruptible driver call or detached vendor daemon. The Windows controller uses an owned Job Object after local process creation; early child creation before attachment remains a limitation. GPU execution is performed by the separate guarded Linux campaign. SSH interruption preserves the remote job rather than treating connection loss as completed GPU cleanup.
