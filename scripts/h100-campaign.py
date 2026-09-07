#!/usr/bin/env python3
"""Bounded, local Linux H100 development acceptance. No SSH or installation.

Build/test success never sets release_qualified. Package-only performs no GPU
work and can recover allowlisted logs after a disconnected/failed setup.
"""
import argparse
import contextlib
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid
import zipfile

METHODS = ("memory_integrity", "fp32_gemm", "bf16_gemm", "tf32_gemm", "hbm_copy",
           "working_set", "h2d", "d2h", "dispatch_latency", "int8_gemm", "fp8_gemm", "numa_transfer")
TOOLS = ("memcheck", "initcheck", "racecheck", "synccheck")
UUID = re.compile(r"GPU-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
PCI = re.compile(r"[0-9a-fA-F]{4,8}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]\Z")
MAX_FILE = 16 << 20
MAX_EXPORT = 128 << 20
EVIDENCE = {"report.json", "report.html", "evidence-index.json", "evidence.jsonl", "guide.md", "ticket.md"}
RUN_FILES = {"terminal.log", "verification.log", "checklist.json", "remaining-checklist.txt", "run-status.json"}
SAN_FILES = {"worker.json", "sanitizer.log", "stdout.log", "stderr.log", "validation.log", "guard-before.json", "guard-after.json", "status.json"}
ROOT_FILES = {"campaign-status.json", "remaining-checklist.json", "remaining-checklist.txt", "build-provenance.txt"}
LOG_FILES = {"build.log", "preflight.json", "sanitizer-version.log", "setup.log", "setup-status.json"}
RELEASE_GATES = (
    ("WP1", "Review native Linux H100 isolation: remapped ordinals, multiple/restricted visible GPUs, MIG refusal, disappearance and cancellation."),
    ("WP2", "Review pinned driver/NVML ABI, host/container permission denials, journal and DCGM availability on the selected H100 variant."),
    ("WP3", "Review SM90 known answers and controlled corruption, all four sanitizer tools, headroom/cancellation, and relocated worker/library behavior."),
    ("WP4", "Acquire independently tracked healthy allocations/hosts, retain runs and exclusions, and sign an exact-configuration healthy reference."),
    ("WP5", "Review independently labeled false positives/negatives and real outcomes, evidence-linked findings and provider-facing drafts."),
    ("WP6", "Review dependency/license inventory, production key custody/rotation, reproducible signed distribution, privacy and cleanup."),
    ("WP7", "Review the authorized H100 rental campaign with all attempts, actual duration/cost, checksums and limits; obtain a human release decision."),
)


class StopCampaign(RuntimeError):
    pass


def allowed_path(name):
    p = name.split("/")
    return (name in ROOT_FILES or
            len(p) == 2 and p[0] == "logs" and p[1] in LOG_FILES or
            len(p) == 3 and p[0] == "runs" and p[1] in ("quick", "standard") and p[2] in RUN_FILES or
            len(p) == 4 and p[0] == "runs" and p[1] in ("quick", "standard") and p[2] == "evidence" and p[3] in EVIDENCE or
            len(p) == 4 and p[0] == "sanitizer" and p[1] in TOOLS and p[2] in METHODS and p[3] in SAN_FILES)


def finite(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def file_sha256(stream):
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(1 << 20), b""):
        digest.update(block)
    return digest.hexdigest()


def checked_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise StopCampaign("duplicate_json_key")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    except (ValueError, UnicodeError) as error:
        raise StopCampaign("invalid_json") from error


def read_text(path, limit=MAX_FILE):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise StopCampaign("artifact_not_bounded_regular_file")
    raw = path.read_bytes()
    if len(raw) > limit or b"\0" in raw or b"PRIVATE KEY-----" in raw:
        raise StopCampaign("artifact_has_forbidden_contents")
    try:
        return raw.decode("utf-8")
    except UnicodeError as error:
        raise StopCampaign("artifact_not_utf8") from error


def private_directory(path, new=False):
    if new:
        path.mkdir(mode=0o700, parents=False)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink():
        raise StopCampaign("private_directory_required")
    if os.name == "posix" and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
        raise StopCampaign("owned_private_directory_required")


def write_text(path, text):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Never replace a symlink or a directory with campaign state.
    if path.exists() or path.is_symlink():
        if not stat.S_ISREG(path.lstat().st_mode):
            raise StopCampaign("unsafe_existing_artifact")
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_json(path, value):
    write_text(path, json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def field(snapshot, name):
    if snapshot.get("status") != "PASS":
        raise StopCampaign("selected_nvml_state_unavailable")
    item = snapshot.get("fields", {}).get(name, {})
    if item.get("status") != "PASS" or "value" not in item:
        raise StopCampaign("required_guard_field_unavailable:" + name)
    return item["value"]


def select_h100(discovery, requested=None, nvidia_visibility=None):
    if discovery.get("status") != "PASS" or discovery.get("cuda_status") != "PASS":
        raise StopCampaign("permitted_cuda_identity_unavailable")
    visible = discovery.get("cuda_uuids", [])
    if not visible or len(visible) > 1024 or len(set(visible)) != len(visible) or any(not UUID.fullmatch(x) for x in visible):
        raise StopCampaign("ambiguous_cuda_visibility")
    permitted = set(visible)
    if nvidia_visibility is not None and nvidia_visibility != "all":
        declared = nvidia_visibility.split(",")
        if not declared or any(not UUID.fullmatch(x) for x in declared):
            raise StopCampaign("nvidia_allocation_requires_full_uuid_visibility")
        permitted.intersection_update(declared)
    if not requested and len(permitted) != 1:
        raise StopCampaign("multiple_permitted_gpus_require_explicit_uuid")
    candidates = []
    seen = set()
    for device in discovery.get("devices", []):
        identity = device.get("uuid", "")
        if not UUID.fullmatch(identity) or identity in seen:
            raise StopCampaign("ambiguous_nvml_identity")
        seen.add(identity)
        if identity in permitted and re.search(r"\bH100\b", device.get("name", "")) and str(device.get("mig_mode")) in ("0", "disabled") and str(device.get("virtualization_mode")) in ("0", "1", "none", "passthrough"):
            candidates.append(device)
    if requested:
        if not UUID.fullmatch(requested):
            raise StopCampaign("full_selected_uuid_required")
        candidates = [x for x in candidates if x["uuid"] == requested]
    if len(candidates) != 1:
        raise StopCampaign("select_one_permitted_full_h100_explicitly")
    if not PCI.fullmatch(candidates[0].get("pci_address", "")):
        raise StopCampaign("selected_pci_identity_unavailable")
    return candidates[0]


def guard(snapshot, device, memory_mib, max_temp, active=False, baseline=None):
    expected = {"uuid": device["uuid"], "pci_address": device["pci_address"], "name": device["name"],
                "driver_version": device["driver_version"], "compute_capability": "9.0"}
    for name, value in expected.items():
        got = field(snapshot, name)
        if (str(got).lower() if name == "pci_address" else got) != (value.lower() if name == "pci_address" else value):
            raise StopCampaign("selected_identity_changed:" + name)
    if field(snapshot, "mig_current") != 0 or field(snapshot, "mig_pending") != 0 or field(snapshot, "virtualization_mode") not in (0, 1):
        raise StopCampaign("selected_partition_or_virtualization_state_changed")
    for name in ("temperature_gpu_c", "memory_free_bytes", "memory_total_bytes", "compute_process_count", "utilization_gpu_percent", "ecc_uncorrected_volatile", "ecc_corrected_volatile"):
        value = field(snapshot, name)
        if not finite(value) or value < 0:
            raise StopCampaign("invalid_guard_value:" + name)
    if field(snapshot, "temperature_gpu_c") >= max_temp:
        raise StopCampaign("selected_temperature_ceiling")
    total, free = field(snapshot, "memory_total_bytes"), field(snapshot, "memory_free_bytes")
    if total != device["memory_bytes"] or free > total:
        raise StopCampaign("selected_memory_identity_changed")
    reserve = max(512 << 20, total // 10)
    if free < reserve + (0 if active else memory_mib << 20):
        raise StopCampaign("insufficient_selected_memory_headroom")
    count, utilization = field(snapshot, "compute_process_count"), field(snapshot, "utilization_gpu_percent")
    if count != int(count) or count > (1 if active else 0) or (not active and utilization > 5):
        raise StopCampaign("selected_gpu_not_exclusively_idle" if not active else "additional_selected_gpu_process")
    for name in ("ecc_uncorrected_volatile", "row_remap_failure", "row_remap_pending"):
        if field(snapshot, name) not in (0, False):
            raise StopCampaign("critical_selected_health_signal:" + name)
    if baseline is not None and field(snapshot, "ecc_corrected_volatile") != field(baseline, "ecc_corrected_volatile"):
        raise StopCampaign("selected_ecc_counter_changed")
    return snapshot


def sanitizer_outcome(tool, log, worker, exit_code, validated):
    correctness = worker.get("correctness", {})
    if worker.get("status") in ("mismatch", "test_error", "budget_exhausted") or correctness.get("mismatch_count", 0) != 0:
        return "STOP", "worker_failed_or_incomplete"
    blocked = ("not supported", "unsupported", "unable to", "failed to", "not enabled", "no attachable process", "no instrumented", "not instrumented", "timed out", "permission denied", "internal error")
    if any(x in log.lower() for x in blocked):
        return "STOP", "instrumentation_unavailable_or_incomplete"
    if re.search(r"(?:ERROR SUMMARY:|RACECHECK SUMMARY:)\s*[1-9][0-9]*", log) or re.search(r"(?im)^=+\s*(?:Invalid |Program hit |Race reported)", log):
        return "STOP", "instrumentation_reported_errors"
    if worker.get("status") in ("unsupported", "blocked") and validated and exit_code in (0, 2):
        return "PENDING", "method_unavailable"
    if not validated or worker.get("status") != "ok" or correctness.get("checked") is not True or not finite(correctness.get("checked_values")) or correctness["checked_values"] <= 0 or correctness.get("synthetic") is not False:
        return "STOP", "numerical_result_not_verified"
    summary = r"RACECHECK SUMMARY:\s*0 hazards displayed \(0 errors, 0 warnings\)" if tool == "racecheck" else r"ERROR SUMMARY:\s*0 errors"
    if exit_code != 0 or "COMPUTE-SANITIZER" not in log or not re.search(summary, log):
        return "STOP", "instrumentation_clean_summary_missing"
    return "PASS", "numerical_output_and_clean_instrumentation_checked"


@contextlib.contextmanager
def selected_lock(home, identity):
    import fcntl
    root = home / ".cache" / "gri" / "locks"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_directory(root)
    path = root / (hashlib.sha256(identity.lower().encode("ascii")).hexdigest() + ".lock")
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise StopCampaign("selected_lock_not_private")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise StopCampaign("another_gri_run_holds_selected_lock") from error
        yield
    finally:
        os.close(fd)


def report_coverage(report):
    values = {name: "PENDING" for name in METHODS}
    critical = report.get("cancelled") is True or str(report.get("verdict", "")).startswith("DO NOT START")
    for observation in report.get("observations", []):
        method = observation.get("method_id", "")
        status = observation.get("status")
        if status in ("FAIL", "TIME_BUDGET_EXHAUSTED", "TOOL_ERROR") and (method.split(".")[0] in METHODS or method.startswith("guard.")):
            critical = True
        if method.endswith(".validation") and method[:-11] in METHODS:
            name = method[:-11]
            checked = observation.get("value", {}).get("correctness", {})
            if status == "PASS" and checked.get("checked") is True and checked.get("checked_values", 0) > 0 and checked.get("mismatch_count") == 0:
                values[name] = "PASS"
            else:
                values[name] = status or "PENDING"
    return values, critical


class Campaign:
    def __init__(self, args):
        self.args = args
        self.output = Path(args.output).absolute()
        if args.package_only:
            self.output.mkdir(mode=0o700, parents=True, exist_ok=True)
        else:
            self.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            private_directory(self.output, new=True)
        private_directory(self.output)
        self.started = time.monotonic()
        self.elapsed_base = 0
        self.deadline = self.started + args.total_seconds
        self.home = Path.home()
        self.environment = {"PATH": "/usr/bin:/bin", "HOME": str(self.home), "LANG": "C", "LC_ALL": "C"}
        for name in ("CUDA_VISIBLE_DEVICES", "NVIDIA_VISIBLE_DEVICES"):
            if name in os.environ:
                self.environment[name] = os.environ[name]
        self.state = {"schema_version": 1, "campaign_id": "h100-" + uuid.uuid4().hex,
                      "release_qualified": False, "status": "RUNNING", "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                      "running_step": None, "steps": {}, "coverage": {}, "pending": [], "verified_runs": [],
                      "limits": {"total_seconds": args.total_seconds, "memory_mib": args.memory_mib, "sanitizer_memory_mib": args.sanitizer_memory_mib, "max_temperature_c": args.max_temperature_c}}
        old = self.output / "campaign-status.json"
        if args.package_only and old.exists():
            self.state = checked_json(read_text(old))
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}", self.state.get("campaign_id", "")) or self.state.get("release_qualified") is not False:
                raise StopCampaign("invalid_recovery_campaign_state")
            self.elapsed_base = self.state.get("elapsed_seconds", 0)
        self.device = None
        self.baseline = None
        self.gri = None
        self.log_bytes = 0
        self.log_lock = threading.Lock()
        self.bundle = Path(args.bundle).absolute() if args.bundle else self.output / "private-bundle"

    def save(self):
        self.state["updated_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.state["elapsed_seconds"] = round(self.elapsed_base + time.monotonic() - self.started, 3)
        write_json(self.output / "campaign-status.json", self.state)

    def progress(self, step, status, reason=""):
        self.state["steps"][step] = {"status": status, "reason": reason}
        self.state["running_step"] = step if status == "RUNNING" else None
        self.save()
        print(json.dumps({"campaign_id": self.state["campaign_id"], "step": step, "status": status, "reason": reason}), flush=True)

    def remaining(self, cap):
        value = min(cap, self.deadline - time.monotonic())
        if value < 1:
            raise StopCampaign("campaign_total_budget_exhausted")
        return value

    def run(self, command, stdout, seconds, stderr=None, environment=None, monitor=None, watched=None, output_limit=8 << 20):
        duration = self.remaining(seconds)
        dest = self.output / stdout
        dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        streams = [open(dest, "x", encoding="utf-8", newline="\n")]
        if stderr:
            streams.append(open(self.output / stderr, "x", encoding="utf-8", newline="\n"))
        failed = threading.Event()
        process = None
        threads = []
        start = time.monotonic()
        def drain(pipe, stream):
            count = 0
            try:
                while True:
                    data = pipe.read(4096)
                    if not data:
                        break
                    text = data.decode("utf-8", errors="replace").replace("\0", "[NUL]")
                    size = len(text.encode("utf-8"))
                    count += size
                    with self.log_lock:
                        self.log_bytes += size
                        aggregate_exceeded = self.log_bytes > 64 << 20
                    if count > output_limit or aggregate_exceeded:
                        failed.set()
                        break
                    stream.write(text)
                    stream.flush()
            finally:
                pipe.close()
        try:
            process = subprocess.Popen(command, cwd=str(self.output), env=environment or self.environment,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE if stderr else subprocess.STDOUT,
                                       start_new_session=os.name == "posix")
            threads = [threading.Thread(target=drain, args=(process.stdout, streams[0]), daemon=True)]
            if stderr:
                threads.append(threading.Thread(target=drain, args=(process.stderr, streams[1]), daemon=True))
            for thread in threads:
                thread.start()
            next_guard, heartbeat = start, start + 20
            watched_seen = 0
            while process.poll() is None:
                now = time.monotonic()
                if now - start >= duration:
                    raise StopCampaign("step_or_campaign_timeout")
                if watched and watched.exists():
                    size = watched.stat().st_size
                    with self.log_lock:
                        self.log_bytes += max(0, size - watched_seen)
                    watched_seen = size
                    if size > 8 << 20 or self.log_bytes > 64 << 20:
                        failed.set()
                if failed.is_set():
                    raise StopCampaign("step_output_limit_exceeded")
                if monitor and now >= next_guard:
                    monitor()
                    next_guard = time.monotonic() + 2
                if now >= heartbeat:
                    self.save()
                    print(json.dumps({"step": self.state["running_step"], "status": "RUNNING", "elapsed_seconds": round(now-start)}), flush=True)
                    heartbeat = now + 20
                time.sleep(0.05)
            for thread in threads:
                thread.join(timeout=2)
                if thread.is_alive():
                    raise StopCampaign("child_pipe_still_open")
            if failed.is_set():
                raise StopCampaign("step_output_limit_exceeded")
            return process.returncode, (time.monotonic() - start) * 1000
        finally:
            if process is not None:
                if os.name == "posix":
                    group_exists = False
                    try:
                        os.killpg(process.pid, 0)
                        group_exists = True
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    if group_exists:
                        # The direct child may exit while its own descendants
                        # ignore TERM. Always finish this exact owned group.
                        time.sleep(0.2)
                        with contextlib.suppress(ProcessLookupError):
                            os.killpg(process.pid, signal.SIGKILL)
                elif process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    if os.name == "posix":
                        with contextlib.suppress(ProcessLookupError):
                            os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
                    process.wait(timeout=2)
            for thread in threads:
                thread.join(timeout=2)
            for stream in streams:
                stream.close()

    def native(self, mode, selected=True):
        command = [str(self.gri), "__collect-nvml", mode]
        if selected:
            command.append(self.device["uuid"])
        name = "private-probes/" + uuid.uuid4().hex
        stdout, stderr = name + ".stdout", name + ".stderr"
        try:
            code, _ = self.run(command, stdout, 5, stderr, output_limit=2 << 20)
            if code != 0 or read_text(self.output / stderr, 2 << 20):
                raise StopCampaign("native_guard_failed")
            return checked_json(read_text(self.output / stdout, 2 << 20))
        finally:
            for relative in (stdout, stderr):
                with contextlib.suppress(FileNotFoundError):
                    (self.output / relative).unlink()

    def snapshot(self, active=False, memory=None):
        snapshot = self.native("snapshot")
        guard(snapshot, self.device, memory or self.args.memory_mib, self.args.max_temperature_c, active, self.baseline)
        return snapshot

    def ready(self, memory):
        # Two independent quiet snapshots, without retrying a bad state.
        before = self.snapshot(memory=memory)
        time.sleep(min(1, self.remaining(1)))
        self.snapshot(memory=memory)
        return before

    def verify_bundle(self):
        private_directory(self.bundle)
        lines = read_text(self.bundle / "SHA256SUMS", 1 << 20).splitlines()
        needed = {"bin/gri", "libexec/gri-cuda-worker", "worker-public.pem", "worker-manifest.json", "worker-envelope.json"}
        found = set()
        for line in lines:
            match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_./-]+)", line)
            if not match:
                raise StopCampaign("invalid_bundle_checksum_list")
            digest, name = match.groups()
            if name not in needed:
                continue
            if name in found:
                raise StopCampaign("duplicate_bundle_checksum")
            path = self.bundle / name
            if path.is_symlink() or not path.is_file():
                raise StopCampaign("unsafe_bundle_artifact")
            with path.open("rb") as stream:
                actual = file_sha256(stream)
            if actual != digest:
                raise StopCampaign("bundle_checksum_mismatch")
            found.add(name)
        if found != needed:
            raise StopCampaign("incomplete_bundle_checksums")
        self.gri = self.bundle / "bin/gri"
        provenance = self.bundle / "build-provenance.txt"
        if provenance.exists():
            write_text(self.output / "build-provenance.txt", read_text(provenance))

    def build(self):
        self.progress("build", "RUNNING")
        if not self.args.bundle:
            source = Path(self.args.source).resolve(strict=True)
            environment = dict(self.environment)
            # Setup's explicit pinned toolchain PATH is needed only while building.
            environment["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
            for key in ("TMPDIR", "GOTOOLCHAIN", "GOPROXY", "GOSUMDB"):
                if key in os.environ:
                    environment[key] = os.environ[key]
            command = ["/bin/bash", str(source / "scripts/build-linux-h100.sh"), "--cuda-root", self.args.cuda_root,
                       "--build-dir", str(self.output / "private-build"), "--output", str(self.bundle)]
            code, _ = self.run(command, "logs/build.log", self.args.build_seconds, environment=environment)
            if code:
                raise StopCampaign("linux_build_or_software_checks_failed")
        self.verify_bundle()
        self.progress("build", "PASS", "development_bundle_only")

    def preflight(self):
        self.progress("preflight", "RUNNING")
        discovery = self.native("discover", selected=False)
        self.device = select_h100(discovery, self.args.device, self.environment.get("NVIDIA_VISIBLE_DEVICES"))
        self.environment["CUDA_VISIBLE_DEVICES"] = self.device["uuid"]
        self.environment["NVIDIA_VISIBLE_DEVICES"] = self.device["uuid"]
        self.baseline = self.snapshot()
        write_json(self.output / "logs/preflight.json", {"selected": self.device, "guard": self.baseline,
                   "visibility": "selected UUID belongs to inherited runtime-visible allocation", "release_qualified": False})
        self.state["selected_device"] = self.device
        self.progress("preflight", "PASS", "read_only_reported_identity_not_attestation")

    def scan(self, tier):
        self.progress(tier, "RUNNING")
        self.ready(self.args.memory_mib)
        prefix = "runs/" + tier
        root = self.output / prefix
        root.mkdir(mode=0o700, parents=True)
        seconds = min(self.args.quick_seconds if tier == "quick" else self.args.standard_seconds, self.remaining(900)-10)
        if seconds < 20:
            raise StopCampaign("insufficient_scan_budget")
        command = [str(self.gri), "scan", "--device", self.device["uuid"], "--tier", tier,
                   "--budget-seconds", str(int(seconds)), "--memory-mib", str(self.args.memory_mib), "--seed", "42",
                   "--max-temperature-c", str(self.args.max_temperature_c), "--worker", str(self.bundle / "libexec/gri-cuda-worker"),
                   "--worker-manifest", str(self.bundle / "worker-envelope.json"), "--worker-public-key", str(self.bundle / "worker-public.pem"),
                   "--allow-unqualified-worker", "--output", str(root / "evidence")]
        if tier == "standard" and self.args.dcgm:
            command += ["--dcgm", "--dcgm-budget-seconds", "40"]
        if self.args.expected_sku:
            command += ["--expected-sku", self.args.expected_sku]
        code, duration = self.run(command, prefix + "/terminal.log", seconds + 10)
        verify, _ = self.run([str(self.gri), "verify", "--report-dir", str(root / "evidence")], prefix + "/verification.log", 15)
        if verify:
            raise StopCampaign("scan_report_failed_integrity_verification")
        self.state["verified_runs"].append(tier)
        report = checked_json(read_text(root / "evidence/report.json"))
        if report.get("device", {}).get("uuid") != self.device["uuid"]:
            raise StopCampaign("scan_report_selected_uuid_mismatch")
        coverage, critical = report_coverage(report)
        self.state["coverage"][tier] = coverage
        self.state["steps"][tier] = {"status": "RUNNING", "scan_verdict": report.get("verdict"), "scan_exit_code": code}
        for name, extra in (("checklist.json", ["--json"]), ("remaining-checklist.txt", [])):
            status, _ = self.run([str(self.gri), "checklist", "--report", str(root / "evidence/report.json")] + extra, prefix + "/" + name, 15)
            if status:
                raise StopCampaign("scan_checklist_failed")
        write_json(root / "run-status.json", {"scan_exit_code": code, "verify_exit_code": verify, "duration_ms": duration,
                   "verdict": report.get("verdict"), "release_qualified": False, "method_coverage": coverage})
        if critical or code not in (0, 3):
            raise StopCampaign("scan_critical_or_incomplete_active_execution")
        self.snapshot()
        self.progress(tier, "COMPLETED", "verdict=" + str(report.get("verdict")))

    def sanitizer(self):
        executable = Path(self.args.cuda_root) / "compute-sanitizer/compute-sanitizer"
        if not executable.is_file():
            self.state["pending"].append("Compute Sanitizer is unavailable; all four real instrumentation gates remain pending.")
            return
        code, _ = self.run([str(executable), "--version"], "logs/sanitizer-version.log", 10)
        if code:
            raise StopCampaign("compute_sanitizer_version_unavailable")
        for tool in TOOLS:
            for method in METHODS:
                step = tool + "/" + method
                self.progress(step, "RUNNING")
                prefix = "sanitizer/" + step
                root = self.output / prefix
                root.mkdir(mode=0o700, parents=True)
                outcome, reason = "STOP", "interrupted_before_completed_evidence"
                try:
                    with selected_lock(self.home, self.device["uuid"]):
                        self.verify_bundle()
                        before = self.ready(self.args.sanitizer_memory_mib)
                        write_json(root / "guard-before.json", before)
                        seconds = min(self.args.sanitizer_seconds, self.remaining(300)-10)
                        if seconds < 5:
                            raise StopCampaign("insufficient_sanitizer_budget")
                        budget_ms = int(seconds * 1000)
                        command = [str(executable), "--tool", tool, "--error-exitcode", "99", "--target-processes", "application-only",
                                   "--log-file", str(root / "sanitizer.log"), "--destroy-on-device-error", "context",
                                   str(self.bundle / "libexec/gri-cuda-worker"), "--device", self.device["uuid"], "--method", method,
                                   "--budget-ms", str(budget_ms), "--memory-mib", str(self.args.sanitizer_memory_mib), "--seed", "42", "--tier", "quick"]
                        code, duration = self.run(command, prefix + "/stdout.log", seconds + 5, prefix + "/stderr.log",
                                                  monitor=lambda: self.snapshot(active=True, memory=self.args.sanitizer_memory_mib), watched=root / "sanitizer.log")
                        stdout = read_text(root / "stdout.log", 2 << 20)
                        worker = checked_json(stdout)
                        write_json(root / "worker.json", worker)
                        validation, _ = self.run([str(self.gri), "worker-validate", "--input", str(root / "worker.json"), "--device", self.device["uuid"],
                            "--method", method, "--elapsed-ms", str(math.ceil(duration)), "--tier", "quick", "--memory-mib", str(self.args.sanitizer_memory_mib),
                            "--seed", "42", "--budget-ms", str(budget_ms)], prefix + "/validation.log", 10)
                        sanitizer_log = read_text(root / "sanitizer.log") if (root / "sanitizer.log").exists() else ""
                        candidate, candidate_reason = sanitizer_outcome(tool, sanitizer_log, worker, code, validation == 0)
                        # Sampling may retain recent utilization briefly. No new load while settling.
                        time.sleep(min(2, self.remaining(2)))
                        after = self.snapshot(memory=self.args.sanitizer_memory_mib)
                        write_json(root / "guard-after.json", after)
                        outcome, reason = candidate, candidate_reason
                        if outcome == "STOP":
                            raise StopCampaign(reason)
                except (StopCampaign, OSError, subprocess.SubprocessError, KeyboardInterrupt) as error:
                    outcome = "STOP"
                    reason = str(error) if isinstance(error, StopCampaign) else type(error).__name__
                    raise
                finally:
                    write_json(root / "status.json", {"status": outcome, "reason": reason, "release_qualified": False})
                self.progress(step, outcome, reason)

    def package(self):
        pending = list(self.state.get("pending", []))
        for method in METHODS:
            if self.state.get("coverage", {}).get("standard", {}).get(method) != "PASS":
                pending.append("Standard numerical/placement acceptance pending: " + method)
        for tool in TOOLS:
            for method in METHODS:
                if self.state.get("steps", {}).get(tool + "/" + method, {}).get("status") != "PASS":
                    pending.append("Real clean instrumentation pending: " + tool + "/" + method)
        pending += [identity + ": " + required for identity, required in RELEASE_GATES]
        pending += ["Production qualification remains false; development signing and a single bounded campaign do not establish release trust or physical authenticity."]
        self.state["pending"] = list(dict.fromkeys(pending))
        self.save()
        write_json(self.output / "remaining-checklist.json", {"release_qualified": False, "pending": self.state["pending"],
                   "release_gates": [{"id": identity, "status": "NOT_TESTED", "required": required} for identity, required in RELEASE_GATES]})
        write_text(self.output / "remaining-checklist.txt", "H100 development acceptance: remaining items\n\n" + "\n".join("- " + x for x in self.state["pending"]) + "\n")
        files, total = [], 0
        # Enumerate only fixed roots, never recurse through private build/toolchain/key trees.
        candidates = [self.output / x for x in ROOT_FILES]
        candidates += [self.output / "logs" / x for x in LOG_FILES]
        for tier in ("quick", "standard"):
            candidates += [self.output / "runs" / tier / x for x in RUN_FILES]
            if tier in self.state.get("verified_runs", []):
                candidates += [self.output / "runs" / tier / "evidence" / x for x in EVIDENCE]
        for tool in TOOLS:
            for method in METHODS:
                candidates += [self.output / "sanitizer" / tool / method / x for x in SAN_FILES]
        for path in sorted(candidates):
            if not path.exists() and not path.is_symlink():
                continue
            for parent in path.parents:
                if parent == self.output:
                    break
                if parent.is_symlink():
                    raise StopCampaign("artifact_parent_is_symlink")
            name = path.relative_to(self.output).as_posix()
            if not allowed_path(name):
                raise StopCampaign("artifact_outside_export_allowlist")
            data = read_text(path).encode("utf-8")
            total += len(data)
            if total > MAX_EXPORT:
                raise StopCampaign("campaign_export_limit_exceeded")
            files.append({"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
        manifest = {"schema_version": 1, "campaign_id": self.state["campaign_id"], "release_qualified": False, "files": files}
        write_json(self.output / "campaign-manifest.json", manifest)
        archive = self.output / "campaign.zip"
        temporary = self.output / ("campaign.zip.tmp-" + uuid.uuid4().hex)
        with zipfile.ZipFile(temporary, "x", compression=zipfile.ZIP_DEFLATED, allowZip64=False) as stream:
            for item in [{"path": "campaign-manifest.json"}] + files:
                name = item["path"]
                data = read_text(self.output / name).encode("utf-8")
                entry = zipfile.ZipInfo(name)
                entry.create_system = 3
                entry.external_attr = (stat.S_IFREG | 0o600) << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                stream.writestr(entry, data)
        os.replace(temporary, archive)
        with archive.open("rb") as stream:
            digest = file_sha256(stream)
        write_text(self.output / "campaign.zip.sha256", digest + "  campaign.zip\n")

    def execute(self):
        code = 0
        try:
            if self.args.package_only:
                if self.state.get("running_step") or self.args.failure_reason:
                    self.state["status"] = "STOPPED"
                    self.state["pending"].append(self.args.failure_reason or "Interrupted campaign; no GPU work resumed.")
                    self.state["interrupted_step"] = self.state.get("running_step")
                    self.state["running_step"] = None
                return 0
            if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
                raise StopCampaign("native_linux_x86_64_required")
            for source, name in ((self.args.setup_log, "setup.log"), (self.args.setup_status, "setup-status.json")):
                if source:
                    write_text(self.output / "logs" / name, read_text(Path(source)))
            self.build()
            self.preflight()
            self.scan("quick")
            self.scan("standard")
            if self.args.sanitizer:
                self.sanitizer()
            self.state["status"] = "COMPLETED_UNQUALIFIED"
        except (StopCampaign, OSError, subprocess.SubprocessError, KeyboardInterrupt) as error:
            code = 2
            reason = str(error) if isinstance(error, StopCampaign) else type(error).__name__
            self.state["status"] = "STOPPED"
            self.state["pending"].append(reason)
            self.progress(self.state.get("running_step") or "campaign", "STOPPED", reason)
        finally:
            self.package()
        return code


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source")
    parser.add_argument("--output", required=True)
    parser.add_argument("--bundle")
    parser.add_argument("--cuda-root", default=os.environ.get("CUDA_ROOT", "/usr/local/cuda"))
    parser.add_argument("--device")
    parser.add_argument("--expected-sku", choices=("h100-pcie-80gb", "h100-sxm-80gb", "h100-nvl-94gb"))
    parser.add_argument("--sanitizer", action="store_true")
    parser.add_argument("--dcgm", action="store_true")
    parser.add_argument("--package-only", action="store_true")
    parser.add_argument("--failure-reason", default="")
    parser.add_argument("--setup-log")
    parser.add_argument("--setup-status")
    for name, default in (("total-seconds", 3600), ("build-seconds", 1800), ("quick-seconds", 120), ("standard-seconds", 300), ("sanitizer-seconds", 120), ("memory-mib", 1024), ("sanitizer-memory-mib", 256), ("max-temperature-c", 80)):
        aliases = ["--" + name]
        if name == "total-seconds":
            aliases.append("--total-budget-seconds")
        parser.add_argument(*aliases, type=int, default=default)
    args = parser.parse_args(argv)
    if not args.package_only and not (args.source or args.bundle):
        parser.error("--source or --bundle is required for execution")
    for name in ("total_seconds", "build_seconds", "quick_seconds", "standard_seconds", "sanitizer_seconds"):
        if not 10 <= getattr(args, name) <= (21600 if name == "total_seconds" else 3600 if name == "build_seconds" else 900 if name != "sanitizer_seconds" else 300):
            parser.error("invalid bounded time argument: " + name)
    if not 1 <= args.memory_mib <= 8192 or not 1 <= args.sanitizer_memory_mib <= 1024 or not 30 <= args.max_temperature_c <= 80:
        parser.error("memory/temperature limit outside supported bounded range")
    if len(args.failure_reason) > 160 or not re.fullmatch(r"[A-Za-z0-9_ .:/-]*", args.failure_reason):
        parser.error("invalid fixed failure reason")
    return args


def main(argv=None):
    os.umask(0o077)
    args = arguments(argv)
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt()
    for name in ("SIGINT", "SIGTERM", "SIGHUP"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), interrupted)
    try:
        return Campaign(args).execute()
    except (StopCampaign, OSError, ValueError) as error:
        print("Campaign could not create a safe evidence bundle: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
