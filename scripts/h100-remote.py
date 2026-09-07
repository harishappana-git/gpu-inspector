#!/usr/bin/env python3
"""One explicitly configured SSH server: prepare, run, recover and import data.

No provider discovery, password storage, remote-key execution or host-key bypass.
Only the generated remote job directory is written. Remote GPU work is delegated
to the bounded campaign; reconnecting never starts a second campaign.
"""
import argparse
import ctypes
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request
import webbrowser
import zipfile

REPO = Path(__file__).resolve().parent.parent
GO_VERSION = "go1.24.5"
CONFIG_KEYS = {"host", "user", "port", "identity_file", "known_hosts_file", "host_key_sha256",
               "device", "expected_sku", "install_system_deps", "sanitizer", "dcgm",
               "setup_budget_seconds", "campaign_budget_seconds", "cuda_root", "open_report"}
NODE_KEYS = CONFIG_KEYS - {"host", "user", "port", "identity_file", "known_hosts_file", "host_key_sha256", "open_report"}


def strict_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON field")
            result[key] = value
        return result
    if Path(path).stat().st_size > 65536:
        raise ValueError("Configuration/state file is too large")
    return json.loads(Path(path).read_text(encoding="utf-8-sig"), object_pairs_hook=unique)


def config_validate(value):
    if not isinstance(value, dict) or set(value) - CONFIG_KEYS:
        raise ValueError("Unknown server configuration fields")
    c = dict(value)
    if not isinstance(c.get("host"), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}", c["host"]):
        raise ValueError("host must be one DNS name, IPv4 address or configured SSH alias")
    if not isinstance(c.get("user"), str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", c["user"]):
        raise ValueError("user must be one SSH username")
    defaults = {"port": 22, "identity_file": "", "known_hosts_file": "", "host_key_sha256": "",
                "device": "", "expected_sku": "", "install_system_deps": True, "sanitizer": True,
                "dcgm": True, "setup_budget_seconds": 1800, "campaign_budget_seconds": 3600,
                "cuda_root": "", "open_report": True}
    for key, default in defaults.items():
        c.setdefault(key, default)
        if type(c[key]) is not type(default):
            raise ValueError("Invalid configuration type: " + key)
    if not 1 <= c["port"] <= 65535 or not 60 <= c["setup_budget_seconds"] <= 3600 or not 120 <= c["campaign_budget_seconds"] <= 14400:
        raise ValueError("Port or time budget is outside supported bounds")
    if c["device"] and not re.fullmatch(r"GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", c["device"]):
        raise ValueError("device must be an exact full GPU UUID; empty permits only unique-device selection")
    if c["expected_sku"] not in ("", "h100-pcie-80gb", "h100-sxm-80gb", "h100-nvl-94gb"):
        raise ValueError("Unsupported expected H100 variant")
    if c["host_key_sha256"] and not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", c["host_key_sha256"]):
        raise ValueError("host_key_sha256 must be an independently obtained SHA256 SSH fingerprint")
    for field in ("identity_file", "known_hosts_file"):
        if c[field]:
            if any(ord(x) < 32 or x == '"' for x in c[field]):
                raise ValueError(field + " contains unsupported characters")
            path = Path(c[field]).expanduser().resolve(strict=True)
            if not path.is_file():
                raise ValueError(field + " must be an existing local file")
            c[field] = str(path)
    if c["cuda_root"] and (not c["cuda_root"].startswith("/") or any(ord(x) < 32 for x in c["cuda_root"])):
        raise ValueError("cuda_root must be an absolute Linux path")
    return c


def check_ancestors(path):
    for item in (path, *path.parents):
        if item.exists() or item.is_symlink():
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("Symlink/reparse paths are not accepted for controller evidence")


def private_mkdir(path):
    path = Path(path).absolute()
    check_ancestors(path)
    if path.exists():
        raise FileExistsError("Output must be new: " + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        path.mkdir(mode=0o700)
        return
    # Windows DACL is installed atomically at CreateDirectory, before any data.
    from ctypes import wintypes as w
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = w.HANDLE
    adv.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
    adv.GetTokenInformation.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD)]
    adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(w.LPWSTR)]
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [w.LPCWSTR, w.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [w.HANDLE]
    class SA(ctypes.Structure):
        _fields_ = [("length", w.DWORD), ("descriptor", ctypes.c_void_p), ("inherit", w.BOOL)]
    kernel.CreateDirectoryW.argtypes = [w.LPCWSTR, ctypes.POINTER(SA)]
    token, size, sidtext, descriptor = w.HANDLE(), w.DWORD(), w.LPWSTR(), ctypes.c_void_p()
    try:
        if not adv.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        adv.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        data = ctypes.create_string_buffer(size.value)
        if not adv.GetTokenInformation(token, 1, data, size, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = ctypes.cast(data, ctypes.POINTER(ctypes.c_void_p))[0]
        if not adv.ConvertSidToStringSidW(sid, ctypes.byref(sidtext)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;OICI;FA;;;" + sidtext.value + ")", 1, ctypes.byref(descriptor), None):
            raise ctypes.WinError(ctypes.get_last_error())
        attributes = SA(ctypes.sizeof(SA), descriptor, False)
        if not kernel.CreateDirectoryW(str(path), ctypes.byref(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        if descriptor:
            kernel.LocalFree(descriptor)
        if sidtext:
            kernel.LocalFree(ctypes.cast(sidtext, ctypes.c_void_p))
        if token:
            kernel.CloseHandle(token)


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


class LocalProcessTree:
    """Own local subprocess descendants; the detached SSH server job is separate."""
    def __init__(self, process):
        self.process, self.job = process, None
        self.closed = False
        if os.name != "nt":
            return
        from ctypes import wintypes as w
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, w.LPCWSTR]
        kernel.CreateJobObjectW.restype = w.HANDLE
        kernel.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
        kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        kernel.CloseHandle.argtypes = [w.HANDLE]
        class Basic(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong), ("flags", w.DWORD),
                        ("min_ws", ctypes.c_size_t), ("max_ws", ctypes.c_size_t), ("active", w.DWORD),
                        ("affinity", ctypes.c_size_t), ("priority", w.DWORD), ("scheduling", w.DWORD)]
        class Extended(ctypes.Structure):
            _fields_ = [("basic", Basic), ("io", ctypes.c_ulonglong * 6), ("process_memory", ctypes.c_size_t),
                        ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]
        handle = kernel.CreateJobObjectW(None, None)
        info = Extended()
        info.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not handle or not kernel.SetInformationJobObject(handle, 9, ctypes.byref(info), ctypes.sizeof(info)) or not kernel.AssignProcessToJobObject(handle, w.HANDLE(int(process._handle))):
            failure = ctypes.get_last_error()
            if handle:
                kernel.CloseHandle(handle)
            process.kill()
            process.wait()
            raise ctypes.WinError(failure)
        self.job, self.kernel = handle, kernel

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.job:
            self.kernel.CloseHandle(self.job)
            self.job = None
        elif os.name == "posix":
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def command(args, *, cwd=None, input_data=b"", timeout=60, limit=4 << 20, log=None):
    """Shell-free local process with bounded stdout/stderr and deadline."""
    p = subprocess.Popen([str(x) for x in args], cwd=cwd, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         start_new_session=os.name == "posix",
                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    tree = LocalProcessTree(p)
    chunks, overflow = [bytearray(), bytearray()], threading.Event()
    def drain(stream, index):
        while True:
            data = stream.read(8192)
            if not data:
                return
            remaining = limit - len(chunks[index])
            chunks[index].extend(data[:max(0, remaining)])
            if len(data) > remaining:
                overflow.set()
                try:
                    p.kill()
                except OSError:
                    pass
    threads = [threading.Thread(target=drain, args=(p.stdout, 0), daemon=True),
               threading.Thread(target=drain, args=(p.stderr, 1), daemon=True)]
    def feed():
        try:
            p.stdin.write(input_data)
            p.stdin.close()
        except (BrokenPipeError, OSError):
            pass
    threads.append(threading.Thread(target=feed, daemon=True))
    for thread in threads:
        thread.start()
    expired = False
    interrupted = None
    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        expired = True
        tree.close()
        p.kill()
        p.wait()
    except BaseException as error:
        tree.close()
        p.kill()
        p.wait()
        interrupted = error
    finally:
        tree.close()
    for thread in threads:
        thread.join(timeout=5)
    out, err = bytes(chunks[0]), bytes(chunks[1])
    if not any(thread.is_alive() for thread in threads):
        for pipe in (p.stdin, p.stdout, p.stderr):
            try:
                pipe.close()
            except BrokenPipeError:
                pass
    if log:
        with Path(log).open("ab") as stream:
            stream.write(out + err)
    if interrupted is not None:
        raise interrupted
    if expired or overflow.is_set() or any(thread.is_alive() for thread in threads):
        raise RuntimeError("Owned local command exceeded its time/output bound")
    return p.returncode, out, err


def download(url, destination, sha256=None, maximum=200 << 20):
    if not url.startswith("https://"):
        raise ValueError("Downloads require HTTPS")
    started, count = time.monotonic(), 0
    with urllib.request.urlopen(url, timeout=30) as source, Path(destination).open("xb") as output:
        if not source.geturl().startswith("https://"):
            raise ValueError("Download was redirected away from HTTPS")
        while True:
            block = source.read(1 << 20)
            if not block:
                break
            count += len(block)
            if count > maximum or time.monotonic() - started > 600:
                raise ValueError("Download exceeded bounds")
            output.write(block)
    if sha256 and digest(destination) != sha256:
        raise ValueError("Download SHA256 mismatch; artifact was not executed")


def safe_tool_extract(archive, destination, prefix="go/"):
    total = 0
    def allowed(name, size):
        nonlocal total
        if not name.startswith(prefix) or "\\" in name or any(part in ("", ".", "..") for part in name.rstrip("/").split("/")):
            raise ValueError("Tool archive path rejected")
        total += size
        if size > 256 << 20 or total > 1 << 30:
            raise ValueError("Tool archive exceeded size limits")
        return Path(destination).joinpath(*PurePosixPath(name).parts)
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as z:
            for entry in z.infolist():
                target = allowed(entry.filename, entry.file_size)
                if stat.S_ISLNK(entry.external_attr >> 16):
                    raise ValueError("Tool archive link rejected")
                if entry.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(entry) as source, target.open("xb") as output:
                        shutil.copyfileobj(source, output)
    else:
        with tarfile.open(archive, "r:gz") as tar:
            for entry in tar:
                target = allowed(entry.name, entry.size)
                if entry.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif entry.isfile():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(entry) as source, target.open("xb") as output:
                        shutil.copyfileobj(source, output)
                    os.chmod(target, entry.mode & 0o700)
                else:
                    raise ValueError("Tool archive special file rejected")


def local_inspector(local_dir):
    executable = local_dir / ("gri.exe" if os.name == "nt" else "gri")
    if executable.exists():
        return executable
    go = shutil.which("go")
    existing = REPO / "build/.toolchains/go/bin" / ("go.exe" if os.name == "nt" else "go")
    if not go and existing.is_file():
        go = str(existing)
    if go:
        code, version, _ = command([go, "version"], timeout=15, limit=4096)
        found = re.search(rb"\bgo(\d+)\.(\d+)", version)
        if code or not found or tuple(map(int, found.groups())) < (1, 24):
            go = None
    if not go:
        platform = "windows" if os.name == "nt" else "darwin" if sys.platform == "darwin" else "linux"
        import platform as host_platform
        arch = "arm64" if host_platform.machine().lower() in ("arm64", "aarch64") else "amd64"
        metadata = local_dir / "go-downloads.json"
        download("https://go.dev/dl/?mode=json&include=all", metadata, maximum=8 << 20)
        versions = json.loads(metadata.read_text(encoding="utf-8"))
        matches = [f for v in versions if v["version"] == GO_VERSION for f in v["files"]
                   if f["os"] == platform and f["arch"] == arch and f["kind"] == "archive"]
        if len(matches) != 1 or not re.fullmatch(r"[0-9a-f]{64}", matches[0]["sha256"]):
            raise ValueError("Pinned Go download metadata unavailable")
        item = matches[0]
        if not re.fullmatch(r"go1\.24\.5\.[a-z0-9-]+\.(?:zip|tar\.gz)", item["filename"]):
            raise ValueError("Go download filename rejected")
        archive = local_dir / item["filename"]
        print("Downloading pinned local Go toolchain", flush=True)
        download("https://go.dev/dl/" + item["filename"], archive, item["sha256"])
        safe_tool_extract(archive, local_dir)
        go = str(local_dir / "go/bin" / ("go.exe" if os.name == "nt" else "go"))
    print("Building the local report verifier", flush=True)
    code, _, _ = command([go, "build", "-trimpath", "-o", executable, "./cmd/gri"], cwd=REPO,
                         timeout=600, log=local_dir / "local-build.log")
    if code:
        raise RuntimeError("Local verifier build failed; see local-build.log")
    return executable


def source_zip(destination):
    roots = ["cmd", "internal", "worker", "scripts", "docs"]
    fixed = ["go.mod", "go.sum", "Makefile", "README.md", "GPU_Rental_Inspector_Design_v2_0.md", ".gitattributes"]
    suffixes = {".go", ".cu", ".cuh", ".hpp", ".h", ".cpp", ".json", ".md", ".sh", ".py", ".ps1", ".cmd", ".txt"}
    files = [REPO / name for name in fixed if (REPO / name).is_file()]
    for root in roots:
        for directory, dirs, names in os.walk(REPO / root, followlinks=False):
            dirs[:] = [name for name in dirs if name not in ("build", "__pycache__", ".git", ".venv")]
            for name in names:
                path = Path(directory) / name
                relative = path.relative_to(REPO).as_posix()
                allowed_json = relative == "internal/catalog/checks.json" or name.endswith(".example.json")
                allowed_text = relative == "worker/CMakeLists.txt"
                if path.suffix in suffixes and not name.startswith(".") and (path.suffix != ".json" or allowed_json) and (path.suffix != ".txt" or allowed_text):
                    files.append(path)
    total = 0
    temporary = Path(destination).with_suffix(".zip.partial")
    if temporary.exists():
        temporary.unlink()
    with zipfile.ZipFile(temporary, "x", compression=zipfile.ZIP_DEFLATED) as z:
        for path in sorted(files):
            check_ancestors(path)
            if not path.is_file() or path.stat().st_size > 8 << 20 or path.name.lower() in ("private.pem", "credentials.json", "secrets.json"):
                raise ValueError("Unexpected source file")
            total += path.stat().st_size
            if total > 64 << 20 or len(files) > 4096:
                raise ValueError("Source package exceeds bounds")
            z.write(path, path.relative_to(REPO).as_posix())
    temporary.replace(destination)
    return digest(destination)


def ssh_options(config, known_hosts=""):
    options = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15",
               "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3", "-o", "ForwardAgent=no",
               "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no"]
    if config["identity_file"]:
        options += ["-i", config["identity_file"], "-o", "IdentitiesOnly=yes"]
    if known_hosts or config["known_hosts_file"]:
        host_file = str(known_hosts or config["known_hosts_file"]).replace("\\", "/")
        if '"' in host_file or any(ord(x) < 32 for x in host_file):
            raise ValueError("Unsupported known-hosts path")
        options += ["-o", 'UserKnownHostsFile="' + host_file + '"']
    if known_hosts:
        options += ["-o", 'GlobalKnownHostsFile="' + host_file + '"', "-o", "KnownHostsCommand=none",
                    "-o", "VerifyHostKeyDNS=no", "-o", "UpdateHostKeys=no"]
    return options


def pinned_host_key(config, local_dir):
    if not config["host_key_sha256"]:
        return ""
    keyscan, keygen = shutil.which("ssh-keyscan"), shutil.which("ssh-keygen")
    if not keyscan or not keygen:
        raise RuntimeError("OpenSSH ssh-keyscan and ssh-keygen are required for fingerprint pinning")
    code, out, _ = command([keyscan, "-T", "10", "-p", config["port"], config["host"]], timeout=15, limit=65536)
    if code:
        raise RuntimeError("Could not read server public host keys")
    accepted = []
    for line in out.decode("utf-8", "strict").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        if len(line.split()) != 3:
            raise ValueError("Unexpected SSH host-key record")
        candidate = local_dir / "host-key-candidate"
        candidate.write_text(line + "\n", encoding="ascii")
        result, fingerprint, _ = command([keygen, "-lf", candidate, "-E", "sha256"], timeout=10, limit=65536)
        parts = fingerprint.decode("utf-8", "strict").split()
        if result == 0 and len(parts) >= 2 and parts[1] == config["host_key_sha256"]:
            accepted.append(line)
    if not accepted:
        raise RuntimeError("Server host-key fingerprint mismatch; SSH login was not attempted")
    path = local_dir / "known-hosts.pinned"
    path.write_text("\n".join(accepted) + "\n", encoding="ascii")
    return str(path)


class Remote:
    def __init__(self, config, local_dir):
        self.config, self.local_dir = config, local_dir
        self.ssh, self.scp = shutil.which("ssh"), shutil.which("scp")
        if not self.ssh or not self.scp:
            raise RuntimeError("Install/enable the local OpenSSH client before connecting")
        self.options = ssh_options(config, pinned_host_key(config, local_dir))
        self.destination = config["user"] + "@" + config["host"]

    def shell(self, script, timeout=60):
        return command([self.ssh, *self.options, "-p", self.config["port"], "-T", self.destination, "bash -s"],
                       input_data=script.encode("utf-8"), timeout=timeout, limit=65536)

    def copy(self, source, target, timeout=300):
        code, _, _ = command([self.scp, "-B", "-q", *self.options, "-P", self.config["port"], source, target],
                              cwd=self.local_dir, timeout=timeout, log=self.local_dir / "transfer.log")
        if code:
            raise RuntimeError("SSH file transfer failed; see transfer.log")

    def fetch(self, remote_path, target, maximum, timeout=300):
        """Stream a fixed artifact over authenticated SSH; stop before disk overflow."""
        if not re.fullmatch(r"/tmp/gri-h100-[0-9a-f]{24}/campaign/campaign\.zip(?:\.sha256)?", remote_path):
            raise ValueError("Unexpected remote artifact path")
        args = [self.ssh, *self.options, "-p", str(self.config["port"]), "-T", self.destination,
                "test -f '" + remote_path + "' && test ! -L '" + remote_path + "' && cat -- '" + remote_path + "'"]
        proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=os.name == "posix",
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        tree = LocalProcessTree(proc)
        errors, problem = bytearray(), []
        def receive():
            try:
                with Path(target).open("wb") as output:
                    count = 0
                    while True:
                        block = proc.stdout.read(65536)
                        if not block:
                            break
                        count += len(block)
                        if count > maximum:
                            raise ValueError("Remote artifact exceeded download size limit")
                        output.write(block)
            except Exception as error:
                problem.append(error)
                proc.kill()
        def stderr_drain():
            while True:
                block = proc.stderr.read(4096)
                if not block:
                    break
                errors.extend(block[:max(0, 65536 - len(errors))])
                if len(errors) >= 65536:
                    problem.append(ValueError("Remote transfer error output exceeded limit"))
                    proc.kill()
                    break
        threads = [threading.Thread(target=receive, daemon=True), threading.Thread(target=stderr_drain, daemon=True)]
        for thread in threads:
            thread.start()
        try:
            proc.wait(timeout=timeout)
        except BaseException:
            tree.close()
            proc.kill()
            proc.wait()
            raise
        finally:
            tree.close()
            for thread in threads:
                thread.join(timeout=5)
            if not any(thread.is_alive() for thread in threads):
                proc.stdout.close()
                proc.stderr.close()
        if problem or proc.returncode or any(thread.is_alive() for thread in threads):
            raise RuntimeError("Bounded artifact download failed" + (": " + str(problem[0]) if problem else ""))


def progress_safe(data):
    return "".join(ch for ch in data.decode("utf-8", "replace") if ch in "\n\t" or 32 <= ord(ch) < 127 or ord(ch) >= 160)


def resume_hint(local_dir):
    if os.name == "nt":
        return '& "' + str(REPO / "scripts/test-h100-server.cmd") + '" -Resume "' + str(local_dir) + '"'
    import shlex
    return shlex.join([sys.executable, str(REPO / "scripts/h100-remote.py"), "--resume", str(local_dir)])


def execute(local_dir, state, prepare_only=False):
    config = config_validate(state["config"])
    job_id = state["job_id"]
    if not re.fullmatch(r"gri-h100-[0-9a-f]{24}", job_id):
        raise ValueError("Invalid saved job identifier")
    root = "/tmp/" + job_id
    inspector = local_inspector(local_dir)
    inspector_hash = digest(inspector)
    if state.get("inspector_sha256", inspector_hash) != inspector_hash:
        raise ValueError("Local verifier changed since preparation")
    state["inspector_sha256"] = inspector_hash
    archive = local_dir / "source.zip"
    if not archive.exists():
        state["source_sha256"] = source_zip(archive)
    if "source_sha256" not in state:
        raise ValueError("Source package lacks saved provenance; create a new preparation directory")
    if digest(archive) != state["source_sha256"]:
        raise ValueError("Local source archive changed since preparation")
    atomic_json(local_dir / "node-config.json", {key: config[key] for key in sorted(NODE_KEYS)})
    atomic_json(local_dir / "state.json", state)
    if prepare_only:
        print("Prepared source, local verifier and node configuration. No server connection or GPU work occurred.")
        print("Continue: " + resume_hint(local_dir))
        return 0
    remote = Remote(config, local_dir)
    if not state.get("started"):
        initialize = """set -eu
umask 077
test "$(uname -s)" = Linux
test "$(uname -m)" = x86_64
test -f /etc/os-release
. /etc/os-release
test "$ID" = ubuntu
case "$VERSION_ID" in 22.04|24.04) ;; *) exit 42;; esac
root='/tmp/JOBID'
if [ -e "$root" ]; then
  test ! -L "$root" && test -O "$root" && test "$(cat "$root/owner-marker")" = JOBID
else
  mkdir -m 700 -- "$root"
  printf '%s\\n' JOBID > "$root/owner-marker"
fi
if [ -d "$root/launched" ]; then printf 'ALREADY_STARTED\\n'; exit 0; fi
command -v python3 >/dev/null || exit 41
""".replace("JOBID", job_id)
        code, initialized, err = remote.shell(initialize)
        if code == 0 and initialized.startswith(b"ALREADY_STARTED\n"):
            state["started"] = True
            atomic_json(local_dir / "state.json", state)
        if code == 41 and config["install_system_deps"]:
            code, _, err = remote.shell("""set -eu
if [ "$(id -u)" = 0 ]; then elevate=''; else sudo -n true; elevate='sudo -n'; fi
$elevate env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l timeout --kill-after=5 120 apt-get -o DPkg::Lock::Timeout=15 update >/dev/null 2>&1
$elevate env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l timeout --kill-after=5 120 apt-get -o DPkg::Lock::Timeout=15 -o Dpkg::Options::=--force-confold install -y --no-install-recommends python3 >/dev/null 2>&1
""", timeout=260)
        if code:
            raise RuntimeError("Remote initialization failed (Linux x86-64, Python3 and noninteractive permissions are required): " + progress_safe(err)[:1000])
        if not state.get("started"):
            remote.copy("source.zip", remote.destination + ":" + root + "/source.zip")
            remote.copy("node-config.json", remote.destination + ":" + root + "/node-config.json")
        launch = """set -eu
umask 077
root='/tmp/JOBID'
test ! -L "$root" && test -O "$root" && test "$(cat "$root/owner-marker")" = JOBID
cd -- "$root"
printf '%s  source.zip\\n' SOURCEHASH | sha256sum --check --status
if [ ! -d launched ]; then
python3 - <<'PY'
import os, pathlib, stat, zipfile
root=pathlib.Path('source'); root.mkdir(mode=0o700, exist_ok=True)
with zipfile.ZipFile('source.zip') as z:
 total=0; seen=set()
 for entry in z.infolist():
  p=pathlib.PurePosixPath(entry.filename); total+=entry.file_size
  if p.is_absolute() or '..' in p.parts or '\\\\' in entry.filename or entry.filename in seen or stat.S_ISLNK(entry.external_attr>>16) or entry.file_size>8<<20 or total>64<<20 or len(seen)>4096: raise ValueError('source archive rejected')
  seen.add(entry.filename); dest=root.joinpath(*p.parts)
  if entry.is_dir(): dest.mkdir(parents=True,exist_ok=True)
  else:
   dest.parent.mkdir(parents=True,exist_ok=True)
   with z.open(entry) as src, open(dest,'wb') as out: out.write(src.read())
   os.chmod(dest,0o600)
PY
  mkdir -m 700 launched
  nohup bash "$root/source/scripts/remote-h100-job.sh" "$root" </dev/null >"$root/progress.log" 2>&1 &
  printf '%s\\n' "$!" > "$root/launcher.pid"
fi
printf 'STARTED\\n'
""".replace("JOBID", job_id).replace("SOURCEHASH", state["source_sha256"])
        state["launch_attempted"] = True
        atomic_json(local_dir / "state.json", state)
        code, _, err = (0, b"", b"") if state.get("started") else remote.shell(launch)
        if code:
            raise RuntimeError("Source verification or job launch failed: " + progress_safe(err)[:1000])
        state["started"] = True
        atomic_json(local_dir / "state.json", state)
    print("Remote job: " + root, flush=True)
    print("Setup and campaign continue within their budgets if SSH disconnects. Resume retrieves this same job.", flush=True)
    last, failures = "", 0
    deadline = time.monotonic() + config["setup_budget_seconds"] + config["campaign_budget_seconds"] + 600
    while True:
        code, out, err = remote.shell("""root='/tmp/JOBID'
if [ -f "$root/job-finished.json" ]; then printf 'FINISHED\\n'; head -c 4096 "$root/job-finished.json"; else printf 'RUNNING\\n'; fi
printf '\\nPROGRESS\\n'
tail -c 8192 "$root/progress.log" 2>/dev/null || true
""".replace("JOBID", job_id), timeout=30)
        if code:
            failures += 1
            if failures >= 3:
                raise RuntimeError("SSH connection interrupted. Resume this directory to retrieve the same bounded job; do not start another test.")
        else:
            failures = 0
            text = progress_safe(out)
            if text != last:
                print(text, flush=True)
                last = text
                (local_dir / "last-progress.txt").write_text(text, encoding="utf-8")
            if out.startswith(b"FINISHED\n"):
                break
        if time.monotonic() >= deadline:
            raise RuntimeError("Controller wait bound reached. Server budgets remain active; resume retrieval after inspecting saved progress.")
        time.sleep(5)
    for filename, maximum in (("campaign.zip.sha256", 256), ("campaign.zip", 256 << 20)):
        remote.fetch(root + "/campaign/" + filename, local_dir / (filename + ".download"), maximum)
    hash_text = (local_dir / "campaign.zip.sha256.download").read_text(encoding="ascii").strip().split()
    if len(hash_text) != 2 or not re.fullmatch(r"[0-9a-fA-F]{64}", hash_text[0]) or hash_text[1].lstrip("*") != "campaign.zip":
        raise ValueError("Unexpected server archive checksum record")
    if digest(local_dir / "campaign.zip.download") != hash_text[0].lower():
        raise ValueError("Downloaded archive checksum mismatch")
    imported = local_dir / ("imported-" + secrets.token_hex(4))
    code, out, err = command([inspector, "import", "--archive", local_dir / "campaign.zip.download", "--output", imported, "--json"], timeout=120)
    if code:
        raise RuntimeError("Local artifact validation/import failed: " + progress_safe(err)[:2000])
    result = json.loads(out)
    if result.get("archive_sha256") != hash_text[0].lower() or result.get("release_qualified") is not False:
        raise ValueError("Local importer did not confirm this archive and qualification state")
    index = Path(result["index_path"]).resolve(strict=True)
    if index.parent != imported.resolve() or index.name != "index.html":
        raise ValueError("Local importer returned an unexpected report index path")
    state["import"] = result
    state["downloaded_sha256"] = hash_text[0].lower()
    state["retrieved"] = True
    atomic_json(local_dir / "state.json", state)
    print("Verified local report index: " + result["index_path"], flush=True)
    print("The server workspace is retained for investigation; rental termination is controlled by the provider account.")
    if config["open_report"]:
        webbrowser.open(Path(result["index_path"]).resolve().as_uri())
    return 0


def run_main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--config", type=Path)
    group.add_argument("--resume", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--prepare-only", action="store_true", help="Build/package locally without connecting or running a GPU")
    args = parser.parse_args()
    if args.resume and args.output:
        raise ValueError("--output cannot be combined with --resume")
    if args.resume:
        local_dir = args.resume.absolute()
        check_ancestors(local_dir)
        state = strict_json(local_dir / "state.json")
        if not isinstance(state, dict) or state.get("schema_version") != 1:
            raise ValueError("Unsupported recovery-state format")
    else:
        config = config_validate(strict_json(args.config))
        local_dir = (args.output or REPO / "build" / ("h100-remote-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4))).absolute()
        private_mkdir(local_dir)
        state = {"schema_version": 1, "job_id": "gri-h100-" + secrets.token_hex(12), "config": config, "release_qualified": False}
        atomic_json(local_dir / "state.json", state)
    print("Local recovery directory: " + str(local_dir), flush=True)
    try:
        return execute(local_dir, state, args.prepare_only)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        message = str(error) or "Controller interrupted; the bounded remote job may continue"
        atomic_json(local_dir / "controller-error.json", {"error": message, "remote_job_may_continue": state.get("started", False) or state.get("launch_attempted", False), "release_qualified": False})
        print("H100 controller: " + message, file=sys.stderr)
        print("Recovery: " + resume_hint(local_dir), file=sys.stderr)
        return 1


def main():
    try:
        return run_main()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("H100 controller configuration: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
