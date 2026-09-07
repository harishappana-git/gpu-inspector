#!/usr/bin/env python3
"""Hermetic controller tests: local helper processes and mocked SSH only.

Run with: python scripts/test_h100_remote.py
No test connects to a server, downloads a toolchain, installs packages or runs a GPU.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock
import zipfile


SPEC = importlib.util.spec_from_file_location("h100_remote", Path(__file__).with_name("h100-remote.py"))
REMOTE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REMOTE)
JOB_ID = "gri-h100-" + "1234567890abcdef12345678"
GPU = "GPU-12345678-1234-1234-1234-1234567890ab"


class TemporaryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gri-controller-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        # An accidentally unmocked download must fail locally, before any request.
        self.network = mock.patch.object(REMOTE.urllib.request, "urlopen", side_effect=AssertionError("Network is forbidden in fixtures"))
        self.network.start()
        self.addCleanup(self.network.stop)

    def config(self, **updates):
        return REMOTE.config_validate({"host": "h100.example.invalid", "user": "ubuntu", "open_report": False, **updates})

    def file(self, relative, data="fixture\n"):
        path = self.directory / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data, encoding="utf-8")
        return path


class ConfigurationTests(TemporaryTest):
    def test_defaults_and_explicit_target(self):
        config = self.config(device=GPU, expected_sku="h100-sxm-80gb", port=2222)
        self.assertEqual(config["device"], GPU)
        self.assertEqual(config["setup_budget_seconds"], 1800)
        self.assertEqual(config["campaign_budget_seconds"], 3600)
        self.assertTrue(config["sanitizer"])
        self.assertTrue(config["dcgm"])

    def test_strict_types_names_and_bounds(self):
        invalid = [
            {"host": "host; touch secret"}, {"host": "-oProxyCommand=bad"},
            {"host": "host\nother"}, {"user": "root@another"},
            {"user": "-root"}, {"password": "never-send-this"},
            {"port": True}, {"port": 0}, {"port": 65536},
            {"setup_budget_seconds": 59}, {"setup_budget_seconds": 3601},
            {"campaign_budget_seconds": 119}, {"campaign_budget_seconds": 14401},
            {"campaign_budget_seconds": "300"}, {"dcgm": 1},
            {"install_system_deps": "true"}, {"open_report": None},
            {"device": "0"}, {"device": "GPU-1234"},
            {"device": "MIG-" + GPU[4:]}, {"expected_sku": "rtx-5080"},
            {"cuda_root": "relative/path"}, {"cuda_root": "/cuda\nexport EVIL=1"},
            {"host_key_sha256": "SHA256:too-short"},
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.config(**value)

    def test_local_key_paths_are_resolved_and_must_exist(self):
        identity = self.file("keys with spaces/client key", "key fixture only")
        known = self.file("keys with spaces/known hosts", "known fixture only")
        config = self.config(identity_file=str(identity), known_hosts_file=str(known))
        self.assertEqual(Path(config["identity_file"]), identity.resolve())
        self.assertEqual(Path(config["known_hosts_file"]), known.resolve())
        with self.assertRaises((ValueError, OSError)):
            self.config(identity_file=str(self.directory / "absent"))
        with self.assertRaises(ValueError):
            self.config(identity_file=str(self.directory))

    def test_json_duplicate_fields_and_size_rejected(self):
        for content in ('{"host":"one","host":"two"}', '{"nested":{"x":1,"x":2}}'):
            with self.subTest(content=content), self.assertRaises(ValueError):
                REMOTE.strict_json(self.file("bad.json", content))
        with self.assertRaises(ValueError):
            REMOTE.strict_json(self.file("huge.json", " " * 65537))
        bom = self.file("bom.json", '\ufeff{"host":"one"}')
        self.assertEqual(REMOTE.strict_json(bom), {"host": "one"})

    def test_private_output_is_new_and_cannot_follow_links(self):
        output = self.directory / "new private output"
        REMOTE.private_mkdir(output)
        self.assertTrue(output.is_dir())
        with self.assertRaises(FileExistsError):
            REMOTE.private_mkdir(output)
        link = self.directory / "linked"
        try:
            link.symlink_to(output, target_is_directory=True)
        except (OSError, NotImplementedError):
            return  # Windows may deny symlink creation without Developer Mode.
        with self.assertRaises(ValueError):
            REMOTE.private_mkdir(link / "child")


class SourceArchiveTests(TemporaryTest):
    def test_source_allowlist_excludes_local_configuration_and_secrets(self):
        wanted = ["go.mod", "go.sum", "README.md", ".gitattributes", "cmd/gri/main.go",
                  "internal/catalog/checks.json", "worker/CMakeLists.txt", "worker/main.cu",
                  "scripts/h100-remote.py", "scripts/h100-server.example.json", "docs/H100.md"]
        excluded = ["id_ed25519", ".env", "build/key.json", "scripts/.env",
                    "scripts/h100-server.json", "scripts/credentials.json", "docs/secrets.json",
                    "internal/token.json", "scripts/ssh-password.txt", "docs/token.txt",
                    "scripts/private.pem", "scripts/__pycache__/secret.py",
                    "worker/build/generated.cpp", "internal/.venv/secret.py"]
        for path in wanted + excluded:
            self.file(path)
        archive = self.directory / "source.zip"
        with mock.patch.object(REMOTE, "REPO", self.directory):
            checksum = REMOTE.source_zip(archive)
        with zipfile.ZipFile(archive) as source:
            names = set(source.namelist())
            self.assertEqual(names, set(wanted))
            self.assertTrue(all(not name.startswith("/") and ".." not in Path(name).parts for name in names))
        self.assertEqual(checksum, hashlib.sha256(archive.read_bytes()).hexdigest())
        self.assertFalse(archive.with_suffix(".zip.partial").exists())

    def test_oversized_source_does_not_publish_a_zip(self):
        oversized = self.file("internal/oversized.go")
        with oversized.open("wb") as stream:
            stream.truncate((8 << 20) + 1)
        archive = self.directory / "source.zip"
        with mock.patch.object(REMOTE, "REPO", self.directory), self.assertRaises(ValueError):
            REMOTE.source_zip(archive)
        self.assertFalse(archive.exists())

    def test_tool_archive_rejects_traversal_and_links(self):
        cases = [("go/../escape", b"bad", None), ("other/go", b"bad", None),
                 ("go/link", b"../outside", 0o120777)]
        for index, (name, data, mode) in enumerate(cases):
            with self.subTest(name=name):
                archive = self.directory / ("tool-%d.zip" % index)
                with zipfile.ZipFile(archive, "w") as out:
                    entry = zipfile.ZipInfo("placeholder")
                    entry.filename = name  # ZipInfo's constructor normalizes '\\' on Windows.
                    if mode:
                        entry.external_attr = mode << 16
                    out.writestr(entry, data)
                with self.assertRaises(ValueError):
                    REMOTE.safe_tool_extract(archive, self.directory / ("extract-%d" % index))
        self.assertFalse((self.directory / "escape").exists())
        # tarfile preserves backslashes on Windows; ZipInfo normalizes them when
        # reading, so a raw-backslash rejection fixture must use tar here.
        archive = self.directory / "backslash.tar.gz"
        with tarfile.open(archive, "w:gz") as out:
            entry = tarfile.TarInfo("go\\bin\\go")
            entry.size = 3
            out.addfile(entry, io.BytesIO(b"bad"))
        with self.assertRaises(ValueError):
            REMOTE.safe_tool_extract(archive, self.directory / "extract-backslash")


class CommandTests(TemporaryTest):
    def test_arguments_stay_literal_and_streams_are_separate(self):
        literal = "$(echo secret); & | `never-execute` \" spaced"
        code, out, err = REMOTE.command(
            [sys.executable, "-c", "import sys; print(sys.argv[1]); print('stderr fixture', file=sys.stderr)", literal], timeout=5)
        self.assertEqual(code, 0)
        self.assertEqual(out.decode().strip(), literal)
        self.assertEqual(err.decode().strip(), "stderr fixture")

    def test_timeout_and_output_bounds(self):
        start = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, "bound"):
            REMOTE.command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=.1)
        self.assertLess(time.monotonic() - start, 2)
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream), self.assertRaisesRegex(RuntimeError, "bound"):
                REMOTE.command([sys.executable, "-c", "import sys; sys.%s.write('x'*65536)" % stream], timeout=5, limit=1024)

    def test_deadline_includes_writing_input_to_a_slow_reader(self):
        # Finite delay keeps even a broken implementation from hanging this test.
        script = "import sys,time; time.sleep(1); sys.stdin.buffer.read()"
        start = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, "bound"):
            REMOTE.command([sys.executable, "-c", script], input_data=b"x" * (1 << 20), timeout=.1)
        self.assertLess(time.monotonic() - start, .8)

    def test_returning_parent_does_not_leave_its_pipe_holding_descendant(self):
        ready, late = self.directory / "descendant-ready", self.directory / "descendant-late"
        child = ("import pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text('ready'); "
                 "time.sleep(.7); pathlib.Path(sys.argv[2]).write_text('escaped')")
        parent = ("import pathlib,subprocess,sys,time; "
                  "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2],sys.argv[3]]); "
                  "deadline=time.monotonic()+2\n"
                  "while not pathlib.Path(sys.argv[2]).exists() and time.monotonic()<deadline: time.sleep(.01)\n"
                  "assert pathlib.Path(sys.argv[2]).exists(); print('parent finished')")
        start = time.monotonic()
        code, out, _ = REMOTE.command([sys.executable, "-c", parent, child, ready, late], timeout=3)
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), b"parent finished")
        self.assertTrue(ready.exists())
        self.assertLess(time.monotonic() - start, .6, "Descendant retained the parent's output pipe")
        time.sleep(.8)  # The finite helper exits independently even if cleanup regresses.
        self.assertFalse(late.exists(), "Descendant continued work after its owning command returned")


class HostPinTests(TemporaryTest):
    def test_mismatched_fingerprint_never_attempts_ssh_login(self):
        commands = []
        config = self.config(host_key_sha256="SHA256:" + "A" * 43)

        def fake_command(args, **kwargs):
            commands.append(args)
            if args[0] == "ssh-keyscan":
                return 0, b"h100.example.invalid ssh-ed25519 AAAAC3fixture\n", b""
            if args[0] == "ssh-keygen":
                return 0, ("256 SHA256:" + "B" * 43 + " h100 (ED25519)\n").encode(), b""
            self.fail("SSH login/transfer must not occur after a pin mismatch")

        with mock.patch.object(REMOTE.shutil, "which", side_effect=lambda name: name), mock.patch.object(REMOTE, "command", side_effect=fake_command):
            with self.assertRaisesRegex(RuntimeError, "fingerprint mismatch"):
                REMOTE.Remote(config, self.directory)
        self.assertEqual([args[0] for args in commands], ["ssh-keyscan", "ssh-keygen"])
        self.assertFalse((self.directory / "known-hosts.pinned").exists())

    def test_only_matching_scanned_key_is_pinned(self):
        wanted = "SHA256:" + "A" * 43
        config = self.config(host_key_sha256=wanted)

        def fake_command(args, **kwargs):
            if args[0] == "ssh-keyscan":
                return 0, b"# fixture\nh100.example.invalid ssh-rsa wrong\nh100.example.invalid ssh-ed25519 right\n", b""
            candidate = Path(args[2]).read_text(encoding="ascii")
            fingerprint = wanted if " right" in candidate else "SHA256:" + "B" * 43
            return 0, ("256 " + fingerprint + " fixture\n").encode(), b""

        with mock.patch.object(REMOTE.shutil, "which", side_effect=lambda name: name), mock.patch.object(REMOTE, "command", side_effect=fake_command):
            pinned = REMOTE.pinned_host_key(config, self.directory)
        self.assertEqual(Path(pinned).read_text(encoding="ascii"), "h100.example.invalid ssh-ed25519 right\n")
        options = REMOTE.ssh_options(config, pinned)
        self.assertIn("StrictHostKeyChecking=yes", options)
        self.assertIn("BatchMode=yes", options)
        self.assertIn("ForwardAgent=no", options)
        self.assertTrue(any(option.startswith("UserKnownHostsFile=") and "known-hosts.pinned" in option for option in options))
        self.assertTrue(any(option.startswith("GlobalKnownHostsFile=") and "known-hosts.pinned" in option for option in options))
        self.assertIn("KnownHostsCommand=none", options)
        self.assertIn("VerifyHostKeyDNS=no", options)
        self.assertIn("UpdateHostKeys=no", options)


class ArtifactFetchTests(TemporaryTest):
    def setUp(self):
        super().setUp()
        self.remote = REMOTE.Remote.__new__(REMOTE.Remote)
        self.remote.config = self.config()
        self.remote.ssh = "fixture-ssh-never-executed"
        self.remote.options = REMOTE.ssh_options(self.remote.config)
        self.remote.destination = "ubuntu@h100.example.invalid"
        self.remote_path = "/tmp/" + JOB_ID + "/campaign/campaign.zip"

    def fetch_helper(self, script, maximum, timeout=5):
        actual_popen = subprocess.Popen

        def local_only(args, **kwargs):
            self.assertEqual(args[0], "fixture-ssh-never-executed")
            self.assertIn("StrictHostKeyChecking=yes", args)
            self.assertIn(self.remote_path, args[-1])
            return actual_popen([sys.executable, "-c", script], **kwargs)

        with mock.patch.object(REMOTE.subprocess, "Popen", side_effect=local_only):
            self.remote.fetch(self.remote_path, self.directory / "download", maximum, timeout=timeout)

    def test_download_streams_only_the_allowed_artifact(self):
        self.fetch_helper("import sys; sys.stdout.buffer.write(b'fixture bytes')", maximum=64)
        self.assertEqual((self.directory / "download").read_bytes(), b"fixture bytes")

    def test_download_cannot_exceed_its_disk_or_time_bound(self):
        with self.assertRaisesRegex(RuntimeError, "download failed"):
            self.fetch_helper("import sys; sys.stdout.buffer.write(b'x'*131072)", maximum=1024)
        self.assertLessEqual((self.directory / "download").stat().st_size, 1024)
        start = time.monotonic()
        with self.assertRaises((RuntimeError, subprocess.TimeoutExpired)):
            self.fetch_helper("import time; time.sleep(5)", maximum=1024, timeout=.1)
        self.assertLess(time.monotonic() - start, 2)

    def test_unexpected_remote_paths_are_rejected_before_process_creation(self):
        invalid = ["/etc/shadow", self.remote_path + "; echo bad", self.remote_path.replace("/campaign/", "/../"),
                   self.remote_path.replace(JOB_ID, "another-job"), self.remote_path + ".private"]
        with mock.patch.object(REMOTE.subprocess, "Popen", side_effect=AssertionError("Must reject before connecting")) as popen:
            for path in invalid:
                with self.subTest(path=path), self.assertRaises(ValueError):
                    self.remote.fetch(path, self.directory / "download", 1024)
        popen.assert_not_called()


class ControllerWorkflowTests(TemporaryTest):
    def setUp(self):
        super().setUp()
        self.inspector = self.file("gri.exe" if os.name == "nt" else "gri", "local verifier fixture")
        self.source = self.file("source.zip", "prepared source fixture")
        self.state = {"schema_version": 1, "job_id": JOB_ID, "config": self.config(device=GPU),
                      "source_sha256": REMOTE.digest(self.source), "release_qualified": False}
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("campaign.json", '{"release_qualified":false}')
        self.payload = stream.getvalue()
        self.payload_hash = hashlib.sha256(self.payload).hexdigest()
        self.shells, self.copies, self.fetches = [], [], []
        self.server_launched = False
        self.launch_count = 0
        self.corrupt_download = False
        self.bad_import = None
        self.lose_launch_response = False
        self.remote = mock.Mock()
        self.remote.destination = "ubuntu@h100.example.invalid"
        self.remote.shell.side_effect = self.shell
        self.remote.copy.side_effect = lambda *args, **kwargs: self.copies.append((args, kwargs))
        self.remote.fetch.side_effect = self.fetch
        for patch in (mock.patch.object(REMOTE, "local_inspector", return_value=self.inspector),
                      mock.patch.object(REMOTE, "Remote", return_value=self.remote),
                      mock.patch.object(REMOTE, "command", side_effect=self.import_command),
                      mock.patch.object(REMOTE.webbrowser, "open", side_effect=AssertionError("Browser must not open")),
                      mock.patch.object(REMOTE.time, "sleep", side_effect=AssertionError("Fixtures finish immediately"))):
            patch.start()
            self.addCleanup(patch.stop)

    def shell(self, script, **kwargs):
        self.shells.append(script)
        if "job-finished.json" in script:
            self.assertTrue(self.server_launched)
            return 0, b'FINISHED\n{"release_qualified":false}\nPROGRESS\nfixture complete\n', b""
        if "nohup bash" in script:
            if not self.server_launched:
                self.launch_count += 1
                self.server_launched = True
            if self.lose_launch_response:
                self.lose_launch_response = False
                raise OSError("Fixture SSH acknowledgement lost")
            return 0, b"STARTED\n", b""
        if "ALREADY_STARTED" in script:
            return 0, b"ALREADY_STARTED\n" if self.server_launched else b"", b""
        self.fail("Unexpected remote command in fixture")

    def fetch(self, path, destination, maximum, **kwargs):
        self.fetches.append((path, destination, maximum))
        if path.endswith(".sha256"):
            Path(destination).write_text(self.payload_hash + "  campaign.zip\n", encoding="ascii")
        else:
            Path(destination).write_bytes(self.payload + (b"corrupt" if self.corrupt_download else b""))

    def import_command(self, args, **kwargs):
        self.assertEqual(args[:2], [self.inspector, "import"])
        self.assertEqual(kwargs["timeout"], 120)
        imported = Path(args[args.index("--output") + 1])
        imported.mkdir()
        index = imported / "index.html"
        index.write_text("Fixture report", encoding="utf-8")
        result = {"index_path": str(index), "archive_sha256": self.payload_hash, "release_qualified": False}
        if self.bad_import:
            result.update(self.bad_import)
        return 0, json.dumps(result).encode(), b""

    def execute(self, prepare_only=False):
        with contextlib.redirect_stdout(io.StringIO()):
            return REMOTE.execute(self.directory, self.state, prepare_only=prepare_only)

    def test_prepare_never_connects_and_node_config_excludes_ssh_details(self):
        self.assertEqual(self.execute(prepare_only=True), 0)
        REMOTE.Remote.assert_not_called()
        REMOTE.command.assert_not_called()
        node = json.loads((self.directory / "node-config.json").read_text(encoding="utf-8"))
        self.assertEqual(set(node), REMOTE.NODE_KEYS)
        self.assertEqual(node["device"], GPU)
        for key in ("host", "user", "identity_file", "host_key_sha256", "known_hosts_file"):
            self.assertNotIn(key, node)
        self.assertFalse(self.state.get("started", False))

    def test_changed_source_and_inspector_stop_before_connection(self):
        self.assertEqual(self.execute(prepare_only=True), 0)
        for path in (self.source, self.inspector):
            with self.subTest(path=path):
                original = path.read_bytes()
                path.write_bytes(original + b"modified")
                with self.assertRaisesRegex(ValueError, "changed"):
                    self.execute()
                path.write_bytes(original)
        REMOTE.Remote.assert_not_called()

    def test_resume_after_success_never_reuploads_or_relaunches(self):
        self.assertEqual(self.execute(), 0)
        self.assertEqual(self.launch_count, 1)
        self.assertEqual(len(self.copies), 2)
        self.assertTrue(self.state["retrieved"])
        first_shell_count = len(self.shells)
        self.assertEqual(self.execute(), 0)
        self.assertEqual(self.launch_count, 1)
        self.assertEqual(len(self.copies), 2)
        self.assertEqual(len(self.shells) - first_shell_count, 1)
        self.assertTrue(all("job-finished.json" in script for script in self.shells[first_shell_count:]))
        self.assertEqual(self.state["downloaded_sha256"], self.payload_hash)
        self.assertFalse(self.state["release_qualified"])
        self.assertEqual([item[2] for item in self.fetches], [256, 256 << 20] * 2)

    def test_lost_launch_acknowledgement_resumes_the_existing_job(self):
        self.lose_launch_response = True
        with self.assertRaisesRegex(OSError, "acknowledgement"):
            self.execute()
        persisted = json.loads((self.directory / "state.json").read_text(encoding="utf-8"))
        self.assertTrue(persisted["launch_attempted"])
        self.assertFalse(persisted.get("started", False))
        self.state = persisted
        self.assertEqual(self.execute(), 0)
        self.assertEqual(self.launch_count, 1)
        self.assertEqual(len(self.copies), 2)
        self.assertTrue(self.state["started"])

    def test_archive_checksum_mismatch_prevents_import(self):
        self.corrupt_download = True
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            self.execute()
        REMOTE.command.assert_not_called()
        self.assertFalse(self.state.get("retrieved", False))

    def test_importer_must_confirm_hash_qualification_and_contained_index(self):
        cases = [{"release_qualified": True}, {"archive_sha256": "0" * 64},
                 {"index_path": str(self.file("outside-index.html"))}]
        for change in cases:
            with self.subTest(change=change):
                self.bad_import = change
                with self.assertRaises(ValueError):
                    self.execute()
                self.assertFalse(self.state.get("retrieved", False))


if __name__ == "__main__":
    unittest.main(verbosity=2)
