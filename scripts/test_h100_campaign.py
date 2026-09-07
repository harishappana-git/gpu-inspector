"""Hermetic campaign tests. GPU and Linux acceptance are never simulated as real."""
import contextlib
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest import mock
import zipfile

SOURCE = Path(__file__).with_name("h100-campaign.py")
SPEC = importlib.util.spec_from_file_location("h100_campaign", SOURCE)
campaign = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(campaign)
GPU = "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OTHER = "GPU-11111111-2222-3333-4444-555555555555"


def device(identity=GPU):
    return {"uuid": identity, "name": "NVIDIA H100 PCIe", "pci_address": "00000000:01:00.0", "memory_bytes": 80 << 30,
            "mig_mode": "0", "virtualization_mode": "0", "driver_version": "fixture-only"}


def snapshot():
    values = {"uuid": GPU, "name": "NVIDIA H100 PCIe", "pci_address": "00000000:01:00.0", "compute_capability": "9.0",
              "driver_version": "fixture-only", "memory_total_bytes": 80 << 30, "memory_free_bytes": 79 << 30,
              "mig_current": 0, "mig_pending": 0, "virtualization_mode": 0, "temperature_gpu_c": 40,
              "compute_process_count": 0, "utilization_gpu_percent": 0, "ecc_uncorrected_volatile": 0,
              "ecc_corrected_volatile": 0, "row_remap_pending": False, "row_remap_failure": False}
    return {"status": "PASS", "fields": {key: {"status": "PASS", "value": value} for key, value in values.items()}}


def worker_ok():
    return {"status": "ok", "correctness": {"checked": True, "checked_values": 128, "mismatch_count": 0, "synthetic": False}}


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gri-campaign-fixture-")
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def instance(self, *extra):
        args = campaign.arguments(["--output", str(self.root / "campaign"), "--bundle", str(self.root / "bundle")] + list(extra))
        return campaign.Campaign(args)

    def test_selection_requires_exactly_one_permitted_full_h100(self):
        value = {"status": "PASS", "cuda_status": "PASS", "cuda_uuids": [GPU], "devices": [device()]}
        self.assertEqual(campaign.select_h100(value)["uuid"], GPU)
        value["cuda_uuids"].append(OTHER)
        value["devices"].append(device(OTHER))
        with self.assertRaises(campaign.StopCampaign):
            campaign.select_h100(value)
        self.assertEqual(campaign.select_h100(value, GPU)["uuid"], GPU)
        self.assertEqual(campaign.select_h100(value, nvidia_visibility=GPU)["uuid"], GPU)
        value["devices"][1]["name"] = "NVIDIA RTX 5080"
        with self.assertRaises(campaign.StopCampaign):
            campaign.select_h100(value)
        self.assertEqual(campaign.select_h100(value, GPU)["uuid"], GPU)
        for visibility in ("none", "", "0", "MIG-" + GPU):
            with self.subTest(visibility=visibility), self.assertRaises(campaign.StopCampaign):
                campaign.select_h100(value, GPU, visibility)

    def test_selection_does_not_broaden_visibility_or_allow_mig(self):
        value = {"status": "PASS", "cuda_status": "PASS", "cuda_uuids": [OTHER], "devices": [device()]}
        with self.assertRaises(campaign.StopCampaign):
            campaign.select_h100(value, GPU)
        value["cuda_uuids"] = [GPU]
        for field, changed in (("mig_mode", "1"), ("virtualization_mode", "2"), ("name", "NVIDIA H200"), ("pci_address", "../device")):
            altered = copy.deepcopy(value)
            altered["devices"][0][field] = changed
            with self.subTest(field=field), self.assertRaises(campaign.StopCampaign):
                campaign.select_h100(altered)

    def test_guard_rejects_unknown_busy_identity_temperature_and_health(self):
        campaign.guard(snapshot(), device(), 1024, 80)
        for name, value in (("uuid", OTHER), ("pci_address", "00000000:02:00.0"), ("compute_capability", "12.0"),
                            ("mig_pending", 1), ("virtualization_mode", 2), ("temperature_gpu_c", 80),
                            ("memory_free_bytes", 1), ("compute_process_count", 1), ("utilization_gpu_percent", 6),
                            ("ecc_uncorrected_volatile", 1), ("row_remap_failure", True), ("row_remap_pending", True)):
            changed = snapshot()
            changed["fields"][name]["value"] = value
            with self.subTest(name=name), self.assertRaises(campaign.StopCampaign):
                campaign.guard(changed, device(), 1024, 80)
        unknown = snapshot()
        unknown["fields"]["compute_process_count"] = {"status": "UNSUPPORTED"}
        with self.assertRaises(campaign.StopCampaign):
            campaign.guard(unknown, device(), 1024, 80)

    def test_active_guard_allows_only_one_process_and_stops_counter_change(self):
        active = snapshot()
        active["fields"]["compute_process_count"]["value"] = 1
        active["fields"]["utilization_gpu_percent"]["value"] = 100
        campaign.guard(active, device(), 256, 80, active=True, baseline=snapshot())
        active["fields"]["compute_process_count"]["value"] = 2
        with self.assertRaises(campaign.StopCampaign):
            campaign.guard(active, device(), 256, 80, active=True)
        active["fields"]["compute_process_count"]["value"] = 1
        active["fields"]["ecc_corrected_volatile"]["value"] = 1
        with self.assertRaises(campaign.StopCampaign):
            campaign.guard(active, device(), 256, 80, active=True, baseline=snapshot())

    def test_exit_zero_alone_never_proves_instrumentation(self):
        clean = "========= COMPUTE-SANITIZER\n========= ERROR SUMMARY: 0 errors\n"
        self.assertEqual(campaign.sanitizer_outcome("memcheck", clean, worker_ok(), 0, True)[0], "PASS")
        for log, code, validated in (("", 0, True), (clean, 99, True), (clean, 0, False),
                                      (clean + "Unable to instrument this device", 0, True),
                                      (clean + "ERROR SUMMARY: 1 error", 0, True)):
            with self.subTest(log=log, code=code):
                self.assertEqual(campaign.sanitizer_outcome("memcheck", log, worker_ok(), code, validated)[0], "STOP")
        race = "========= COMPUTE-SANITIZER\n========= RACECHECK SUMMARY: 0 hazards displayed (0 errors, 0 warnings)\n"
        self.assertEqual(campaign.sanitizer_outcome("racecheck", race, worker_ok(), 0, True)[0], "PASS")
        self.assertEqual(campaign.sanitizer_outcome("racecheck", clean, worker_ok(), 0, True)[0], "STOP")

    def test_unavailable_path_is_pending_but_instrumentation_failure_stops(self):
        unsupported = {"status": "unsupported", "correctness": {"checked": False, "checked_values": 0}}
        self.assertEqual(campaign.sanitizer_outcome("memcheck", "", unsupported, 2, True)[0], "PENDING")
        self.assertEqual(campaign.sanitizer_outcome("memcheck", "Unable to instrument", unsupported, 2, True)[0], "STOP")
        self.assertEqual(campaign.sanitizer_outcome("memcheck", "ERROR SUMMARY: 1 error", unsupported, 2, True)[0], "STOP")
        failed = worker_ok()
        failed["correctness"]["mismatch_count"] = 1
        self.assertEqual(campaign.sanitizer_outcome("memcheck", "", failed, 0, True)[0], "STOP")

    def test_duplicate_keys_and_nonfinite_json_are_rejected(self):
        for raw in ('{"status":"ok","status":"unsupported"}', '{"x":NaN}', '{"x":Infinity}'):
            with self.assertRaises(campaign.StopCampaign):
                campaign.checked_json(raw)

    def test_package_only_exports_allowlist_and_hashes_without_build_keys(self):
        c = self.instance("--package-only", "--failure-reason", "setup_failed")
        campaign.write_text(c.output / "logs/setup.log", "Synthetic setup failure fixture.\n")
        campaign.write_text(c.output / "private-build/development-keys/private.pem", "NEVER_EXPORT_THIS_SECRET")
        campaign.write_text(c.output / "runs/standard/evidence/report.json", "incomplete unverified report")
        self.assertEqual(c.execute(), 0)
        with zipfile.ZipFile(c.output / "campaign.zip") as archive:
            names = set(archive.namelist())
            self.assertIn("campaign-status.json", names)
            self.assertIn("remaining-checklist.json", names)
            self.assertIn("remaining-checklist.txt", names)
            self.assertNotIn("runs/standard/evidence/report.json", names)
            self.assertFalse(any("private" in name for name in names))
            manifest = json.loads(archive.read("campaign-manifest.json"))
            self.assertFalse(manifest["release_qualified"])
            checklist = json.loads(archive.read("remaining-checklist.json"))
            self.assertEqual([gate["id"] for gate in checklist["release_gates"]], ["WP" + str(i) for i in range(1, 8)])
            self.assertTrue(all(gate["status"] == "NOT_TESTED" for gate in checklist["release_gates"]))
            self.assertEqual({entry["path"] for entry in manifest["files"]}, names - {"campaign-manifest.json"})
            for entry in manifest["files"]:
                data = archive.read(entry["path"])
                self.assertEqual(hashlib.sha256(data).hexdigest(), entry["sha256"])
                self.assertEqual(len(data), entry["bytes"])
        with (c.output / "campaign.zip").open("rb") as stream:
            self.assertTrue((c.output / "campaign.zip.sha256").read_text().startswith(campaign.file_sha256(stream)))

    def test_package_refuses_secret_renamed_to_allowlisted_log(self):
        c = self.instance("--package-only")
        campaign.write_text(c.output / "logs/build.log", "-----BEGIN PRIVATE KEY-----\nfixture")
        with self.assertRaises(campaign.StopCampaign):
            c.package()
        self.assertFalse((c.output / "campaign.zip").exists())

    def test_interrupted_retrieval_never_resumes_gpu_work(self):
        c = self.instance("--package-only")
        c.state["running_step"] = "memcheck/fp8_gemm"
        with mock.patch.object(c, "build") as build, mock.patch.object(c, "sanitizer") as sanitizer:
            c.execute()
            build.assert_not_called()
            sanitizer.assert_not_called()
        self.assertEqual(c.state["status"], "STOPPED")
        self.assertIsNone(c.state["running_step"])

    def test_process_output_is_bounded_and_deadline_kills_own_child(self):
        c = self.instance()
        with self.assertRaises(campaign.StopCampaign):
            c.run([sys.executable, "-c", "import sys;sys.stdout.write('X'*200000);sys.stdout.flush()"], "logs/build.log", 5, output_limit=4096)
        start = time.monotonic()
        with self.assertRaises(campaign.StopCampaign):
            c.run([sys.executable, "-c", "import time;time.sleep(30)"], "logs/sanitizer-version.log", 1)
        self.assertLess(time.monotonic() - start, 5)

    def test_total_budget_prevents_process_start(self):
        c = self.instance()
        c.deadline = time.monotonic() - 1
        with mock.patch.object(campaign.subprocess, "Popen") as process, self.assertRaises(campaign.StopCampaign):
            c.run(["never"], "logs/build.log", 10)
        process.assert_not_called()

    def test_scan_exit_two_stops_even_with_clean_numerical_fixture(self):
        c = self.instance()
        c.device = device()
        c.gri = self.root / "fixture-gri"
        def run(command, stdout, *unused, **kwargs):
            campaign.write_text(c.output / stdout, "fixture\n")
            if command[1] == "scan":
                campaign.write_json(c.output / "runs/quick/evidence/report.json", {"device": device(), "verdict": "INCONCLUSIVE", "observations": []})
                return 2, 1
            return 0, 1
        with mock.patch.object(c, "ready"), mock.patch.object(c, "run", side_effect=run), mock.patch.object(c, "snapshot") as guard:
            with self.assertRaisesRegex(campaign.StopCampaign, "scan_critical"):
                c.scan("quick")
            guard.assert_not_called()

    def test_post_sanitizer_guard_failure_never_writes_pass(self):
        c = self.instance("--sanitizer")
        c.device = device()
        c.gri = self.root / "fixture-gri"
        c.args.cuda_root = str(self.root / "cuda")
        executable = Path(c.args.cuda_root) / "compute-sanitizer/compute-sanitizer"
        campaign.write_text(executable, "synthetic placeholder never executed")
        def run(command, stdout, *unused, **kwargs):
            if "--tool" in command:
                campaign.write_json(c.output / stdout, worker_ok())
                campaign.write_text(c.output / "sanitizer/memcheck/dispatch_latency/stderr.log", "")
                campaign.write_text(c.output / "sanitizer/memcheck/dispatch_latency/sanitizer.log", "========= COMPUTE-SANITIZER\n========= ERROR SUMMARY: 0 errors\n")
            else:
                campaign.write_text(c.output / stdout, "fixture\n")
            return 0, 50
        with mock.patch.object(campaign, "TOOLS", ("memcheck",)), mock.patch.object(campaign, "METHODS", ("dispatch_latency",)), \
             mock.patch.object(campaign, "selected_lock", return_value=contextlib.nullcontext()), mock.patch.object(campaign.time, "sleep"), \
             mock.patch.object(c, "run", side_effect=run), mock.patch.object(c, "verify_bundle"), mock.patch.object(c, "ready", return_value=snapshot()), \
             mock.patch.object(c, "snapshot", side_effect=campaign.StopCampaign("post_guard_unknown")):
            with self.assertRaisesRegex(campaign.StopCampaign, "post_guard_unknown"):
                c.sanitizer()
        status = json.loads((c.output / "sanitizer/memcheck/dispatch_latency/status.json").read_text())
        self.assertEqual(status["status"], "STOP")
        self.assertEqual(status["reason"], "post_guard_unknown")

    def test_actual_retained_rtx_report_schema_is_readable_without_h100_claim(self):
        path = SOURCE.parent.parent / "reports/h100-extension-rtx5080-final-20260907T1418279930033Z/report.json"
        if not path.exists():
            self.skipTest("optional retained RTX report absent; not an H100 acceptance test")
        value = campaign.checked_json(campaign.read_text(path))
        coverage, critical = campaign.report_coverage(value)
        self.assertFalse(critical)
        self.assertEqual(sum(status == "PASS" for status in coverage.values()), 11)
        self.assertEqual(coverage["numa_transfer"], "UNSUPPORTED")

    def test_actual_read_only_rtx_native_schema_is_rejected_as_h100(self):
        root = SOURCE.parent.parent / "build/windows-validation/campaign-native-schema"
        if not root.exists():
            self.skipTest("optional local read-only NVML fixtures absent")
        discovery = campaign.checked_json(campaign.read_text(root / "rtx-discover.json"))
        native = campaign.checked_json(campaign.read_text(root / "rtx-snapshot.json"))
        self.assertEqual(discovery["status"], "PASS")
        self.assertEqual(discovery["cuda_status"], "PASS")
        self.assertEqual(campaign.field(native, "compute_capability"), "12.0")
        self.assertTrue(campaign.UUID.fullmatch(campaign.field(native, "uuid")))
        self.assertTrue(campaign.PCI.fullmatch(campaign.field(native, "pci_address")))
        with self.assertRaises(campaign.StopCampaign):
            campaign.select_h100(discovery)

    @unittest.skipUnless(os.name == "posix", "real Linux flock/process groups require Linux")
    def test_same_uuid_lock_excludes_competing_campaign(self):
        with campaign.selected_lock(self.root, GPU):
            with self.assertRaises(campaign.StopCampaign):
                with campaign.selected_lock(self.root, GPU):
                    pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
