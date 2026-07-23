"""Deterministic contract tests for Issue #70 P0 v2 feasibility Gate 1."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools import p0_v2_runner_probe as probe


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = (
    REPO_ROOT
    / "contracts/schemas/p0-v2-runner-feasibility-evidence.v1.schema.json"
)
WORKFLOW_PATH = REPO_ROOT / ".github/workflows/p0-v2-runner-feasibility.yml"
TOOL_PATH = REPO_ROOT / "tools/p0_v2_runner_probe.py"
ALLOWED_PATHS = {
    ".github/workflows/p0-v2-runner-feasibility.yml",
    "contracts/schemas/p0-v2-runner-feasibility-evidence.v1.schema.json",
    "tests/test_b3_p0_v2_runner_feasibility.py",
    "tools/p0_v2_runner_probe.py",
}


def _observation(name: str, authority: str, value):
    return {"name": name, "authority": authority, "value": value}


def _stream():
    return {
        "authority": "supervisor_observed",
        "payload_authority": "child_untrusted",
        "byte_count": 0,
        "sha256": hashlib.sha256(b"").hexdigest(),
        "retained_base64": "",
        "retained_byte_count": 0,
        "truncated": False,
        "eof_observed": True,
    }


def _evidence():
    case = {
        "id": "success",
        "outcome": "SUCCESS",
        "outcome_authority": "supervisor_observed",
        "started_monotonic_ns": 2,
        "finished_monotonic_ns": 3,
        "requested_argv": ["/usr/bin/python3", "-I", "/run/probe.py"],
        "kernel_observed_argv": ["/usr/bin/python3", "-I", "/run/probe.py"],
        "requested_environment": {"LANG": "C.UTF-8"},
        "kernel_observed_environment": {"LANG": "C.UTF-8"},
        "stdout": _stream(),
        "stderr": _stream(),
        "cleanup": {
            "authority": "kernel_observed",
            "direct_cgroup_kill_written": True,
            "recursive_populated_zero_observed": True,
            "path_absence_used_as_proof": False,
            "streams_eof_after_empty": True,
            "unit_unloaded_after_empty": True,
        },
        "observations": [_observation("case.main_pid", "kernel_observed", 123)],
        "errors": [],
    }
    return {
        "schema_version": "1.0.0",
        "evidence_kind": "p0-v2-runner-feasibility-candidate",
        "candidate_notice": (
            "candidate evidence only; an independent reviewer owns the GATE1_* decision"
        ),
        "outcome": "SUCCESS",
        "outcome_authority": "supervisor_observed",
        "identity": [
            _observation(f"identity.{index}", "github_context_claim", str(index))
            for index in range(8)
        ],
        "source": [
            _observation(f"source.{index}", "supervisor_observed", str(index))
            for index in range(4)
        ],
        "host": [
            _observation(f"host.{index}", "kernel_observed", str(index))
            for index in range(8)
        ],
        "controls": {
            "requested": [_observation("requested.control", "supervisor_observed", "x")],
            "systemd_reported": [
                _observation("reported.control", "systemd_observed", "x")
            ],
            "effective_observed": [
                _observation("effective.control", "kernel_observed", True)
            ],
        },
        "lifecycle": [
            {
                "name": "supervisor_started",
                "monotonic_ns": 1,
                "authority": "supervisor_observed",
            },
            {
                "name": "evidence_sealed",
                "monotonic_ns": 4,
                "authority": "supervisor_observed",
            },
        ],
        "cases": [case],
        "cancellation": {
            "claim_type": "not_requested",
            "authority": "github_context_claim",
            "finalizer_ran": False,
            "same_vm_cleanup_observed": False,
            "force_cancellation_proven": False,
        },
        "errors": [],
    }


class SchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_schema_is_well_formed(self):
        self.assertEqual("https://json-schema.org/draft/2020-12/schema", self.schema["$schema"])
        self.assertFalse(self.schema["additionalProperties"])
        self.assertIn("$defs", self.schema)

    def test_reference_evidence_is_valid(self):
        probe.validate_evidence(_evidence(), SCHEMA_PATH)

    def test_unknown_top_level_field_fails_closed(self):
        value = _evidence()
        value["final_gate1_decision"] = "GATE1_FEASIBLE_ON_GITHUB_HOSTED"
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_unknown_case_field_fails_closed(self):
        value = _evidence()
        value["cases"][0]["child_claimed_safe"] = True
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_child_cannot_be_authority_for_effective_control(self):
        value = _evidence()
        value["controls"]["effective_observed"][0]["authority"] = "child_untrusted"
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_force_cancellation_can_never_be_claimed_proven(self):
        value = _evidence()
        value["cancellation"]["force_cancellation_proven"] = True
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_every_total_outcome_is_in_schema(self):
        schema_outcomes = set(self.schema["$defs"]["outcome"]["enum"])
        self.assertEqual(probe.OUTCOMES, schema_outcomes)

    def test_every_hosted_case_has_an_expected_outcome(self):
        self.assertEqual(set(probe.CASES), set(probe.EXPECTED_CASE_OUTCOMES) - {"operator-cancel"})
        self.assertEqual("ACTIONS_CANCELLED", probe.EXPECTED_CASE_OUTCOMES["operator-cancel"])

    def test_cleanup_order_is_enforced_beyond_json_schema(self):
        value = _evidence()
        value["cases"][0]["cleanup"]["recursive_populated_zero_observed"] = False
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_lifecycle_monotonicity_is_enforced(self):
        value = _evidence()
        value["lifecycle"][1]["monotonic_ns"] = 0
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)


class DeterministicCoreTests(unittest.TestCase):
    def test_canonical_json_is_stable_and_compact(self):
        left = probe.canonical_json_bytes({"b": 1, "a": [2, 3]})
        right = probe.canonical_json_bytes({"a": [2, 3], "b": 1})
        self.assertEqual(left, right)
        self.assertEqual(b'{"a":[2,3],"b":1}', left)

    def test_stream_capture_hashes_all_bytes_but_retains_a_bound(self):
        capture = probe.StreamCapture(4)
        capture.feed(b"abcdef")
        document = capture.document()
        self.assertEqual(6, document["byte_count"])
        self.assertEqual(4, document["retained_byte_count"])
        self.assertTrue(document["truncated"])
        self.assertEqual(hashlib.sha256(b"abcdef").hexdigest(), document["sha256"])

    def test_safe_unit_name_uses_only_validated_components(self):
        unit = probe.safe_unit_name("123456789", "success", "a" * 16)
        self.assertRegex(unit, probe.SAFE_UNIT_RE)
        with self.assertRaises(probe.ProbeError):
            probe.safe_unit_name("../../x", "success", "a" * 16)

    def test_state_path_rejects_path_traversal(self):
        with self.assertRaises(probe.ProbeError):
            probe.state_path_for("../../root", "1")

    def test_atomic_seal_validates_fsyncs_and_hashes(self):
        value = _evidence()
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "evidence.json"
            digest = probe.atomic_seal(
                destination, value, SCHEMA_PATH, os_getuid(), os_getgid()
            )
            payload = destination.read_bytes()
            self.assertEqual(hashlib.sha256(payload).hexdigest(), digest)
            self.assertEqual(value, json.loads(payload))
            self.assertIn(digest, destination.with_suffix(".json.sha256").read_text())


def os_getuid():
    import os

    return os.getuid()


def os_getgid():
    import os

    return os.getgid()


class SystemdBoundaryTests(unittest.TestCase):
    def test_rendered_command_is_exact_argv_without_shell(self):
        argv = probe.render_systemd_run_argv(
            "p0-v2-g1-123-success-aaaaaaaaaaaaaaaa.service",
            Path("/usr/bin/python3"),
            Path("/run/probe.py"),
            "success",
            Path("/run/state"),
            Path("/run/state/barrier"),
            Path("/run/state/stdout"),
            Path("/run/state/stderr"),
        )
        self.assertEqual("/usr/bin/systemd-run", argv[0])
        self.assertIn("--expand-environment=no", argv)
        self.assertNotIn("/bin/sh", argv)
        self.assertNotIn("bash", argv)
        self.assertEqual(
            ["/usr/bin/python3", "-I", "/run/probe.py", "fixture", "--case", "success"],
            argv[-6:],
        )

    def test_required_hardening_properties_are_requested(self):
        joined = "\n".join(probe.SYSTEMD_PROPERTIES_BASE)
        for token in (
            "DynamicUser=yes",
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateNetwork=yes",
            "ProtectProc=invisible",
            "ProcSubset=pid",
            "RestrictAddressFamilies=none",
            "RestrictNamespaces=yes",
            "MemoryDenyWriteExecute=yes",
            "SystemCallFilter=~",
            "KillMode=control-group",
            "MemorySwapMax=0",
            "MemoryOOMGroup=yes",
            "LimitCORE=0",
        ):
            self.assertIn(token, joined)

    def test_nonseekable_fifo_capture_is_rendered(self):
        properties = probe.systemd_properties(
            Path("/run/state"),
            Path("/run/state/barrier.fifo"),
            Path("/run/state/stdout.fifo"),
            Path("/run/state/stderr.fifo"),
        )
        rendered = "\n".join(properties)
        self.assertIn("StandardOutput=file:/run/state/stdout.fifo", rendered)
        self.assertIn("StandardError=file:/run/state/stderr.fifo", rendered)
        self.assertNotIn("StandardOutput=journal", rendered)

    def test_forbidden_actions_environment_is_unset(self):
        rendered = "\n".join(
            probe.systemd_properties(
                Path("/run/state"),
                Path("/run/state/in"),
                Path("/run/state/out"),
                Path("/run/state/err"),
            )
        )
        for token in ("GITHUB_TOKEN", "GITHUB_ENV", "GITHUB_OUTPUT", "ACTIONS_ID_TOKEN"):
            self.assertIn(token, rendered)

    def test_prohibited_cleanup_fallbacks_are_absent(self):
        text = TOOL_PATH.read_text(encoding="utf-8")
        for token in ("killpg(", "pkill", "pgrep", "getpgid("):
            self.assertNotIn(token, text)
        self.assertIn('cgroup_dir / "cgroup.kill"', text)
        self.assertIn('"populated") == 0', text)

    def test_regular_file_descriptor_tampering_is_a_real_fixture(self):
        text = TOOL_PATH.read_text(encoding="utf-8")
        self.assertIn("os.ftruncate(1, 0)", text)
        self.assertIn("os.lseek(1, 0, os.SEEK_SET)", text)
        self.assertIn("os.dup(1)", text)

    def test_coredump_suppression_is_verified_and_restored(self):
        text = TOOL_PATH.read_text(encoding="utf-8")
        self.assertIn("suppress_core_pattern", text)
        self.assertIn("restore_core_pattern", text)
        self.assertIn("LimitCORE=0", text)


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW_PATH.read_text(encoding="utf-8")

    def test_workflow_is_secretless_permissionless_pull_request_only(self):
        self.assertIn("pull_request:", self.text)
        self.assertNotIn("pull_request_target", self.text)
        self.assertIn("permissions: {}", self.text)
        self.assertNotIn("workflow_dispatch:", self.text)
        self.assertNotIn("id-token:", self.text)

    def test_runner_and_concurrency_are_fixed(self):
        self.assertIn("runs-on: ubuntu-24.04", self.text)
        self.assertIn("cancel-in-progress: false", self.text)

    def test_nonlocal_actions_are_full_sha_pinned(self):
        uses = [
            line.strip().split("uses:", 1)[1].strip()
            for line in self.text.splitlines()
            if "uses:" in line
        ]
        self.assertTrue(uses)
        for use in uses:
            self.assertRegex(use, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")

    def test_exact_pr_head_is_checked_out_without_credentials(self):
        self.assertIn("github.event.pull_request.head.sha", self.text)
        self.assertIn("persist-credentials: false", self.text)
        self.assertIn("git rev-parse HEAD", self.text)

    def test_trusted_tests_do_not_use_isolated_mode_that_hides_checkout(self):
        self.assertIn(
            "/usr/bin/python3 -m unittest discover -s tests "
            "-p 'test_b3_p0_v2_runner_feasibility.py'",
            self.text,
        )
        self.assertNotIn("python3 -I -m unittest", self.text)

    def test_cancel_finalizer_and_artifact_upload_are_always_steps(self):
        self.assertIn("always() && cancelled()", self.text)
        self.assertIn("p0-v2-cancel-canary", self.text)
        self.assertIn(
            "P0_V2_CANCEL_CANARY_ACTIVE",
            TOOL_PATH.read_text(encoding="utf-8"),
        )
        self.assertIn("if: always()", self.text)
        self.assertIn("candidate-evidence.json", self.text)

    def test_only_allowlisted_paths_are_changed(self):
        completed = subprocess_run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=REPO_ROOT,
        )
        changed = {line[3:] for line in completed.splitlines() if line}
        self.assertTrue(changed)
        self.assertEqual(ALLOWED_PATHS, changed)


def subprocess_run(argv, cwd):
    import subprocess

    return subprocess.check_output(argv, cwd=cwd, text=True)


if __name__ == "__main__":
    unittest.main()
