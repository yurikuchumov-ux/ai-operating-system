"""Deterministic contract tests for Issue #70 P0 v2 feasibility Gate 1."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
BASE_SHA = "d4f10b714de3afae84d48dfcd3daa6405092a973"


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
        "requested_argv_authority": "supervisor_observed",
        "kernel_observed_argv": ["/usr/bin/python3", "-I", "/run/probe.py"],
        "kernel_observed_argv_authority": "kernel_observed",
        "requested_environment": {"LANG": "C.UTF-8"},
        "requested_environment_authority": "supervisor_observed",
        "kernel_observed_environment": {"LANG": "C.UTF-8"},
        "kernel_observed_environment_authority": "kernel_observed",
        "stdout": _stream(),
        "stderr": _stream(),
        "cleanup": {
            "direct_cgroup_kill_written": True,
            "direct_cgroup_kill_authority": "kernel_observed",
            "recursive_populated_zero_observed": True,
            "recursive_populated_zero_authority": "kernel_observed",
            "path_absence_used_as_proof": False,
            "streams_eof_after_empty": True,
            "streams_eof_authority": "supervisor_observed",
            "unit_unloaded_after_empty": True,
            "unit_unloaded_authority": "systemd_observed",
        },
        "observations": [_observation("case.main_pid", "kernel_observed", 123)],
        "errors": [],
    }
    cases = []
    for case_id in probe.CASES:
        item = json.loads(json.dumps(case))
        item["id"] = case_id
        item["outcome"] = probe.EXPECTED_CASE_OUTCOMES[case_id]
        cases.append(item)
    lifecycle_names = [
        "supervisor_started",
        "host_preflight_complete",
        "core_pattern_suppressed",
    ]
    for _ in probe.CASES:
        lifecycle_names.extend(
            [
                "unit_created",
                "bootstrap_observed",
                "hostile_released",
                "outcome_observed",
                "cgroup_kill_written",
                "cgroup_empty_observed",
                "streams_eof_observed",
                "unit_unloaded",
            ]
        )
    lifecycle_names.append("core_pattern_restored")
    lifecycle = [
        {
            "name": name,
            "monotonic_ns": index,
            "authority": "supervisor_observed",
        }
        for index, name in enumerate(lifecycle_names, start=1)
    ]
    return {
        "schema_version": "1.0.0",
        "evidence_kind": "p0-v2-runner-feasibility-candidate",
        "candidate_notice": (
            "candidate evidence only; an independent reviewer owns the GATE1_* decision"
        ),
        "outcome": "SUCCESS",
        "outcome_authority": "supervisor_observed",
        "identity": [
            _observation(
                name,
                "kernel_observed"
                if name == "runner.boot_id"
                else "github_context_claim",
                name,
            )
            for name in sorted(probe.REQUIRED_IDENTITY_NAMES)
        ],
        "source": [
            _observation(
                name,
                "github_context_claim"
                if name in {"source.task_commit", "source.task_sha256"}
                else "supervisor_observed",
                name,
            )
            for name in sorted(probe.REQUIRED_SOURCE_NAMES)
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
        "lifecycle": lifecycle,
        "cases": cases,
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

    def test_false_success_with_zero_cases_and_controls_is_rejected(self):
        value = _evidence()
        value["cases"] = []
        value["controls"] = {
            "requested": [],
            "systemd_reported": [],
            "effective_observed": [],
        }
        value["errors"] = []
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_success_with_case_outcome_mismatch_is_rejected(self):
        value = _evidence()
        value["cases"][-1]["outcome"] = "SETUP_ERROR"
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_candidate_cannot_claim_reviewer_authority(self):
        value = _evidence()
        value["identity"][0]["authority"] = "reviewer_api_observed"
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_duplicate_case_id_is_rejected(self):
        value = _evidence()
        value["cases"][-1]["id"] = value["cases"][0]["id"]
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_per_field_authorities_are_required(self):
        value = _evidence()
        del value["cases"][0]["cleanup"]["streams_eof_authority"]
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
            manifest = json.loads(
                destination.with_suffix(".json.manifest.json").read_text()
            )
            self.assertEqual("1.0.0", manifest["manifest_version"])
            self.assertEqual(digest, manifest["evidence_sha256"])
            self.assertEqual(value["identity"], manifest["identity"])
            self.assertFalse(destination.with_suffix(".json.sha256").exists())

    def test_systemd_exit_properties_are_numeric(self):
        self.assertEqual(1, probe.parse_systemd_int("ExecMainCode", "1"))
        with self.assertRaises(probe.ProbeError):
            probe.parse_systemd_int("ExecMainCode", "exited")
        self.assertEqual(
            "SUCCESS",
            probe.classify_systemd_outcome("success", os_cld_exited(), 0),
        )
        self.assertEqual(
            "NONZERO_EXIT",
            probe.classify_systemd_outcome("exit-code", os_cld_exited(), 17),
        )
        self.assertEqual(
            "SIGNAL",
            probe.classify_systemd_outcome("signal", os_cld_killed(), 15),
        )
        self.assertEqual(
            "RESOURCE_OOM",
            probe.classify_systemd_outcome("oom-kill", os_cld_killed(), 9),
        )

    def test_environment_contract_rejects_duplicates_and_extras(self):
        requested = {"LANG": "C.UTF-8"}
        with self.assertRaises(probe.ProbeError):
            probe.validate_observed_environment(
                [b"LANG=C.UTF-8", b"LANG=C.UTF-8"],
                requested,
            )
        with self.assertRaises(probe.ProbeError):
            probe.validate_observed_environment(
                [b"LANG=C.UTF-8", b"UNEXPECTED=value"],
                requested,
            )

    def test_core_pattern_recovery_record_precedes_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            core_pattern = root / "core_pattern"
            state_path = root / "state.json"
            core_pattern.write_bytes(b"|/usr/lib/helper %p\n")
            journal = {
                "phase": "initialized",
                "core_pattern_original_base64": "",
                "core_pattern_original_recorded": False,
                "core_pattern_active_base64": "",
            }
            with mock.patch.object(probe, "CORE_PATTERN_PATH", core_pattern):
                active = probe.suppress_core_pattern(state_path, journal)
                self.assertEqual(b"core\n", active)
                persisted = json.loads(state_path.read_text())
                self.assertTrue(persisted["core_pattern_original_recorded"])
                self.assertEqual("core_pattern_suppressed", persisted["phase"])
                restored = probe.restore_core_pattern(journal)
                self.assertEqual(b"|/usr/lib/helper %p\n", restored)

    def test_core_pattern_restores_after_post_write_journal_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            core_pattern = root / "core_pattern"
            state_path = root / "state.json"
            original = b"|/usr/lib/helper %p\n"
            core_pattern.write_bytes(original)
            journal = {
                "phase": "initialized",
                "core_pattern_original_base64": "",
                "core_pattern_original_recorded": False,
                "core_pattern_active_base64": "",
            }
            real_write_state = probe.write_root_state
            calls = 0

            def fail_second_state_write(path, value):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected phase-journal failure")
                return real_write_state(path, value)

            with (
                mock.patch.object(probe, "CORE_PATTERN_PATH", core_pattern),
                mock.patch.object(
                    probe,
                    "write_root_state",
                    side_effect=fail_second_state_write,
                ),
            ):
                with self.assertRaises(OSError):
                    probe.suppress_core_pattern(state_path, journal)
                probe.restore_core_pattern(journal)
            self.assertEqual(original, core_pattern.read_bytes())

    def test_manifest_seal_is_retryable_after_manifest_rename_failure(self):
        value = _evidence()
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "evidence.json"
            real_replace = probe.os.replace
            calls = 0

            def fail_second_replace(source, target):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected manifest rename failure")
                return real_replace(source, target)

            with mock.patch.object(probe.os, "replace", side_effect=fail_second_replace):
                with self.assertRaises(OSError):
                    probe.atomic_seal(
                        destination,
                        value,
                        SCHEMA_PATH,
                        os_getuid(),
                        os_getgid(),
                    )
            digest = probe.atomic_seal(
                destination,
                value,
                SCHEMA_PATH,
                os_getuid(),
                os_getgid(),
            )
            manifest = json.loads(
                destination.with_suffix(".json.manifest.json").read_text()
            )
            self.assertEqual(digest, manifest["evidence_sha256"])


def os_getuid():
    import os

    return os.getuid()


def os_getgid():
    import os

    return os.getgid()


def os_cld_exited():
    import os

    return os.CLD_EXITED


def os_cld_killed():
    import os

    return os.CLD_KILLED


class SystemdBoundaryTests(unittest.TestCase):
    def test_rendered_command_is_exact_argv_without_shell(self):
        argv = probe.render_systemd_run_argv(
            "p0-v2-g1-123-success-aaaaaaaaaaaaaaaa.service",
            Path("/usr/bin/python3"),
            Path("/run/probe.py"),
            "success",
            "a" * 16,
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
            [
                "/usr/bin/python3",
                "-I",
                "/run/probe.py",
                "fixture",
                "--case",
                "success",
                "--nonce",
                "a" * 16,
            ],
            argv[-8:],
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
            Path("/run/exec/probe.py"),
            Path("/run/state/barrier.fifo"),
            Path("/run/state/stdout.fifo"),
            Path("/run/state/stderr.fifo"),
        )
        rendered = "\n".join(properties)
        self.assertIn("StandardOutput=file:/run/state/stdout.fifo", rendered)
        self.assertIn("StandardError=file:/run/state/stderr.fifo", rendered)
        self.assertIn("BindReadOnlyPaths=/run/exec/probe.py", rendered)
        self.assertIn("InaccessiblePaths=/run/state", rendered)
        self.assertNotIn("StandardOutput=journal", rendered)

    def test_forbidden_actions_environment_is_unset(self):
        rendered = "\n".join(
            probe.systemd_properties(
                Path("/run/state"),
                Path("/run/exec/probe.py"),
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
        self.assertIn("CHILD_CAPTURE_FD_MISMATCH", text)
        self.assertIn("fd_stat.st_ino", text)
        self.assertIn("return 24 if any", text)

    def test_coredump_suppression_is_verified_and_restored(self):
        text = TOOL_PATH.read_text(encoding="utf-8")
        self.assertIn("suppress_core_pattern", text)
        self.assertIn("restore_core_pattern", text)
        self.assertIn("LimitCORE=0", text)
        self.assertIn("core_pattern_original_base64", text)
        self.assertIn("coredump_effect_snapshot", text)

    def test_required_effectiveness_cases_are_present(self):
        for case_id in (
            "writer-handoff",
            "invalid-output",
            "fork-limit",
            "memory-limit",
            "nofile-limit",
            "fsize-limit",
            "tmpfs-limit",
            "sandbox-probe",
            "crash-storm",
        ):
            self.assertIn(case_id, probe.CASES)
            self.assertIn(case_id, probe.EXPECTED_CASE_OUTCOMES)
        text = TOOL_PATH.read_text(encoding="utf-8")
        for token in (
            "perf_event_open",
            "io_uring_setup",
            '"bpf"',
            '"keyctl"',
            "writable-executable-memory",
            "host-process-visible",
            "HOST_TMP_ISOLATION_FAILED",
        ):
            self.assertIn(token, text)

    def test_cancellation_marker_follows_durable_release_state(self):
        text = TOOL_PATH.read_text(encoding="utf-8")
        phase = text.index('journal["phase"] = "fixture_released"')
        durable_write = text.index("write_root_state(state_path, journal)", phase)
        marker = text.index('print("P0_V2_CANCEL_CANARY_ACTIVE=1"', durable_write)
        self.assertLess(phase, durable_write)
        self.assertLess(durable_write, marker)

    def test_finalizer_revalidates_identity_and_restores_outermost(self):
        text = TOOL_PATH.read_text(encoding="utf-8")
        self.assertIn("INVOCATION_ID_MISMATCH", text)
        self.assertIn("CGROUP_IDENTITY_MISMATCH", text)
        self.assertIn("FIFO_IDENTITY_MISMATCH", text)
        self.assertIn("finally:\n        for fd in", text)
        self.assertIn("restored_bytes = restore_core_pattern(state)", text)


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

    def test_exact_pr_base_event_and_workflow_are_bound(self):
        for token in (
            "github.event.pull_request.number == 71",
            "github.event.pull_request.base.repo.full_name",
            "github.event.pull_request.base.ref == 'main'",
            "github.event.pull_request.base.sha ==",
            "github.event.action == 'labeled'",
            "EXPECTED_WORKFLOW_REF",
            "EXPECTED_WORKFLOW_SHA",
            "git diff --name-status --no-renames",
            "git ls-tree",
            "merge_parent_one",
            "merge_parent_two",
        ):
            self.assertIn(token, self.text)
        self.assertNotIn(
            "contains(github.event.pull_request.labels.*.name",
            self.text,
        )

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

    def test_only_allowlisted_paths_are_committed_additions(self):
        completed = subprocess_run(
            [
                "git",
                "diff",
                "--name-status",
                "--no-renames",
                BASE_SHA,
                "HEAD",
            ],
            cwd=REPO_ROOT,
        )
        additions = {
            path
            for status, path in (
                line.split("\t", 1) for line in completed.splitlines() if line
            )
            if status == "A"
        }
        self.assertEqual(ALLOWED_PATHS, additions)
        self.assertEqual(4, len(completed.splitlines()))
        for path in sorted(ALLOWED_PATHS):
            tree_entry = subprocess_run(
                ["git", "ls-tree", "HEAD", "--", path],
                cwd=REPO_ROOT,
            ).strip()
            self.assertRegex(tree_entry, rf"^100644 blob [0-9a-f]{{40}}\t{path}$")

    def test_workflow_requires_a_clean_checkout_before_tests(self):
        self.assertIn(
            '[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]]',
            self.text,
        )


def subprocess_run(argv, cwd):
    import subprocess

    return subprocess.check_output(argv, cwd=cwd, text=True)


if __name__ == "__main__":
    unittest.main()
