"""Deterministic contract tests for Issue #70 P0 v2 feasibility Gate 1."""

from __future__ import annotations

import ast
import base64
import errno
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
import zipfile
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools import p0_v2_runner_probe as probe

try:  # Optional local test dependency (declared in requirements-b0.txt).
    import jsonschema as _jsonschema

    _HAVE_JSONSCHEMA = True
except ImportError:  # pragma: no cover - environment-dependent
    _jsonschema = None
    _HAVE_JSONSCHEMA = False


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


def _capture_doc(data: bytes):
    """A real StreamCapture document for exact untrusted bytes (retained whole)."""
    capture = probe.StreamCapture(probe.MAX_RETAINED_COMBINED // 2)
    capture.feed(data)
    capture.eof_observed = True
    return capture.document()


def _flood_stream(byte_count: int):
    """A truncated high-volume stream document with a chosen total byte count."""
    stream = _stream()
    stream["byte_count"] = byte_count
    stream["truncated"] = byte_count > 0
    return stream


def _raw_argv_b64(argv):
    """Kernel-observed argv encoded exactly as the NUL-delimited /proc bytes are."""
    return [base64.b64encode(item.encode("utf-8")).decode("ascii") for item in argv]


def _raw_env_b64(environment):
    """Kernel-observed environment encoded exactly as the /proc KEY=VALUE bytes."""
    return [
        base64.b64encode(f"{key}={value}".encode("utf-8")).decode("ascii")
        for key, value in environment.items()
    ]


def _case_bootstrap_observations(item):
    """The kernel-observed argv/environment raw encodings every case carries so
    the semantic validator can rebind structured argv/env to the raw bytes."""
    return [
        _observation("case.main_pid", "kernel_observed", 123),
        _observation(
            "bootstrap.argv_raw_base64",
            "kernel_observed",
            _raw_argv_b64(item["kernel_observed_argv"]),
        ),
        _observation(
            "bootstrap.environment_raw_base64",
            "kernel_observed",
            _raw_env_b64(item["kernel_observed_environment"]),
        ),
    ]


def _effective_controls(case_ids):
    """The exact effective-control observation set the supervisor emits for a run
    over ``case_ids``, each carrying the literal boolean ``True``."""
    return [
        _observation(name, authority, True)
        for name, authority in probe.success_effective_control_authorities(
            case_ids
        ).items()
    ]


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
        if case_id == "invalid-output":
            item["stdout"] = _capture_doc(probe.INVALID_OUTPUT_STDOUT)
            item["stderr"] = _capture_doc(probe.INVALID_OUTPUT_STDERR)
            item["observations"] = [
                _observation(
                    "case.invalid_output_contract",
                    "supervisor_observed",
                    probe.verify_invalid_output_contract(
                        item["stdout"], item["stderr"]
                    ),
                )
            ] + _case_bootstrap_observations(item)
        elif case_id == "output-flood":
            item["stdout"] = _flood_stream(4_500_000)
            item["stderr"] = _flood_stream(4_500_000)
            item["observations"] = [
                _observation(
                    "case.output_accounting",
                    "supervisor_observed",
                    probe.build_output_accounting(
                        observed_pipe_max_size=1_048_576,
                        trigger_bytes=probe.MAX_TOTAL_COMBINED + 1,
                        combined_final_bytes=9_000_000,
                    ),
                )
            ] + _case_bootstrap_observations(item)
        else:
            item["observations"] = _case_bootstrap_observations(item)
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
            "effective_observed": _effective_controls(probe.CASES),
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


def _full_journal(**overrides):
    journal = {
        "journal_version": 1,
        "phase": "initialized",
        "run_id": "1",
        "run_attempt": "1",
        "head_sha": "0" * 40,
        "source_sha256": "0" * 64,
        "schema_sha256": "0" * 64,
        "workflow_file_sha256": "0" * 64,
        "test_file_sha256": "0" * 64,
        "evidence_dir": "/run/p0-v2-gate1/evidence",
        "schema_path": "/run/p0-v2-gate1/schema.json",
        "core_pattern_original_base64": "",
        "core_pattern_original_recorded": False,
        "core_pattern_active_base64": "",
        "coredump_before": {},
        "active_case": None,
        "release_marker": None,
        "terminal_evidence_sha256": "",
    }
    journal.update(overrides)
    return journal


_ZERO_SHA = "0" * 64


def _unit_snapshot(unit):
    return {
        "unit": unit,
        "returncode": 0,
        "stdout_byte_count": 42,
        "stdout_sha256": _ZERO_SHA,
        "stderr": "",
        "stderr_byte_count": 0,
        "stderr_sha256": _ZERO_SHA,
        "properties": {name: "observed" for name in probe.COREDUMP_UNIT_PROPERTIES},
    }


def _coredump_snapshot(instance_units=(), **overrides):
    """A fully valid coredump-effect snapshot for validation-layer tests."""
    roots = [str(root) for root in probe.COREDUMP_CONFIG_ROOTS]
    main_candidates = []
    dropin_directories = []
    for priority, root in enumerate(probe.COREDUMP_CONFIG_ROOTS):
        main_candidates.append(
            {
                "path": str(root / "coredump.conf"),
                "exists": False,
                "root_priority": priority,
            }
        )
        dropin_directories.append(
            {
                "root": str(root),
                "root_priority": priority,
                "directory": {
                    "path": str(root / "coredump.conf.d"),
                    "exists": False,
                },
                "entries": [],
            }
        )
    instances = sorted(instance_units)
    snapshot = {
        "package": {
            "returncode": 0,
            "stdout": "install ok installed\t255.4-1ubuntu8",
            "stdout_byte_count": 20,
            "stdout_sha256": _ZERO_SHA,
            "stderr": "",
            "stderr_byte_count": 0,
            "stderr_sha256": _ZERO_SHA,
        },
        "configuration": {
            "precedence_roots_high_to_low": roots,
            "main_candidates": main_candidates,
            "effective_main": None,
            "dropin_directories": dropin_directories,
            "effective_dropins": [],
        },
        "helper_units": {
            "list_command": {
                "returncode": 0,
                "stdout_byte_count": 0,
                "stdout_sha256": _ZERO_SHA,
                "stderr": "",
                "stderr_byte_count": 0,
                "stderr_sha256": _ZERO_SHA,
            },
            "socket": _unit_snapshot(probe.COREDUMP_SOCKET_UNIT),
            "template": _unit_snapshot(probe.COREDUMP_TEMPLATE_UNIT),
            "instances": [_unit_snapshot(unit) for unit in instances],
            "instance_units": list(instances),
            "instance_count": len(instances),
        },
        "storage": [
            {"path": "/var/lib/systemd/coredump", "error": "2:No such file or directory"}
        ],
        "journal_cursor": {
            "returncode": 0,
            "cursor": "s=abc;i=1;b=2;m=3;t=4;x=5",
            "stdout_byte_count": 30,
            "stdout_sha256": _ZERO_SHA,
            "stderr": "",
            "stderr_byte_count": 0,
            "stderr_sha256": _ZERO_SHA,
        },
    }
    snapshot.update(overrides)
    return snapshot


def _journal_interval(**overrides):
    """A valid, complete, empty journal interval for validation-layer tests."""
    start = "s=aaa;i=1;b=2;m=3;t=4;x=5"
    interval = {
        "start_cursor": start,
        "terminal_cursor": start,
        "terminal_cursor_emitted": False,
        "byte_count": 0,
        "sha256": _ZERO_SHA,
        "entry_count": 0,
        "relevant_entry_count": 0,
        "relevant_entries": [],
        "complete": True,
    }
    interval.update(overrides)
    return interval


def _evidence_with_coredump():
    """SUCCESS evidence carrying valid before/after snapshots and a journal delta."""
    value = _evidence()
    value["host"].extend(
        [
            _observation(
                "host.coredump_effects_before",
                "platform_file_observed",
                _coredump_snapshot(),
            ),
            _observation(
                "host.coredump_effects_after",
                "platform_file_observed",
                _coredump_snapshot(),
            ),
            _observation(
                "host.journal_delta", "platform_file_observed", _journal_interval()
            ),
        ]
    )
    return value


def _journal_record(cursor, **fields):
    record = {"__CURSOR": cursor}
    record.update(fields)
    return record


def _journal_payload(records):
    """Serialise records as newline-delimited JSON with journalctl's trailer."""
    lines = [json.dumps(record) for record in records]
    if records:
        lines.append(f"-- cursor: {records[-1]['__CURSOR']}")
    if not lines:
        return b""
    return ("\n".join(lines) + "\n").encode("utf-8")


def _fstat_forcing(*, uid=0, mode=None, size=None):
    real_fstat = os.fstat

    def fake_fstat(fd):
        info = real_fstat(fd)
        forced_mode = (
            info.st_mode
            if mode is None
            else (stat.S_IFMT(info.st_mode) | stat.S_IMODE(mode))
        )
        return os.stat_result(
            (
                forced_mode,
                info.st_ino,
                info.st_dev,
                info.st_nlink,
                uid,
                info.st_gid,
                info.st_size if size is None else size,
                info.st_atime,
                info.st_mtime,
                info.st_ctime,
            )
        )

    return fake_fstat


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
            journal = _full_journal()
            with (
                mock.patch.object(probe, "CORE_PATTERN_PATH", core_pattern),
                mock.patch.object(
                    probe.os,
                    "fstat",
                    side_effect=_fstat_forcing(uid=0),
                ),
            ):
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
            journal = _full_journal()
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
                    probe.os,
                    "fstat",
                    side_effect=_fstat_forcing(uid=0),
                ),
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


class _FakeMonotonicClock:
    def __init__(self):
        self.value = 0.0

    def monotonic(self):
        self.value += 0.1
        return self.value

    def sleep(self, seconds):
        self.value += seconds


class UnloadUnitProofTests(unittest.TestCase):
    UNIT = "p0-v2-g1-proof-test.service"

    @staticmethod
    def _completed(returncode=0, stdout=b"", stderr=b""):
        return subprocess.CompletedProcess(
            args=["/usr/bin/systemctl"],
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )

    def _run_unload(self, show_results, timeout=1.0):
        results = iter(show_results)

        def fake_run(argv, **kwargs):
            if argv[1] in {"stop", "reset-failed"}:
                return self._completed()
            self.assertEqual(
                [
                    "/usr/bin/systemctl",
                    "show",
                    self.UNIT,
                    "--property=Id",
                    "--property=LoadState",
                ],
                argv,
            )
            return next(results)

        clock = _FakeMonotonicClock()
        with (
            mock.patch.object(probe, "run_command", side_effect=fake_run),
            mock.patch.object(probe.time, "monotonic", side_effect=clock.monotonic),
            mock.patch.object(probe.time, "sleep", side_effect=clock.sleep),
        ):
            probe.unload_unit(self.UNIT, timeout=timeout)

    def test_exact_identity_and_not_found_is_affirmative_unload_proof(self):
        self._run_unload(
            [
                self._completed(
                    stdout=(
                        f"Id={self.UNIT}\n"
                        "LoadState=not-found\n"
                    ).encode()
                )
            ]
        )

    def test_nonzero_systemctl_show_is_not_absence_proof(self):
        with self.assertRaises(probe.ProbeError) as raised:
            self._run_unload([self._completed(returncode=1, stderr=b"failed")])
        self.assertEqual("UNIT_UNLOAD_OBSERVATION_FAILED", raised.exception.code)

    def test_empty_or_malformed_show_output_fails_closed(self):
        for stdout in (b"", b"Id-without-equals\nLoadState=not-found\n"):
            with self.subTest(stdout=stdout):
                with self.assertRaises(probe.ProbeError):
                    self._run_unload([self._completed(stdout=stdout)])

    def test_wrong_unit_identity_fails_closed(self):
        with self.assertRaises(probe.ProbeError) as raised:
            self._run_unload(
                [
                    self._completed(
                        stdout=b"Id=p0-v2-g1-other.service\nLoadState=not-found\n"
                    )
                ]
            )
        self.assertEqual("UNIT_UNLOAD_IDENTITY_MISMATCH", raised.exception.code)

    def test_duplicate_required_property_fails_closed(self):
        with self.assertRaises(probe.ProbeError) as raised:
            self._run_unload(
                [
                    self._completed(
                        stdout=(
                            f"Id={self.UNIT}\n"
                            f"Id={self.UNIT}\n"
                            "LoadState=not-found\n"
                        ).encode()
                    )
                ]
            )
        self.assertEqual("SYSTEMD_SHOW_MALFORMED", raised.exception.code)

    def test_loaded_unit_times_out_instead_of_claiming_unloaded(self):
        loaded = self._completed(
            stdout=(f"Id={self.UNIT}\nLoadState=loaded\n").encode()
        )
        with self.assertRaises(probe.ProbeError) as raised:
            self._run_unload([loaded, loaded, loaded], timeout=0.25)
        self.assertEqual("UNIT_UNLOAD_NOT_OBSERVED", raised.exception.code)

    def test_unsafe_unit_name_is_rejected_before_systemctl(self):
        with mock.patch.object(probe, "run_command") as run:
            with self.assertRaises(probe.ProbeError) as raised:
                probe.unload_unit("ssh.service")
        self.assertEqual("UNIT_NAME_UNSAFE", raised.exception.code)
        run.assert_not_called()


class RootStateJournalTests(unittest.TestCase):
    """Fault injection for byte-complete, revalidated recovery journals."""

    def _write_as_root(self, state_path, state):
        with mock.patch.object(
            probe.os,
            "fstat",
            side_effect=_fstat_forcing(uid=0),
        ):
            probe.write_root_state(state_path, state)

    def test_short_write_is_completed_and_publishes_exact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            state = _full_journal()
            payload = probe.canonical_json_bytes(state)
            real_write = os.write
            calls = 0

            def short_first_write(fd, data):
                nonlocal calls
                calls += 1
                if calls == 1:
                    return real_write(fd, bytes(data[:1]))
                return real_write(fd, data)

            with (
                mock.patch.object(
                    probe.os,
                    "write",
                    side_effect=short_first_write,
                ),
                mock.patch.object(
                    probe.os,
                    "fstat",
                    side_effect=_fstat_forcing(uid=0),
                ),
            ):
                probe.write_root_state(state_path, state)
            self.assertGreaterEqual(calls, 2)
            self.assertEqual(payload, state_path.read_bytes())

    def test_zero_write_fails_without_target_or_temporary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "state.json"
            with mock.patch.object(probe.os, "write", return_value=0):
                with self.assertRaises(probe.ProbeError) as raised:
                    probe.write_root_state(state_path, _full_journal())
            self.assertEqual("STATE_WRITE_INCOMPLETE", raised.exception.code)
            self.assertFalse(state_path.exists())
            self.assertEqual([], list(root.iterdir()))

    def test_interrupted_write_is_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            state = _full_journal()
            real_write = os.write
            calls = 0

            def interrupt_first_write(fd, data):
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise InterruptedError("injected")
                return real_write(fd, data)

            with (
                mock.patch.object(
                    probe.os,
                    "write",
                    side_effect=interrupt_first_write,
                ),
                mock.patch.object(
                    probe.os,
                    "fstat",
                    side_effect=_fstat_forcing(uid=0),
                ),
            ):
                probe.write_root_state(state_path, state)
            self.assertGreaterEqual(calls, 2)
            self.assertEqual(
                probe.canonical_json_bytes(state),
                state_path.read_bytes(),
            )

    def test_readback_rejects_wrong_owner_mode_and_size(self):
        payload = probe.canonical_json_bytes(_full_journal())
        for label, fstat_side_effect in (
            ("owner", _fstat_forcing(uid=501)),
            ("mode", _fstat_forcing(uid=0, mode=0o644)),
            ("size", _fstat_forcing(uid=0, size=len(payload) + 1)),
        ):
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as directory:
                    state_path = Path(directory) / "state.json"
                    state_path.write_bytes(payload)
                    os.chmod(state_path, 0o600)
                    with mock.patch.object(
                        probe.os,
                        "fstat",
                        side_effect=fstat_side_effect,
                    ):
                        with self.assertRaises(probe.ProbeError) as raised:
                            probe.verify_published_root_state(
                                state_path,
                                payload,
                            )
                    self.assertEqual(
                        "STATE_READBACK_UNTRUSTED",
                        raised.exception.code,
                    )

    def test_readback_rejects_non_regular_file_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "directory"
            target.mkdir()
            with self.assertRaises(probe.ProbeError) as raised:
                with mock.patch.object(
                    probe.os,
                    "fstat",
                    side_effect=_fstat_forcing(uid=0),
                ):
                    probe.verify_published_root_state(target, b"{}")
            self.assertEqual("STATE_READBACK_UNTRUSTED", raised.exception.code)

            regular = root / "regular"
            regular.write_bytes(b"{}")
            link = root / "link"
            link.symlink_to(regular)
            with self.assertRaises(OSError):
                probe.verify_published_root_state(link, b"{}")

    def test_readback_rejects_byte_json_and_semantic_mismatch(self):
        good = probe.canonical_json_bytes(_full_journal())
        malformed = b'{"broken":'
        noncanonical = json.dumps(_full_journal(), indent=2).encode()
        partial = probe.canonical_json_bytes(
            {"journal_version": 1, "phase": "initialized"}
        )
        cases = (
            ("bytes", good, good[:-1] + b" "),
            ("malformed", malformed, malformed),
            ("noncanonical", noncanonical, noncanonical),
            ("semantic", partial, partial),
        )
        for label, observed, expected in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as directory:
                    state_path = Path(directory) / "state.json"
                    state_path.write_bytes(observed)
                    os.chmod(state_path, 0o600)
                    with mock.patch.object(
                        probe.os,
                        "fstat",
                        side_effect=_fstat_forcing(uid=0),
                    ):
                        with self.assertRaises(probe.ProbeError):
                            probe.verify_published_root_state(
                                state_path,
                                expected,
                            )

    def test_parent_directory_fsync_precedes_successful_readback(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            events = []
            directory_fds = set()
            real_open = os.open
            real_fsync = os.fsync
            real_replace = os.replace
            real_verify = probe.verify_published_root_state

            def track_open(path, flags, *args):
                fd = real_open(path, flags, *args)
                if flags & os.O_DIRECTORY:
                    directory_fds.add(fd)
                return fd

            def track_fsync(fd):
                events.append(("fsync", fd))
                return real_fsync(fd)

            def track_replace(source, target):
                events.append(("replace", None))
                return real_replace(source, target)

            def track_verify(path, payload):
                events.append(("verify", None))
                return real_verify(path, payload)

            with (
                mock.patch.object(probe.os, "open", side_effect=track_open),
                mock.patch.object(probe.os, "fsync", side_effect=track_fsync),
                mock.patch.object(
                    probe.os,
                    "replace",
                    side_effect=track_replace,
                ),
                mock.patch.object(
                    probe.os,
                    "fstat",
                    side_effect=_fstat_forcing(uid=0),
                ),
                mock.patch.object(
                    probe,
                    "verify_published_root_state",
                    side_effect=track_verify,
                ),
            ):
                probe.write_root_state(state_path, _full_journal())

            replace_index = events.index(("replace", None))
            verify_index = events.index(("verify", None))
            self.assertTrue(
                any(
                    event == "fsync" and fd in directory_fds
                    for event, fd in events[replace_index + 1 : verify_index]
                )
            )

    def test_empty_and_oversized_payloads_are_rejected_before_open(self):
        for payload in (b"", b"x" * (probe.MAX_ROOT_STATE_BYTES + 1)):
            with self.subTest(size=len(payload)):
                with (
                    mock.patch.object(
                        probe,
                        "canonical_json_bytes",
                        return_value=payload,
                    ),
                    mock.patch.object(probe.os, "open") as opened,
                ):
                    with self.assertRaises(probe.ProbeError) as raised:
                        probe.write_root_state(
                            Path("/not-used/state.json"),
                            {},
                        )
                self.assertEqual(
                    "STATE_WRITE_SIZE_INVALID",
                    raised.exception.code,
                )
                opened.assert_not_called()

    def test_full_state_semantics_round_trip(self):
        state = _full_journal(phase="evidence_sealed")
        self.assertEqual(state, probe._validate_root_state_fields(state))
        missing = dict(state)
        del missing["run_id"]
        with self.assertRaises(probe.ProbeError) as raised:
            probe._validate_root_state_fields(missing)
        self.assertEqual("STATE_UNTRUSTED", raised.exception.code)
        with mock.patch.object(probe.os, "open") as opened:
            with self.assertRaises(probe.ProbeError):
                probe.write_root_state(Path("/not-used/state.json"), missing)
        opened.assert_not_called()


class CorrectiveGateTests(unittest.TestCase):
    """Deterministic coverage for the Issue #70 corrective changes."""

    def test_runtime_directories_are_searchable_not_listable(self):
        self.assertEqual(0o711, probe.ROOT_RUNTIME_MODE)
        self.assertEqual(0o711, probe.EXEC_DIR_MODE)
        self.assertEqual(0o700, probe.STATE_DIR_MODE)
        for mode in (probe.ROOT_RUNTIME_MODE, probe.EXEC_DIR_MODE):
            self.assertTrue(mode & 0o001, "must be searchable by DynamicUser")
            self.assertFalse(mode & 0o044, "must not be listable")
            self.assertNotEqual(0o700, mode, "0700 regression breaks traversal")
        self.assertEqual(0, probe.STATE_DIR_MODE & 0o077)
        text = TOOL_PATH.read_text(encoding="utf-8")
        self.assertIn("exec_dir.mkdir(mode=EXEC_DIR_MODE)", text)
        self.assertIn("os.chmod(exec_dir, EXEC_DIR_MODE)", text)
        self.assertIn(
            "ROOT_RUNTIME.mkdir(parents=True, exist_ok=True, mode=ROOT_RUNTIME_MODE)",
            text,
        )
        self.assertIn("os.chmod(ROOT_RUNTIME, ROOT_RUNTIME_MODE)", text)
        self.assertIn("EXEC_DIR_TRAVERSAL_MODE_INVALID", text)
        self.assertIn("ROOT_RUNTIME_TRAVERSAL_MODE_INVALID", text)
        self.assertIn("os.chmod(staged_probe, 0o555)", text)

    def test_private_tmpfs_capacity_is_decoupled_from_fsize(self):
        self.assertEqual("12M", probe.PRIVATE_TMPFS_SIZE)
        tmpfs_mib = int(probe.PRIVATE_TMPFS_SIZE.rstrip("M"))
        self.assertGreater(tmpfs_mib, 8)
        self.assertLess(tmpfs_mib, 16)
        joined = "\n".join(probe.SYSTEMD_PROPERTIES_BASE)
        self.assertIn("LimitFSIZE=8M", joined)
        self.assertIn(
            f"/tmp:rw,nodev,nosuid,noexec,size={probe.PRIVATE_TMPFS_SIZE}",
            joined,
        )
        self.assertIn(
            f"/var/tmp:rw,nodev,nosuid,noexec,size={probe.PRIVATE_TMPFS_SIZE}",
            joined,
        )
        self.assertNotIn("size=8M", joined)

    def test_memory_oom_classification_requires_independent_evidence(self):
        self.assertEqual(
            "RESOURCE_OOM",
            probe.classify_memory_limit_outcome(
                "RESOURCE_OOM",
                "oom-kill",
                "oom 0\noom_kill 0",
                "oom 1\noom_kill 1",
            ),
        )
        with self.assertRaises(probe.ProbeError):
            probe.classify_memory_limit_outcome(
                "RESOURCE_OOM", "oom-kill", "", "oom_kill 1"
            )
        with self.assertRaises(probe.ProbeError):
            probe.classify_memory_limit_outcome(
                "RESOURCE_OOM", "oom-kill", "high 0", "high 1"
            )
        with self.assertRaises(probe.ProbeError):
            probe.classify_memory_limit_outcome(
                "RESOURCE_OOM", "oom-kill", "oom_kill 3", "oom_kill 3"
            )
        with self.assertRaises(probe.ProbeError):
            probe.classify_memory_limit_outcome(
                "SIGNAL", "signal", "oom_kill 0", "oom_kill 1"
            )

    def test_only_operator_cancel_gets_a_practical_window(self):
        self.assertEqual(20.0, probe.CASE_TIMEOUT_SECONDS)
        self.assertGreaterEqual(probe.OPERATOR_CANCEL_TIMEOUT_SECONDS, 120.0)
        self.assertGreaterEqual(
            probe.case_timeout_seconds("operator-cancel"),
            120.0,
        )
        self.assertEqual(
            probe.OPERATOR_CANCEL_TIMEOUT_SECONDS,
            probe.case_timeout_seconds("operator-cancel"),
        )
        for case_id in ("success", "timeout", "memory-limit", "fsize-limit"):
            self.assertEqual(
                probe.CASE_TIMEOUT_SECONDS,
                probe.case_timeout_seconds(case_id),
            )
            self.assertLess(probe.case_timeout_seconds(case_id), 120.0)


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

    def test_reviewed_source_hash_bindings_match_exact_files(self):
        discovery_env = self.text.split("  discovery:\n", 1)[1].split(
            "\n    steps:\n", 1
        )[0]
        expected_bindings = {
            "EXPECTED_PROBE_SHA256": TOOL_PATH,
            "EXPECTED_SCHEMA_SHA256": SCHEMA_PATH,
            "EXPECTED_TEST_SHA256": Path(__file__).resolve(),
        }
        for variable, path in expected_bindings.items():
            prefix = f"      {variable}: "
            values = [
                line.removeprefix(prefix)
                for line in discovery_env.splitlines()
                if line.startswith(prefix)
            ]
            self.assertEqual([hashlib.sha256(path.read_bytes()).hexdigest()], values)
        authorization_prefix = "      F7B1_HOSTED_AUTHORIZATION_SHA256: "
        authorization_values = [
            line.removeprefix(authorization_prefix)
            for line in discovery_env.splitlines()
            if line.startswith(authorization_prefix)
        ]
        self.assertEqual(
            [probe.DISCOVERY_F7B1_HOSTED_AUTHORIZATION_SHA256],
            authorization_values,
        )
        self.assertEqual(
            "4bb0e43fa71714b2bdbc31d474fc2903db7c39ecdab3600403681feb66125535",
            probe.DISCOVERY_F7B1_HOSTED_AUTHORIZATION_SHA256,
        )

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
            "BEGIN_F7B2_RAW_COMMIT_PARSER",
            "ordered merge parents mismatch",
            "merge tree does not equal head tree",
        ):
            self.assertIn(token, self.text)
        self.assertNotIn("git show -s --format='%P'", self.text)
        self.assertNotIn(
            "contains(github.event.pull_request.labels.*.name",
            self.text,
        )

    @classmethod
    def _raw_commit_parser(cls):
        blocks = []
        start_marker = "# BEGIN_F7B2_RAW_COMMIT_PARSER"
        end_marker = "# END_F7B2_RAW_COMMIT_PARSER"
        remaining = cls.text
        while start_marker in remaining:
            _, after_start = remaining.split(start_marker, 1)
            body, remaining = after_start.split(end_marker, 1)
            blocks.append(textwrap.dedent(body).strip() + "\n")
        if len(blocks) != 2 or blocks[0] != blocks[1]:
            raise AssertionError("expected two identical raw commit parsers")
        return blocks[0]

    def _run_raw_commit_parser(
        self,
        raw,
        *,
        expected_sha=None,
        base="1" * 40,
        head="2" * 40,
        tree="3" * 40,
    ):
        if expected_sha is None:
            expected_sha = hashlib.sha1(
                b"commit " + str(len(raw)).encode("ascii") + b"\0" + raw
            ).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            raw_path = Path(directory) / "commit.raw"
            raw_path.write_bytes(raw)
            return subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-",
                    str(raw_path),
                    expected_sha,
                    base,
                    head,
                    tree,
                ],
                input=self._raw_commit_parser(),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

    @staticmethod
    def _raw_merge_commit(
        *,
        tree="3" * 40,
        parents=("1" * 40, "2" * 40),
        extra_headers=(),
        message=b"merge\n",
        separator=b"\n\n",
    ):
        lines = [f"tree {tree}".encode("ascii")]
        lines.extend(f"parent {parent}".encode("ascii") for parent in parents)
        lines.extend(
            [
                b"author Test <test@example.com> 1 +0000",
                b"committer Test <test@example.com> 1 +0000",
                *extra_headers,
            ]
        )
        return b"\n".join(lines) + separator + message

    def test_raw_commit_parser_accepts_exact_headers_and_ignores_message(self):
        raw = self._raw_merge_commit(
            message=b"parent deadbeef\ntree deadbeef\nordinary message\n"
        )
        completed = self._run_raw_commit_parser(raw)
        self.assertEqual(0, completed.returncode, completed.stderr)

    def test_raw_commit_parser_rejects_all_adversarial_structural_variants(self):
        variants = {
            "zero-parents": self._raw_merge_commit(parents=()),
            "one-parent": self._raw_merge_commit(parents=("1" * 40,)),
            "three-parents": self._raw_merge_commit(
                parents=("1" * 40, "2" * 40, "4" * 40)
            ),
            "reversed-parents": self._raw_merge_commit(
                parents=("2" * 40, "1" * 40)
            ),
            "wrong-base": self._raw_merge_commit(
                parents=("4" * 40, "2" * 40)
            ),
            "wrong-head": self._raw_merge_commit(
                parents=("1" * 40, "4" * 40)
            ),
            "wrong-tree": self._raw_merge_commit(tree="4" * 40),
            "duplicate-tree": self._raw_merge_commit(
                extra_headers=(f"tree {'3' * 40}".encode("ascii"),)
            ),
            "extra-parent": self._raw_merge_commit(
                extra_headers=(f"parent {'4' * 40}".encode("ascii"),)
            ),
            "missing-separator": self._raw_merge_commit(separator=b"\n"),
            "cr-contamination": self._raw_merge_commit(
                message=b"message\r\n"
            ),
            "nul-contamination": self._raw_merge_commit(
                message=b"message\0\n"
            ),
            "bad-continuation": self._raw_merge_commit(
                extra_headers=(b" invalid continuation",)
            ),
            "malformed-header": self._raw_merge_commit(
                extra_headers=(b"malformed",)
            ),
        }
        for label, raw in variants.items():
            with self.subTest(label=label):
                completed = self._run_raw_commit_parser(raw)
                self.assertNotEqual(0, completed.returncode)

        raw = self._raw_merge_commit()
        completed = self._run_raw_commit_parser(
            raw,
            expected_sha="f" * 40,
        )
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("raw commit SHA-1 mismatch", completed.stderr)

    def test_identity_critical_git_operations_are_replacement_hardened(self):
        self.assertEqual(2, self.text.count("export GIT_NO_REPLACE_OBJECTS=1"))
        self.assertEqual(
            2,
            self.text.count(
                "git for-each-ref --format='%(refname)' refs/replace/"
            ),
        )
        self.assertEqual(
            2,
            self.text.count('graft_path="$(git rev-parse --git-path info/grafts)"'),
        )
        self.assertEqual(2, self.text.count('[[ ! -e "${graft_path}" ]]'))
        self.assertEqual(
            2,
            self.text.count(
                '[[ "$(git rev-parse --show-object-format)" == "sha1" ]]'
            ),
        )
        self.assertEqual(
            2,
            self.text.count(
                '[[ "$(git cat-file -t "${EXPECTED_MERGE_SHA}")" == "commit" ]]'
            ),
        )
        self.assertNotIn("git cat-file --filters", self.text)

    def test_depth_one_real_merge_uses_raw_parents_and_rejects_repo_substitution(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            env = {
                **os.environ,
                "GIT_AUTHOR_NAME": "Test",
                "GIT_AUTHOR_EMAIL": "test@example.com",
                "GIT_COMMITTER_NAME": "Test",
                "GIT_COMMITTER_EMAIL": "test@example.com",
            }

            def git(*args, input_bytes=None):
                return subprocess.run(
                    ["git", *args],
                    cwd=repo,
                    env=env,
                    input=input_bytes,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                ).stdout.strip()

            tree = git("mktree", input_bytes=b"").decode("ascii")
            base = git("commit-tree", tree, "-m", "base").decode("ascii")
            head = git(
                "commit-tree", tree, "-p", base, "-m", "head"
            ).decode("ascii")
            merge = git(
                "commit-tree",
                tree,
                "-p",
                base,
                "-p",
                head,
                "-m",
                "merge",
            ).decode("ascii")
            git_dir = Path(
                git("rev-parse", "--absolute-git-dir").decode("utf-8")
            )
            (git_dir / "shallow").write_text(f"{merge}\n", encoding="ascii")

            visible_parents = git("show", "-s", "--format=%P", merge)
            self.assertEqual(b"", visible_parents)
            raw = git("cat-file", "commit", merge)
            completed = self._run_raw_commit_parser(
                raw + b"\n",
                expected_sha=merge,
                base=base,
                head=head,
                tree=tree,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)

            other = git("commit-tree", tree, "-m", "other").decode("ascii")
            git("replace", merge, other)
            replacement_refs = git(
                "for-each-ref", "--format=%(refname)", "refs/replace/"
            )
            self.assertTrue(replacement_refs)

            graft_path = git_dir / "info" / "grafts"
            graft_path.parent.mkdir(parents=True, exist_ok=True)
            graft_path.write_text(f"{merge} {base} {head}\n", encoding="ascii")
            self.assertTrue(graft_path.exists())

            self.assertEqual(b"tree", git("cat-file", "-t", tree))

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


def _real_supervisor_skip_reason():
    import os
    import subprocess
    import sys

    if os.environ.get("P0_V2_RUNNER_INTEGRATION") != "1":
        return "opt-in P0_V2_RUNNER_INTEGRATION=1 not set"
    if sys.platform != "linux":
        return "not Linux"
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return "not root"
    for required_tool in (
        "/usr/bin/systemd-run",
        "/usr/bin/systemctl",
        "/usr/bin/python3",
    ):
        if not Path(required_tool).exists():
            return f"missing {required_tool}"
    if not Path("/sys/fs/cgroup/cgroup.controllers").exists():
        return "cgroup v2 unified hierarchy unavailable"
    for required_path in (
        "/proc/sys/kernel/core_pattern",
        "/sys/fs/cgroup/cgroup.procs",
        "/sys/fs/cgroup/cgroup.subtree_control",
    ):
        if not Path(required_path).exists():
            return f"missing {required_path}"
    try:
        completed = subprocess.run(
            ["/usr/bin/systemctl", "is-system-running"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"systemctl unusable: {exc!r}"
    system_state = completed.stdout.decode("utf-8", "replace").strip()
    if system_state not in {"running", "degraded"}:
        return f"systemd not usable (state={system_state!r})"
    return None


class RealSupervisorIntegrationTest(unittest.TestCase):
    """Opt-in smoke test for one benign case; not hosted feasibility proof."""

    def test_benign_success_case_runs_traverses_source_and_cleans_up(self):
        reason = _real_supervisor_skip_reason()
        if reason is not None:
            self.skipTest(f"real supervisor integration skipped: {reason}")
        import os
        import shutil
        import tempfile

        case_id = "success"
        self.assertIn(case_id, probe.CASES)
        self.assertEqual("SUCCESS", probe.EXPECTED_CASE_OUTCOMES[case_id])

        source_path = TOOL_PATH
        source_sha256 = probe.sha256_path(source_path)
        root_preexisted = probe.ROOT_RUNTIME.exists()
        probe.ROOT_RUNTIME.mkdir(
            parents=True,
            exist_ok=True,
            mode=probe.ROOT_RUNTIME_MODE,
        )
        os.chown(probe.ROOT_RUNTIME, 0, 0)
        os.chmod(probe.ROOT_RUNTIME, probe.ROOT_RUNTIME_MODE)
        try:
            with tempfile.TemporaryDirectory() as workdir:
                work = Path(workdir)
                journal = {
                    "phase": "core_pattern_suppressed",
                    "active_case": None,
                }
                case = probe.run_case(
                    case_id=case_id,
                    run_id="integration",
                    run_attempt="1",
                    head_sha="0" * 40,
                    source_path=source_path,
                    source_sha256=source_sha256,
                    schema_path=SCHEMA_PATH,
                    evidence_dir=work,
                    evidence_uid=os.getuid(),
                    evidence_gid=os.getgid(),
                    state_path=work / "state.json",
                    journal=journal,
                    lifecycle=[],
                )
            self.assertEqual([], case["errors"])
            self.assertEqual("SUCCESS", case["outcome"])
            cleanup = case["cleanup"]
            for flag in (
                "direct_cgroup_kill_written",
                "recursive_populated_zero_observed",
                "streams_eof_after_empty",
                "unit_unloaded_after_empty",
            ):
                self.assertTrue(cleanup[flag], flag)
            self.assertEqual(
                [],
                list(probe.ROOT_RUNTIME.glob("exec-*"))
                + list(probe.ROOT_RUNTIME.glob("case-*")),
            )
        finally:
            if not root_preexisted:
                shutil.rmtree(probe.ROOT_RUNTIME, ignore_errors=True)


class _FakeSelector:
    """A selector whose map is already empty, i.e. all streams are at EOF."""

    def get_map(self):
        return {}

    def close(self):
        pass


_MARKER_DEFAULT = object()


class FinalizerResumeTests(unittest.TestCase):
    """Resumable, monotonic cancellation-finalizer behaviour (T-F5)."""

    UNIT = "p0-v2-g1-000000000001-operator-cancel-aaaaaaaaaaaaaaaa.service"
    NONCE = "aaaaaaaaaaaaaaaa"

    def _release_marker(self, **overrides):
        marker = {
            "marker_version": probe.RELEASE_MARKER_VERSION,
            "invocation_id": "f" * 32,
            "nonce": self.NONCE,
            "run_id": "1",
            "run_attempt": "1",
            "unit": self.UNIT,
            "released_monotonic_ns": 4242,
        }
        marker.update(overrides)
        return marker

    def _active_case(self):
        active_case = {
            "unit": self.UNIT,
            "invocation_id": "f" * 32,
            "cgroup_path": "/system.slice/" + self.UNIT,
            "cgroup_device": 64,
            "cgroup_inode": 4096,
            "dynamic_uid": 60000,
            "dynamic_gid": 60000,
            "main_pid": 12345,
            "nonce": self.NONCE,
            "staged_probe": f"/run/p0-v2-gate1/exec-{self.NONCE}/probe.py",
            "staged_probe_device": 1,
            "staged_probe_inode": 2,
            "staged_probe_mode": 0o555,
            "staged_probe_uid": 0,
            "staged_probe_gid": 0,
            "host_tmp_sentinel": f"/tmp/p0-v2-host-{self.NONCE}",
            "host_tmp_sentinel_sha256": "0" * 64,
            "stdout_fifo": f"/run/p0-v2-gate1/case-{self.NONCE}/stdout.fifo",
            "stdout_fifo_device": 3,
            "stdout_fifo_inode": 4,
            "stderr_fifo": f"/run/p0-v2-gate1/case-{self.NONCE}/stderr.fifo",
            "stderr_fifo_device": 3,
            "stderr_fifo_inode": 5,
            "state_dir": f"/run/p0-v2-gate1/case-{self.NONCE}",
            "exec_dir": f"/run/p0-v2-gate1/exec-{self.NONCE}",
            "requested_argv": ["/usr/bin/python3", "-I", "/run/probe.py"],
            "kernel_observed_argv": ["/usr/bin/python3", "-I", "/run/probe.py"],
            "kernel_observed_argv_raw_base64": _raw_argv_b64(
                ["/usr/bin/python3", "-I", "/run/probe.py"]
            ),
            "requested_environment": dict(probe.REQUESTED_ENVIRONMENT),
            "kernel_observed_environment": dict(probe.REQUESTED_ENVIRONMENT),
            "kernel_observed_environment_raw_base64": _raw_env_b64(
                dict(probe.REQUESTED_ENVIRONMENT)
            ),
            "capture_fd_identity": {"1": {"target": "x"}, "2": {"target": "y"}},
        }
        active_case["systemd_properties"] = self._props(active_case)
        return active_case

    def _state(self, phase, evidence_dir, release_marker=_MARKER_DEFAULT):
        if release_marker is _MARKER_DEFAULT:
            # Post-release phases carry a matching durable marker; pre-release
            # phases (case_bound and earlier) carry none, mirroring the coupling
            # enforced by _validate_root_state_fields.
            release_marker = (
                None if phase in probe.PRE_RELEASE_PHASES else self._release_marker()
            )
        return {
            "journal_version": 1,
            "phase": phase,
            "run_id": "1",
            "run_attempt": "1",
            "head_sha": "a" * 40,
            "source_sha256": "0" * 64,
            "schema_sha256": "0" * 64,
            "workflow_file_sha256": "0" * 64,
            "test_file_sha256": "0" * 64,
            "evidence_dir": str(evidence_dir),
            "schema_path": str(SCHEMA_PATH),
            "core_pattern_original_base64": "",
            "core_pattern_original_recorded": True,
            "core_pattern_active_base64": "",
            "coredump_before": _coredump_snapshot(),
            "active_case": self._active_case(),
            "release_marker": release_marker,
            "terminal_evidence_sha256": "",
        }

    def _args(self, evidence_dir):
        return SimpleNamespace(
            command="finalize",
            run_id="1",
            run_attempt="1",
            pr_number="71",
            event_action="labeled",
            head_sha="a" * 40,
            head_repository="yurikuchumov-ux/ai-operating-system",
            head_ref="agent/issue-70-p0-v2-feasibility-gate1",
            base_sha=BASE_SHA,
            base_repository="yurikuchumov-ux/ai-operating-system",
            base_ref="main",
            merge_sha="b" * 40,
            repository="yurikuchumov-ux/ai-operating-system",
            workflow="p0-v2-runner-feasibility",
            workflow_ref=(
                "yurikuchumov-ux/ai-operating-system/.github/workflows/"
                "p0-v2-runner-feasibility.yml@refs/pull/71/merge"
            ),
            workflow_sha="c" * 40,
            workflow_file="/x/workflow.yml",
            test_file="/x/test.py",
            event_name="pull_request",
            runner_image="ubuntu-24.04",
            runner_arch="X64",
            source_path="/x/probe.py",
            schema_path=str(SCHEMA_PATH),
            evidence_dir=str(evidence_dir),
            evidence_uid=os.getuid(),
            evidence_gid=os.getgid(),
        )

    def _props(self, active_case):
        # Exactly the SYSTEMD_SHOW_PROPERTIES key set, matching what the real
        # systemctl_properties returns, so the fixture is also a valid durable
        # active case under _validate_root_state_fields.
        properties = {name: "observed" for name in probe.SYSTEMD_SHOW_PROPERTIES}
        properties.update(
            {
                "Type": "exec",
                "InvocationID": active_case["invocation_id"],
                "ControlGroup": active_case["cgroup_path"],
                "MainPID": str(active_case["main_pid"]),
            }
        )
        return properties

    def _host_obs(self):
        return [
            probe.observation(f"host.probe_{index}", "kernel_observed", str(index))
            for index in range(6)
        ]

    def _drive(self, phase, *, bind_error=None, cgroup_error=None,
               systemctl_error=None, verify_error=None,
               sentinel_error=None, write_error_phase=None,
               real_seal=False, evidence_dir=None,
               release_marker=_MARKER_DEFAULT, args_overrides=None):
        evidence_dir = evidence_dir or "/run/p0-v2-gate1/evidence"
        state = self._state(phase, evidence_dir, release_marker=release_marker)
        args = self._args(evidence_dir)
        for key, value in (args_overrides or {}).items():
            setattr(args, key, value)
        active_case = state["active_case"]
        recorded = []
        opened_fds = []

        def _dev(flags):
            fd = os.open(os.devnull, flags)
            opened_fds.append(fd)
            return fd

        def _record_write(_state_path, current):
            if current["phase"] == write_error_phase:
                raise probe.ProbeError("STATE_WRITE_INJECTED", current["phase"])
            # Do not let the harness "persist" an impossible journal. This keeps
            # mocked finalizer tests honest with the real hardened writer.
            probe._validate_root_state_fields(current)
            recorded.append(current["phase"])

        def _bind(_active_case):
            if bind_error is not None:
                raise bind_error
            return _FakeSelector(), _dev(os.O_RDONLY)

        def _open_cgroup(_active_case):
            if cgroup_error is not None:
                raise cgroup_error
            return _dev(os.O_RDONLY), _dev(os.O_WRONLY)

        sealed = {}

        def _seal(_path, evidence, _schema_path, _uid, _gid):
            sealed["evidence"] = evidence
            return "d" * 64

        stack = ExitStack()
        self.addCleanup(stack.close)
        enter = stack.enter_context
        enter(mock.patch("os.geteuid", return_value=0))
        enter(mock.patch.object(probe, "CORE_PATTERN_PATH",
                                Path("/nonexistent-core-pattern-xyz")))
        enter(
            mock.patch.object(
                probe,
                "load_root_state",
                side_effect=lambda _path: probe._validate_root_state_fields(state),
            )
        )
        enter(mock.patch.object(probe, "write_root_state", side_effect=_record_write))
        enter(mock.patch.object(probe, "sha256_path", return_value="0" * 64))
        enter(mock.patch.object(probe, "read_text", return_value="boot"))
        enter(mock.patch.object(probe, "read_limited_bytes", return_value=b""))
        enter(mock.patch.object(probe, "host_preflight",
                                return_value=(self._host_obs(), [])))
        enter(mock.patch.object(probe, "coredump_effect_snapshot",
                                return_value=_coredump_snapshot()))
        enter(mock.patch.object(probe, "journal_delta_since",
                                return_value=_journal_interval()))
        systemctl = enter(mock.patch.object(
            probe,
            "systemctl_properties",
            return_value=self._props(active_case),
            side_effect=systemctl_error,
        ))
        enter(mock.patch.object(probe, "wait_cgroup_empty", return_value=True))
        enter(mock.patch.object(probe, "drain_streams", return_value=0))
        enter(mock.patch.object(probe, "restore_core_pattern", return_value=b"x"))
        verify = enter(mock.patch.object(
            probe,
            "finalizer_verify_live_child_identity",
            side_effect=verify_error,
        ))
        write_kill = enter(mock.patch.object(probe, "finalizer_write_cgroup_kill"))
        unload = enter(mock.patch.object(probe, "unload_unit"))
        sentinel_verify = enter(
            mock.patch.object(
                probe,
                "finalizer_verify_host_sentinel",
                side_effect=sentinel_error,
            )
        )
        consume = enter(mock.patch.object(probe, "finalizer_consume_host_sentinel"))
        bind = enter(mock.patch.object(probe, "finalizer_bind_capture_fifos",
                                       side_effect=_bind))
        cgroup = enter(mock.patch.object(probe, "finalizer_open_trusted_cgroup",
                                         side_effect=_open_cgroup))
        if not real_seal:
            enter(mock.patch.object(probe, "atomic_seal", side_effect=_seal))
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            return_code = probe.finalize_cancelled(args)
        return SimpleNamespace(
            rc=return_code,
            out=buffer.getvalue(),
            state=state,
            recorded=recorded,
            evidence=sealed.get("evidence"),
            verify=verify,
            write_kill=write_kill,
            unload=unload,
            sentinel_verify=sentinel_verify,
            consume=consume,
            systemctl=systemctl,
            bind=bind,
            cgroup=cgroup,
        )

    def test_phase_rank_orders_entries_and_rejects_unknown(self):
        self.assertEqual(-1, probe.finalizer_phase_rank("fixture_released"))
        self.assertEqual(-1, probe.finalizer_phase_rank("case_bound"))
        self.assertEqual(0, probe.finalizer_phase_rank("finalizer_started"))
        self.assertEqual(2, probe.finalizer_phase_rank("cgroup_kill_written"))
        self.assertEqual(9, probe.finalizer_phase_rank("evidence_sealed"))
        for bad in ("initialized", "core_pattern_suppressed", "bogus"):
            with self.assertRaises(probe.ProbeError) as ctx:
                probe.finalizer_phase_rank(bad)
            self.assertEqual("FINALIZER_PHASE_UNKNOWN", ctx.exception.code)

    def test_phase_transition_rejects_regression_and_unknown(self):
        probe.validate_finalizer_phase_transition("fixture_released", "finalizer_started")
        probe.validate_finalizer_phase_transition("finalizer_started", "finalizer_bound")
        probe.validate_finalizer_phase_transition(
            "unit_unloaded", "host_sentinel_verified"
        )
        probe.validate_finalizer_phase_transition(
            "host_sentinel_consumed", "core_pattern_restored"
        )
        for current, target in (
            ("cgroup_kill_written", "finalizer_bound"),
            ("cgroup_kill_written", "cgroup_kill_written"),
            ("evidence_sealed", "unit_unloaded"),
        ):
            with self.assertRaises(probe.ProbeError) as ctx:
                probe.validate_finalizer_phase_transition(current, target)
            self.assertEqual("FINALIZER_PHASE_REGRESSION", ctx.exception.code)
        with self.assertRaises(probe.ProbeError) as ctx2:
            probe.validate_finalizer_phase_transition("finalizer_started", "bogus")
        self.assertEqual("FINALIZER_PHASE_UNKNOWN", ctx2.exception.code)
        with self.assertRaises(probe.ProbeError) as ctx3:
            probe.validate_finalizer_phase_transition(
                "unit_unloaded", "core_pattern_restored"
            )
        self.assertEqual("FINALIZER_PHASE_GAP", ctx3.exception.code)

    def test_resume_plan_gates_live_checks_on_pre_kill_phases(self):
        table = {
            "fixture_released": (
                False, False, False, False, False, False, False, False, True
            ),
            "finalizer_started": (
                True, False, False, False, False, False, False, False, True
            ),
            "finalizer_bound": (
                True, False, False, False, False, False, False, False, True
            ),
            "cgroup_kill_written": (
                True, True, False, False, False, False, False, False, False
            ),
            "cgroup_empty_observed": (
                True, True, True, False, False, False, False, False, False
            ),
            "stream_eof_observed": (
                True, True, True, True, False, False, False, False, False
            ),
            "unit_unloaded": (
                True, True, True, True, True, False, False, False, False
            ),
            "host_sentinel_verified": (
                True, True, True, True, True, True, False, False, False
            ),
            "host_sentinel_consumed": (
                True, True, True, True, True, True, True, False, False
            ),
            "core_pattern_restored": (
                True, True, True, True, True, True, True, True, False
            ),
        }
        for phase, expected in table.items():
            plan = probe.plan_finalizer_resume(phase)
            got = (
                plan.started,
                plan.kill_written,
                plan.empty,
                plan.eof,
                plan.unloaded,
                plan.sentinel_verified,
                plan.sentinel_consumed,
                plan.restored,
                plan.run_live_identity_checks,
            )
            self.assertEqual(expected, got, phase)

    def test_trusted_cgroup_open_fails_closed_without_touching_kill(self):
        active_case = {
            "cgroup_path": "/system.slice/x.service",
            "cgroup_device": 1,
            "cgroup_inode": 2,
        }
        mismatched = os.stat_result(
            (stat.S_IFDIR | 0o755, 999, 999, 1, 0, 0, 0, 0, 0, 0)
        )
        opened = []

        def fake_open(path, *args, **kwargs):
            opened.append(str(path))
            return os.open(os.devnull, os.O_RDONLY)

        with mock.patch.object(probe.Path, "stat", return_value=mismatched), \
                mock.patch("os.open", side_effect=fake_open):
            with self.assertRaises(probe.ProbeError) as ctx:
                probe.finalizer_open_trusted_cgroup(active_case)
        self.assertEqual("CGROUP_IDENTITY_MISMATCH", ctx.exception.code)
        self.assertEqual([], opened)

    def test_live_child_identity_reports_specific_mismatches(self):
        active_case = self._active_case()
        good = self._props(active_case)
        bad_invocation = dict(good, InvocationID="0" * 32)
        with self.assertRaises(probe.ProbeError) as ctx:
            probe.finalizer_verify_live_child_identity(active_case, bad_invocation)
        self.assertEqual("INVOCATION_ID_MISMATCH", ctx.exception.code)
        bad_pid = dict(good, MainPID="999999")
        with self.assertRaises(probe.ProbeError) as ctx2:
            probe.finalizer_verify_live_child_identity(active_case, bad_pid)
        self.assertEqual("MAIN_PID_MISMATCH", ctx2.exception.code)

    def test_pre_kill_phases_validate_live_child_and_kill_once(self):
        for phase in ("fixture_released", "finalizer_started", "finalizer_bound"):
            with self.subTest(phase=phase):
                result = self._drive(phase)
                self.assertEqual(0, result.rc, result.out)
                self.assertIn("ACTIONS_CANCELLED", result.out)
                self.assertTrue(result.verify.called)
                self.assertTrue(result.write_kill.called)

    def test_resume_at_or_after_kill_never_touches_dead_child(self):
        for phase in (
            "cgroup_kill_written",
            "cgroup_empty_observed",
            "stream_eof_observed",
            "unit_unloaded",
            "host_sentinel_verified",
            "host_sentinel_consumed",
            "core_pattern_restored",
        ):
            with self.subTest(phase=phase):
                result = self._drive(phase)
                self.assertEqual(0, result.rc, result.out)
                self.assertIn("ACTIONS_CANCELLED", result.out)
                self.assertFalse(result.verify.called)
                self.assertFalse(result.write_kill.called)

    def test_resume_after_unload_does_not_repeat_destructive_cleanup(self):
        result = self._drive("unit_unloaded")
        self.assertEqual(0, result.rc, result.out)
        self.assertIn("ACTIONS_CANCELLED", result.out)
        self.assertFalse(result.write_kill.called)
        self.assertFalse(result.unload.called)
        self.assertTrue(result.sentinel_verify.called)
        self.assertTrue(result.consume.called)
        self.assertFalse(result.systemctl.called)
        self.assertFalse(result.cgroup.called)
        self.assertIn("host_sentinel_verified", result.recorded)
        self.assertIn("host_sentinel_consumed", result.recorded)
        self.assertIn("core_pattern_restored", result.recorded)
        self.assertIn("evidence_sealed", result.recorded)

    def test_resume_after_verified_sentinel_accepts_crash_after_unlink(self):
        result = self._drive("host_sentinel_verified")
        self.assertEqual(0, result.rc, result.out)
        self.assertFalse(result.unload.called)
        self.assertFalse(result.sentinel_verify.called)
        result.consume.assert_called_once_with(
            result.consume.call_args.args[0],
            allow_already_absent=True,
        )
        self.assertFalse(result.systemctl.called)
        self.assertIn("host_sentinel_consumed", result.recorded)

    def test_resume_after_consumed_sentinel_repeats_no_one_shot_action(self):
        result = self._drive("host_sentinel_consumed")
        self.assertEqual(0, result.rc, result.out)
        self.assertFalse(result.unload.called)
        self.assertFalse(result.sentinel_verify.called)
        self.assertFalse(result.consume.called)
        self.assertFalse(result.systemctl.called)

    def test_missing_sentinel_requires_durable_prior_verification(self):
        active_case = self._active_case()
        with mock.patch.object(Path, "unlink", side_effect=FileNotFoundError):
            probe.finalizer_consume_host_sentinel(
                active_case,
                allow_already_absent=True,
            )
            with self.assertRaises(probe.ProbeError) as ctx:
                probe.finalizer_consume_host_sentinel(
                    active_case,
                    allow_already_absent=False,
                )
        self.assertEqual("HOST_TMP_ISOLATION_FAILED", ctx.exception.code)

    def test_failed_consumed_phase_write_rolls_back_to_durable_verified_phase(self):
        result = self._drive(
            "host_sentinel_verified",
            write_error_phase="host_sentinel_consumed",
        )
        self.assertEqual(3, result.rc, result.out)
        self.assertEqual("host_sentinel_verified", result.state["phase"])
        self.assertTrue(result.consume.called)
        self.assertNotIn("core_pattern_restored", result.recorded)
        self.assertNotIn("evidence_sealed", result.recorded)

    def test_failed_sentinel_verification_cannot_skip_to_restored_phase(self):
        result = self._drive(
            "unit_unloaded",
            sentinel_error=probe.ProbeError("HOST_TMP_ISOLATION_FAILED", "sentinel"),
        )
        self.assertEqual(1, result.rc, result.out)
        self.assertIn("CLEANUP_FAILURE", result.out)
        self.assertEqual("unit_unloaded", result.state["phase"])
        self.assertFalse(result.consume.called)
        self.assertNotIn("core_pattern_restored", result.recorded)
        self.assertNotIn("evidence_sealed", result.recorded)

    def test_resume_after_empty_completes_eof_and_unload_once(self):
        result = self._drive("cgroup_empty_observed")
        self.assertEqual(0, result.rc, result.out)
        self.assertFalse(result.write_kill.called)
        self.assertFalse(result.cgroup.called)
        self.assertTrue(result.unload.called)
        self.assertTrue(result.consume.called)

    def test_resume_after_eof_unloads_without_rebinding_streams(self):
        result = self._drive("stream_eof_observed")
        self.assertEqual(0, result.rc, result.out)
        self.assertFalse(result.bind.called)
        self.assertFalse(result.write_kill.called)
        self.assertTrue(result.unload.called)
        self.assertTrue(result.consume.called)

    def test_pre_kill_fifo_mismatch_still_kills_and_refuses_positive_proof(self):
        result = self._drive(
            "fixture_released",
            bind_error=probe.ProbeError("FIFO_IDENTITY_MISMATCH", "stdout"),
        )
        self.assertTrue(result.write_kill.called)
        self.assertEqual(1, result.rc)
        self.assertIn("CLEANUP_FAILURE", result.out)
        self.assertNotIn("ACTIONS_CANCELLED", result.out)
        codes = [item["code"] for item in result.evidence["errors"]]
        self.assertIn("FIFO_IDENTITY_MISMATCH", codes)
        self.assertFalse(
            result.evidence["cancellation"]["same_vm_cleanup_observed"]
        )

    def test_pre_kill_fifo_open_error_still_kills_and_refuses_positive_proof(self):
        result = self._drive(
            "fixture_released",
            bind_error=FileNotFoundError("fifo unavailable"),
        )
        self.assertTrue(result.write_kill.called)
        self.assertEqual(1, result.rc)
        codes = [item["code"] for item in result.evidence["errors"]]
        self.assertIn("FIFO_BIND_FAILED", codes)

    def test_systemctl_timeout_still_kills_and_refuses_positive_proof(self):
        result = self._drive(
            "fixture_released",
            systemctl_error=subprocess.TimeoutExpired(["systemctl"], 1),
        )
        self.assertTrue(result.write_kill.called)
        self.assertFalse(result.verify.called)
        self.assertEqual(1, result.rc)
        codes = [item["code"] for item in result.evidence["errors"]]
        self.assertIn("SYSTEMD_PROPERTIES_UNAVAILABLE", codes)

    def test_live_proc_disappearance_still_kills_and_refuses_positive_proof(self):
        result = self._drive(
            "fixture_released",
            verify_error=FileNotFoundError("/proc/12345/fd/1"),
        )
        self.assertTrue(result.write_kill.called)
        self.assertEqual(1, result.rc)
        codes = [item["code"] for item in result.evidence["errors"]]
        self.assertIn("LIVE_CHILD_IDENTITY_UNAVAILABLE", codes)

    def test_cgroup_identity_mismatch_fails_closed_without_kill(self):
        result = self._drive(
            "fixture_released",
            cgroup_error=probe.ProbeError("CGROUP_IDENTITY_MISMATCH", "cgroup"),
        )
        self.assertFalse(result.write_kill.called)
        self.assertEqual(1, result.rc)
        self.assertIn("CLEANUP_FAILURE", result.out)
        codes = [item["code"] for item in result.evidence["errors"]]
        self.assertIn("CGROUP_IDENTITY_MISMATCH", codes)
        self.assertFalse(
            result.evidence["cases"][0]["cleanup"]["direct_cgroup_kill_written"]
        )

    def test_fresh_cancel_seals_valid_actions_cancelled_evidence(self):
        with tempfile.TemporaryDirectory() as evidence_dir:
            result = self._drive(
                "fixture_released", real_seal=True, evidence_dir=evidence_dir
            )
            self.assertEqual(0, result.rc, result.out)
            self.assertIn("ACTIONS_CANCELLED", result.out)
            sealed = json.loads(
                (Path(evidence_dir) / "candidate-evidence.json").read_text(
                    encoding="utf-8"
                )
            )
        self.assertEqual("ACTIONS_CANCELLED", sealed["outcome"])
        self.assertEqual(
            [
                "finalizer_started",
                "cgroup_kill_written",
                "cgroup_empty_observed",
                "streams_eof_observed",
                "unit_unloaded",
                "core_pattern_restored",
                "finalizer_complete",
            ],
            [event["name"] for event in sealed["lifecycle"]],
        )
        host_names = {o["name"] for o in sealed["host"]}
        self.assertIn("host.coredump_effects_before", host_names)
        self.assertIn("host.coredump_effects_after", host_names)
        self.assertIn("host.journal_delta", host_names)
        probe.validate_evidence(sealed, SCHEMA_PATH)

    def test_evidence_sealed_phase_is_idempotent(self):
        with tempfile.TemporaryDirectory() as evidence_dir:
            evidence_path = Path(evidence_dir) / "candidate-evidence.json"
            payload = json.dumps(
                {
                    "outcome": "ACTIONS_CANCELLED",
                    "cancellation": {
                        "claim_type": "ordinary_github_cancellation",
                    },
                }
            ).encode("utf-8")
            evidence_path.write_bytes(payload)
            digest = probe.sha256_bytes(payload)
            manifest = {
                "manifest_version": "1.0.0",
                "evidence_file": evidence_path.name,
                "evidence_sha256": digest,
            }
            evidence_path.with_suffix(
                evidence_path.suffix + ".manifest.json"
            ).write_text(json.dumps(manifest), encoding="utf-8")
            state = self._state("evidence_sealed", evidence_dir)
            state["terminal_evidence_sha256"] = digest
            args = self._args(evidence_dir)
            stack = ExitStack()
            self.addCleanup(stack.close)
            stack.enter_context(mock.patch("os.geteuid", return_value=0))
            stack.enter_context(
                mock.patch.object(probe, "load_root_state", return_value=state)
            )
            def _sha(path, _digest=digest):
                if str(path).endswith("candidate-evidence.json"):
                    return _digest
                return "0" * 64

            stack.enter_context(
                mock.patch.object(probe, "sha256_path", side_effect=_sha)
            )
            kill = stack.enter_context(
                mock.patch.object(probe, "finalizer_write_cgroup_kill")
            )
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                return_code = probe.finalize_cancelled(args)
        self.assertEqual(0, return_code, buffer.getvalue())
        self.assertIn("ACTIONS_CANCELLED", buffer.getvalue())
        self.assertIn(digest, buffer.getvalue())
        self.assertFalse(kill.called)

    # --- T-F4: durable post-release cancellation proof ------------------------

    def test_durable_case_bound_cleans_up_but_seals_unobserved(self):
        # Cancellation observed at a durable case_bound (no post-release marker):
        # the identity-bound safety kill and full cleanup still run, yet the seal
        # is INCONCLUSIVE / unobserved and never claims ordinary cancellation.
        result = self._drive("case_bound")
        self.assertEqual(1, result.rc, result.out)
        self.assertNotIn("ACTIONS_CANCELLED", result.out)
        self.assertIn("P0_V2_FINALIZER_STATUS=INCONCLUSIVE", result.out)
        self.assertTrue(result.write_kill.called)
        self.assertTrue(result.unload.called)
        self.assertTrue(result.consume.called)
        evidence = result.evidence
        self.assertEqual("INCONCLUSIVE", evidence["outcome"])
        self.assertEqual("INCONCLUSIVE", evidence["cases"][0]["outcome"])
        cancellation = evidence["cancellation"]
        self.assertEqual("unobserved", cancellation["claim_type"])
        self.assertNotEqual("ordinary_github_cancellation", cancellation["claim_type"])
        self.assertTrue(cancellation["finalizer_ran"])
        # cleanup fully succeeded, so same_vm_cleanup_observed reports that fact
        # rather than being falsely equated with cancellation proof.
        self.assertTrue(cancellation["same_vm_cleanup_observed"])
        self.assertFalse(cancellation["force_cancellation_proven"])
        # The proof-ineligible path still advances every F5 recovery phase, so a
        # crash never replays already completed destructive cleanup.
        self.assertEqual(
            [
                "finalizer_started",
                "finalizer_bound",
                "cgroup_kill_written",
                "cgroup_empty_observed",
                "stream_eof_observed",
                "unit_unloaded",
                "host_sentinel_verified",
                "host_sentinel_consumed",
                "core_pattern_restored",
                "evidence_sealed",
            ],
            result.recorded,
        )
        case_obs = {o["name"]: o for o in evidence["cases"][0]["observations"]}
        self.assertIsNone(case_obs["cancellation.release_marker"]["value"])
        self.assertFalse(case_obs["cancellation.release_proof_eligible"]["value"])

    def test_case_bound_inconclusive_evidence_passes_validators(self):
        with tempfile.TemporaryDirectory() as evidence_dir:
            result = self._drive(
                "case_bound", real_seal=True, evidence_dir=evidence_dir
            )
            self.assertEqual(1, result.rc, result.out)
            self.assertNotIn("ACTIONS_CANCELLED", result.out)
            sealed = json.loads(
                (Path(evidence_dir) / "candidate-evidence.json").read_text("utf-8")
            )
        self.assertEqual("INCONCLUSIVE", sealed["outcome"])
        self.assertEqual("unobserved", sealed["cancellation"]["claim_type"])
        self.assertNotIn("finalizer_complete", [e["name"] for e in sealed["lifecycle"]])
        # Both the probe validator (which also runs the JSON schema) accept it.
        probe.validate_evidence(sealed, SCHEMA_PATH)

    def test_fixture_released_matching_marker_keeps_positive_proof(self):
        result = self._drive("fixture_released")
        self.assertEqual(0, result.rc, result.out)
        self.assertIn("P0_V2_FINALIZER_STATUS=ACTIONS_CANCELLED", result.out)
        cancellation = result.evidence["cancellation"]
        self.assertEqual(
            "ordinary_github_cancellation", cancellation["claim_type"]
        )
        self.assertTrue(cancellation["same_vm_cleanup_observed"])
        self.assertFalse(cancellation["force_cancellation_proven"])

    def test_missing_marker_at_fixture_released_is_rejected(self):
        state = self._state(
            "fixture_released",
            "/run/p0-v2-gate1/evidence",
            release_marker=None,
        )
        with self.assertRaises(probe.ProbeError) as ctx:
            probe._validate_root_state_fields(state)
        self.assertEqual("STATE_UNTRUSTED", ctx.exception.code)

    def test_marker_free_finalizer_phases_are_valid_nonproof_recovery(self):
        for phase in probe.FINALIZER_PHASE_SEQUENCE:
            with self.subTest(phase=phase):
                state = self._state(
                    phase,
                    "/run/p0-v2-gate1/evidence",
                    release_marker=None,
                )
                self.assertEqual(state, probe._validate_root_state_fields(state))

    def test_pre_release_phase_rejects_injected_marker(self):
        for phase in (
            "initialized",
            "core_pattern_original_recorded",
            "core_pattern_suppressed",
            "case_bound",
        ):
            with self.subTest(phase=phase):
                state = self._state(
                    phase,
                    "/run/p0-v2-gate1/evidence",
                    release_marker=self._release_marker(),
                )
                with self.assertRaises(probe.ProbeError) as ctx:
                    probe._validate_root_state_fields(state)
                self.assertEqual("STATE_UNTRUSTED", ctx.exception.code)

    def test_valid_released_marker_round_trips_through_validation(self):
        state = self._state("fixture_released", "/run/p0-v2-gate1/evidence")
        self.assertEqual(state, probe._validate_root_state_fields(state))

    def test_marker_field_and_binding_faults_fail_closed(self):
        base = "/run/p0-v2-gate1/evidence"
        for label, marker in (
            ("version", self._release_marker(marker_version=2)),
            ("extra_field", {**self._release_marker(), "extra": 1}),
            ("bad_invocation", self._release_marker(invocation_id="z" * 32)),
            ("bad_nonce", self._release_marker(nonce="zz")),
            ("negative_ts", self._release_marker(released_monotonic_ns=-1)),
            ("bool_ts", self._release_marker(released_monotonic_ns=True)),
            ("run_id_binding", self._release_marker(run_id="999")),
            ("run_attempt_binding", self._release_marker(run_attempt="9")),
            ("invocation_binding", self._release_marker(invocation_id="0" * 32)),
            ("nonce_binding", self._release_marker(nonce="b" * 16)),
            ("unit_binding", self._release_marker(unit=self.UNIT.replace("aaaa", "bbbb"))),
        ):
            with self.subTest(label=label):
                state = self._state("fixture_released", base, release_marker=marker)
                with self.assertRaises(probe.ProbeError) as ctx:
                    probe._validate_root_state_fields(state)
                self.assertEqual("STATE_UNTRUSTED", ctx.exception.code)

    def test_finalizer_run_mismatch_suppresses_proof_not_cleanup(self):
        # The marker remains valid against its trusted journal and active case,
        # but mismatched finalizer job arguments cannot authorize proof.
        for label, args_overrides in (
            ("run_id", {"run_id": "999"}),
            ("run_attempt", {"run_attempt": "2"}),
        ):
            with self.subTest(dimension=label):
                result = self._drive(
                    "fixture_released",
                    args_overrides=args_overrides,
                )
                self.assertEqual(1, result.rc, result.out)
                self.assertNotIn("ACTIONS_CANCELLED", result.out)
                self.assertIn("P0_V2_FINALIZER_STATUS=INCONCLUSIVE", result.out)
                # safe cleanup still ran to completion
                self.assertTrue(result.write_kill.called)
                self.assertTrue(result.unload.called)
                cancellation = result.evidence["cancellation"]
                self.assertEqual("unobserved", cancellation["claim_type"])
                self.assertTrue(cancellation["same_vm_cleanup_observed"])

    def test_marker_free_resume_after_unload_never_replays_destructive_cleanup(self):
        result = self._drive("unit_unloaded", release_marker=None)
        self.assertEqual(1, result.rc, result.out)
        self.assertIn("P0_V2_FINALIZER_STATUS=INCONCLUSIVE", result.out)
        self.assertFalse(result.write_kill.called)
        self.assertFalse(result.unload.called)
        self.assertFalse(result.systemctl.called)
        self.assertFalse(result.cgroup.called)
        self.assertTrue(result.sentinel_verify.called)
        self.assertTrue(result.consume.called)
        self.assertEqual(
            [
                "host_sentinel_verified",
                "host_sentinel_consumed",
                "core_pattern_restored",
                "evidence_sealed",
            ],
            result.recorded,
        )

    def test_marker_free_terminal_inconclusive_is_idempotent(self):
        with tempfile.TemporaryDirectory() as evidence_dir:
            evidence_path = Path(evidence_dir) / "candidate-evidence.json"
            payload = json.dumps(
                {
                    "outcome": "INCONCLUSIVE",
                    "cancellation": {"claim_type": "unobserved"},
                }
            ).encode("utf-8")
            evidence_path.write_bytes(payload)
            digest = probe.sha256_bytes(payload)
            evidence_path.with_suffix(
                evidence_path.suffix + ".manifest.json"
            ).write_text(
                json.dumps(
                    {
                        "manifest_version": "1.0.0",
                        "evidence_file": evidence_path.name,
                        "evidence_sha256": digest,
                    }
                ),
                encoding="utf-8",
            )
            state = self._state(
                "evidence_sealed",
                evidence_dir,
                release_marker=None,
            )
            state["terminal_evidence_sha256"] = digest
            args = self._args(evidence_dir)
            with (
                mock.patch("os.geteuid", return_value=0),
                mock.patch.object(probe, "load_root_state", return_value=state),
                mock.patch.object(
                    probe,
                    "sha256_path",
                    side_effect=lambda path: (
                        digest
                        if str(path).endswith("candidate-evidence.json")
                        else "0" * 64
                    ),
                ),
                mock.patch.object(probe, "finalizer_write_cgroup_kill") as kill,
                redirect_stdout(io.StringIO()) as buffer,
            ):
                rc = probe.finalize_cancelled(args)
        self.assertEqual(1, rc, buffer.getvalue())
        self.assertIn("P0_V2_FINALIZER_STATUS=INCONCLUSIVE", buffer.getvalue())
        self.assertIn(digest, buffer.getvalue())
        self.assertFalse(kill.called)

    def test_failed_release_marker_write_cannot_authorize_proof(self):
        # A fixture_released journal with no bound marker is rejected before any
        # bytes are published, so a partial or failed marker/phase write can never
        # leave a durable state that authorizes ordinary-cancellation proof.
        state = self._state(
            "fixture_released", "/run/p0-v2-gate1/evidence", release_marker=None
        )
        with mock.patch.object(probe.os, "open") as opened:
            with self.assertRaises(probe.ProbeError) as ctx:
                probe.write_root_state(Path("/unused/state.json"), state)
        self.assertEqual("STATE_UNTRUSTED", ctx.exception.code)
        opened.assert_not_called()

    def test_matching_marker_evidence_embeds_marker_and_validates(self):
        with tempfile.TemporaryDirectory() as evidence_dir:
            result = self._drive(
                "fixture_released", real_seal=True, evidence_dir=evidence_dir
            )
            self.assertEqual(0, result.rc, result.out)
            self.assertIn("ACTIONS_CANCELLED", result.out)
            sealed = json.loads(
                (Path(evidence_dir) / "candidate-evidence.json").read_text("utf-8")
            )
        self.assertEqual("ACTIONS_CANCELLED", sealed["outcome"])
        self.assertEqual(
            "ordinary_github_cancellation", sealed["cancellation"]["claim_type"]
        )
        case_obs = {o["name"]: o for o in sealed["cases"][0]["observations"]}
        marker_obs = case_obs["cancellation.release_marker"]
        self.assertEqual("supervisor_observed", marker_obs["authority"])
        self.assertEqual(self._release_marker(), marker_obs["value"])
        self.assertTrue(case_obs["cancellation.release_proof_eligible"]["value"])
        # Passes both current validators (probe validator runs the JSON schema).
        probe.validate_evidence(sealed, SCHEMA_PATH)
        schema = json.loads(SCHEMA_PATH.read_text("utf-8"))
        probe.validate_schema_instance(sealed, schema, schema)

    def test_release_marker_matches_requires_exact_five_way_binding(self):
        active_case = self._active_case()
        marker = self._release_marker()
        self.assertTrue(
            probe.release_marker_matches(marker, active_case, "1", "1")
        )
        self.assertFalse(probe.release_marker_matches(None, active_case, "1", "1"))
        self.assertFalse(
            probe.release_marker_matches(marker, active_case, "1", "2")
        )
        self.assertFalse(
            probe.release_marker_matches(
                self._release_marker(unit="p0-v2-g1-other.service"),
                active_case,
                "1",
                "1",
            )
        )


class ReleaseMarkerSupervisorSourceTests(unittest.TestCase):
    """The supervisor binds and clears the durable release marker correctly."""

    def _publish(self, journal):
        probe.release_fixture_and_record(
            barrier_fd=17,
            state_path=Path("/unused/state.json"),
            journal=journal,
            invocation_id="f" * 32,
            nonce="a" * 16,
            run_id="1",
            run_attempt="2",
            unit="p0-v2-g1-test.service",
        )

    def test_complete_release_and_durable_write_publish_exact_marker(self):
        journal = {"phase": "case_bound", "release_marker": None}
        with (
            mock.patch.object(probe.os, "write", return_value=1) as release,
            mock.patch.object(probe.time, "monotonic_ns", return_value=4242),
            mock.patch.object(probe, "write_root_state") as write_state,
        ):
            self._publish(journal)
        release.assert_called_once_with(17, b"R")
        write_state.assert_called_once_with(Path("/unused/state.json"), journal)
        self.assertEqual("fixture_released", journal["phase"])
        self.assertEqual(
            {
                "marker_version": probe.RELEASE_MARKER_VERSION,
                "invocation_id": "f" * 32,
                "nonce": "a" * 16,
                "run_id": "1",
                "run_attempt": "2",
                "unit": "p0-v2-g1-test.service",
                "released_monotonic_ns": 4242,
            },
            journal["release_marker"],
        )

    def test_incomplete_release_byte_never_builds_or_persists_marker(self):
        journal = {"phase": "case_bound", "release_marker": None}
        with (
            mock.patch.object(probe.os, "write", return_value=0),
            mock.patch.object(probe, "write_root_state") as write_state,
            self.assertRaises(probe.ProbeError) as ctx,
        ):
            self._publish(journal)
        self.assertEqual("FIXTURE_RELEASE_WRITE_INCOMPLETE", ctx.exception.code)
        self.assertEqual({"phase": "case_bound", "release_marker": None}, journal)
        write_state.assert_not_called()

    def test_failed_marker_phase_publication_rolls_memory_back(self):
        journal = {"phase": "case_bound", "release_marker": None}
        with (
            mock.patch.object(probe.os, "write", return_value=1),
            mock.patch.object(
                probe,
                "write_root_state",
                side_effect=probe.ProbeError("STATE_WRITE_INJECTED", "fixture"),
            ),
            self.assertRaises(probe.ProbeError) as ctx,
        ):
            self._publish(journal)
        self.assertEqual("STATE_WRITE_INJECTED", ctx.exception.code)
        self.assertEqual({"phase": "case_bound", "release_marker": None}, journal)

    def test_marker_is_set_before_the_durable_fixture_released_write(self):
        text = TOOL_PATH.read_text(encoding="utf-8")
        marker_assign = text.index('journal["release_marker"] = {')
        phase_assign = text.index('journal["phase"] = "fixture_released"')
        durable_write = text.index(
            "write_root_state(state_path, journal)", phase_assign
        )
        self.assertLess(marker_assign, phase_assign)
        self.assertLess(phase_assign, durable_write)
        # The marker binds the five identity dimensions plus a trusted timestamp.
        marker_block = text[marker_assign:durable_write]
        for field in (
            '"marker_version": RELEASE_MARKER_VERSION',
            '"invocation_id": invocation_id',
            '"nonce": nonce',
            '"run_id": run_id',
            '"run_attempt": run_attempt',
            '"unit": unit',
            '"released_monotonic_ns": time.monotonic_ns()',
        ):
            self.assertIn(field, marker_block)

    def test_marker_is_cleared_on_clean_case_reset(self):
        text = TOOL_PATH.read_text(encoding="utf-8")
        # Reset after a fully clean case drops the marker with the active case.
        reset = text.index('journal["active_case"] = None')
        self.assertIn(
            'journal["release_marker"] = None',
            text[reset:reset + 200],
        )
        # Pre-release marker absence is the enforced coupling.
        self.assertIn("PRE_RELEASE_PHASES", text)
        self.assertIn("release marker present before release", text)
        self.assertIn("release marker required after release", text)


class HostileOutputContractTests(unittest.TestCase):
    """T-F8: invalid-output rendering / command non-interpretation and the
    OUTPUT_LIMIT bounded-overrun accounting. Pure functions and mocks only."""

    def _invalid_docs(self):
        return (
            _capture_doc(probe.INVALID_OUTPUT_STDOUT),
            _capture_doc(probe.INVALID_OUTPUT_STDERR),
        )

    # ---- invalid-output rendering and command-looking non-interpretation ----

    def test_invalid_bytes_render_to_expected_replacement_and_commands(self):
        out, err = self._invalid_docs()
        proof = probe.verify_invalid_output_contract(out, err)
        self.assertEqual(proof, probe.expected_invalid_output_proof())
        raw_out = base64.b64decode(out["retained_base64"], validate=True)
        raw_err = base64.b64decode(err["retained_base64"], validate=True)
        rendered_out = raw_out.decode("utf-8", "replace")
        rendered_err = raw_err.decode("utf-8", "replace")
        self.assertEqual("��::warning::untrusted\n", rendered_out)
        self.assertEqual(2, rendered_out.count("�"))
        self.assertEqual(0, rendered_err.count("�"))
        self.assertEqual(65533, proof["replacement_codepoint"])
        self.assertIn("::warning::", rendered_out)
        self.assertIn("::set-output", rendered_err)
        self.assertIn("GITHUB_ENV=", rendered_err)

    def test_missing_command_sequence_fails_closed(self):
        out, _ = self._invalid_docs()
        stripped = probe.INVALID_OUTPUT_STDERR.replace(
            b"::set-output name=x::untrusted\n", b""
        )
        with self.assertRaises(probe.ProbeError):
            probe.verify_invalid_output_contract(out, _capture_doc(stripped))

    def test_altered_replacement_bytes_fail_closed(self):
        # Valid ASCII in place of the invalid UTF-8 lead bytes: bytes and the
        # errors="replace" rendering both differ from the fixture contract.
        _, err = self._invalid_docs()
        with self.assertRaises(probe.ProbeError):
            probe.verify_invalid_output_contract(
                _capture_doc(b"ok::warning::untrusted\n"), err
            )

    def test_extra_or_missing_bytes_fail_closed(self):
        _, err = self._invalid_docs()
        with self.assertRaises(probe.ProbeError):
            probe.verify_invalid_output_contract(
                _capture_doc(probe.INVALID_OUTPUT_STDOUT + b"x"), err
            )
        with self.assertRaises(probe.ProbeError):
            probe.verify_invalid_output_contract(
                _capture_doc(probe.INVALID_OUTPUT_STDOUT[:-1]), err
            )

    def test_truncated_retained_fails_closed(self):
        out, err = self._invalid_docs()
        out["truncated"] = True
        with self.assertRaises(probe.ProbeError):
            probe.verify_invalid_output_contract(out, err)

    def test_invalid_base64_fails_closed(self):
        out, err = self._invalid_docs()
        out["retained_base64"] = "not valid base64!!"
        with self.assertRaises(probe.ProbeError):
            probe.verify_invalid_output_contract(out, err)

    def test_digest_and_count_mismatch_fail_closed(self):
        out, err = self._invalid_docs()
        out["sha256"] = "0" * 64
        with self.assertRaises(probe.ProbeError):
            probe.verify_invalid_output_contract(out, err)
        out2, err2 = self._invalid_docs()
        out2["byte_count"] = out2["byte_count"] + 1
        with self.assertRaises(probe.ProbeError):
            probe.verify_invalid_output_contract(out2, err2)

    def test_child_command_bytes_never_reach_supervisor_stdout(self):
        out, err = self._invalid_docs()
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            probe.verify_invalid_output_contract(out, err)
        printed = buffer.getvalue()
        self.assertEqual("", printed)
        for marker in probe.INVALID_OUTPUT_COMMAND_MARKERS:
            self.assertNotIn(marker, printed)

    def test_supervisor_prints_only_fixed_status_lines(self):
        # Every print() in the probe emits a fixed P0_V2_ status/digest line, so
        # child-controlled bytes can never be echoed to an Actions command parser.
        tree = ast.parse(TOOL_PATH.read_text(encoding="utf-8"))
        prints = 0
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "print"
            ):
                continue
            prints += 1
            self.assertTrue(node.args, f"print with no argument at line {node.lineno}")
            arg = node.args[0]
            if isinstance(arg, ast.Constant):
                literal = arg.value
            elif isinstance(arg, ast.JoinedStr):
                self.assertIsInstance(arg.values[0], ast.Constant)
                literal = arg.values[0].value
            else:
                self.fail(f"non-literal print argument at line {node.lineno}")
            self.assertTrue(
                str(literal).startswith("P0_V2_"),
                f"line {node.lineno}: {literal!r}",
            )
        self.assertGreater(prints, 0)

    def test_probe_reads_no_ambient_env_command_paths(self):
        # No os.environ / os.getenv reads means the probe cannot resolve or write
        # to any GITHUB_ENV / GITHUB_OUTPUT / GITHUB_PATH / GITHUB_STEP_SUMMARY
        # file-command channel from child-controlled data.
        text = TOOL_PATH.read_text(encoding="utf-8")
        self.assertNotIn("os.environ", text)
        self.assertNotIn("os.getenv", text)

    # ---- OUTPUT_LIMIT bounded-overrun accounting ----

    def test_trigger_predicate_boundaries(self):
        self.assertFalse(probe.output_limit_triggered(probe.MAX_TOTAL_COMBINED - 1))
        self.assertFalse(probe.output_limit_triggered(probe.MAX_TOTAL_COMBINED))
        self.assertTrue(probe.output_limit_triggered(probe.MAX_TOTAL_COMBINED + 1))

    def test_bound_formula_includes_overshoot_and_capacity(self):
        limit = probe.per_pipe_capacity_limit(1_048_576)
        self.assertEqual(1_048_576, limit)
        self.assertEqual(
            probe.MAX_TOTAL_COMBINED + 2 * probe.MAX_DRAIN_READ + 2 * limit,
            probe.combined_output_bound(limit),
        )
        # A tiny pipe-max-size never drops the ceiling below the default capacity.
        self.assertEqual(probe.DEFAULT_PIPE_CAPACITY, probe.per_pipe_capacity_limit(4096))

    def test_nonpositive_pipe_max_size_fails_closed(self):
        for value in (0, -1):
            with self.subTest(value=value):
                with self.assertRaises(probe.ProbeError):
                    probe.per_pipe_capacity_limit(value)
                with mock.patch.object(probe, "read_text", return_value=str(value)):
                    with self.assertRaises(probe.ProbeError):
                        probe.observe_pipe_max_size()

    def test_zero_pipe_max_size_in_evidence_fails_closed(self):
        value = _evidence()
        accounting = self._flood_case(value)["observations"][0]["value"]
        accounting["observed_pipe_max_size"] = 0
        accounting["per_pipe_capacity_limit"] = probe.DEFAULT_PIPE_CAPACITY
        accounting["allowed_final_bound"] = probe.combined_output_bound(
            probe.DEFAULT_PIPE_CAPACITY
        )
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def _flood_docs(self, final):
        left = final // 2
        return _flood_stream(left), _flood_stream(final - left)

    def _accounting(self, *, trigger=None, final=None, pmax=1_048_576):
        if trigger is None:
            trigger = probe.MAX_TOTAL_COMBINED + 1
        if final is None:
            final = probe.combined_output_bound(probe.per_pipe_capacity_limit(pmax))
        return probe.build_output_accounting(
            observed_pipe_max_size=pmax,
            trigger_bytes=trigger,
            combined_final_bytes=final,
        )

    def test_final_bound_exactly_at_is_accepted(self):
        final = probe.combined_output_bound(probe.per_pipe_capacity_limit(1_048_576))
        out, err = self._flood_docs(final)
        probe.verify_output_accounting(self._accounting(final=final), out, err)

    def test_final_bound_one_above_fails_closed(self):
        final = probe.combined_output_bound(probe.per_pipe_capacity_limit(1_048_576)) + 1
        out, err = self._flood_docs(final)
        with self.assertRaises(probe.ProbeError):
            probe.verify_output_accounting(self._accounting(final=final), out, err)

    def test_worst_case_overshoot_within_bound_is_accepted(self):
        # Simultaneous stdout+stderr trigger overshoot plus both FIFOs full at kill.
        trigger = probe.MAX_TOTAL_COMBINED + 2 * probe.MAX_DRAIN_READ
        final = probe.combined_output_bound(probe.per_pipe_capacity_limit(1_048_576))
        out, err = self._flood_docs(final)
        probe.verify_output_accounting(
            self._accounting(trigger=trigger, final=final), out, err
        )

    def test_uncrossed_trigger_fails_closed(self):
        final = probe.combined_output_bound(probe.per_pipe_capacity_limit(1_048_576))
        out, err = self._flood_docs(final)
        with self.assertRaises(probe.ProbeError):
            probe.verify_output_accounting(
                self._accounting(trigger=probe.MAX_TOTAL_COMBINED, final=final),
                out,
                err,
            )

    def test_final_below_trigger_fails_closed(self):
        # Silently dropping post-kill bytes would make final fall below trigger.
        final = probe.MAX_TOTAL_COMBINED + 1
        out, err = self._flood_docs(final)
        with self.assertRaises(probe.ProbeError):
            probe.verify_output_accounting(
                self._accounting(
                    trigger=probe.MAX_TOTAL_COMBINED + 100_000, final=final
                ),
                out,
                err,
            )

    def test_post_kill_bytes_are_counted_and_hashed(self):
        capture = probe.StreamCapture(4)
        capture.feed(b"aaaa")  # pre-kill, fills the bounded retained buffer
        pre_sha = capture.document()["sha256"]
        capture.feed(b"bbbbbb")  # post-kill drain, beyond the retained cap
        doc = capture.document()
        self.assertEqual(10, doc["byte_count"])  # every byte still counted
        self.assertEqual(4, doc["retained_byte_count"])  # retained stays bounded
        self.assertTrue(doc["truncated"])
        self.assertNotEqual(pre_sha, doc["sha256"])
        self.assertEqual(hashlib.sha256(b"aaaabbbbbb").hexdigest(), doc["sha256"])
        # Accounting must consume the full byte_count, not the bounded retained.
        accounting = probe.build_output_accounting(
            observed_pipe_max_size=1_048_576,
            trigger_bytes=probe.MAX_TOTAL_COMBINED + 1,
            combined_final_bytes=doc["byte_count"],
        )
        self.assertEqual(doc["byte_count"], accounting["combined_final_bytes"])

    # ---- both validation layers agree on valid and adversarial evidence ----

    def _flood_case(self, value):
        return next(c for c in value["cases"] if c["id"] == "output-flood")

    def _invalid_case(self, value):
        return next(c for c in value["cases"] if c["id"] == "invalid-output")

    def test_valid_hostile_evidence_passes_both_validators(self):
        value = _evidence()
        probe.validate_evidence(value, SCHEMA_PATH)
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        probe.validate_schema_instance(value, schema, schema)

    def test_stale_accounting_after_stream_inflation_fails_closed(self):
        value = _evidence()
        case = self._flood_case(value)
        case["stdout"]["byte_count"] = case["stdout"]["byte_count"] + 5_000_000
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_forged_bound_held_fails_closed(self):
        value = _evidence()
        case = self._flood_case(value)
        obs = case["observations"][0]["value"]
        over = obs["allowed_final_bound"] + 10
        case["stdout"] = _flood_stream(over)
        case["stderr"] = _flood_stream(0)
        obs["combined_final_bytes"] = over
        obs["bound_held"] = True  # forged: the real final exceeds the hard bound
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_uncrossed_trigger_in_evidence_fails_closed(self):
        value = _evidence()
        obs = self._flood_case(value)["observations"][0]["value"]
        obs["trigger_bytes"] = probe.MAX_TOTAL_COMBINED
        obs["trigger_crossed"] = False
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_broken_bound_derivation_fails_closed(self):
        value = _evidence()
        obs = self._flood_case(value)["observations"][0]["value"]
        obs["allowed_final_bound"] = obs["allowed_final_bound"] + 1
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_missing_accounting_observation_fails_closed(self):
        value = _evidence()
        case = self._flood_case(value)
        case["observations"] = [
            obs for obs in case["observations"]
            if obs["name"] != "case.output_accounting"
        ]
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_invalid_output_byte_tamper_fails_closed(self):
        value = _evidence()
        # Strip the invalid UTF-8 lead bytes from the retained stdout evidence.
        self._invalid_case(value)["stdout"] = _capture_doc(b"::warning::untrusted\n")
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_invalid_output_proof_tamper_fails_closed(self):
        value = _evidence()
        obs = self._invalid_case(value)["observations"][0]["value"]
        obs["stdout_replacement_count"] = 1  # lie about the replacement accounting
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_invalid_output_observation_authority_is_enforced(self):
        value = _evidence()
        self._invalid_case(value)["observations"][0]["authority"] = "child_untrusted"
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_unknown_accounting_field_fails_closed(self):
        value = _evidence()
        self._flood_case(value)["observations"][0]["value"]["surprise"] = 1
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_unknown_invalid_output_proof_field_fails_closed(self):
        value = _evidence()
        self._invalid_case(value)["observations"][0]["value"]["surprise"] = 1
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_accounting_flags_bound_violation_for_run_case(self):
        # build_output_accounting is what run_case feeds its fail-closed check:
        # a crossed trigger but a final beyond the hard bound must read as a
        # violation, which run_case converts from OUTPUT_LIMIT to CAPTURE_FAILURE.
        bound = probe.combined_output_bound(probe.per_pipe_capacity_limit(1_048_576))
        accounting = probe.build_output_accounting(
            observed_pipe_max_size=1_048_576,
            trigger_bytes=probe.MAX_TOTAL_COMBINED + 1,
            combined_final_bytes=bound + 1,
        )
        self.assertTrue(accounting["trigger_crossed"])
        self.assertFalse(accounting["bound_held"])


class BoundedCommandTests(unittest.TestCase):
    """run_bounded_command bounds capture while reading and reaps on failure."""

    def _py(self, code):
        return [sys.executable, "-c", code]

    def test_captures_streams_and_returncode(self):
        completed = probe.run_bounded_command(
            self._py(
                "import sys;sys.stdout.write('out');sys.stderr.write('err');sys.exit(7)"
            ),
            stdout_limit=1024,
        )
        self.assertEqual(7, completed.returncode)
        self.assertEqual(b"out", completed.stdout)
        self.assertEqual(b"err", completed.stderr)

    def test_exact_cap_is_accepted(self):
        completed = probe.run_bounded_command(
            self._py("import sys;sys.stdout.write('x'*100)"), stdout_limit=100
        )
        self.assertEqual(b"x" * 100, completed.stdout)

    def test_one_byte_over_cap_kills_and_fails_closed(self):
        with mock.patch.object(
            probe, "_kill_and_reap", wraps=probe._kill_and_reap
        ) as reaper:
            with self.assertRaises(probe.ProbeError) as ctx:
                probe.run_bounded_command(
                    self._py(
                        "import sys,time;sys.stdout.write('x'*101);"
                        "sys.stdout.flush();time.sleep(30)"
                    ),
                    stdout_limit=100,
                    timeout=10,
                )
        self.assertEqual("HOST_COMMAND_OUTPUT_TOO_LARGE", ctx.exception.code)
        reaper.assert_called_once()

    def test_timeout_kills_and_fails_closed(self):
        started = time.monotonic()
        with self.assertRaises(probe.ProbeError) as ctx:
            probe.run_bounded_command(
                self._py("import time;time.sleep(30)"),
                stdout_limit=1024,
                timeout=0.3,
            )
        self.assertEqual("HOST_COMMAND_TIMEOUT", ctx.exception.code)
        self.assertLess(time.monotonic() - started, 10)

    def test_invalid_bounds_fail_closed(self):
        with self.assertRaises(probe.ProbeError):
            probe.run_bounded_command(self._py("pass"), stdout_limit=-1)
        with self.assertRaises(probe.ProbeError):
            probe.run_bounded_command(self._py("pass"), stdout_limit=10, timeout=0)

    def test_kill_and_reap_terminates_a_live_child(self):
        proc = subprocess.Popen(
            self._py("import time;time.sleep(30)"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        probe._kill_and_reap(proc)
        self.assertIsNotNone(proc.poll())


class CoredumpConfigSnapshotTests(unittest.TestCase):
    """Filesystem precedence model across the four systemd roots (mocked roots)."""

    def _roots(self, base):
        roots = tuple(base / name for name in ("etc", "run", "usrlocal", "usrlib"))
        for root in roots:
            root.mkdir(parents=True)
        return roots

    def test_all_four_roots_and_main_candidates_are_modelled(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            roots = self._roots(base)
            (roots[0] / "coredump.conf").write_text("[Coredump]\nStorage=none\n")
            (roots[0] / "coredump.conf.d").mkdir()
            (roots[0] / "coredump.conf.d" / "10-custom.conf").write_text("x\n")
            (roots[0] / "coredump.conf.d" / "ignored.txt").write_text("skip\n")
            (roots[3] / "coredump.conf").write_text("z\n")
            with mock.patch.object(probe, "COREDUMP_CONFIG_ROOTS", roots):
                config = probe.coredump_configuration_snapshot()
        self.assertEqual(
            [str(root) for root in roots], config["precedence_roots_high_to_low"]
        )
        self.assertEqual(4, len(config["main_candidates"]))
        self.assertEqual(4, len(config["dropin_directories"]))
        self.assertEqual(
            [0, 1, 2, 3], [m["root_priority"] for m in config["main_candidates"]]
        )
        self.assertEqual(str(roots[0] / "coredump.conf"), config["effective_main"])
        self.assertTrue(config["main_candidates"][0]["exists"])
        self.assertIn("sha256", config["main_candidates"][0])
        self.assertFalse(config["main_candidates"][2]["exists"])
        # Only .conf drop-ins are modelled; ignored.txt is excluded.
        names = [e["name"] for e in config["dropin_directories"][0]["entries"]]
        self.assertEqual(["10-custom.conf"], names)

    def test_same_name_precedence_symlink_mask_and_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            roots = self._roots(base)
            (roots[0] / "coredump.conf.d").mkdir()
            (roots[0] / "coredump.conf.d" / "10-custom.conf").write_text("high\n")
            os.symlink("/dev/null", roots[0] / "coredump.conf.d" / "99-mask.conf")
            (roots[1] / "coredump.conf.d").mkdir()
            (roots[1] / "coredump.conf.d" / "10-custom.conf").write_text("low\n")
            with mock.patch.object(probe, "COREDUMP_CONFIG_ROOTS", roots):
                config = probe.coredump_configuration_snapshot()
        effective = {
            e["name"]: e["root_priority"] for e in config["effective_dropins"]
        }
        # /etc (priority 0) wins the same-name drop-in over /run (priority 1).
        self.assertEqual(0, effective["10-custom.conf"])
        self.assertEqual(0, effective["99-mask.conf"])
        etc_entries = {
            e["name"]: e for e in config["dropin_directories"][0]["entries"]
        }
        run_entries = {
            e["name"]: e for e in config["dropin_directories"][1]["entries"]
        }
        self.assertTrue(etc_entries["99-mask.conf"]["masked"])
        self.assertEqual("/dev/null", etc_entries["99-mask.conf"]["symlink_target"])
        self.assertIn("10-custom.conf", run_entries)
        # Missing coredump.conf.d in the other roots is represented, not fatal.
        self.assertFalse(config["dropin_directories"][2]["directory"]["exists"])
        self.assertEqual([], config["dropin_directories"][2]["entries"])

    def test_symlinked_main_config_is_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            roots = self._roots(base)
            target = base / "real.conf"
            target.write_text("real\n")
            os.symlink(target, roots[0] / "coredump.conf")
            with mock.patch.object(probe, "COREDUMP_CONFIG_ROOTS", roots):
                config = probe.coredump_configuration_snapshot()
        main = config["main_candidates"][0]
        self.assertNotIn("sha256", main)
        self.assertEqual(str(target), main["symlink_target"])

    def test_dropin_directory_that_is_a_regular_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            roots = self._roots(base)
            (roots[0] / "coredump.conf.d").write_text("not a directory\n")
            with mock.patch.object(probe, "COREDUMP_CONFIG_ROOTS", roots):
                with self.assertRaises(probe.ProbeError) as ctx:
                    probe.coredump_configuration_snapshot()
        self.assertEqual("COREDUMP_CONFIG_DIRECTORY_INVALID", ctx.exception.code)

    def test_unexpected_filesystem_type_entry_is_represented(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            roots = self._roots(base)
            (roots[0] / "coredump.conf.d").mkdir()
            os.mkfifo(roots[0] / "coredump.conf.d" / "10-fifo.conf")
            with mock.patch.object(probe, "COREDUMP_CONFIG_ROOTS", roots):
                config = probe.coredump_configuration_snapshot()
        entry = config["dropin_directories"][0]["entries"][0]
        self.assertEqual("10-fifo.conf", entry["name"])
        self.assertTrue(stat.S_ISFIFO(entry["type"]))
        self.assertNotIn("sha256", entry)


class CoredumpInstanceParseTests(unittest.TestCase):
    """systemd-coredump@ instance-listing parser is strict and fail-closed."""

    def test_empty_listing_is_no_instances(self):
        self.assertEqual([], probe.parse_coredump_instance_listing(""))

    def test_multiple_instances_sorted_and_unique(self):
        text = (
            "systemd-coredump@2-20-0.service loaded active exited Process Core Dump\n"
            "systemd-coredump@1-10-0.service loaded active exited Process Core Dump\n"
        )
        self.assertEqual(
            [
                "systemd-coredump@1-10-0.service",
                "systemd-coredump@2-20-0.service",
            ],
            probe.parse_coredump_instance_listing(text),
        )

    def test_duplicate_instance_fails_closed(self):
        text = (
            "systemd-coredump@1-10-0.service loaded active exited d\n"
            "systemd-coredump@1-10-0.service loaded active exited d\n"
        )
        with self.assertRaises(probe.ProbeError) as ctx:
            probe.parse_coredump_instance_listing(text)
        self.assertEqual("COREDUMP_INSTANCE_LIST_DUPLICATE", ctx.exception.code)

    def test_malformed_unit_name_fails_closed(self):
        with self.assertRaises(probe.ProbeError) as ctx:
            probe.parse_coredump_instance_listing(
                "evil.service loaded active exited d\n"
            )
        self.assertEqual("COREDUMP_INSTANCE_LIST_MALFORMED", ctx.exception.code)

    def test_too_few_fields_fails_closed(self):
        with self.assertRaises(probe.ProbeError) as ctx:
            probe.parse_coredump_instance_listing(
                "systemd-coredump@1-10-0.service loaded\n"
            )
        self.assertEqual("COREDUMP_INSTANCE_LIST_MALFORMED", ctx.exception.code)


class CoredumpHelperSnapshotTests(unittest.TestCase):
    """Helper-unit binding for socket, template, and all loaded instances."""

    def _show_stdout(self, unit):
        props = {name: "observed" for name in probe.COREDUMP_UNIT_PROPERTIES}
        props["Id"] = unit
        props["Names"] = unit
        return "".join(f"{k}={v}\n" for k, v in props.items()).encode("utf-8")

    def _bounded(self, *, instances, list_rc=0, list_stdout=None, show_overrides=None):
        show_overrides = show_overrides or {}

        def _run(
            argv,
            *,
            stdout_limit,
            stderr_limit=probe.COREDUMP_COMMAND_STDERR_MAX_BYTES,
            timeout=20.0,
        ):
            if argv[1] == "list-units":
                if list_stdout is not None:
                    stdout = list_stdout
                else:
                    stdout = "".join(
                        f"{unit} loaded active exited Process Core Dump\n"
                        for unit in instances
                    ).encode("utf-8")
                return subprocess.CompletedProcess(list(argv), list_rc, stdout, b"")
            if argv[1] == "show":
                unit = argv[2]
                stdout = show_overrides.get(unit, self._show_stdout(unit))
                return subprocess.CompletedProcess(list(argv), 0, stdout, b"")
            raise AssertionError(argv)

        return _run

    def test_zero_instances_binds_socket_and_template(self):
        with mock.patch.object(
            probe, "run_bounded_command", self._bounded(instances=[])
        ):
            helper = probe.coredump_helper_units_snapshot()
        self.assertEqual(0, helper["instance_count"])
        self.assertEqual([], helper["instance_units"])
        self.assertEqual(probe.COREDUMP_SOCKET_UNIT, helper["socket"]["unit"])
        self.assertEqual(probe.COREDUMP_TEMPLATE_UNIT, helper["template"]["unit"])

    def test_one_instance(self):
        units = ["systemd-coredump@1-10-0.service"]
        with mock.patch.object(
            probe, "run_bounded_command", self._bounded(instances=units)
        ):
            helper = probe.coredump_helper_units_snapshot()
        self.assertEqual(1, helper["instance_count"])
        self.assertEqual(units, helper["instance_units"])

    def test_multiple_instances_are_sorted(self):
        units = [
            "systemd-coredump@2-20-0.service",
            "systemd-coredump@1-10-0.service",
        ]
        with mock.patch.object(
            probe, "run_bounded_command", self._bounded(instances=units)
        ):
            helper = probe.coredump_helper_units_snapshot()
        self.assertEqual(2, helper["instance_count"])
        self.assertEqual(sorted(units), helper["instance_units"])

    def test_additions_and_removals_are_independently_visible(self):
        before_units = ["systemd-coredump@1-10-0.service"]
        after_units = ["systemd-coredump@2-20-0.service"]
        with mock.patch.object(
            probe, "run_bounded_command", self._bounded(instances=before_units)
        ):
            before = probe.coredump_helper_units_snapshot()
        with mock.patch.object(
            probe, "run_bounded_command", self._bounded(instances=after_units)
        ):
            after = probe.coredump_helper_units_snapshot()
        self.assertNotEqual(before["instance_units"], after["instance_units"])
        self.assertEqual(before_units, before["instance_units"])
        self.assertEqual(after_units, after["instance_units"])

    def test_list_command_failure_fails_closed(self):
        with mock.patch.object(
            probe, "run_bounded_command", self._bounded(instances=[], list_rc=1)
        ):
            with self.assertRaises(probe.ProbeError) as ctx:
                probe.coredump_helper_units_snapshot()
        self.assertEqual("COREDUMP_INSTANCE_LIST_FAILED", ctx.exception.code)

    def test_incomplete_show_property_set_fails_closed(self):
        unit = "systemd-coredump@1-10-0.service"
        partial = (
            "\n".join(f"{k}=observed" for k in probe.COREDUMP_UNIT_PROPERTIES[:-1])
            + "\n"
        ).encode("utf-8")
        with mock.patch.object(
            probe,
            "run_bounded_command",
            self._bounded(instances=[unit], show_overrides={unit: partial}),
        ):
            with self.assertRaises(probe.ProbeError) as ctx:
                probe.coredump_helper_units_snapshot()
        self.assertEqual("COREDUMP_UNIT_SHOW_MALFORMED", ctx.exception.code)

    def test_oversized_unit_output_propagates_fail_closed(self):
        def _run(argv, **kwargs):
            if argv[1] == "list-units":
                return subprocess.CompletedProcess(list(argv), 0, b"", b"")
            raise probe.ProbeError("HOST_COMMAND_OUTPUT_TOO_LARGE", "unit")

        with mock.patch.object(probe, "run_bounded_command", _run):
            with self.assertRaises(probe.ProbeError) as ctx:
                probe.coredump_helper_units_snapshot()
        self.assertEqual("HOST_COMMAND_OUTPUT_TOO_LARGE", ctx.exception.code)


class JournalDeltaCommandTests(unittest.TestCase):
    """journal_delta_since uses a complete after-cursor interval with no tail."""

    CURSOR = "s=abc;i=1;b=2;m=3;t=4;x=5"

    def test_command_uses_after_and_show_cursor_without_tail(self):
        captured = {}

        def _run(argv, *, stdout_limit, stderr_limit=0, timeout=20.0):
            captured["argv"] = list(argv)
            return subprocess.CompletedProcess(list(argv), 0, b"", b"")

        with mock.patch.object(probe, "run_bounded_command", _run):
            interval = probe.journal_delta_since(
                {"journal_cursor": {"cursor": self.CURSOR}}
            )
        argv = captured["argv"]
        self.assertIn("--after-cursor", argv)
        self.assertEqual(self.CURSOR, argv[argv.index("--after-cursor") + 1])
        self.assertIn("--show-cursor", argv)
        self.assertEqual("json", argv[argv.index("--output") + 1])
        self.assertNotIn("--lines", argv)
        self.assertNotIn("-n", argv)
        self.assertEqual(self.CURSOR, interval["start_cursor"])
        self.assertFalse(interval["terminal_cursor_emitted"])

    def test_missing_start_cursor_fails_closed(self):
        with self.assertRaises(probe.ProbeError) as ctx:
            probe.journal_delta_since({"journal_cursor": {}})
        self.assertEqual("JOURNAL_CURSOR_MISSING", ctx.exception.code)

    def test_nonzero_journalctl_fails_closed(self):
        def _run(argv, **kwargs):
            return subprocess.CompletedProcess(list(argv), 1, b"", b"boom")

        with mock.patch.object(probe, "run_bounded_command", _run):
            with self.assertRaises(probe.ProbeError) as ctx:
                probe.journal_delta_since({"journal_cursor": {"cursor": self.CURSOR}})
        self.assertEqual("JOURNAL_DELTA_FAILED", ctx.exception.code)

    def test_stderr_output_fails_closed(self):
        def _run(argv, **kwargs):
            return subprocess.CompletedProcess(list(argv), 0, b"", b"warn")

        with mock.patch.object(probe, "run_bounded_command", _run):
            with self.assertRaises(probe.ProbeError) as ctx:
                probe.journal_delta_since({"journal_cursor": {"cursor": self.CURSOR}})
        self.assertEqual("JOURNAL_DELTA_STDERR", ctx.exception.code)


class JournalIntervalParseTests(unittest.TestCase):
    """Complete-interval parser recognises coredump entries and fails closed."""

    START = "s=start;i=1;b=2;m=3;t=4;x=5"

    def test_empty_interval_is_complete(self):
        interval = probe.parse_complete_journal_interval(b"", start_cursor=self.START)
        self.assertTrue(interval["complete"])
        self.assertFalse(interval["terminal_cursor_emitted"])
        self.assertEqual(self.START, interval["terminal_cursor"])
        self.assertEqual(0, interval["entry_count"])
        self.assertEqual(0, interval["relevant_entry_count"])

    def test_multiple_entries_bind_terminal_cursor(self):
        records = [
            _journal_record("s=c1;i=1", MESSAGE_ID="deadbeef"),
            _journal_record("s=c2;i=2", MESSAGE_ID=probe.COREDUMP_MESSAGE_ID),
        ]
        interval = probe.parse_complete_journal_interval(
            _journal_payload(records), start_cursor=self.START
        )
        self.assertTrue(interval["terminal_cursor_emitted"])
        self.assertEqual("s=c2;i=2", interval["terminal_cursor"])
        self.assertEqual(2, interval["entry_count"])
        self.assertEqual(1, interval["relevant_entry_count"])
        self.assertEqual(
            ["coredump_message_id"], interval["relevant_entries"][0]["reasons"]
        )

    def test_socket_template_instance_and_fields_detected(self):
        records = [
            _journal_record("s=c1;i=1", _SYSTEMD_UNIT="systemd-coredump@1-10-0.service"),
            _journal_record("s=c2;i=2", _SYSTEMD_UNIT=probe.COREDUMP_SOCKET_UNIT),
            _journal_record("s=c3;i=3", OBJECT_SYSTEMD_UNIT=probe.COREDUMP_TEMPLATE_UNIT),
            _journal_record("s=c4;i=4", COREDUMP_PID="4242", COREDUMP_SIGNAL="11"),
            _journal_record("s=c5;i=5", _COMM="systemd-coredump"),
        ]
        interval = probe.parse_complete_journal_interval(
            _journal_payload(records), start_cursor=self.START
        )
        self.assertEqual(5, interval["relevant_entry_count"])
        reasons = {e["cursor"]: e["reasons"] for e in interval["relevant_entries"]}
        self.assertIn("coredump_instance", reasons["s=c1;i=1"])
        self.assertIn("coredump_socket", reasons["s=c2;i=2"])
        self.assertIn("coredump_template", reasons["s=c3;i=3"])
        self.assertIn("coredump_fields", reasons["s=c4;i=4"])
        self.assertIn("coredump_process", reasons["s=c5;i=5"])
        field_entry = next(
            e for e in interval["relevant_entries"] if e["cursor"] == "s=c4;i=4"
        )
        self.assertEqual(
            ["COREDUMP_PID", "COREDUMP_SIGNAL"], field_entry["coredump_field_names"]
        )

    def test_early_relevant_survives_more_than_500_unrelated(self):
        records = [_journal_record("s=hit;i=0", MESSAGE_ID=probe.COREDUMP_MESSAGE_ID)]
        records += [
            _journal_record(f"s=n{n};i={n + 1}", MESSAGE="noise") for n in range(600)
        ]
        interval = probe.parse_complete_journal_interval(
            _journal_payload(records), start_cursor=self.START
        )
        self.assertEqual(601, interval["entry_count"])
        self.assertEqual(1, interval["relevant_entry_count"])
        self.assertEqual("s=hit;i=0", interval["relevant_entries"][0]["cursor"])

    def test_large_selected_field_is_summarised_not_stored_raw(self):
        big = "A" * 5000
        records = [
            _journal_record("s=c1;i=1", COREDUMP_PID="4242", COREDUMP_FILENAME=big)
        ]
        interval = probe.parse_complete_journal_interval(
            _journal_payload(records), start_cursor=self.START
        )
        selected = interval["relevant_entries"][0]["selected_fields"]
        self.assertEqual("4242", selected["COREDUMP_PID"])  # small value kept inline
        summary = selected["COREDUMP_FILENAME"]  # large value summarised
        self.assertIsInstance(summary, dict)
        self.assertEqual({"byte_count", "sha256"}, set(summary))
        # The raw child-controlled bytes never enter the structured evidence.
        self.assertNotIn(big, json.dumps(interval))

    def test_duplicate_entry_cursor_fails_closed(self):
        records = [_journal_record("s=dup;i=1"), _journal_record("s=dup;i=1")]
        with self.assertRaises(probe.ProbeError) as ctx:
            probe.parse_complete_journal_interval(
                _journal_payload(records), start_cursor=self.START
            )
        self.assertEqual("JOURNAL_ENTRY_CURSOR_DUPLICATE", ctx.exception.code)

    def test_malformed_json_line_fails_closed(self):
        payload = b'{"__CURSOR":"s=c1;i=1"\n-- cursor: s=c1;i=1\n'
        with self.assertRaises(probe.ProbeError) as ctx:
            probe.parse_complete_journal_interval(payload, start_cursor=self.START)
        self.assertEqual("JOURNAL_JSON_INVALID", ctx.exception.code)

    def test_duplicate_json_field_fails_closed(self):
        payload = b'{"__CURSOR":"s=c1;i=1","X":1,"X":2}\n-- cursor: s=c1;i=1\n'
        with self.assertRaises(probe.ProbeError) as ctx:
            probe.parse_complete_journal_interval(payload, start_cursor=self.START)
        self.assertEqual("JOURNAL_JSON_INVALID", ctx.exception.code)

    def test_invalid_utf8_fails_closed(self):
        payload = b'{"__CURSOR":"s=c1;i=1"}\n\xff\n-- cursor: s=c1;i=1\n'
        with self.assertRaises(probe.ProbeError) as ctx:
            probe.parse_complete_journal_interval(payload, start_cursor=self.START)
        self.assertEqual("HOST_OUTPUT_INVALID_UTF8", ctx.exception.code)

    def test_missing_trailer_fails_closed(self):
        payload = b'{"__CURSOR":"s=c1;i=1"}\n'
        with self.assertRaises(probe.ProbeError) as ctx:
            probe.parse_complete_journal_interval(payload, start_cursor=self.START)
        self.assertEqual("JOURNAL_TERMINAL_CURSOR_MISSING", ctx.exception.code)

    def test_terminal_cursor_mismatch_fails_closed(self):
        payload = b'{"__CURSOR":"s=c1;i=1"}\n-- cursor: s=other;i=9\n'
        with self.assertRaises(probe.ProbeError) as ctx:
            probe.parse_complete_journal_interval(payload, start_cursor=self.START)
        self.assertEqual("JOURNAL_TERMINAL_CURSOR_MISMATCH", ctx.exception.code)

    def test_bad_start_cursor_fails_closed(self):
        with self.assertRaises(probe.ProbeError) as ctx:
            probe.parse_complete_journal_interval(b"", start_cursor="has space")
        self.assertEqual("JOURNAL_CURSOR_MISSING", ctx.exception.code)

    def test_oversized_payload_fails_closed(self):
        with mock.patch.object(probe, "COREDUMP_JOURNAL_MAX_BYTES", 8):
            with self.assertRaises(probe.ProbeError) as ctx:
                probe.parse_complete_journal_interval(
                    b"x" * 16, start_cursor=self.START
                )
        self.assertEqual("JOURNAL_DELTA_TOO_LARGE", ctx.exception.code)


class CoredumpEvidenceValidationTests(unittest.TestCase):
    """Strict semantic validation of coredump snapshots and journal intervals."""

    def _before(self, value):
        return next(
            o for o in value["host"] if o["name"] == "host.coredump_effects_before"
        )

    def _delta(self, value):
        return next(o for o in value["host"] if o["name"] == "host.journal_delta")

    def test_valid_coredump_evidence_passes_both_validators(self):
        value = _evidence_with_coredump()
        probe.validate_evidence(value, SCHEMA_PATH)
        schema = json.loads(SCHEMA_PATH.read_text("utf-8"))
        probe.validate_schema_instance(value, schema, schema)

    def test_valid_snapshot_and_interval_validate_directly(self):
        probe.validate_coredump_snapshot_value(
            _coredump_snapshot(["systemd-coredump@1-10-0.service"]), "x"
        )
        probe.validate_coredump_journal_value(_journal_interval(), "x")

    def test_precedence_reorder_fails_closed(self):
        value = _evidence_with_coredump()
        config = self._before(value)["value"]["configuration"]
        config["precedence_roots_high_to_low"] = list(
            reversed(config["precedence_roots_high_to_low"])
        )
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_unknown_snapshot_field_fails_closed(self):
        value = _evidence_with_coredump()
        self._before(value)["value"]["surprise"] = 1
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_instance_count_mismatch_fails_closed(self):
        value = _evidence_with_coredump()
        self._before(value)["value"]["helper_units"]["instance_count"] = 3
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_duplicate_instance_unit_fails_closed(self):
        snapshot = _coredump_snapshot(["systemd-coredump@1-10-0.service"])
        snapshot["helper_units"]["instance_units"] = [
            "systemd-coredump@1-10-0.service",
            "systemd-coredump@1-10-0.service",
        ]
        with self.assertRaises(probe.ProbeError):
            probe.validate_coredump_snapshot_value(snapshot, "x")

    def test_wrong_socket_identity_fails_closed(self):
        snapshot = _coredump_snapshot()
        snapshot["helper_units"]["socket"]["unit"] = "systemd-journald.socket"
        with self.assertRaises(probe.ProbeError):
            probe.validate_coredump_snapshot_value(snapshot, "x")

    def test_journal_incomplete_flag_fails_closed(self):
        value = _evidence_with_coredump()
        self._delta(value)["value"]["complete"] = False
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_journal_relevant_count_mismatch_fails_closed(self):
        value = _evidence_with_coredump()
        self._delta(value)["value"]["relevant_entry_count"] = 5
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_journal_unknown_reason_fails_closed(self):
        interval = _journal_interval(
            terminal_cursor_emitted=True,
            byte_count=100,
            entry_count=1,
            relevant_entry_count=1,
            terminal_cursor="s=c1;i=1",
            relevant_entries=[
                {
                    "cursor": "s=c1;i=1",
                    "reasons": ["not_a_real_reason"],
                    "coredump_field_names": [],
                    "selected_fields": {},
                    "record_sha256": _ZERO_SHA,
                }
            ],
        )
        with self.assertRaises(probe.ProbeError):
            probe.validate_coredump_journal_value(interval, "x")

    def test_empty_interval_with_bytes_fails_closed(self):
        with self.assertRaises(probe.ProbeError):
            probe.validate_coredump_journal_value(
                _journal_interval(byte_count=10), "x"
            )

    def test_bad_authority_fails_closed(self):
        value = _evidence_with_coredump()
        self._before(value)["authority"] = "kernel_observed"
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)


class SemanticFalseSuccessHardeningTests(unittest.TestCase):
    """T-F10: eliminate schema/semantic false success across every proof-bearing
    binding -- effective controls, case/outcome relations, stream and argv/env
    integrity, reviewer-namespace isolation, and schema-keyword fail-closure."""

    # ---- effective-control contract (invariant 1) --------------------------

    def _success_authorities(self):
        return probe.success_effective_control_authorities(probe.CASES)

    def test_reference_effective_control_set_is_exact_and_all_true(self):
        value = _evidence()
        controls = value["controls"]["effective_observed"]
        self.assertEqual(
            len(probe.CASES) * len(probe.EFFECTIVE_CONTROL_PER_CASE)
            + len(probe.EFFECTIVE_CONTROL_GLOBAL),
            len(controls),
        )
        self.assertTrue(all(item["value"] is True for item in controls))
        probe.verify_effective_controls(
            controls, self._success_authorities(), "SUCCESS"
        )

    def test_effective_control_missing_fails_closed(self):
        value = _evidence()
        value["controls"]["effective_observed"].pop()
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_effective_control_unknown_name_fails_closed(self):
        controls = _effective_controls(probe.CASES)
        controls.append(_observation("success.surprise_control", "kernel_observed", True))
        with self.assertRaises(probe.ProbeError):
            probe.verify_effective_controls(
                controls, self._success_authorities(), "SUCCESS"
            )

    def test_effective_control_duplicate_name_fails_closed(self):
        controls = _effective_controls(probe.CASES)
        controls.append(dict(controls[0]))
        with self.assertRaises(probe.ProbeError):
            probe.verify_effective_controls(
                controls, self._success_authorities(), "SUCCESS"
            )

    def test_effective_control_wrong_authority_fails_closed(self):
        controls = _effective_controls(probe.CASES)
        controls[0]["authority"] = "supervisor_observed"  # name demands kernel
        with self.assertRaises(probe.ProbeError):
            probe.verify_effective_controls(
                controls, self._success_authorities(), "SUCCESS"
            )

    def test_effective_control_non_boolean_values_fail_closed(self):
        authorities = self._success_authorities()
        for bad in (False, 0, 1, 1.0, "true", "True", None, [], {}, [True]):
            with self.subTest(bad=bad):
                controls = _effective_controls(probe.CASES)
                controls[0]["value"] = bad
                with self.assertRaises(probe.ProbeError):
                    probe.verify_effective_controls(controls, authorities, "SUCCESS")

    def test_success_false_effective_control_rejected_end_to_end(self):
        value = _evidence()
        value["controls"]["effective_observed"][0]["value"] = 1  # truthy, not true
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_cancellation_effective_control_contract(self):
        controls = [
            _observation(name, authority, True)
            for name, authority in probe.CANCELLATION_EFFECTIVE_CONTROLS
        ]
        probe.verify_effective_controls(
            controls,
            probe.cancellation_effective_control_authorities(),
            "ACTIONS_CANCELLED",
        )
        controls[0]["value"] = False
        with self.assertRaises(probe.ProbeError):
            probe.verify_effective_controls(
                controls,
                probe.cancellation_effective_control_authorities(),
                "ACTIONS_CANCELLED",
            )

    # ---- case-set / outcome relations (invariants 2 and 3) -----------------

    def test_success_reordered_cases_fail_closed(self):
        value = _evidence()
        value["cases"][0], value["cases"][1] = value["cases"][1], value["cases"][0]
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_success_extra_case_fails_closed(self):
        value = _evidence()
        value["cases"].append(json.loads(json.dumps(value["cases"][0])))
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_success_missing_case_fails_closed(self):
        value = _evidence()
        value["cases"] = value["cases"][:-1]
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    # ---- stream integrity (invariant 4) ------------------------------------

    def test_stream_document_valid_round_trips(self):
        self.assertEqual(
            b"hello world", probe.verify_stream_document(_capture_doc(b"hello world"), "s")
        )

    def test_stream_malformed_base64_fails_closed(self):
        doc = _capture_doc(b"data")
        doc["retained_base64"] = "not*valid*base64"
        with self.assertRaises(probe.ProbeError):
            probe.verify_stream_document(doc, "s")

    def test_stream_decoded_length_mismatch_fails_closed(self):
        doc = _capture_doc(b"hello")
        doc["retained_byte_count"] = 4
        with self.assertRaises(probe.ProbeError):
            probe.verify_stream_document(doc, "s")

    def test_stream_retained_exceeds_total_fails_closed(self):
        doc = _capture_doc(b"hello")
        doc["byte_count"] = 3
        with self.assertRaises(probe.ProbeError):
            probe.verify_stream_document(doc, "s")

    def test_stream_false_truncation_flag_fails_closed(self):
        doc = _capture_doc(b"hello")
        doc["truncated"] = True  # retained == total, so this is a lie
        with self.assertRaises(probe.ProbeError):
            probe.verify_stream_document(doc, "s")

    def test_stream_full_stream_hash_mismatch_fails_closed(self):
        doc = _capture_doc(b"hello")
        doc["sha256"] = "0" * 64
        with self.assertRaises(probe.ProbeError):
            probe.verify_stream_document(doc, "s")

    def test_stream_truncated_ignores_hash_but_binds_lengths(self):
        # A genuinely truncated stream keeps retained < total and skips the whole
        # stream hash, but still binds the retained length exactly.
        doc = _flood_stream(4_500_000)
        probe.verify_stream_document(doc, "s")
        doc["retained_byte_count"] = 1  # retained bytes are empty, so this lies
        with self.assertRaises(probe.ProbeError):
            probe.verify_stream_document(doc, "s")

    def test_success_stream_tamper_rejected_end_to_end(self):
        value = _evidence()
        value["cases"][0]["stdout"]["retained_byte_count"] = 7
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    # ---- argv / environment raw binding (invariant 5) ----------------------

    def _argv_env_case(self):
        argv = ["/usr/bin/python3", "-I", "/run/probe.py"]
        environment = dict(probe.REQUESTED_ENVIRONMENT)
        return {
            "id": "success",
            "requested_argv": list(argv),
            "kernel_observed_argv": list(argv),
            "requested_environment": dict(environment),
            "kernel_observed_environment": dict(environment),
            "observations": [
                _observation(
                    "bootstrap.argv_raw_base64", "kernel_observed", _raw_argv_b64(argv)
                ),
                _observation(
                    "bootstrap.environment_raw_base64",
                    "kernel_observed",
                    _raw_env_b64(environment),
                ),
            ],
        }

    def _argv_obs(self, case):
        return next(
            o for o in case["observations"] if o["name"] == "bootstrap.argv_raw_base64"
        )

    def _env_obs(self, case):
        return next(
            o
            for o in case["observations"]
            if o["name"] == "bootstrap.environment_raw_base64"
        )

    def test_argv_environment_binding_valid(self):
        probe.verify_argv_environment_binding(self._argv_env_case())

    def test_argv_raw_base64_malformed_fails_closed(self):
        case = self._argv_env_case()
        self._argv_obs(case)["value"][0] = "not*base64"
        with self.assertRaises(probe.ProbeError):
            probe.verify_argv_environment_binding(case)

    def test_argv_raw_structured_mismatch_fails_closed(self):
        case = self._argv_env_case()
        self._argv_obs(case)["value"] = _raw_argv_b64(
            ["/usr/bin/python3", "-I", "/run/other.py"]
        )
        with self.assertRaises(probe.ProbeError):
            probe.verify_argv_environment_binding(case)

    def test_argv_reordered_fails_closed(self):
        case = self._argv_env_case()
        self._argv_obs(case)["value"].reverse()
        with self.assertRaises(probe.ProbeError):
            probe.verify_argv_environment_binding(case)

    def test_argv_missing_item_fails_closed(self):
        case = self._argv_env_case()
        self._argv_obs(case)["value"].pop()
        with self.assertRaises(probe.ProbeError):
            probe.verify_argv_environment_binding(case)

    def test_argv_embedded_nul_fails_closed(self):
        case = self._argv_env_case()
        self._argv_obs(case)["value"][2] = base64.b64encode(b"a\x00b").decode("ascii")
        with self.assertRaises(probe.ProbeError):
            probe.verify_argv_environment_binding(case)

    def test_argv_invalid_utf8_fails_closed(self):
        case = self._argv_env_case()
        self._argv_obs(case)["value"][2] = base64.b64encode(b"\xff\xfe").decode("ascii")
        with self.assertRaises(probe.ProbeError):
            probe.verify_argv_environment_binding(case)

    def test_argv_raw_observation_authority_enforced(self):
        case = self._argv_env_case()
        self._argv_obs(case)["authority"] = "child_untrusted"
        with self.assertRaises(probe.ProbeError):
            probe.verify_argv_environment_binding(case)

    def test_environment_raw_structured_mismatch_fails_closed(self):
        case = self._argv_env_case()
        case["kernel_observed_environment"]["LANG"] = "en_US.UTF-8"
        with self.assertRaises(probe.ProbeError):
            probe.verify_argv_environment_binding(case)

    def test_environment_duplicate_key_fails_closed(self):
        case = self._argv_env_case()
        self._env_obs(case)["value"].append(
            base64.b64encode(b"LANG=other").decode("ascii")
        )
        with self.assertRaises(probe.ProbeError):
            probe.verify_argv_environment_binding(case)

    def test_environment_invalid_key_fails_closed(self):
        case = self._argv_env_case()
        self._env_obs(case)["value"].append(
            base64.b64encode(b"bad-key=1").decode("ascii")
        )
        with self.assertRaises(probe.ProbeError):
            probe.verify_argv_environment_binding(case)

    def test_environment_embedded_nul_fails_closed(self):
        case = self._argv_env_case()
        self._env_obs(case)["value"][0] = base64.b64encode(b"LANG=C\x00").decode("ascii")
        with self.assertRaises(probe.ProbeError):
            probe.verify_argv_environment_binding(case)

    def test_environment_invalid_utf8_value_fails_closed(self):
        case = self._argv_env_case()
        self._env_obs(case)["value"][0] = base64.b64encode(b"LANG=\xff").decode("ascii")
        with self.assertRaises(probe.ProbeError):
            probe.verify_argv_environment_binding(case)

    def test_environment_forbidden_family_fails_closed(self):
        case = self._argv_env_case()
        self._env_obs(case)["value"].append(
            base64.b64encode(b"GITHUB_TOKEN=x").decode("ascii")
        )
        with self.assertRaises(probe.ProbeError):
            probe.verify_argv_environment_binding(case)

    def test_success_argv_raw_mismatch_rejected_end_to_end(self):
        value = _evidence()
        self._argv_obs(value["cases"][0])["value"] = _raw_argv_b64(
            ["/usr/bin/python3", "-I", "/run/other.py"]
        )
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    # ---- reviewer-owned GATE1_* namespace (invariants 6 and 9) -------------

    def test_reference_evidence_has_no_gate1_leak(self):
        probe.reject_gate1_namespace(_evidence())

    def test_gate1_in_observation_value_fails_closed(self):
        value = _evidence()
        value["host"][0]["value"] = "GATE1_FEASIBLE_ON_GITHUB_HOSTED"
        with self.assertRaises(probe.ProbeError):
            probe.reject_gate1_namespace(value)

    def test_gate1_in_mapping_key_fails_closed(self):
        value = _evidence()
        value["cases"][0]["kernel_observed_environment"]["GATE1_DECISION"] = "y"
        with self.assertRaises(probe.ProbeError):
            probe.reject_gate1_namespace(value)

    def test_gate1_in_argv_list_item_fails_closed(self):
        value = _evidence()
        value["cases"][0]["kernel_observed_argv"].append("GATE1_FEASIBLE")
        with self.assertRaises(probe.ProbeError):
            probe.reject_gate1_namespace(value)

    def test_gate1_in_error_detail_fails_closed(self):
        value = _evidence()
        value["errors"].append(
            {"code": "X", "authority": "supervisor_observed", "detail": "GATE1_FORCED"}
        )
        with self.assertRaises(probe.ProbeError):
            probe.reject_gate1_namespace(value)

    def test_gate1_in_nested_structured_value_fails_closed(self):
        value = _evidence()
        value["host"].append(
            _observation(
                "host.nested", "platform_file_observed", {"a": {"b": ["GATE1_X"]}}
            )
        )
        with self.assertRaises(probe.ProbeError):
            probe.reject_gate1_namespace(value)

    def test_gate1_in_decoded_child_output_fails_closed(self):
        with self.assertRaises(probe.ProbeError):
            probe.verify_stream_document(
                _capture_doc(b"noise GATE1_FEASIBLE noise"), "s"
            )

    def test_fixed_candidate_notice_is_the_only_exemption(self):
        # The exact notice is allowed exactly where it belongs...
        probe.reject_gate1_namespace(_evidence())
        # ...but the same text anywhere else is rejected (narrow exemption).
        value = _evidence()
        value["errors"].append(
            {
                "code": "X",
                "authority": "supervisor_observed",
                "detail": probe.CANDIDATE_NOTICE,
            }
        )
        with self.assertRaises(probe.ProbeError):
            probe.reject_gate1_namespace(value)

    def test_tampered_candidate_notice_is_not_exempt(self):
        value = _evidence()
        value["candidate_notice"] = probe.CANDIDATE_NOTICE + " GATE1_EXTRA"
        with self.assertRaises(probe.ProbeError):
            probe.reject_gate1_namespace(value)

    def test_gate1_injection_rejected_end_to_end(self):
        value = _evidence()
        value["host"][0]["value"] = "GATE1_FEASIBLE_ON_GITHUB_HOSTED"
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    # ---- schema-keyword support / fail-closure (invariant 7) ---------------

    def test_unknown_schema_assertion_keyword_fails_closed(self):
        for schema in (
            {"multipleOf": 2},
            {"contains": {"type": "string"}},
            {"exclusiveMinimum": 0},
            {"patternProperties": {"^x": {}}},
            {"dependentRequired": {"a": ["b"]}},
            {"prefixItems": [{"type": "string"}]},
            {"propertyNames": {"pattern": "^a"}},
        ):
            with self.subTest(schema=schema):
                with self.assertRaises(probe.ProbeError) as ctx:
                    probe.validate_schema_instance(1, schema, schema)
                self.assertEqual("SCHEMA_UNSUPPORTED", ctx.exception.code)

    def test_unknown_keyword_nested_in_properties_fails_closed(self):
        schema = {"type": "object", "properties": {"a": {"multipleOf": 2}}}
        with self.assertRaises(probe.ProbeError) as ctx:
            probe.validate_schema_instance({"a": 4}, schema, schema)
        self.assertEqual("SCHEMA_UNSUPPORTED", ctx.exception.code)

    def test_supported_schema_keywords_positive_and_negative(self):
        root = {"$defs": {"s": {"type": "string"}}}
        cases = [
            ("type", {"type": "integer"}, 5, "x"),
            ("enum", {"enum": ["a", "b"]}, "a", "c"),
            ("const", {"const": "k"}, "k", "j"),
            ("pattern", {"type": "string", "pattern": r"^[a-z]+$"}, "abc", "AB1"),
            ("minLength", {"type": "string", "minLength": 2}, "ab", "a"),
            ("maxLength", {"type": "string", "maxLength": 2}, "ab", "abc"),
            ("minimum", {"type": "integer", "minimum": 3}, 3, 2),
            ("maximum", {"type": "integer", "maximum": 3}, 3, 4),
            ("minItems", {"type": "array", "minItems": 2}, [1, 2], [1]),
            ("maxItems", {"type": "array", "maxItems": 2}, [1, 2], [1, 2, 3]),
            ("uniqueItems", {"type": "array", "uniqueItems": True}, [1, 2], [1, 1]),
            ("items", {"type": "array", "items": {"type": "integer"}}, [1, 2], [1, "x"]),
            ("required", {"type": "object", "required": ["a"]}, {"a": 1}, {}),
            (
                "additionalProperties",
                {"type": "object", "additionalProperties": False, "properties": {"a": {}}},
                {"a": 1},
                {"b": 2},
            ),
            ("allOf", {"allOf": [{"type": "integer"}, {"minimum": 1}]}, 2, 0),
        ]
        for keyword, schema, good, bad in cases:
            with self.subTest(keyword=keyword):
                probe.validate_schema_instance(good, schema, root)
                with self.assertRaises(probe.ProbeError):
                    probe.validate_schema_instance(bad, schema, root)
        probe.validate_schema_instance("ok", {"$ref": "#/$defs/s"}, root)
        with self.assertRaises(probe.ProbeError):
            probe.validate_schema_instance(5, {"$ref": "#/$defs/s"}, root)

    def test_if_then_conditional_is_enforced_not_ignored(self):
        schema = {
            "if": {"properties": {"kind": {"const": "a"}}, "required": ["kind"]},
            "then": {"required": ["extra"]},
            "else": {"required": ["other"]},
        }
        probe.validate_schema_instance({"kind": "a", "extra": 1}, schema, schema)
        probe.validate_schema_instance({"kind": "b", "other": 1}, schema, schema)
        with self.assertRaises(probe.ProbeError):
            probe.validate_schema_instance({"kind": "a"}, schema, schema)
        with self.assertRaises(probe.ProbeError):
            probe.validate_schema_instance({"kind": "b"}, schema, schema)

    def test_anyof_oneof_not_are_enforced(self):
        probe.validate_schema_instance(
            5, {"anyOf": [{"type": "integer"}, {"type": "string"}]}, {}
        )
        with self.assertRaises(probe.ProbeError):
            probe.validate_schema_instance(
                [], {"anyOf": [{"type": "integer"}, {"type": "string"}]}, {}
            )
        probe.validate_schema_instance(
            5, {"oneOf": [{"type": "integer"}, {"type": "string"}]}, {}
        )
        with self.assertRaises(probe.ProbeError):
            probe.validate_schema_instance(
                5, {"oneOf": [{"minimum": 1}, {"type": "integer"}]}, {}
            )
        probe.validate_schema_instance(5, {"not": {"type": "string"}}, {})
        with self.assertRaises(probe.ProbeError):
            probe.validate_schema_instance("x", {"not": {"type": "string"}}, {})

    def test_const_and_enum_never_conflate_boolean_and_number(self):
        for bad in (0, 1, True, "false", None):
            with self.subTest(bad=bad):
                with self.assertRaises(probe.ProbeError):
                    probe.validate_schema_instance(bad, {"const": False}, {})
        probe.validate_schema_instance(False, {"const": False}, {})
        probe.validate_schema_instance(True, {"enum": [True, "yes"]}, {})
        with self.assertRaises(probe.ProbeError):
            probe.validate_schema_instance(1, {"enum": [True, "yes"]}, {})

    def test_force_cancellation_proven_numeric_is_rejected(self):
        value = _evidence()
        value["cancellation"]["force_cancellation_proven"] = 0
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)

    def test_success_conditional_is_enforced_by_internal_schema_layer(self):
        # The internal validator now enforces the schema's if/then, so a SUCCESS
        # with the wrong case count fails at the schema layer, not only semantics.
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        value = _evidence()
        value["cases"] = value["cases"][:-1]
        with self.assertRaises(probe.ProbeError):
            probe.validate_schema_instance(value, schema, schema)

    # ---- both validation layers agree (invariant 8) ------------------------

    @unittest.skipUnless(_HAVE_JSONSCHEMA, "jsonschema is not installed")
    def test_schema_is_valid_draft2020(self):
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        _jsonschema.Draft202012Validator.check_schema(schema)

    @unittest.skipUnless(_HAVE_JSONSCHEMA, "jsonschema is not installed")
    def test_reference_evidence_passes_both_validators(self):
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        validator = _jsonschema.Draft202012Validator(schema)
        for value in (_evidence(), _evidence_with_coredump()):
            probe.validate_evidence(value, SCHEMA_PATH)
            validator.validate(value)

    @unittest.skipUnless(_HAVE_JSONSCHEMA, "jsonschema is not installed")
    def test_schema_representable_mutation_fails_both_validators(self):
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        value = _evidence()
        value["cancellation"]["force_cancellation_proven"] = True
        with self.assertRaises(probe.ProbeError):
            probe.validate_schema_instance(value, schema, schema)
        with self.assertRaises(_jsonschema.ValidationError):
            _jsonschema.Draft202012Validator(schema).validate(value)


_VALID_STATUS = {
    "NoNewPrivs": "1",
    "Uid": "61234 61234 61234 61234",
    "Gid": "61234 61234 61234 61234",
    "Groups": "",
    "CapInh": "0000000000000000",
    "CapPrm": "0000000000000000",
    "CapEff": "0000000000000000",
    "CapBnd": "0000000000000000",
    "CapAmb": "0000000000000000",
}
_VALID_MOUNTINFO = (
    "24 30 0:21 / / rw,relatime shared:1 - overlay overlay rw\n"
    "25 24 0:22 / /tmp rw,nosuid,nodev,noexec,relatime shared:5 - tmpfs tmpfs rw,size=12288k\n"
    "26 24 0:23 / /var/tmp rw,nosuid,nodev,noexec,relatime shared:6 - tmpfs tmpfs rw,size=12288k\n"
)
_NS_CHILD = {
    "mnt": "mnt:[4026532100]",
    "net": "net:[4026532200]",
    "ipc": "ipc:[4026532300]",
    "uts": "uts:[4026532400]",
}
_NS_SUPERVISOR = {
    "mnt": "mnt:[4026531840]",
    "net": "net:[4026531992]",
    "ipc": "ipc:[4026531839]",
    "uts": "uts:[4026531838]",
}
_VALID_LIMITS = (
    "Limit                     Soft Limit           Hard Limit           Units\n"
    "Max open files            128                  128                  files\n"
    "Max file size             8388608              8388608              bytes\n"
    "Max core file size        0                    0                    bytes\n"
)
_VALID_STATUS_RAW = (
    "".join(f"{key}:\t{value}\n" for key, value in _VALID_STATUS.items())
    + "Umask:\t0077\n"
)
_VALID_WORKING_DIRECTORY = {
    "cwd_path": "/run/p0-v2-gate1/exec-abcd",
    "cwd_device": 66,
    "cwd_inode": 424242,
    "exec_dir_path": "/run/p0-v2-gate1/exec-abcd",
    "exec_dir_device": 66,
    "exec_dir_inode": 424242,
}
_VALID_CGROUP_LIMITS = {
    "pids.max": "64",
    "memory.max": "268435456",
    "memory.swap.max": "0",
    "memory.oom.group": "1",
    "cpu.max": "100000 100000",
}
_WITNESS_DIGEST = hashlib.sha256(b"valid-elf-witness-bytes").hexdigest()


def _bootstrap_case(
    status=None,
    mountinfo=None,
    namespaces=None,
    supervisor_namespaces=None,
    limits=None,
    status_raw=None,
    working_directory=None,
    cgroup_limits=None,
    observations=None,
):
    """A case dict carrying the trusted kernel-observed bootstrap observations the
    per-case effect predicates are re-derived from."""
    if observations is None:
        observations = [
            _observation(
                "bootstrap.status",
                "kernel_observed",
                _VALID_STATUS if status is None else status,
            ),
            _observation(
                "bootstrap.mountinfo",
                "kernel_observed",
                _VALID_MOUNTINFO if mountinfo is None else mountinfo,
            ),
            _observation(
                "bootstrap.namespaces",
                "kernel_observed",
                _NS_CHILD if namespaces is None else namespaces,
            ),
            _observation(
                "bootstrap.supervisor_namespaces",
                "kernel_observed",
                _NS_SUPERVISOR if supervisor_namespaces is None else supervisor_namespaces,
            ),
            _observation(
                "bootstrap.limits",
                "kernel_observed",
                _VALID_LIMITS if limits is None else limits,
            ),
            _observation(
                "bootstrap.status_raw",
                "kernel_observed",
                _VALID_STATUS_RAW if status_raw is None else status_raw,
            ),
            _observation(
                "bootstrap.working_directory",
                "kernel_observed",
                _VALID_WORKING_DIRECTORY if working_directory is None else working_directory,
            ),
            _observation(
                "cgroup.limits",
                "kernel_observed",
                _VALID_CGROUP_LIMITS if cgroup_limits is None else cgroup_limits,
            ),
        ]
    return {"id": "success", "observations": observations}


def _noexec_witness_record(**over):
    """A fully valid trusted noexec witness record; keyword overrides shallow-merge
    into the named top-level section (source/positive_control/noexec_attempt)."""
    record = {
        "authority": "kernel_observed",
        "source": {
            "requested_path": "/usr/bin/true",
            "resolved_path": "/usr/bin/true",
            "sha256": _WITNESS_DIGEST,
            "size": 35000,
            "elf_magic": True,
        },
        "positive_control": {
            "path": "/run/p0-v2-gate1/noexec-witness-x/control/witness",
            "staged_sha256": _WITNESS_DIGEST,
            "classification": probe.EXECVE_EXECUTED,
            "outcome": {"kind": "executed", "exit_code": 0},
        },
        "noexec_attempt": {
            "path": "/run/p0-v2-gate1/noexec-witness-x/noexec/witness",
            "staged_sha256": _WITNESS_DIGEST,
            "readback_sha256": _WITNESS_DIGEST,
            "mount_options": ["nodev", "noexec", "nosuid", "relatime", "rw"],
            "classification": probe.EXECVE_NOEXEC_DENIED,
            "outcome": {"kind": "oserror", "errno": 13},
        },
    }
    for key, value in over.items():
        if isinstance(value, dict) and isinstance(record.get(key), dict):
            merged = dict(record[key])
            merged.update(value)
            record[key] = merged
        else:
            record[key] = value
    return record


def _set_effective(value, name, new_value):
    for item in value["controls"]["effective_observed"]:
        if item["name"] == name:
            item["value"] = new_value
            return
    raise AssertionError(f"effective control {name} not present")


class NoexecWitnessProvenanceTests(unittest.TestCase):
    """T-F7.1: valid, provenance-bound ELF selection and byte-identity binding."""

    def _make_file(self, content, mode=0o755):
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(directory, ignore_errors=True))
        path = directory / "witness"
        path.write_bytes(content)
        os.chmod(path, mode)
        return path

    def _validate(self, path, *, uid=0, mode=None, size=None):
        fd = os.open(str(path), os.O_RDONLY)
        try:
            with mock.patch("os.fstat", _fstat_forcing(uid=uid, mode=mode, size=size)):
                return probe.validate_witness_elf_fd(fd, str(path))
        finally:
            os.close(fd)

    def test_valid_root_owned_elf_is_accepted_and_digest_bound(self):
        content = probe.ELF_MAGIC + b"\x00" * 300
        path = self._make_file(content)
        digest, size = self._validate(path)
        self.assertEqual(hashlib.sha256(content).hexdigest(), digest)
        self.assertEqual(len(content), size)

    def test_non_elf_magic_is_rejected(self):
        path = self._make_file(b"#!/bin/sh\n" + b"x" * 300)
        with self.assertRaises(probe.ProbeError) as caught:
            self._validate(path)
        self.assertEqual("NOEXEC_WITNESS_NOT_ELF", caught.exception.code)

    def test_truncated_file_below_minimum_is_rejected(self):
        path = self._make_file(probe.ELF_MAGIC + b"\x00" * 4)
        with self.assertRaises(probe.ProbeError) as caught:
            self._validate(path)
        self.assertEqual("NOEXEC_WITNESS_SIZE_OUT_OF_BOUNDS", caught.exception.code)

    def test_oversized_file_is_rejected(self):
        path = self._make_file(probe.ELF_MAGIC + b"\x00" * 300)
        with self.assertRaises(probe.ProbeError) as caught:
            self._validate(path, size=probe.NOEXEC_WITNESS_MAX_ELF_BYTES + 1)
        self.assertEqual("NOEXEC_WITNESS_SIZE_OUT_OF_BOUNDS", caught.exception.code)

    def test_size_that_disagrees_with_bytes_is_rejected(self):
        path = self._make_file(probe.ELF_MAGIC + b"\x00" * 300)
        with self.assertRaises(probe.ProbeError) as caught:
            self._validate(path, size=len(probe.ELF_MAGIC) + 300 + 500)
        self.assertEqual("NOEXEC_WITNESS_SIZE_UNSTABLE", caught.exception.code)

    def test_non_root_owned_is_rejected(self):
        path = self._make_file(probe.ELF_MAGIC + b"\x00" * 300)
        with self.assertRaises(probe.ProbeError) as caught:
            self._validate(path, uid=1000)
        self.assertEqual("NOEXEC_WITNESS_NOT_ROOT_OWNED", caught.exception.code)

    def test_group_or_other_writable_is_rejected(self):
        path = self._make_file(probe.ELF_MAGIC + b"\x00" * 300)
        with self.assertRaises(probe.ProbeError) as caught:
            self._validate(path, mode=0o775)
        self.assertEqual("NOEXEC_WITNESS_WRITABLE", caught.exception.code)

    def test_non_regular_file_is_rejected(self):
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(directory, ignore_errors=True))
        fifo = directory / "witness.fifo"
        os.mkfifo(fifo)
        fd = os.open(str(fifo), os.O_RDONLY | os.O_NONBLOCK)
        try:
            with self.assertRaises(probe.ProbeError) as caught:
                probe.validate_witness_elf_fd(fd, str(fifo))
        finally:
            os.close(fd)
        self.assertEqual("NOEXEC_WITNESS_NOT_REGULAR", caught.exception.code)

    def test_non_executable_regular_file_is_rejected(self):
        path = self._make_file(probe.ELF_MAGIC + b"\x00" * 300, mode=0o644)
        with self.assertRaises(probe.ProbeError) as caught:
            self._validate(path, mode=0o644)
        self.assertEqual("NOEXEC_WITNESS_NOT_EXECUTABLE", caught.exception.code)

    def test_select_skips_non_root_candidates_and_fails_closed(self):
        content = probe.ELF_MAGIC + b"\x00" * 300
        path = self._make_file(content)
        with self.assertRaises(probe.ProbeError) as caught:
            probe.select_noexec_witness_elf(candidates=[str(path)])
        self.assertEqual("NOEXEC_WITNESS_UNAVAILABLE", caught.exception.code)

    def test_select_binds_first_valid_candidate_by_digest(self):
        content = probe.ELF_MAGIC + b"\x00" * 300
        path = self._make_file(content)
        with mock.patch("os.fstat", _fstat_forcing(uid=0)):
            selected = probe.select_noexec_witness_elf(candidates=["/nonexistent/x", str(path)])
        try:
            self.assertEqual(hashlib.sha256(content).hexdigest(), selected["sha256"])
            # The bound path is the fixed candidate itself (no realpath rewrite):
            # a non-symlink regular file is used exactly as named.
            self.assertEqual(str(path), selected["resolved_path"])
        finally:
            os.close(selected["fd"])

    def test_symlink_candidate_to_valid_target_is_rejected_fail_closed(self):
        # F7 provenance rejects any candidate that is itself a symlink -- even one
        # pointing at an otherwise valid, root-owned, ELF-magic target -- so a
        # symlink can never be substituted for a fixed provenance path.
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(directory, ignore_errors=True))
        target = directory / "payload"
        target.write_bytes(probe.ELF_MAGIC + b"\x00" * 300)
        os.chmod(target, 0o755)
        link = directory / "link"
        os.symlink(target, link)
        # The target itself passes provenance (with forced root ownership) — proving
        # the rejection is due to the symlink candidate, not the target's contents.
        target_fd = os.open(str(target), os.O_RDONLY)
        try:
            with mock.patch("os.fstat", _fstat_forcing(uid=0)):
                probe.validate_witness_elf_fd(target_fd, str(target))
        finally:
            os.close(target_fd)
        with mock.patch("os.fstat", _fstat_forcing(uid=0)):
            with self.assertRaises(probe.ProbeError) as caught:
                probe.select_noexec_witness_elf(candidates=[str(link)])
        self.assertEqual("NOEXEC_WITNESS_UNAVAILABLE", caught.exception.code)
        self.assertIn("symlink", caught.exception.detail)

    def test_o_nofollow_absence_is_fail_closed(self):
        with mock.patch.object(probe.os, "O_NOFOLLOW", 0, create=True):
            with self.assertRaises(probe.ProbeError) as caught:
                probe.select_noexec_witness_elf(candidates=["/usr/bin/true"])
        self.assertEqual("O_NOFOLLOW_UNSUPPORTED", caught.exception.code)


class ExecveClassificationTests(unittest.TestCase):
    """T-F7.1/F7.3: only an EACCES noexec denial credits; everything else fails."""

    def test_eacces_is_the_only_noexec_denial(self):
        self.assertEqual(
            probe.EXECVE_NOEXEC_DENIED,
            probe.classify_execve_witness({"kind": "oserror", "errno": errno.EACCES}),
        )

    def test_enoexec_is_wrong_format(self):
        self.assertEqual(
            probe.EXECVE_WRONG_FORMAT,
            probe.classify_execve_witness({"kind": "oserror", "errno": errno.ENOEXEC}),
        )

    def test_missing_loader_errnos(self):
        self.assertEqual(
            probe.EXECVE_MISSING_LOADER,
            probe.classify_execve_witness({"kind": "oserror", "errno": errno.ENOENT}),
        )

    def test_unrelated_permission_error(self):
        self.assertEqual(
            probe.EXECVE_PERMISSION_DENIED,
            probe.classify_execve_witness({"kind": "oserror", "errno": errno.EPERM}),
        )

    def test_other_errno_is_other_error(self):
        self.assertEqual(
            probe.EXECVE_OTHER_ERROR,
            probe.classify_execve_witness({"kind": "oserror", "errno": errno.EIO}),
        )

    def test_executed_signal_timeout_and_ambiguous(self):
        self.assertEqual(
            probe.EXECVE_EXECUTED,
            probe.classify_execve_witness({"kind": "executed", "exit_code": 0}),
        )
        self.assertEqual(
            probe.EXECVE_TERMINATED_BY_SIGNAL,
            probe.classify_execve_witness({"kind": "signal", "signal": 9}),
        )
        self.assertEqual(
            probe.EXECVE_TIMED_OUT, probe.classify_execve_witness({"kind": "timeout"})
        )
        self.assertEqual(probe.EXECVE_AMBIGUOUS, probe.classify_execve_witness({}))


class ExecveProbeRuntimeTests(unittest.TestCase):
    """T-F7.1: the trusted execve probe reports only kernel-authored outcomes.

    Exercised with benign, non-hostile executables (the interpreter, a missing
    path, and an invalid-format regular file). No systemd, cgroup, or hostile
    fixture is ever executed; this only proves the probe's outcome plumbing feeds
    classify_execve_witness correctly. The actual noexec-mount EACCES effect stays
    hosted-only."""

    @unittest.skipUnless(hasattr(os, "fork"), "requires os.fork")
    def test_successful_exec_is_reported_executed(self):
        outcome = probe._run_execve_probe(sys.executable, timeout=30.0)
        self.assertEqual("executed", outcome["kind"])
        self.assertEqual(probe.EXECVE_EXECUTED, probe.classify_execve_witness(outcome))

    @unittest.skipUnless(hasattr(os, "fork"), "requires os.fork")
    def test_missing_path_is_reported_as_enoent_oserror(self):
        outcome = probe._run_execve_probe("/nonexistent/p0-v2-witness-xyz", timeout=30.0)
        self.assertEqual("oserror", outcome["kind"])
        self.assertEqual(errno.ENOENT, outcome["errno"])
        self.assertEqual(
            probe.EXECVE_MISSING_LOADER, probe.classify_execve_witness(outcome)
        )

    @unittest.skipUnless(hasattr(os, "fork"), "requires os.fork")
    def test_invalid_format_regular_file_is_not_executed(self):
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(directory, ignore_errors=True))
        garbage = directory / "garbage"
        garbage.write_bytes(b"\x00\x01\x02\x03 not a program\n")
        os.chmod(garbage, 0o755)
        outcome = probe._run_execve_probe(str(garbage), timeout=30.0)
        self.assertEqual("oserror", outcome["kind"])
        self.assertNotIn(
            probe.classify_execve_witness(outcome),
            {probe.EXECVE_EXECUTED, probe.EXECVE_NOEXEC_DENIED},
        )


class NoexecWitnessCompositionTests(unittest.TestCase):
    """T-F7.1: the exact noexec denial is credited only with every provenance and
    byte-identity binding intact."""

    def test_full_valid_witness_passes(self):
        probe.verify_noexec_witness(_noexec_witness_record())

    def test_control_must_execute(self):
        for bad in (
            probe.EXECVE_WRONG_FORMAT,
            probe.EXECVE_NOEXEC_DENIED,
            probe.EXECVE_TIMED_OUT,
            probe.EXECVE_AMBIGUOUS,
        ):
            with self.assertRaises(probe.ProbeError) as caught:
                probe.verify_noexec_witness(
                    _noexec_witness_record(positive_control={"classification": bad})
                )
            self.assertEqual(
                "NOEXEC_WITNESS_CONTROL_NOT_EXECUTABLE", caught.exception.code
            )

    def test_control_bytes_must_be_byte_identical(self):
        with self.assertRaises(probe.ProbeError) as caught:
            probe.verify_noexec_witness(
                _noexec_witness_record(positive_control={"staged_sha256": "f" * 64})
            )
        self.assertEqual("NOEXEC_WITNESS_CONTROL_DIGEST_MISMATCH", caught.exception.code)

    def test_noexec_staged_and_readback_bytes_must_match_source(self):
        with self.assertRaises(probe.ProbeError) as caught:
            probe.verify_noexec_witness(
                _noexec_witness_record(noexec_attempt={"staged_sha256": "e" * 64})
            )
        self.assertEqual("NOEXEC_WITNESS_ATTEMPT_DIGEST_MISMATCH", caught.exception.code)
        with self.assertRaises(probe.ProbeError) as caught:
            probe.verify_noexec_witness(
                _noexec_witness_record(noexec_attempt={"readback_sha256": "d" * 64})
            )
        self.assertEqual("NOEXEC_WITNESS_READBACK_MISMATCH", caught.exception.code)

    def test_every_non_denial_classification_is_rejected(self):
        for classification in (
            probe.EXECVE_EXECUTED,
            probe.EXECVE_WRONG_FORMAT,
            probe.EXECVE_MISSING_LOADER,
            probe.EXECVE_PERMISSION_DENIED,
            probe.EXECVE_TERMINATED_BY_SIGNAL,
            probe.EXECVE_TIMED_OUT,
            probe.EXECVE_OTHER_ERROR,
            probe.EXECVE_AMBIGUOUS,
        ):
            with self.assertRaises(probe.ProbeError) as caught:
                probe.verify_noexec_witness(
                    _noexec_witness_record(
                        noexec_attempt={"classification": classification}
                    )
                )
            self.assertEqual("NOEXEC_WITNESS_NOT_DENIED", caught.exception.code)

    def test_eacces_on_a_non_noexec_mount_is_not_credited(self):
        # The isolation from an unrelated EACCES: a denial is credited only when
        # the mount the bytes were staged into independently shows noexec.
        with self.assertRaises(probe.ProbeError) as caught:
            probe.verify_noexec_witness(
                _noexec_witness_record(noexec_attempt={"mount_options": ["rw", "relatime"]})
            )
        self.assertEqual("NOEXEC_WITNESS_MOUNT_NOT_NOEXEC", caught.exception.code)

    def test_source_provenance_bindings_are_required(self):
        for over, code in (
            ({"source": {"sha256": "nothex"}}, "NOEXEC_WITNESS_INVALID"),
            ({"source": {"size": "35000"}}, "NOEXEC_WITNESS_INVALID"),
            ({"source": {"size": 10}}, "NOEXEC_WITNESS_INVALID"),
            ({"source": {"elf_magic": False}}, "NOEXEC_WITNESS_INVALID"),
        ):
            with self.assertRaises(probe.ProbeError) as caught:
                probe.verify_noexec_witness(_noexec_witness_record(**over))
            self.assertEqual(code, caught.exception.code)

    def test_classification_derived_from_outcome_still_verifies(self):
        outcome = {"kind": "oserror", "errno": errno.EACCES}
        record = _noexec_witness_record(
            noexec_attempt={
                "classification": probe.classify_execve_witness(outcome),
                "outcome": outcome,
            }
        )
        probe.verify_noexec_witness(record)

    def test_runtime_witness_fails_closed_when_no_elf_is_available(self):
        # The runtime wrapper never raises and never executes anything when no
        # provenance-bound ELF exists; it fails closed so SUCCESS is unreachable.
        with mock.patch.object(
            probe,
            "select_noexec_witness_elf",
            side_effect=probe.ProbeError("NOEXEC_WITNESS_UNAVAILABLE", "none"),
        ):
            ok, record = probe.run_noexec_substrate_witness()
        self.assertFalse(ok)
        self.assertIn("error", record)
        self.assertFalse(record.get("verified"))


class MountinfoNoexecTests(unittest.TestCase):
    """T-F7.1: independently interpretable per-case noexec from /proc mountinfo."""

    def test_hardened_tmp_mounts_are_recognised(self):
        self.assertTrue(probe.mountinfo_noexec_enforced(_VALID_MOUNTINFO))

    def test_missing_target_mount_is_not_hardened(self):
        only_tmp = (
            "25 24 0:22 / /tmp rw,nosuid,nodev,noexec,relatime shared:5 - tmpfs tmpfs rw\n"
        )
        self.assertFalse(probe.mountinfo_noexec_enforced(only_tmp))

    def test_missing_any_required_flag_is_not_hardened(self):
        exec_tmp = _VALID_MOUNTINFO.replace(
            "rw,nosuid,nodev,noexec,relatime shared:5", "rw,nosuid,nodev,relatime shared:5"
        )
        self.assertFalse(probe.mountinfo_noexec_enforced(exec_tmp))
        evaluation = probe.evaluate_noexec_mounts(exec_tmp)
        self.assertFalse(evaluation["/tmp"]["hardened"])
        self.assertTrue(evaluation["/var/tmp"]["hardened"])

    def test_last_stacked_mount_at_the_exact_point_wins(self):
        stacked = _VALID_MOUNTINFO + (
            "40 24 0:44 / /tmp rw,nosuid,nodev,noexec,relatime shared:9 - tmpfs tmpfs rw\n"
        )
        self.assertTrue(probe.mountinfo_noexec_enforced(stacked))
        shadowed = _VALID_MOUNTINFO + (
            "40 24 0:44 / /tmp rw,relatime shared:9 - tmpfs tmpfs rw\n"
        )
        self.assertFalse(probe.mountinfo_noexec_enforced(shadowed))

    def test_parent_mount_noexec_does_not_satisfy_child_point(self):
        parent_only = (
            "24 30 0:21 / / rw,noexec,nosuid,nodev,relatime shared:1 - overlay overlay rw\n"
            "25 24 0:22 / /tmp rw,relatime shared:5 - tmpfs tmpfs rw\n"
            "26 24 0:23 / /var/tmp rw,relatime shared:6 - tmpfs tmpfs rw\n"
        )
        self.assertFalse(probe.mountinfo_noexec_enforced(parent_only))

    def test_malformed_mountinfo_fails_closed(self):
        self.assertFalse(probe.mountinfo_noexec_enforced("garbage line without separator"))
        with self.assertRaises(probe.ProbeError):
            probe.parse_mountinfo("1 2 3 4 5 6 no-dash-here fields")

    def test_octal_escaped_mount_point_is_decoded(self):
        escaped = (
            "25 24 0:22 / /wei\\040rd rw,noexec shared:5 - tmpfs tmpfs rw\n"
        )
        entries = probe.parse_mountinfo(escaped)
        self.assertEqual("/wei rd", entries[0]["mount_point"])


class BootstrapEffectDerivationTests(unittest.TestCase):
    """T-F7.2: each per-case effect predicate is re-derived from a distinct trusted
    kernel observation and fails closed independently."""

    def test_all_effects_true_for_a_healthy_case(self):
        effects = probe.derive_bootstrap_effect_controls(_bootstrap_case())
        self.assertTrue(all(effects.values()))
        self.assertEqual(
            {
                "dedicated_uid_effective",
                "no_new_privileges_effective",
                "capability_bounding_empty",
                "private_namespaces_effective",
                "private_uts_namespace_effective",
                "private_tmp_noexec_enforced",
                "resource_limits_effective",
                "umask_effective",
                "working_directory_effective",
                "tasks_max_effective",
                "memory_max_effective",
                "memory_swap_max_effective",
                "memory_oom_group_effective",
                "cpu_quota_effective",
            },
            set(effects),
        )

    def test_derived_effect_keys_match_the_per_case_effect_contract(self):
        # The emitted per-case effect set must never drift from the derivation.
        derived = set(probe.derive_bootstrap_effect_controls(_bootstrap_case()))
        per_case = {name for name, _ in probe.EFFECTIVE_CONTROL_PER_CASE}
        self.assertTrue(derived <= per_case)
        # Every inventory per-case effect_proven control is a derived key.
        inventory_per_case = {
            entry.effect_control
            for entry in probe.MANDATORY_CONTROL_INVENTORY
            if entry.effect_control is not None and entry.scope == "per_case"
        }
        self.assertEqual(inventory_per_case, derived)

    def test_no_new_privileges_effect_isolated(self):
        status = dict(_VALID_STATUS, NoNewPrivs="0")
        effects = probe.derive_bootstrap_effect_controls(_bootstrap_case(status=status))
        self.assertFalse(effects["no_new_privileges_effective"])
        self.assertTrue(effects["capability_bounding_empty"])
        self.assertTrue(effects["private_tmp_noexec_enforced"])

    def test_dedicated_uid_effect_rejects_root_or_inconsistent(self):
        for uid in ("0 0 0 0", "61234 0 61234 61234", "61234 61234 61234"):
            status = dict(_VALID_STATUS, Uid=uid)
            self.assertFalse(
                probe.derive_bootstrap_effect_controls(
                    _bootstrap_case(status=status)
                )["dedicated_uid_effective"]
            )

    def test_dedicated_uid_effect_rejects_supplementary_groups(self):
        status = dict(_VALID_STATUS, Groups="61234 27")
        self.assertFalse(
            probe.derive_bootstrap_effect_controls(
                _bootstrap_case(status=status)
            )["dedicated_uid_effective"]
        )

    def test_capability_effect_rejects_nonzero_mask(self):
        status = dict(_VALID_STATUS, CapBnd="000001ffffffffff")
        self.assertFalse(
            probe.derive_bootstrap_effect_controls(
                _bootstrap_case(status=status)
            )["capability_bounding_empty"]
        )

    def test_namespace_effect_rejects_shared_namespace(self):
        shared = dict(_NS_CHILD, mnt=_NS_SUPERVISOR["mnt"])
        self.assertFalse(
            probe.derive_bootstrap_effect_controls(
                _bootstrap_case(namespaces=shared)
            )["private_namespaces_effective"]
        )

    def test_private_tmp_effect_rejects_exec_mount(self):
        exec_tmp = _VALID_MOUNTINFO.replace("nosuid,nodev,noexec", "nosuid,nodev")
        self.assertFalse(
            probe.derive_bootstrap_effect_controls(
                _bootstrap_case(mountinfo=exec_tmp)
            )["private_tmp_noexec_enforced"]
        )

    def test_resource_limits_effect_rejects_wrong_ceiling(self):
        limits = _VALID_LIMITS.replace("128", "1024")
        self.assertFalse(
            probe.derive_bootstrap_effect_controls(
                _bootstrap_case(limits=limits)
            )["resource_limits_effective"]
        )

    def test_missing_wrong_authority_or_duplicate_observation_fails_closed(self):
        self.assertFalse(
            all(probe.derive_bootstrap_effect_controls({"observations": []}).values())
        )
        wrong_authority = _bootstrap_case()
        wrong_authority["observations"][0]["authority"] = "child_untrusted"
        self.assertFalse(
            probe.derive_bootstrap_effect_controls(wrong_authority)[
                "no_new_privileges_effective"
            ]
        )
        duplicated = _bootstrap_case()
        duplicated["observations"].append(dict(duplicated["observations"][0]))
        self.assertFalse(
            probe.derive_bootstrap_effect_controls(duplicated)[
                "no_new_privileges_effective"
            ]
        )


class DirectStateEffectTests(unittest.TestCase):
    """T-F7-A: exact positive/negative kernel-state derivations for the eight
    properties moved from effect_unproven to effect_proven."""

    # ---- UMask from /proc/<pid>/status -------------------------------------

    def test_status_field_rejects_missing_and_duplicate(self):
        self.assertEqual("0077", probe.parse_status_field("Umask:\t0077\n", "Umask"))
        self.assertIsNone(probe.parse_status_field("Name:\tx\n", "Umask"))
        self.assertIsNone(
            probe.parse_status_field("Umask:\t0077\nUmask:\t0022\n", "Umask")
        )
        self.assertIsNone(probe.parse_status_field(None, "Umask"))

    def test_umask_positive_and_negative(self):
        self.assertTrue(probe.status_umask_is_0077("Umask:\t0077\n"))
        self.assertTrue(probe.status_umask_is_0077("Umask:\t077\n"))
        self.assertFalse(probe.status_umask_is_0077("Umask:\t0022\n"))
        self.assertFalse(probe.status_umask_is_0077("Umask:\t7777\n"))
        self.assertFalse(probe.status_umask_is_0077("Umask:\t0o77\n"))
        self.assertFalse(probe.status_umask_is_0077("Umask:\t\n"))
        self.assertFalse(probe.status_umask_is_0077("Umask:\t0077\nUmask:\t0077\n"))
        self.assertFalse(probe.status_umask_is_0077(""))

    def test_umask_effect_blocks_via_derive(self):
        bad = probe.derive_bootstrap_effect_controls(
            _bootstrap_case(status_raw="Umask:\t0022\n")
        )
        self.assertFalse(bad["umask_effective"])

    # ---- WorkingDirectory from /proc/<pid>/cwd -----------------------------

    def test_working_directory_identity_positive(self):
        self.assertTrue(
            probe.working_directory_identity_effective(_VALID_WORKING_DIRECTORY)
        )

    def test_working_directory_rejects_prefix_and_identity_mismatch(self):
        prefix = dict(_VALID_WORKING_DIRECTORY, cwd_path="/run/p0-v2-gate1/exec-abcd/sub")
        self.assertFalse(probe.working_directory_identity_effective(prefix))
        wrong_dev = dict(_VALID_WORKING_DIRECTORY, cwd_device=99)
        self.assertFalse(probe.working_directory_identity_effective(wrong_dev))
        wrong_ino = dict(_VALID_WORKING_DIRECTORY, cwd_inode=1)
        self.assertFalse(probe.working_directory_identity_effective(wrong_ino))

    def test_working_directory_rejects_missing_and_wrong_type(self):
        self.assertFalse(probe.working_directory_identity_effective({}))
        self.assertFalse(probe.working_directory_identity_effective(None))
        bad_type = dict(_VALID_WORKING_DIRECTORY, cwd_inode="424242")
        self.assertFalse(probe.working_directory_identity_effective(bad_type))
        bool_dev = dict(_VALID_WORKING_DIRECTORY, cwd_device=True)
        self.assertFalse(probe.working_directory_identity_effective(bool_dev))

    # ---- ProtectHostname from the UTS namespace ----------------------------

    def test_uts_namespace_private_positive_and_negative(self):
        self.assertTrue(probe.uts_namespace_private(_NS_CHILD, _NS_SUPERVISOR))
        same = dict(_NS_CHILD, uts=_NS_SUPERVISOR["uts"])
        self.assertFalse(probe.uts_namespace_private(same, _NS_SUPERVISOR))
        self.assertFalse(probe.uts_namespace_private({"mnt": "x"}, _NS_SUPERVISOR))
        self.assertFalse(
            probe.uts_namespace_private(dict(_NS_CHILD, uts=""), _NS_SUPERVISOR)
        )

    # ---- cgroup controller-limit files -------------------------------------

    def test_cgroup_scalar_single_token_only(self):
        limits = {"pids.max": "64", "bad": "64 extra", "empty": "", "null": None}
        self.assertEqual("64", probe._cgroup_scalar(limits, "pids.max"))
        self.assertIsNone(probe._cgroup_scalar(limits, "bad"))
        self.assertIsNone(probe._cgroup_scalar(limits, "empty"))
        self.assertIsNone(probe._cgroup_scalar(limits, "null"))
        self.assertIsNone(probe._cgroup_scalar(limits, "absent"))
        self.assertIsNone(probe._cgroup_scalar("notamap", "pids.max"))

    def test_parse_cpu_max_forms(self):
        self.assertEqual((100000, 100000), probe.parse_cpu_max("100000 100000"))
        self.assertIsNone(probe.parse_cpu_max("max 100000"))
        self.assertIsNone(probe.parse_cpu_max("100000"))
        self.assertIsNone(probe.parse_cpu_max("100000 100000 0"))
        self.assertIsNone(probe.parse_cpu_max("100000 0"))
        self.assertIsNone(probe.parse_cpu_max("-1 100000"))
        self.assertIsNone(probe.parse_cpu_max("1.0 100000"))
        self.assertIsNone(probe.parse_cpu_max(None))

    def test_cpu_quota_full_single_cpu(self):
        self.assertTrue(probe.cpu_quota_is_full_single_cpu("100000 100000"))
        self.assertTrue(probe.cpu_quota_is_full_single_cpu("50000 50000"))
        self.assertFalse(probe.cpu_quota_is_full_single_cpu("200000 100000"))
        self.assertFalse(probe.cpu_quota_is_full_single_cpu("50000 100000"))
        self.assertFalse(probe.cpu_quota_is_full_single_cpu("max 100000"))

    def test_derive_cgroup_limit_controls_positive_and_each_wrong(self):
        self.assertTrue(all(probe.derive_cgroup_limit_controls(_VALID_CGROUP_LIMITS).values()))
        for key, bad in (
            ("pids.max", "max"),
            ("memory.max", "max"),
            ("memory.swap.max", "8"),
            ("memory.oom.group", "0"),
            ("cpu.max", "max 100000"),
        ):
            limits = dict(_VALID_CGROUP_LIMITS, **{key: bad})
            self.assertFalse(
                all(probe.derive_cgroup_limit_controls(limits).values()),
                f"{key}={bad} must break some cgroup limit effect",
            )

    def test_read_cgroup_limits_reads_regular_and_fails_closed(self):
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(directory, ignore_errors=True))
        (directory / "pids.max").write_text("64\n")
        (directory / "memory.max").write_text("268435456\n")
        (directory / "memory.swap.max").write_text("0\n")
        (directory / "memory.oom.group").write_text("1\n")
        (directory / "cpu.max").write_text("100000 100000\n")
        limits = probe.read_cgroup_limits(directory)
        self.assertTrue(all(probe.derive_cgroup_limit_controls(limits).values()))

    def test_read_cgroup_limits_rejects_symlink_and_missing(self):
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(directory, ignore_errors=True))
        # symlink substitution for a controller file must fail closed to None.
        target = directory / "real"
        target.write_text("64\n")
        os.symlink(target, directory / "pids.max")
        # memory.max missing entirely; others regular.
        (directory / "memory.swap.max").write_text("0\n")
        (directory / "memory.oom.group").write_text("1\n")
        (directory / "cpu.max").write_text("100000 100000\n")
        limits = probe.read_cgroup_limits(directory)
        self.assertIsNone(limits["pids.max"])
        self.assertIsNone(limits["memory.max"])
        self.assertFalse(probe.derive_cgroup_limit_controls(limits)["tasks_max_effective"])
        self.assertFalse(probe.derive_cgroup_limit_controls(limits)["memory_max_effective"])

    def test_read_cgroup_limits_rejects_oversized(self):
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(directory, ignore_errors=True))
        (directory / "pids.max").write_bytes(b"6" * 8192)
        limits = probe.read_cgroup_limits(directory)
        self.assertIsNone(limits["pids.max"])

    # ---- each new effect blocks candidate SUCCESS on its own ---------------

    def _bad_case_for(self, **overrides):
        cases = [_perfect_case(cid) for cid in probe.CASES]
        bad = _bootstrap_case(**overrides)
        cases[0]["observations"] = bad["observations"]
        return cases

    def test_every_new_effect_false_blocks_success(self):
        scenarios = (
            {"status_raw": "Umask:\t0022\n"},
            {"working_directory": dict(_VALID_WORKING_DIRECTORY, cwd_inode=1)},
            {"namespaces": dict(_NS_CHILD, uts=_NS_SUPERVISOR["uts"])},
            {"cgroup_limits": dict(_VALID_CGROUP_LIMITS, **{"pids.max": "max"})},
            {"cgroup_limits": dict(_VALID_CGROUP_LIMITS, **{"memory.max": "max"})},
            {"cgroup_limits": dict(_VALID_CGROUP_LIMITS, **{"memory.swap.max": "8"})},
            {"cgroup_limits": dict(_VALID_CGROUP_LIMITS, **{"memory.oom.group": "0"})},
            {"cgroup_limits": dict(_VALID_CGROUP_LIMITS, **{"cpu.max": "max 100000"})},
        )
        for overrides in scenarios:
            cases = self._bad_case_for(**overrides)
            self.assertFalse(
                probe.candidate_run_succeeds(
                    cases=cases,
                    requested_case_ids=probe.CASES,
                    errors=[],
                    witness_ok=True,
                    mandatory_blockers=[],
                ),
                f"{overrides} must block SUCCESS",
            )

    def test_new_effect_wrong_authority_observation_is_ignored(self):
        # A cgroup.limits observation carrying the wrong authority is not read, so
        # the derived cgroup effects fail closed.
        case = _bootstrap_case()
        for item in case["observations"]:
            if item["name"] == "cgroup.limits":
                item["authority"] = "supervisor_observed"
        effects = probe.derive_bootstrap_effect_controls(case)
        self.assertFalse(effects["tasks_max_effective"])


class ControlInventoryTests(unittest.TestCase):
    """T-F7.2/F7.3: the mandatory-control inventory is exact and self-checking."""

    def test_inventory_is_synchronized(self):
        probe.verify_control_inventory_synchronized()

    def test_inventory_covers_exactly_the_mandatory_properties(self):
        effect = set()
        manager = set()
        for entry in probe.MANDATORY_CONTROL_INVENTORY:
            if entry.effect_control is None:
                manager |= set(entry.manager_properties)
            else:
                effect |= set(entry.manager_properties)
        self.assertEqual(set(), effect & manager)
        self.assertEqual(probe.MANDATORY_MANAGER_PROPERTIES, effect | manager)

    def test_every_effect_maps_to_one_authority_and_one_record(self):
        per_case = dict(probe.EFFECTIVE_CONTROL_PER_CASE)
        globals_ = dict(probe.EFFECTIVE_CONTROL_GLOBAL)
        names = []
        for entry in probe.MANDATORY_CONTROL_INVENTORY:
            if entry.effect_control is None:
                continue
            names.append(entry.effect_control)
            self.assertNotEqual(probe.EFFECT_UNPROVEN, entry.authority)
            if entry.scope == "per_case":
                self.assertEqual(entry.authority, per_case[entry.effect_control])
            else:
                self.assertEqual(entry.authority, globals_[entry.effect_control])
        self.assertEqual(len(names), len(set(names)))

    def test_added_mandatory_property_without_accounting_desyncs(self):
        with mock.patch.object(
            probe,
            "MANDATORY_MANAGER_PROPERTIES",
            probe.MANDATORY_MANAGER_PROPERTIES | {"NewlyRequiredProperty"},
        ):
            with self.assertRaises(probe.ProbeError) as caught:
                probe.verify_control_inventory_synchronized()
        self.assertEqual("CONTROL_INVENTORY_DESYNC", caught.exception.code)

    def test_removed_mandatory_property_still_accounted_desyncs(self):
        shrunk = frozenset(probe.MANDATORY_MANAGER_PROPERTIES - {"NoNewPrivileges"})
        with mock.patch.object(probe, "MANDATORY_MANAGER_PROPERTIES", shrunk):
            with self.assertRaises(probe.ProbeError) as caught:
                probe.verify_control_inventory_synchronized()
        self.assertEqual("CONTROL_INVENTORY_DESYNC", caught.exception.code)

    def test_one_effect_record_credited_to_two_controls_is_rejected(self):
        duplicate = probe.MANDATORY_CONTROL_INVENTORY + (
            probe.ControlInventoryEntry(
                ("NoNewPrivileges",),
                "dedicated_uid_effective",
                "kernel_observed",
                "per_case",
                "duplicate effect record",
                "n/a",
            ),
        )
        with mock.patch.object(probe, "MANDATORY_CONTROL_INVENTORY", duplicate):
            with self.assertRaises(probe.ProbeError) as caught:
                probe.verify_control_inventory_synchronized()
        self.assertEqual("CONTROL_INVENTORY_INVALID", caught.exception.code)

    def test_effect_property_also_marked_unproven_is_rejected(self):
        overlapping = probe.MANDATORY_CONTROL_INVENTORY + (
            probe.ControlInventoryEntry(
                ("DynamicUser",),
                None,
                probe.EFFECT_UNPROVEN,
                "unproven",
                "overlap",
                "n/a",
            ),
        )
        with mock.patch.object(probe, "MANDATORY_CONTROL_INVENTORY", overlapping):
            with self.assertRaises(probe.ProbeError) as caught:
                probe.verify_control_inventory_synchronized()
        self.assertEqual("CONTROL_INVENTORY_INVALID", caught.exception.code)

    def test_effect_control_absent_from_contract_is_rejected(self):
        unknown = probe.MANDATORY_CONTROL_INVENTORY + (
            probe.ControlInventoryEntry(
                ("Nonexistent",),
                "not_a_real_effect_control",
                "kernel_observed",
                "per_case",
                "phantom",
                "n/a",
            ),
        )
        with mock.patch.object(probe, "MANDATORY_CONTROL_INVENTORY", unknown):
            with self.assertRaises(probe.ProbeError):
                probe.verify_control_inventory_synchronized()


def _perfect_case(case_id):
    """A case that passes every per-case SUCCESS predicate: matching argv/env,
    complete cleanup, and healthy trusted bootstrap observations (so all six
    derived effects are True). Used to prove that the *only* thing standing
    between a flawless run and SUCCESS is the unproven-mandatory-control gate."""
    case = _bootstrap_case()
    case["id"] = case_id
    case["outcome"] = probe.EXPECTED_CASE_OUTCOMES[case_id]
    case["errors"] = []
    case["requested_argv"] = ["/usr/bin/python3", "-I", "/run/probe.py"]
    case["kernel_observed_argv"] = ["/usr/bin/python3", "-I", "/run/probe.py"]
    case["requested_environment"] = {"LANG": "C.UTF-8"}
    case["kernel_observed_environment"] = {"LANG": "C.UTF-8"}
    case["cleanup"] = {
        "direct_cgroup_kill_written": True,
        "recursive_populated_zero_observed": True,
        "streams_eof_after_empty": True,
        "unit_unloaded_after_empty": True,
    }
    return case


class SupervisorOutcomeGateTests(unittest.TestCase):
    """T-F7.2/F7.3: direct tests of the actual candidate-SUCCESS outcome gate
    (candidate_run_succeeds), proving manager equality never substitutes for a
    missing effect proof and every unproven mandatory property blocks SUCCESS."""

    def _cases(self):
        return [_perfect_case(cid) for cid in probe.CASES]

    def test_blocker_list_is_nonempty_so_success_is_structurally_unreachable(self):
        self.assertTrue(probe.mandatory_effect_blockers())

    def test_blocker_list_equals_the_effect_unproven_inventory_exactly(self):
        unproven = set()
        for entry in probe.MANDATORY_CONTROL_INVENTORY:
            if entry.effect_control is None:
                unproven |= set(entry.manager_properties)
        self.assertEqual(sorted(unproven), probe.mandatory_effect_blockers())
        self.assertTrue(unproven <= probe.MANDATORY_MANAGER_PROPERTIES)

    def test_flawless_run_is_not_success_while_blockers_exist(self):
        # A perfect run -- every case passing, witness true, no errors, and thus
        # systemd_properties_match true -- is still NOT success because unproven
        # mandatory controls remain. Manager equality cannot stand in.
        self.assertFalse(
            probe.candidate_run_succeeds(
                cases=self._cases(),
                requested_case_ids=probe.CASES,
                errors=[],
                witness_ok=True,
                mandatory_blockers=probe.mandatory_effect_blockers(),
            )
        )

    def test_flawless_run_would_be_success_only_with_zero_blockers(self):
        self.assertTrue(
            probe.candidate_run_succeeds(
                cases=self._cases(),
                requested_case_ids=probe.CASES,
                errors=[],
                witness_ok=True,
                mandatory_blockers=[],
            )
        )

    def test_each_unproven_property_individually_blocks_success(self):
        cases = self._cases()
        for prop in probe.mandatory_effect_blockers():
            self.assertFalse(
                probe.candidate_run_succeeds(
                    cases=cases,
                    requested_case_ids=probe.CASES,
                    errors=[],
                    witness_ok=True,
                    mandatory_blockers=[prop],
                ),
                f"{prop} must block SUCCESS on its own",
            )

    def test_noexec_witness_failure_blocks_success(self):
        self.assertFalse(
            probe.candidate_run_succeeds(
                cases=self._cases(),
                requested_case_ids=probe.CASES,
                errors=[],
                witness_ok=False,
                mandatory_blockers=[],
            )
        )

    def test_run_level_error_blocks_success(self):
        self.assertFalse(
            probe.candidate_run_succeeds(
                cases=self._cases(),
                requested_case_ids=probe.CASES,
                errors=[{"code": "SOMETHING"}],
                witness_ok=True,
                mandatory_blockers=[],
            )
        )

    def test_a_single_false_derived_effect_blocks_success(self):
        cases = self._cases()
        for item in cases[0]["observations"]:
            if item["name"] == "bootstrap.mountinfo":
                item["value"] = _VALID_MOUNTINFO.replace("noexec,", "")
        self.assertFalse(
            probe.candidate_run_succeeds(
                cases=cases,
                requested_case_ids=probe.CASES,
                errors=[],
                witness_ok=True,
                mandatory_blockers=[],
            )
        )

    def test_missing_case_blocks_success(self):
        self.assertFalse(
            probe.candidate_run_succeeds(
                cases=self._cases()[:-1],
                requested_case_ids=probe.CASES,
                errors=[],
                witness_ok=True,
                mandatory_blockers=[],
            )
        )

    def test_supervisor_gate_source_uses_the_pure_decision(self):
        # The runner's outcome gate must delegate to candidate_run_succeeds rather
        # than re-implement an ad-hoc SUCCESS condition that could omit the blocker.
        text = TOOL_PATH.read_text(encoding="utf-8")
        self.assertIn("if candidate_run_succeeds(", text)
        self.assertIn("mandatory_blockers = mandatory_effect_blockers()", text)
        self.assertIn("MANDATORY_CONTROL_EFFECT_UNPROVEN", text)


class EffectControlSuccessRejectionTests(unittest.TestCase):
    """T-F7.2/F7.3: mutating any F7 effect false/missing/non-boolean/wrong-authority
    makes candidate SUCCESS unreachable."""

    F7_CONTROLS = (
        "success.dedicated_uid_effective",
        "success.no_new_privileges_effective",
        "success.capability_bounding_empty",
        "success.private_namespaces_effective",
        "success.private_uts_namespace_effective",
        "success.private_tmp_noexec_enforced",
        "success.resource_limits_effective",
        "success.umask_effective",
        "success.working_directory_effective",
        "success.tasks_max_effective",
        "success.memory_max_effective",
        "success.memory_swap_max_effective",
        "success.memory_oom_group_effective",
        "success.cpu_quota_effective",
        "host.noexec_execve_denied",
    )

    def test_reference_success_carries_every_f7_control(self):
        probe.validate_evidence(_evidence(), SCHEMA_PATH)
        names = {
            item["name"]
            for item in _evidence()["controls"]["effective_observed"]
        }
        for control in self.F7_CONTROLS:
            self.assertIn(control, names)

    def test_each_f7_effect_false_rejects_success(self):
        for control in self.F7_CONTROLS:
            value = _evidence()
            _set_effective(value, control, False)
            with self.assertRaises(probe.ProbeError):
                probe.validate_evidence(value, SCHEMA_PATH)

    def test_each_f7_effect_non_boolean_rejects_success(self):
        for control in self.F7_CONTROLS:
            value = _evidence()
            _set_effective(value, control, 1)
            with self.assertRaises(probe.ProbeError):
                probe.validate_evidence(value, SCHEMA_PATH)

    def test_each_f7_effect_missing_rejects_success(self):
        for control in self.F7_CONTROLS:
            value = _evidence()
            value["controls"]["effective_observed"] = [
                item
                for item in value["controls"]["effective_observed"]
                if item["name"] != control
            ]
            with self.assertRaises(probe.ProbeError):
                probe.validate_evidence(value, SCHEMA_PATH)

    def test_kernel_effect_downgraded_to_child_authority_rejects_success(self):
        value = _evidence()
        for item in value["controls"]["effective_observed"]:
            if item["name"] == "success.private_tmp_noexec_enforced":
                item["authority"] = "child_untrusted"
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(value, SCHEMA_PATH)


class OverlappingDenialIsolationTests(unittest.TestCase):
    """T-F7.3: one opaque denial cannot satisfy two controls; the child's own
    statement is never the authority for its confinement."""

    def test_noexec_has_two_independent_proofs_from_distinct_sources(self):
        # The per-case mountinfo proof and the global execve witness are distinct
        # effect records fed by distinct inputs: mutating one never moves the other.
        mount_only = probe.derive_bootstrap_effect_controls(
            _bootstrap_case(mountinfo=_VALID_MOUNTINFO.replace("noexec,", ""))
        )
        self.assertFalse(mount_only["private_tmp_noexec_enforced"])
        # The witness classification is computed only from the trusted execve
        # outcome, wholly independent of any mountinfo text.
        self.assertEqual(
            probe.EXECVE_NOEXEC_DENIED,
            probe.classify_execve_witness({"kind": "oserror", "errno": errno.EACCES}),
        )

    def test_child_sandbox_failure_is_not_an_effect_authority(self):
        # Effects derive only from trusted kernel bootstrap observations; a case
        # whose (hostile) child output claims success but whose bootstrap is
        # ineffective still derives False, and a case with a hostile-looking child
        # payload but sound bootstrap still derives True.
        hostile_child = _bootstrap_case()
        hostile_child["observations"].append(
            _observation("child.self_report", "child_untrusted", "all-controls-passed")
        )
        self.assertTrue(
            all(probe.derive_bootstrap_effect_controls(hostile_child).values())
        )
        broken = _bootstrap_case(status=dict(_VALID_STATUS, NoNewPrivs="0"))
        broken["observations"].append(
            _observation("child.self_report", "child_untrusted", "all-controls-passed")
        )
        self.assertFalse(
            probe.derive_bootstrap_effect_controls(broken)["no_new_privileges_effective"]
        )

    def test_child_invalid_file_noexec_inference_is_gone(self):
        text = TOOL_PATH.read_text(encoding="utf-8")
        self.assertNotIn("not-an-executable", text)
        self.assertNotIn("unknown-executable", text)
        self.assertNotIn("p0-v2-unknown", text)


def _discovery_values(*, abi_present=True, bpf_success=True):
    os_release_raw = b'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n'
    systemd_feature_output = " ".join(
        f"+{name}" for name in probe.DISCOVERY_SYSTEMD_V255_FEATURE_ORDER
    ) + " default-hierarchy=unified"
    systemd_raw = (
        b"systemd 255 (255.4-1ubuntu8)\n"
        + systemd_feature_output.encode("ascii")
        + b"\n"
    )
    controllers_raw = b"cpu memory pids\n"
    proc_cgroup_raw = b"0::/\n"
    mountinfo_raw = (
        b"21 1 0:20 / /sys/fs/cgroup rw,nosuid,nodev,noexec "
        b"- cgroup2 cgroup rw,nsdelegate\n"
    )
    return {
        "runner_image": {
            "runner_label": "ubuntu-24.04",
            "image_os": "ubuntu24",
            "image_version": "20260720.1.0",
            "image_release": (
                "https://github.com/actions/runner-images/releases/tag/"
                "ubuntu24%2F20260720.1"
            ),
            "arch": "X64",
            "os_release": os_release_raw.decode("utf-8"),
            "os_release_raw_base64": probe._discovery_raw_base64(
                os_release_raw
            ),
        },
        "kernel": {"release": "6.8.0-test", "version": "#1 SMP test"},
        "systemd": {
            "version_output": "systemd 255 (255.4-1ubuntu8)",
            "feature_output": systemd_feature_output,
            "stdout_raw_base64": probe._discovery_raw_base64(systemd_raw),
        },
        "cgroup_topology": {
            "unified": True,
            "controllers": ["cpu", "memory", "pids"],
            "controllers_raw_base64": probe._discovery_raw_base64(
                controllers_raw
            ),
            "proc_cgroup": proc_cgroup_raw.decode("utf-8"),
            "proc_cgroup_raw_base64": probe._discovery_raw_base64(
                proc_cgroup_raw
            ),
        },
        "mountinfo_topology": {
            "raw_base64": probe._discovery_raw_base64(mountinfo_raw),
            "entries": [
                {
                    "mount_id": "21",
                    "parent_id": "1",
                    "major_minor": "0:20",
                    "root": "/",
                    "mount_point": "/sys/fs/cgroup",
                    "mount_options": ["nodev", "noexec", "nosuid", "rw"],
                    "optional_fields": [],
                    "fs_type": "cgroup2",
                    "mount_source": "cgroup",
                    "super_options": ["nsdelegate", "rw"],
                }
            ]
        },
        "bpf_prog_query": {
            "attempted": True,
            "success": bpf_success,
            "errno": None if bpf_success else errno.EPERM,
            "errno_name": None if bpf_success else "EPERM",
        },
        "device_nodes": {
            "candidates": [
                {
                    "path": "/dev/kvm",
                    "type": "char",
                    "major": 10,
                    "minor": 232,
                    "uid": 0,
                    "gid": 108,
                    "mode": 0o660,
                }
            ]
        },
        "executable_abis": {
            "binaries": (
                ([
                    {
                        "path": "/usr/bin/python3",
                        "sha256": "a" * 64,
                        "elf_class": 64,
                        "endianness": "little",
                        "machine": 62,
                    }
                ]
                if abi_present
                else [])
                + [
                    {
                        "path": "/usr/lib/systemd/systemd",
                        "sha256": "b" * 64,
                        "elf_class": 64,
                        "endianness": "little",
                        "machine": 62,
                    }
                ]
            ),
            "absence_unresolved": True,
        },
        "field_availability": {
            "fields": [
                {
                    "name": name,
                    "path": path,
                    "available": True,
                    "errno": None,
                }
                for name, path in probe._DISCOVERY_FIELD_PATHS
            ]
        },
    }


def _discovery_evidence(*, abi_present=True, bpf_success=True):
    return probe.build_discovery_evidence(
        identity={
            "repository": "yurikuchumov-ux/ai-operating-system",
            "repository_id": "123456789",
            "pr_number": "71",
            "event_name": "pull_request",
            "event_action": "labeled",
            "event_ref": "refs/pull/71/merge",
            "label": "p0-v2-discovery",
            "sender_login": "yurikuchumov-ux",
            "sender_id": "299144523",
            "actor_login": "yurikuchumov-ux",
            "actor_id": "299144523",
            "run_id": "123",
            "run_attempt": "1",
            "head_sha": "1" * 40,
            "base_sha": "7" * 40,
            "merge_sha": "8" * 40,
            "workflow": "P0 v2 runner feasibility Gate 1",
            "workflow_ref": (
                "yurikuchumov-ux/ai-operating-system/.github/workflows/"
                "p0-v2-runner-feasibility.yml@refs/pull/71/merge"
            ),
            "workflow_sha": "2" * 40,
            "runner_label": "ubuntu-24.04",
            "image_os": "ubuntu24",
            "image_version": "20260720.1.0",
            "image_release": (
                "https://github.com/actions/runner-images/releases/tag/"
                "ubuntu24%2F20260720.1"
            ),
            "runner_arch": "X64",
            "boot_id": "00000000-0000-4000-8000-000000000001",
            "invocation_id": "00000000000040008000000000000001",
        },
        source={
            "probe_sha256": probe.sha256_path(TOOL_PATH),
            "schema_sha256": probe.sha256_path(SCHEMA_PATH),
            "discovery_schema_sha256": probe.discovery_schema_sha256(),
            "workflow_sha256": probe.sha256_path(WORKFLOW_PATH),
            "test_sha256": "4" * 64,
            "implementation_commit": "1" * 40,
            "source_authoring_anchor": probe.DISCOVERY_SOURCE_AUTHORING_ANCHOR,
            "f7b0_authoring_task_sha256": (
                probe.DISCOVERY_F7B0_AUTHORING_TASK_SHA256
            ),
            "f7b1_hosted_authorization_sha256": (
                probe.DISCOVERY_F7B1_HOSTED_AUTHORIZATION_SHA256
            ),
        },
        values=_discovery_values(
            abi_present=abi_present, bpf_success=bpf_success
        ),
    )


def _refresh_discovery_record(value, surface):
    record = next(item for item in value["records"] if item["surface"] == surface)
    record["value_sha256"] = probe.sha256_bytes(
        probe.canonical_json_bytes(record["value"])
    )
    return record


def _standalone_discovery_validator_path():
    configured = os.environ.get("P0_V2_DISCOVERY_STANDALONE_VALIDATOR")
    if configured:
        return Path(configured)
    workspace_copy = (
        REPO_ROOT.parents[1]
        / "artifacts/issue-70-p0-v2-f7b1-independent-discovery-validator.py"
    )
    return workspace_copy


def _hosted_discovery_evidence():
    value = _discovery_evidence()
    value["identity"]["repository_id"] = "1296950956"
    return value


def _write_discovery_zip(directory, evidence):
    evidence_raw = probe.canonical_json_bytes(evidence)
    manifest = {
        "manifest_version": "1.0.0",
        "evidence_kind": probe.DISCOVERY_EVIDENCE_KIND,
        "evidence_file": "discovery-evidence.json",
        "evidence_sha256": probe.sha256_bytes(evidence_raw),
        "replay_binding_sha256": probe.discovery_replay_binding(evidence),
        "identity": evidence["identity"],
        "source": evidence["source"],
        "proof_eligible": False,
    }
    manifest_raw = probe.canonical_json_bytes(manifest)
    archive_path = directory / "discovery.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, raw in (
            ("discovery-evidence.json", evidence_raw),
            ("discovery-evidence.json.manifest.json", manifest_raw),
        ):
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o444) << 16
            archive.writestr(info, raw)
    return archive_path, evidence_raw, manifest_raw


def _standalone_validator_argv(validator_path, archive_path, evidence):
    identity = evidence["identity"]
    source = evidence["source"]
    return [
        sys.executable,
        str(validator_path),
        str(archive_path),
        "--run-id",
        identity["run_id"],
        "--head-sha",
        identity["head_sha"],
        "--base-sha",
        identity["base_sha"],
        "--merge-sha",
        identity["merge_sha"],
        "--workflow-ref",
        identity["workflow_ref"],
        "--workflow-sha",
        identity["workflow_sha"],
        "--probe-sha256",
        source["probe_sha256"],
        "--schema-sha256",
        source["schema_sha256"],
        "--workflow-sha256",
        source["workflow_sha256"],
        "--test-sha256",
        source["test_sha256"],
        "--discovery-schema-sha256",
        source["discovery_schema_sha256"],
        "--source-authoring-anchor",
        source["source_authoring_anchor"],
        "--f7b0-authoring-task-sha256",
        source["f7b0_authoring_task_sha256"],
        "--f7b1-hosted-authorization-sha256",
        source["f7b1_hosted_authorization_sha256"],
    ]


class ProofIneligibleDiscoveryContractTests(unittest.TestCase):
    """F7-B0: discovery is a separate typed domain, never effect evidence."""

    def assertDiscoveryInvalid(self, value, **kwargs):
        with self.assertRaises(probe.ProbeError):
            probe.validate_discovery_evidence(value, SCHEMA_PATH, **kwargs)

    def test_reference_discovery_is_valid_and_fixed_proof_ineligible(self):
        value = _discovery_evidence()
        probe.validate_discovery_evidence(
            value, SCHEMA_PATH, source_path=TOOL_PATH
        )
        self.assertFalse(value["proof_eligible"])
        self.assertEqual("DISCOVERY_ONLY", value["outcome"])
        self.assertEqual(
            probe.mandatory_effect_blockers(),
            value["mandatory_effect_blockers"],
        )
        self.assertEqual(27, len(value["mandatory_effect_blockers"]))

    def test_discovery_and_candidate_validators_reject_each_other(self):
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(_discovery_evidence(), SCHEMA_PATH)
        with self.assertRaises(probe.ProbeError):
            probe.validate_discovery_evidence(_evidence(), SCHEMA_PATH)

    def test_discovery_mode_has_no_hostile_release_or_candidate_outcome_call(self):
        for function in (
            probe.discovery,
            probe.collect_discovery_values,
            probe.build_discovery_evidence,
        ):
            names = set(function.__code__.co_names)
            self.assertNotIn("release_fixture_and_record", names)
            self.assertNotIn("candidate_run_succeeds", names)

    def test_discovery_cli_rejects_mixed_candidate_arguments(self):
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                probe.parse_args(
                    [
                        "discover",
                        "--pr-number",
                        "71",
                    ]
                )

    def test_record_count_order_unknown_and_duplicate_fail_closed(self):
        missing = _discovery_evidence()
        missing["records"].pop()
        self.assertDiscoveryInvalid(missing)

        reordered = _discovery_evidence()
        reordered["records"][0], reordered["records"][1] = (
            reordered["records"][1],
            reordered["records"][0],
        )
        self.assertDiscoveryInvalid(reordered)

        unknown = _discovery_evidence()
        unknown["records"][0]["surface"] = "unknown_surface"
        self.assertDiscoveryInvalid(unknown)

        duplicate = _discovery_evidence()
        duplicate["records"][1]["sequence"] = 0
        self.assertDiscoveryInvalid(duplicate)

    def test_record_digest_and_byte_bound_fail_closed(self):
        digest = _discovery_evidence()
        digest["records"][0]["value"]["image"] = "ubuntu-modified"
        self.assertDiscoveryInvalid(digest)

        oversized = _discovery_evidence()
        record = next(
            item
            for item in oversized["records"]
            if item["surface"] == "mountinfo_topology"
        )
        template = record["value"]["entries"][0]
        record["value"]["entries"] = [
            dict(template, mount_id=str(index + 1), mount_source="x" * 4000)
            for index in range(100)
        ]
        _refresh_discovery_record(oversized, "mountinfo_topology")
        self.assertDiscoveryInvalid(oversized)

    def test_discovery_file_reads_stop_at_limit_plus_one(self):
        with tempfile.TemporaryDirectory() as raw_directory:
            path = Path(raw_directory) / "oversized"
            path.write_bytes(b"x" * 1024)
            original_read = probe.os.read
            observed = bytearray()

            def tracked_read(fd, count):
                self.assertLessEqual(count, 5)
                chunk = original_read(fd, count)
                observed.extend(chunk)
                return chunk

            with mock.patch.object(probe.os, "read", side_effect=tracked_read):
                with self.assertRaises(probe.ProbeError):
                    probe.read_bytes(path, 4)
            self.assertEqual(5, len(observed))

    def test_authority_separation_and_substitution_fail_closed(self):
        value = _discovery_evidence()
        bpf = next(
            item for item in value["records"] if item["surface"] == "bpf_prog_query"
        )
        self.assertEqual(probe.TRUSTED_BOOTSTRAP_OBSERVED, bpf["authority"])
        bpf["authority"] = "kernel_observed"
        self.assertDiscoveryInvalid(value)

        candidate = _evidence()
        candidate["host"][0]["authority"] = probe.TRUSTED_BOOTSTRAP_OBSERVED
        with self.assertRaises(probe.ProbeError):
            probe.validate_evidence(candidate, SCHEMA_PATH)

    def test_bpf_query_exact_success_and_errno_forms(self):
        for success in (True, False):
            probe.validate_discovery_evidence(
                _discovery_evidence(bpf_success=success), SCHEMA_PATH
            )
        contradictory = _discovery_evidence()
        record = next(
            item
            for item in contradictory["records"]
            if item["surface"] == "bpf_prog_query"
        )
        record["value"]["success"] = True
        record["value"]["errno"] = errno.EPERM
        record["value"]["errno_name"] = "EPERM"
        _refresh_discovery_record(contradictory, "bpf_prog_query")
        self.assertDiscoveryInvalid(contradictory)

    def test_bpf_query_uses_exact_zeroed_64_byte_uapi_layout(self):
        self.assertEqual(64, probe.ctypes.sizeof(probe._BpfProgQueryAttr))
        self.assertEqual(28, probe._BpfProgQueryAttr._padding.offset)
        self.assertEqual(32, probe._BpfProgQueryAttr.prog_attach_flags.offset)
        self.assertEqual(40, probe._BpfProgQueryAttr.link_ids.offset)
        self.assertEqual(48, probe._BpfProgQueryAttr.link_attach_flags.offset)
        self.assertEqual(56, probe._BpfProgQueryAttr.revision.offset)

        observed = {}

        def inspect_syscall(number, command, attr_pointer, attr_size):
            attr = attr_pointer._obj
            observed.update(
                {
                    "number": number,
                    "command": command,
                    "size": attr_size,
                    "target_fd": attr.target_fd,
                    "raw": probe.ctypes.string_at(
                        probe.ctypes.addressof(attr), attr_size
                    ),
                }
            )
            return -1

        fake_libc = SimpleNamespace(
            syscall=mock.Mock(side_effect=inspect_syscall)
        )
        with (
            mock.patch.object(
                probe.os,
                "uname",
                return_value=SimpleNamespace(machine="x86_64"),
            ),
            mock.patch.object(probe.os, "open", return_value=123),
            mock.patch.object(probe.os, "close"),
            mock.patch.object(probe.ctypes, "CDLL", return_value=fake_libc),
            mock.patch.object(probe.ctypes, "set_errno"),
            mock.patch.object(probe.ctypes, "get_errno", return_value=errno.EPERM),
        ):
            self.assertEqual(
                {
                    "attempted": True,
                    "success": False,
                    "errno": errno.EPERM,
                    "errno_name": "EPERM",
                },
                probe.discover_bpf_prog_query(),
            )

        self.assertEqual(321, observed["number"])
        self.assertEqual(16, observed["command"])
        self.assertEqual(64, observed["size"])
        self.assertEqual(123, observed["target_fd"])
        self.assertEqual((123).to_bytes(4, "little"), observed["raw"][:4])
        self.assertEqual(b"\0" * 60, observed["raw"][4:])

    def test_collectors_reject_operation_impossible_errnos(self):
        for impossible_errno in (errno.EFAULT, errno.EINVAL, 133):
            with self.subTest(bpf_errno=impossible_errno):
                fake_libc = SimpleNamespace(
                    syscall=mock.Mock(return_value=-1)
                )
                with (
                    mock.patch.object(
                        probe.os,
                        "uname",
                        return_value=SimpleNamespace(machine="x86_64"),
                    ),
                    mock.patch.object(probe.os, "open", return_value=123),
                    mock.patch.object(probe.os, "close"),
                    mock.patch.object(
                        probe.ctypes, "CDLL", return_value=fake_libc
                    ),
                    mock.patch.object(probe.ctypes, "set_errno"),
                    mock.patch.object(
                        probe.ctypes,
                        "get_errno",
                        return_value=impossible_errno,
                    ),
                ):
                    with self.assertRaises(probe.ProbeError) as caught:
                        probe.discover_bpf_prog_query()
                    self.assertEqual(
                        "DISCOVERY_BPF_ERRNO_IMPOSSIBLE",
                        caught.exception.code,
                    )

        impossible = OSError(133, "operation-impossible")
        impossible.errno = 133
        with mock.patch.object(probe.os, "open", side_effect=impossible):
            with self.assertRaises(probe.ProbeError) as caught:
                probe.discover_field_availability()
            self.assertEqual(
                "DISCOVERY_FIELD_ERRNO_IMPOSSIBLE",
                caught.exception.code,
            )

        def missing_proc_status(path, flags):
            if str(path) == "/proc/self/status":
                raise FileNotFoundError(errno.ENOENT, "impossible", str(path))
            return 123

        with (
            mock.patch.object(probe.os, "open", side_effect=missing_proc_status),
            mock.patch.object(probe.os, "close"),
        ):
            with self.assertRaises(probe.ProbeError) as caught:
                probe.discover_field_availability()
            self.assertEqual(
                "DISCOVERY_FIELD_ERRNO_IMPOSSIBLE",
                caught.exception.code,
            )

        def missing_cpu_max(path, flags):
            if str(path) == "/sys/fs/cgroup/cpu.max":
                raise FileNotFoundError(errno.ENOENT, "impossible", str(path))
            return 123

        with (
            mock.patch.object(probe.os, "open", side_effect=missing_cpu_max),
            mock.patch.object(probe.os, "close"),
        ):
            with self.assertRaises(probe.ProbeError) as caught:
                probe.discover_field_availability(controllers=("cpu",))
            self.assertEqual(
                "DISCOVERY_FIELD_ERRNO_IMPOSSIBLE",
                caught.exception.code,
            )

    def test_mount_cgroup_device_abi_and_field_shapes_fail_closed(self):
        cgroup = _discovery_evidence()
        record = _refresh_discovery_record(cgroup, "cgroup_topology")
        record["value"]["controllers"] = ["pids", "cpu"]
        _refresh_discovery_record(cgroup, "cgroup_topology")
        self.assertDiscoveryInvalid(cgroup)

        mount = _discovery_evidence()
        record = next(
            item
            for item in mount["records"]
            if item["surface"] == "mountinfo_topology"
        )
        record["value"]["entries"][0].pop("fs_type")
        _refresh_discovery_record(mount, "mountinfo_topology")
        self.assertDiscoveryInvalid(mount)

        device = _discovery_evidence()
        record = next(
            item
            for item in device["records"]
            if item["surface"] == "device_nodes"
        )
        record["value"]["candidates"][0]["major"] = -1
        _refresh_discovery_record(device, "device_nodes")
        self.assertDiscoveryInvalid(device)

        abi = _discovery_evidence()
        record = next(
            item
            for item in abi["records"]
            if item["surface"] == "executable_abis"
        )
        record["value"]["binaries"][0]["sha256"] = "not-a-digest"
        _refresh_discovery_record(abi, "executable_abis")
        self.assertDiscoveryInvalid(abi)

        field = _discovery_evidence()
        record = next(
            item
            for item in field["records"]
            if item["surface"] == "field_availability"
        )
        record["value"]["fields"][0]["available"] = False
        _refresh_discovery_record(field, "field_availability")
        self.assertDiscoveryInvalid(field)

    def test_identity_source_and_replay_mismatch_fail_closed(self):
        value = _discovery_evidence()
        binding = probe.discovery_replay_binding(value)
        probe.validate_discovery_evidence(
            value,
            SCHEMA_PATH,
            expected_identity={
                "run_id": "123",
                "runner_label": "ubuntu-24.04",
                "image_version": "20260720.1.0",
            },
            expected_replay_binding=binding,
        )
        self.assertDiscoveryInvalid(
            value, expected_identity={"run_id": "999"}
        )
        self.assertDiscoveryInvalid(
            value, expected_replay_binding="0" * 64
        )
        schema_mismatch = _discovery_evidence()
        schema_mismatch["source"]["schema_sha256"] = "0" * 64
        self.assertDiscoveryInvalid(schema_mismatch)

    def test_corrected_hosted_authority_fields_are_non_interchangeable(self):
        value = _discovery_evidence()
        self.assertEqual(
            value["identity"]["head_sha"],
            value["source"]["implementation_commit"],
        )
        self.assertEqual(
            probe.DISCOVERY_SOURCE_AUTHORING_ANCHOR,
            value["source"]["source_authoring_anchor"],
        )
        self.assertEqual(
            probe.DISCOVERY_F7B0_AUTHORING_TASK_SHA256,
            value["source"]["f7b0_authoring_task_sha256"],
        )
        self.assertEqual(
            probe.DISCOVERY_F7B1_HOSTED_AUTHORIZATION_SHA256,
            value["source"]["f7b1_hosted_authorization_sha256"],
        )
        for key in (
            "implementation_commit",
            "source_authoring_anchor",
            "f7b0_authoring_task_sha256",
            "f7b1_hosted_authorization_sha256",
        ):
            changed = _discovery_evidence()
            changed["source"][key] = (
                "0" * 40 if key.endswith(("commit", "anchor")) else "0" * 64
            )
            self.assertDiscoveryInvalid(changed)

    def test_hosted_discovery_job_has_no_test_to_root_continuation(self):
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        discovery_job = workflow.split("  discovery:\n", 1)[1].split(
            "\n  gate1:\n", 1
        )[0]
        self.assertNotIn("unittest", discovery_job)
        self.assertNotIn("pytest", discovery_job)
        self.assertIn("sudo -n /usr/bin/env -i", discovery_job)
        self.assertIn("/usr/bin/python3 -I", discovery_job)
        self.assertIn("${P0_V2_TRUSTED_STAGE}/p0_v2_runner_probe.py", discovery_job)
        self.assertIn("root -g root -m 0444", discovery_job)
        self.assertIn('chmod 0555 "${trusted_stage}"', discovery_job)
        self.assertIn("--evidence-uid 0", discovery_job)
        self.assertIn("--evidence-gid 0", discovery_job)
        self.assertNotIn("--cancel-canary", discovery_job)
        self.assertNotIn(" supervisor ", discovery_job)
        self.assertNotIn(" finalize ", discovery_job)

    def test_hosted_discovery_job_is_owner_once_and_uploads_sealed_files(self):
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        discovery_job = workflow.split("  discovery:\n", 1)[1].split(
            "\n  gate1:\n", 1
        )[0]
        self.assertIn("github.run_attempt == 1", discovery_job)
        self.assertIn("github.event.sender.id == 299144523", discovery_job)
        self.assertIn("github.actor_id == '299144523'", discovery_job)
        self.assertIn("github.event.pull_request.draft == true", discovery_job)
        self.assertIn("refs/pull/71/merge", discovery_job)
        self.assertIn("p0-v2-discovery", discovery_job)
        self.assertIn("os.lstat", discovery_job)
        self.assertIn("info.st_nlink != 1", discovery_job)
        self.assertIn("unexpected discovery directory entries", discovery_job)
        self.assertIn("duplicate JSON key", discovery_job)
        self.assertIn("id: discovery-artifact", discovery_job)
        self.assertIn(
            "actions/upload-artifact@"
            "ea165f8d65b6e75b540449e92b4886f43607fa02",
            discovery_job,
        )
        self.assertNotIn("if: always()", discovery_job)

    def test_producer_inline_and_standalone_share_exact_canonical_bytes(self):
        validator_path = _standalone_discovery_validator_path()
        self.assertTrue(validator_path.is_file(), validator_path)
        evidence = _hosted_discovery_evidence()
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            evidence_path = directory / "discovery-evidence.json"
            probe.atomic_seal_discovery(
                evidence_path,
                evidence,
                SCHEMA_PATH,
                TOOL_PATH,
                os.getuid(),
                os.getgid(),
            )
            evidence_raw = evidence_path.read_bytes()
            manifest_raw = evidence_path.with_suffix(
                evidence_path.suffix + ".manifest.json"
            ).read_bytes()
            self.assertFalse(evidence_raw.endswith(b"\n"))
            self.assertFalse(manifest_raw.endswith(b"\n"))

            workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
            canonical_source = workflow.split(
                "          def canonical(value):\n", 1
            )[1].split("\n\n          directory_info =", 1)[0]
            canonical_source = (
                "def canonical(value):\n"
                + "\n".join(
                    line[10:] if line.startswith("          ") else line
                    for line in canonical_source.splitlines()
                )
            )
            namespace = {"json": json}
            exec(compile(canonical_source, "<workflow-canonical>", "exec"), namespace)
            self.assertEqual(
                evidence_raw,
                namespace["canonical"](json.loads(evidence_raw)),
            )
            self.assertEqual(
                manifest_raw,
                namespace["canonical"](json.loads(manifest_raw)),
            )

            archive_path, archived_evidence, archived_manifest = (
                _write_discovery_zip(directory, evidence)
            )
            self.assertEqual(evidence_raw, archived_evidence)
            self.assertEqual(manifest_raw, archived_manifest)
            completed = subprocess.run(
                _standalone_validator_argv(
                    validator_path, archive_path, evidence
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(
                0,
                completed.returncode,
                completed.stderr.decode("utf-8", "replace"),
            )
            result = json.loads(completed.stdout)
            self.assertEqual("VALID_PROOF_INELIGIBLE_DISCOVERY", result["status"])

    def test_standalone_archive_is_single_descriptor_nofollow_bound(self):
        validator_path = _standalone_discovery_validator_path()
        validator_source = validator_path.read_text(encoding="utf-8")
        self.assertIn("nofollow = getattr(os, \"O_NOFOLLOW\", 0)", validator_source)
        self.assertIn("nonblock = getattr(os, \"O_NONBLOCK\", 0)", validator_source)
        self.assertIn("preflight = os.lstat(path)", validator_source)
        self.assertIn("| nonblock", validator_source)
        self.assertIn("archive_stat = os.fstat(fd)", validator_source)
        self.assertIn("archive_raw = b\"\".join(chunks)", validator_source)
        self.assertIn("zipfile.ZipFile(io.BytesIO(archive_raw))", validator_source)
        self.assertNotIn("zipfile.ZipFile(path)", validator_source)

        evidence = _hosted_discovery_evidence()
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            archive_path, _, _ = _write_discovery_zip(directory, evidence)
            symlink_path = directory / "discovery-symlink.zip"
            symlink_path.symlink_to(archive_path)
            completed = subprocess.run(
                _standalone_validator_argv(
                    validator_path, symlink_path, evidence
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertNotEqual(0, completed.returncode)

    def test_standalone_archive_fifo_rejection_never_blocks(self):
        validator_path = _standalone_discovery_validator_path()
        evidence = _hosted_discovery_evidence()
        with tempfile.TemporaryDirectory() as raw_directory:
            fifo_path = Path(raw_directory) / "discovery-fifo.zip"
            os.mkfifo(fifo_path)
            started = time.monotonic()
            completed = subprocess.run(
                _standalone_validator_argv(
                    validator_path, fifo_path, evidence
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=2,
            )
            elapsed = time.monotonic() - started
        self.assertNotEqual(0, completed.returncode)
        self.assertLess(elapsed, 2)

    def test_standalone_validator_rejects_rehashed_semantic_forgeries(self):
        validator_path = _standalone_discovery_validator_path()
        self.assertTrue(validator_path.is_file(), validator_path)

        def scalar_record(value):
            value["records"][1]["value"] = "forged"
            _refresh_discovery_record(value, "kernel")

        def nested_authority(value):
            value["records"][0]["value"]["authority"] = "reviewer_api_observed"
            _refresh_discovery_record(value, "runner_image")

        def forged_image_release(value):
            forged = "https://example.invalid/forged"
            value["identity"]["image_release"] = forged
            record = _refresh_discovery_record(value, "runner_image")
            record["value"]["image_release"] = forged
            _refresh_discovery_record(value, "runner_image")

        def systemd_extra_field(value):
            record = _refresh_discovery_record(value, "systemd")
            record["value"]["review"] = "forged"
            _refresh_discovery_record(value, "systemd")

        def cgroup_noncanonical(value):
            record = _refresh_discovery_record(value, "cgroup_topology")
            record["value"]["controllers"] = ["pids", "cpu"]
            _refresh_discovery_record(value, "cgroup_topology")

        def malformed_mount(value):
            record = _refresh_discovery_record(value, "mountinfo_topology")
            record["value"]["entries"][0].pop("fs_type")
            _refresh_discovery_record(value, "mountinfo_topology")

        def duplicate_mount_id(value):
            record = _refresh_discovery_record(value, "mountinfo_topology")
            duplicate = dict(record["value"]["entries"][0])
            duplicate["mount_point"] = "/conflicting"
            record["value"]["entries"].append(duplicate)
            _refresh_discovery_record(value, "mountinfo_topology")

        def numeric_alias_mount_id(value):
            record = _refresh_discovery_record(value, "mountinfo_topology")
            duplicate = dict(record["value"]["entries"][0])
            duplicate["mount_id"] = "021"
            record["value"]["entries"].append(duplicate)
            _refresh_discovery_record(value, "mountinfo_topology")

        def noncanonical_major_minor(value):
            record = _refresh_discovery_record(value, "mountinfo_topology")
            record["value"]["entries"][0]["major_minor"] = "00:020"
            _refresh_discovery_record(value, "mountinfo_topology")

        def unsorted_mount_options(value):
            record = _refresh_discovery_record(value, "mountinfo_topology")
            record["value"]["entries"][0]["mount_options"] = ["rw", "nodev"]
            _refresh_discovery_record(value, "mountinfo_topology")

        def empty_mount_options(value):
            record = _refresh_discovery_record(value, "mountinfo_topology")
            record["value"]["entries"][0]["mount_options"] = []
            _refresh_discovery_record(value, "mountinfo_topology")

        def empty_super_options(value):
            record = _refresh_discovery_record(value, "mountinfo_topology")
            record["value"]["entries"][0]["super_options"] = []
            _refresh_discovery_record(value, "mountinfo_topology")

        def impossible_mount_option_token(value):
            record = _refresh_discovery_record(value, "mountinfo_topology")
            record["value"]["entries"][0]["mount_options"] = ["nodev\nrw"]
            _refresh_discovery_record(value, "mountinfo_topology")

        def impossible_optional_field_token(value):
            record = _refresh_discovery_record(value, "mountinfo_topology")
            record["value"]["entries"][0]["optional_fields"] = ["shared:1 bad"]
            _refresh_discovery_record(value, "mountinfo_topology")

        def impossible_filesystem_type_token(value):
            record = _refresh_discovery_record(value, "mountinfo_topology")
            record["value"]["entries"][0]["fs_type"] = "cgroup2 bad"
            _refresh_discovery_record(value, "mountinfo_topology")

        def mismatched_mountinfo_raw(value):
            record = _refresh_discovery_record(value, "mountinfo_topology")
            record["value"]["raw_base64"] = probe._discovery_raw_base64(
                b"22 1 0:20 / /sys/fs/cgroup rw,nodev,nosuid,noexec "
                b"- cgroup2 cgroup rw,nsdelegate\n"
            )
            _refresh_discovery_record(value, "mountinfo_topology")

        def zero_mount_id(value):
            record = _refresh_discovery_record(value, "mountinfo_topology")
            record["value"]["entries"][0]["mount_id"] = "0"
            _refresh_discovery_record(value, "mountinfo_topology")

        def oversized_mount_id(value):
            record = _refresh_discovery_record(value, "mountinfo_topology")
            record["value"]["entries"][0]["mount_id"] = "9" * 1000
            record["value"]["entries"][0]["parent_id"] = "9" * 1000
            _refresh_discovery_record(value, "mountinfo_topology")

        def oversized_mount_major_minor(value):
            record = _refresh_discovery_record(value, "mountinfo_topology")
            record["value"]["entries"][0]["major_minor"] = (
                f"{probe.DISCOVERY_DEVICE_MAJOR_MAX + 1}:"
                f"{probe.DISCOVERY_DEVICE_MINOR_MAX + 1}"
            )
            _refresh_discovery_record(value, "mountinfo_topology")

        def contradictory_bpf(value):
            record = _refresh_discovery_record(value, "bpf_prog_query")
            record["value"]["success"] = True
            record["value"]["errno"] = errno.EPERM
            record["value"]["errno_name"] = "EPERM"
            _refresh_discovery_record(value, "bpf_prog_query")

        def malformed_device(value):
            record = _refresh_discovery_record(value, "device_nodes")
            record["value"]["candidates"][0]["major"] = -1
            _refresh_discovery_record(value, "device_nodes")

        def oversized_device_identity(value):
            record = _refresh_discovery_record(value, "device_nodes")
            candidate = record["value"]["candidates"][0]
            candidate["major"] = probe.DISCOVERY_DEVICE_MAJOR_MAX + 1
            candidate["minor"] = probe.DISCOVERY_DEVICE_MINOR_MAX + 1
            candidate["uid"] = probe.DISCOVERY_UID_GID_MAX + 1
            candidate["gid"] = probe.DISCOVERY_UID_GID_MAX + 1
            _refresh_discovery_record(value, "device_nodes")

        def arbitrary_device_path(value):
            record = _refresh_discovery_record(value, "device_nodes")
            record["value"]["candidates"][0]["path"] = "/tmp/not-device"
            _refresh_discovery_record(value, "device_nodes")

        def duplicate_device_path(value):
            record = _refresh_discovery_record(value, "device_nodes")
            duplicate = dict(record["value"]["candidates"][0])
            duplicate["minor"] += 1
            record["value"]["candidates"].append(duplicate)
            _refresh_discovery_record(value, "device_nodes")

        def malformed_abi(value):
            record = _refresh_discovery_record(value, "executable_abis")
            record["value"]["binaries"][0]["sha256"] = "not-a-digest"
            _refresh_discovery_record(value, "executable_abis")

        def arbitrary_abi_path(value):
            record = _refresh_discovery_record(value, "executable_abis")
            record["value"]["binaries"][0]["path"] = "/tmp/attacker"
            _refresh_discovery_record(value, "executable_abis")

        def duplicate_abi_path(value):
            record = _refresh_discovery_record(value, "executable_abis")
            duplicate = dict(record["value"]["binaries"][0])
            duplicate["sha256"] = "c" * 64
            record["value"]["binaries"].insert(1, duplicate)
            _refresh_discovery_record(value, "executable_abis")

        def missing_systemd_abi(value):
            record = _refresh_discovery_record(value, "executable_abis")
            record["value"]["binaries"] = [
                item
                for item in record["value"]["binaries"]
                if item["path"] != "/usr/lib/systemd/systemd"
            ]
            _refresh_discovery_record(value, "executable_abis")

        def contradictory_field(value):
            record = _refresh_discovery_record(value, "field_availability")
            record["value"]["fields"][0]["available"] = False
            _refresh_discovery_record(value, "field_availability")

        def empty_fields(value):
            record = _refresh_discovery_record(value, "field_availability")
            record["value"]["fields"] = []
            _refresh_discovery_record(value, "field_availability")

        def wrong_field_path(value):
            record = _refresh_discovery_record(value, "field_availability")
            record["value"]["fields"][0]["path"] = "/tmp/not-the-field"
            _refresh_discovery_record(value, "field_availability")

        def duplicate_field_name(value):
            record = _refresh_discovery_record(value, "field_availability")
            duplicate = dict(record["value"]["fields"][0])
            duplicate["path"] = "/tmp/conflicting"
            record["value"]["fields"].insert(1, duplicate)
            _refresh_discovery_record(value, "field_availability")

        def errno_name_mismatch(value):
            record = _refresh_discovery_record(value, "bpf_prog_query")
            record["value"]["success"] = False
            record["value"]["errno"] = errno.EPERM
            record["value"]["errno_name"] = "ENOENT"
            _refresh_discovery_record(value, "bpf_prog_query")

        def unknown_errno(value):
            record = _refresh_discovery_record(value, "bpf_prog_query")
            record["value"]["success"] = False
            record["value"]["errno"] = 999999
            record["value"]["errno_name"] = "E999999"
            _refresh_discovery_record(value, "bpf_prog_query")

        def impossible_bpf_operation_errno(value):
            record = _refresh_discovery_record(value, "bpf_prog_query")
            record["value"]["success"] = False
            record["value"]["errno"] = 133
            record["value"]["errno_name"] = "EHWPOISON"
            _refresh_discovery_record(value, "bpf_prog_query")

        def impossible_bpf_efault(value):
            record = _refresh_discovery_record(value, "bpf_prog_query")
            record["value"]["success"] = False
            record["value"]["errno"] = errno.EFAULT
            record["value"]["errno_name"] = "EFAULT"
            _refresh_discovery_record(value, "bpf_prog_query")

        def impossible_bpf_einval(value):
            record = _refresh_discovery_record(value, "bpf_prog_query")
            record["value"]["success"] = False
            record["value"]["errno"] = errno.EINVAL
            record["value"]["errno_name"] = "EINVAL"
            _refresh_discovery_record(value, "bpf_prog_query")

        def linux_errno_alias(value):
            record = _refresh_discovery_record(value, "bpf_prog_query")
            record["value"]["success"] = False
            record["value"]["errno"] = 95
            record["value"]["errno_name"] = "ENOTSUP"
            _refresh_discovery_record(value, "bpf_prog_query")

        def noncanonical_device_path(value):
            record = _refresh_discovery_record(value, "device_nodes")
            record["value"]["candidates"][0]["path"] = "/dev//kvm"
            _refresh_discovery_record(value, "device_nodes")

        def oversized_elf_machine(value):
            record = _refresh_discovery_record(value, "executable_abis")
            record["value"]["binaries"][0]["machine"] = 70000
            _refresh_discovery_record(value, "executable_abis")

        def contradictory_cgroup_mode(value):
            record = _refresh_discovery_record(value, "cgroup_topology")
            record["value"]["unified"] = False
            _refresh_discovery_record(value, "cgroup_topology")

        def unknown_field_errno(value):
            record = _refresh_discovery_record(value, "field_availability")
            field = record["value"]["fields"][0]
            field["available"] = False
            field["errno"] = 999999
            _refresh_discovery_record(value, "field_availability")

        def impossible_field_operation_errno(value):
            record = _refresh_discovery_record(value, "field_availability")
            field = next(
                item
                for item in record["value"]["fields"]
                if item["name"] == "cgroup.events"
            )
            field["available"] = False
            field["errno"] = 133
            _refresh_discovery_record(value, "field_availability")

        def impossible_proc_status_enoent(value):
            record = _refresh_discovery_record(value, "field_availability")
            field = next(
                item
                for item in record["value"]["fields"]
                if item["name"] == "proc.status"
            )
            field["available"] = False
            field["errno"] = errno.ENOENT
            _refresh_discovery_record(value, "field_availability")

        def impossible_cpu_max_with_controller(value):
            record = _refresh_discovery_record(value, "field_availability")
            field = next(
                item
                for item in record["value"]["fields"]
                if item["name"] == "cpu.max"
            )
            field["available"] = False
            field["errno"] = errno.ENOENT
            _refresh_discovery_record(value, "field_availability")

        def impossible_memory_events_with_controller(value):
            record = _refresh_discovery_record(value, "field_availability")
            field = next(
                item
                for item in record["value"]["fields"]
                if item["name"] == "memory.events"
            )
            field["available"] = False
            field["errno"] = errno.ENOENT
            _refresh_discovery_record(value, "field_availability")

        def contradictory_os_release(value):
            record = _refresh_discovery_record(value, "runner_image")
            record["value"]["os_release"] = 'ID=debian\nVERSION_ID="12"\n'
            _refresh_discovery_record(value, "runner_image")

        def duplicate_os_release_identity(value):
            record = _refresh_discovery_record(value, "runner_image")
            record["value"]["os_release"] = (
                'ID=debian\nID=ubuntu\nVERSION_ID="12"\nVERSION_ID="24.04"\n'
            )
            _refresh_discovery_record(value, "runner_image")

        def mismatched_os_release_raw(value):
            record = _refresh_discovery_record(value, "runner_image")
            record["value"]["os_release_raw_base64"] = (
                probe._discovery_raw_base64(
                    b'ID=debian\nVERSION_ID="12"\n'
                )
            )
            _refresh_discovery_record(value, "runner_image")

        def contradictory_mountinfo_availability(value):
            record = _refresh_discovery_record(value, "field_availability")
            field = next(
                item
                for item in record["value"]["fields"]
                if item["name"] == "proc.mountinfo"
            )
            field["available"] = False
            field["errno"] = errno.ENOENT
            _refresh_discovery_record(value, "field_availability")

        def contradictory_read_field_availability(value):
            record = _refresh_discovery_record(value, "field_availability")
            for field in record["value"]["fields"]:
                if field["name"] in {"etc.os-release", "proc.cgroup"}:
                    field["available"] = False
                    field["errno"] = errno.ENOENT
            _refresh_discovery_record(value, "field_availability")

        def impossible_runner_arch(value):
            value["identity"]["runner_arch"] = "banana"
            record = _refresh_discovery_record(value, "runner_image")
            record["value"]["arch"] = "banana"
            _refresh_discovery_record(value, "runner_image")

        def arbitrary_workflow(value):
            value["identity"]["workflow"] = "forged workflow"

        def impossible_image_date(value):
            value["identity"]["image_version"] = "00000000.0.0"
            value["identity"]["image_release"] = (
                "https://github.com/actions/runner-images/releases/tag/"
                "ubuntu24%2F00000000.0"
            )
            record = _refresh_discovery_record(value, "runner_image")
            record["value"]["image_version"] = value["identity"]["image_version"]
            record["value"]["image_release"] = value["identity"]["image_release"]
            _refresh_discovery_record(value, "runner_image")

        def empty_kernel_identity(value):
            record = _refresh_discovery_record(value, "kernel")
            record["value"]["release"] = ""
            record["value"]["version"] = ""
            _refresh_discovery_record(value, "kernel")

        def oversized_kernel_uts_identity(value):
            record = _refresh_discovery_record(value, "kernel")
            record["value"]["release"] = "x" * 65
            _refresh_discovery_record(value, "kernel")

        def zero_invocation_uuid(value):
            value["identity"]["invocation_id"] = "0" * 32

        def wrong_version_invocation_uuid(value):
            value["identity"]["invocation_id"] = (
                "00000000000050008000000000000001"
            )

        def wrong_variant_invocation_uuid(value):
            value["identity"]["invocation_id"] = (
                "00000000000040007000000000000001"
            )

        def wrong_version_boot_uuid(value):
            value["identity"]["boot_id"] = (
                "00000000-0000-5000-8000-000000000001"
            )

        def embedded_newline_systemd_version(value):
            record = _refresh_discovery_record(value, "systemd")
            record["value"]["version_output"] = "systemd 255\nforged"
            _refresh_discovery_record(value, "systemd")

        def oversized_joint_systemd_fields(value):
            record = _refresh_discovery_record(value, "systemd")
            record["value"]["version_output"] = "v" * 65536
            record["value"]["feature_output"] = "f" * 65536
            _refresh_discovery_record(value, "systemd")

        def replace_systemd_source(value, version_output, feature_output):
            record = _refresh_discovery_record(value, "systemd")
            record["value"]["version_output"] = version_output
            record["value"]["feature_output"] = feature_output
            record["value"]["stdout_raw_base64"] = (
                probe._discovery_raw_base64(
                    f"{version_output}\n{feature_output}\n".encode("ascii")
                )
            )
            _refresh_discovery_record(value, "systemd")

        def arbitrary_systemd_two_lines(value):
            replace_systemd_source(value, "forged version", "forged features")

        def incomplete_systemd_features(value):
            replace_systemd_source(
                value,
                "systemd 255 (255.4-1ubuntu8)",
                "+PAM",
            )

        def misordered_systemd_features(value):
            features = [
                f"+{name}"
                for name in probe.DISCOVERY_SYSTEMD_V255_FEATURE_ORDER
            ]
            features[0], features[1] = features[1], features[0]
            replace_systemd_source(
                value,
                "systemd 255 (255.4-1ubuntu8)",
                " ".join(features) + " default-hierarchy=unified",
            )

        def wrong_systemd_project_version(value):
            record = _refresh_discovery_record(value, "systemd")
            replace_systemd_source(
                value,
                "systemd 254 (255.4-1ubuntu8)",
                record["value"]["feature_output"],
            )

        def mismatched_systemd_raw(value):
            record = _refresh_discovery_record(value, "systemd")
            record["value"]["stdout_raw_base64"] = (
                probe._discovery_raw_base64(b"systemd forged\n")
            )
            _refresh_discovery_record(value, "systemd")

        def nonterminated_systemd_raw(value):
            record = _refresh_discovery_record(value, "systemd")
            record["value"]["version_output"] = "systemd 255"
            record["value"]["feature_output"] = "features"
            record["value"]["stdout_raw_base64"] = (
                probe._discovery_raw_base64(b"systemd 255\nfeatures")
            )
            _refresh_discovery_record(value, "systemd")

        def three_line_systemd_raw(value):
            record = _refresh_discovery_record(value, "systemd")
            record["value"]["version_output"] = "systemd 255"
            record["value"]["feature_output"] = "features\nextra"
            record["value"]["stdout_raw_base64"] = (
                probe._discovery_raw_base64(
                    b"systemd 255\nfeatures\nextra\n"
                )
            )
            _refresh_discovery_record(value, "systemd")

        def blank_systemd_record(value):
            record = _refresh_discovery_record(value, "systemd")
            record["value"]["version_output"] = "systemd 255"
            record["value"]["feature_output"] = "\nextra"
            record["value"]["stdout_raw_base64"] = (
                probe._discovery_raw_base64(b"systemd 255\n\nextra\n")
            )
            _refresh_discovery_record(value, "systemd")

        def systemd_separator(value, separator):
            record = _refresh_discovery_record(value, "systemd")
            record["value"]["version_output"] = "systemd 255"
            record["value"]["feature_output"] = "features"
            record["value"]["stdout_raw_base64"] = (
                probe._discovery_raw_base64(
                    f"systemd 255{separator}features\n".encode("utf-8")
                )
            )
            _refresh_discovery_record(value, "systemd")

        def crlf_systemd_raw(value):
            record = _refresh_discovery_record(value, "systemd")
            record["value"]["version_output"] = "systemd 255"
            record["value"]["feature_output"] = "features"
            record["value"]["stdout_raw_base64"] = (
                probe._discovery_raw_base64(
                    b"systemd 255\r\nfeatures\r\n"
                )
            )
            _refresh_discovery_record(value, "systemd")

        def vertical_tab_systemd_raw(value):
            systemd_separator(value, "\v")

        def form_feed_systemd_raw(value):
            systemd_separator(value, "\f")

        def nel_systemd_raw(value):
            systemd_separator(value, "\u0085")

        def unicode_line_separator_systemd_raw(value):
            systemd_separator(value, "\u2028")

        def mismatched_controller_raw(value):
            record = _refresh_discovery_record(value, "cgroup_topology")
            record["value"]["controllers_raw_base64"] = (
                probe._discovery_raw_base64(b"cpu pids\n")
            )
            _refresh_discovery_record(value, "cgroup_topology")

        def noncanonical_controller_raw(value):
            record = _refresh_discovery_record(value, "cgroup_topology")
            record["value"]["controllers_raw_base64"] = (
                probe._discovery_raw_base64(b"cpu  memory pids\n")
            )
            _refresh_discovery_record(value, "cgroup_topology")

        def mismatched_proc_cgroup_raw(value):
            record = _refresh_discovery_record(value, "cgroup_topology")
            record["value"]["proc_cgroup_raw_base64"] = (
                probe._discovery_raw_base64(b"0::/other\n")
            )
            _refresh_discovery_record(value, "cgroup_topology")

        def malformed_proc_cgroup_raw(value):
            record = _refresh_discovery_record(value, "cgroup_topology")
            record["value"]["proc_cgroup"] = "1:cpu:/\n"
            record["value"]["proc_cgroup_raw_base64"] = (
                probe._discovery_raw_base64(b"1:cpu:/\n")
            )
            _refresh_discovery_record(value, "cgroup_topology")

        def noncanonical_proc_cgroup_path(value, path):
            record = _refresh_discovery_record(value, "cgroup_topology")
            raw = f"0::{path}\n".encode("utf-8")
            record["value"]["proc_cgroup"] = raw.decode("utf-8")
            record["value"]["proc_cgroup_raw_base64"] = (
                probe._discovery_raw_base64(raw)
            )
            _refresh_discovery_record(value, "cgroup_topology")

        def double_slash_proc_cgroup(value):
            noncanonical_proc_cgroup_path(value, "//forged")

        def dotdot_proc_cgroup(value):
            noncanonical_proc_cgroup_path(value, "/../forged")

        def dot_proc_cgroup(value):
            noncanonical_proc_cgroup_path(value, "/foo/./bar")

        def trailing_slash_proc_cgroup(value):
            noncanonical_proc_cgroup_path(value, "/foo/")

        def replace_mountinfo_source(
            value,
            raw,
            *,
            mount_options=None,
            super_options=None,
            optional_fields=None,
            root=None,
            mount_point=None,
            mount_source=None,
            fs_type=None,
        ):
            record = _refresh_discovery_record(value, "mountinfo_topology")
            entry = record["value"]["entries"][0]
            record["value"]["raw_base64"] = probe._discovery_raw_base64(raw)
            if mount_options is not None:
                entry["mount_options"] = sorted(mount_options)
            if super_options is not None:
                entry["super_options"] = sorted(super_options)
            if optional_fields is not None:
                entry["optional_fields"] = optional_fields
            if root is not None:
                entry["root"] = root
            if mount_point is not None:
                entry["mount_point"] = mount_point
            if mount_source is not None:
                entry["mount_source"] = mount_source
            if fs_type is not None:
                entry["fs_type"] = fs_type
            _refresh_discovery_record(value, "mountinfo_topology")

        def nonterminated_mountinfo_raw(value):
            replace_mountinfo_source(
                value,
                (
                    b"21 1 0:20 / /sys/fs/cgroup "
                    b"rw,nodev,nosuid,noexec - cgroup2 cgroup rw,nsdelegate"
                ),
            )

        def leading_blank_mountinfo_raw(value):
            replace_mountinfo_source(
                value,
                (
                    b"\n21 1 0:20 / /sys/fs/cgroup "
                    b"rw,nodev,nosuid,noexec - cgroup2 cgroup rw,nsdelegate\n"
                ),
            )

        def crlf_mountinfo_raw(value):
            replace_mountinfo_source(
                value,
                (
                    b"21 1 0:20 / /sys/fs/cgroup "
                    b"rw,nodev,nosuid,noexec - cgroup2 cgroup "
                    b"rw,nsdelegate\r\n"
                ),
            )

        def mountinfo_without_access_mode(value):
            replace_mountinfo_source(
                value,
                (
                    b"21 1 0:20 / /sys/fs/cgroup "
                    b"nodev,nosuid,noexec - cgroup2 cgroup rw,nsdelegate\n"
                ),
                mount_options=["nodev", "nosuid", "noexec"],
            )

        def mountinfo_super_without_access_mode(value):
            replace_mountinfo_source(
                value,
                (
                    b"21 1 0:20 / /sys/fs/cgroup "
                    b"rw,nodev,nosuid,noexec - cgroup2 cgroup nsdelegate\n"
                ),
                super_options=["nsdelegate"],
            )

        def malformed_known_mount_optional(value):
            replace_mountinfo_source(
                value,
                (
                    b"21 1 0:20 / /sys/fs/cgroup rw,nodev,nosuid,noexec "
                    b"shared:notdecimal - cgroup2 cgroup rw,nsdelegate\n"
                ),
                optional_fields=["shared:notdecimal"],
            )

        def duplicate_known_mount_optional(value):
            replace_mountinfo_source(
                value,
                (
                    b"21 1 0:20 / /sys/fs/cgroup rw,nodev,nosuid,noexec "
                    b"shared:7 shared:7 - cgroup2 cgroup rw,nsdelegate\n"
                ),
                optional_fields=["shared:7", "shared:7"],
            )

        def misordered_known_mount_optional(value):
            replace_mountinfo_source(
                value,
                (
                    b"21 1 0:20 / /sys/fs/cgroup rw,nodev,nosuid,noexec "
                    b"unbindable shared:7 - cgroup2 cgroup rw,nsdelegate\n"
                ),
                optional_fields=["unbindable", "shared:7"],
            )

        def propagate_from_without_master(value):
            replace_mountinfo_source(
                value,
                (
                    b"21 1 0:20 / /sys/fs/cgroup rw,nosuid,nodev,noexec "
                    b"propagate_from:7 - cgroup2 cgroup rw,nsdelegate\n"
                ),
                optional_fields=["propagate_from:7"],
            )

        def propagate_from_equals_master(value):
            replace_mountinfo_source(
                value,
                (
                    b"21 1 0:20 / /sys/fs/cgroup rw,nosuid,nodev,noexec "
                    b"master:7 propagate_from:7 "
                    b"- cgroup2 cgroup rw,nsdelegate\n"
                ),
                optional_fields=["master:7", "propagate_from:7"],
            )

        def unknown_mount_option(value):
            replace_mountinfo_source(
                value,
                (
                    b"21 1 0:20 / /sys/fs/cgroup rw,nosuid,forged "
                    b"- cgroup2 cgroup rw,nsdelegate\n"
                ),
                mount_options=["rw", "nosuid", "forged"],
            )

        def misordered_producer_mount_options(value):
            replace_mountinfo_source(
                value,
                (
                    b"21 1 0:20 / /sys/fs/cgroup rw,nodev,nosuid,noexec "
                    b"- cgroup2 cgroup rw,nsdelegate\n"
                ),
                mount_options=["rw", "nodev", "nosuid", "noexec"],
            )

        def literal_hash_filesystem_type(value):
            replace_mountinfo_source(
                value,
                (
                    b"21 1 0:20 / /sys/fs/cgroup rw,nosuid,nodev,noexec "
                    b"- fs#type cgroup rw,nsdelegate\n"
                ),
                fs_type="fs#type",
            )

        def unknown_escape_filesystem_type(value):
            replace_mountinfo_source(
                value,
                (
                    b"21 1 0:20 / /sys/fs/cgroup rw,nosuid,nodev,noexec "
                    b"- fs\\999type cgroup rw,nsdelegate\n"
                ),
                fs_type=r"fs\999type",
            )

        def misordered_producer_super_options(value):
            replace_mountinfo_source(
                value,
                (
                    b"21 1 0:20 / /sys/fs/cgroup rw,nosuid,nodev,noexec "
                    b"- cgroup2 cgroup rw,lazytime,sync\n"
                ),
                super_options=["lazytime", "rw", "sync"],
            )

        def fixed_super_option_after_filesystem_option(value):
            replace_mountinfo_source(
                value,
                (
                    b"21 1 0:20 / /sys/fs/cgroup rw,nosuid,nodev,noexec "
                    b"- cgroup2 cgroup rw,nsdelegate,sync\n"
                ),
                super_options=["nsdelegate", "rw", "sync"],
            )

        def noncanonical_mount_path(value, *, root, mount_point):
            replace_mountinfo_source(
                value,
                (
                    f"21 1 0:20 {root} {mount_point} "
                    "rw,nosuid,nodev,noexec "
                    "- cgroup2 cgroup rw,nsdelegate\n"
                ).encode("ascii"),
                root=root,
                mount_point=mount_point,
            )

        def double_slash_mount_root(value):
            noncanonical_mount_path(
                value, root="//forged", mount_point="/sys/fs/cgroup"
            )

        def dotdot_mount_root(value):
            noncanonical_mount_path(
                value, root="/foo/../bar", mount_point="/sys/fs/cgroup"
            )

        def double_slash_mount_point(value):
            noncanonical_mount_path(
                value, root="/", mount_point="/sys//fs/cgroup"
            )

        def dot_mount_point(value):
            noncanonical_mount_path(
                value, root="/", mount_point="/sys/./fs/cgroup"
            )

        def trailing_slash_mount_point(value):
            noncanonical_mount_path(
                value, root="/", mount_point="/sys/fs/cgroup/"
            )

        def hash_escape_in_mount_root(value):
            replace_mountinfo_source(
                value,
                (
                    b"21 1 0:20 /dev\\043root /sys/fs/cgroup "
                    b"rw,nosuid,nodev,noexec "
                    b"- cgroup2 cgroup rw,nsdelegate\n"
                ),
                root="/dev#root",
            )

        def blocker_substitution(value):
            value["mandatory_effect_blockers"] = [
                "SystemCallArchitectures",
                *[f"InventedBlocker{index}" for index in range(26)],
            ]

        def error_bearing(value):
            value["errors"] = [
                {
                    "code": "OBSERVATION_FAILED",
                    "authority": "supervisor_observed",
                    "detail": "forensic only",
                }
            ]

        def notice_drift(value):
            value["discovery_notice"] = "proof-ineligible-ish"

        mutations = {
            "scalar_record": scalar_record,
            "nested_authority": nested_authority,
            "forged_image_release": forged_image_release,
            "systemd_extra_field": systemd_extra_field,
            "cgroup_noncanonical": cgroup_noncanonical,
            "malformed_mount": malformed_mount,
            "duplicate_mount_id": duplicate_mount_id,
            "numeric_alias_mount_id": numeric_alias_mount_id,
            "noncanonical_major_minor": noncanonical_major_minor,
            "unsorted_mount_options": unsorted_mount_options,
            "empty_mount_options": empty_mount_options,
            "empty_super_options": empty_super_options,
            "impossible_mount_option_token": impossible_mount_option_token,
            "impossible_optional_field_token": impossible_optional_field_token,
            "impossible_filesystem_type_token": impossible_filesystem_type_token,
            "mismatched_mountinfo_raw": mismatched_mountinfo_raw,
            "zero_mount_id": zero_mount_id,
            "oversized_mount_id": oversized_mount_id,
            "oversized_mount_major_minor": oversized_mount_major_minor,
            "contradictory_bpf": contradictory_bpf,
            "errno_name_mismatch": errno_name_mismatch,
            "unknown_errno": unknown_errno,
            "impossible_bpf_operation_errno": impossible_bpf_operation_errno,
            "impossible_bpf_efault": impossible_bpf_efault,
            "impossible_bpf_einval": impossible_bpf_einval,
            "linux_errno_alias": linux_errno_alias,
            "malformed_device": malformed_device,
            "oversized_device_identity": oversized_device_identity,
            "arbitrary_device_path": arbitrary_device_path,
            "duplicate_device_path": duplicate_device_path,
            "noncanonical_device_path": noncanonical_device_path,
            "malformed_abi": malformed_abi,
            "arbitrary_abi_path": arbitrary_abi_path,
            "duplicate_abi_path": duplicate_abi_path,
            "oversized_elf_machine": oversized_elf_machine,
            "missing_systemd_abi": missing_systemd_abi,
            "contradictory_field": contradictory_field,
            "empty_fields": empty_fields,
            "wrong_field_path": wrong_field_path,
            "duplicate_field_name": duplicate_field_name,
            "empty_kernel_identity": empty_kernel_identity,
            "oversized_kernel_uts_identity": oversized_kernel_uts_identity,
            "zero_invocation_uuid": zero_invocation_uuid,
            "wrong_version_invocation_uuid": wrong_version_invocation_uuid,
            "wrong_variant_invocation_uuid": wrong_variant_invocation_uuid,
            "wrong_version_boot_uuid": wrong_version_boot_uuid,
            "embedded_newline_systemd_version": embedded_newline_systemd_version,
            "oversized_joint_systemd_fields": oversized_joint_systemd_fields,
            "arbitrary_systemd_two_lines": arbitrary_systemd_two_lines,
            "incomplete_systemd_features": incomplete_systemd_features,
            "misordered_systemd_features": misordered_systemd_features,
            "wrong_systemd_project_version": wrong_systemd_project_version,
            "mismatched_systemd_raw": mismatched_systemd_raw,
            "nonterminated_systemd_raw": nonterminated_systemd_raw,
            "three_line_systemd_raw": three_line_systemd_raw,
            "blank_systemd_record": blank_systemd_record,
            "crlf_systemd_raw": crlf_systemd_raw,
            "vertical_tab_systemd_raw": vertical_tab_systemd_raw,
            "form_feed_systemd_raw": form_feed_systemd_raw,
            "nel_systemd_raw": nel_systemd_raw,
            "unicode_line_separator_systemd_raw": (
                unicode_line_separator_systemd_raw
            ),
            "mismatched_controller_raw": mismatched_controller_raw,
            "noncanonical_controller_raw": noncanonical_controller_raw,
            "mismatched_proc_cgroup_raw": mismatched_proc_cgroup_raw,
            "malformed_proc_cgroup_raw": malformed_proc_cgroup_raw,
            "double_slash_proc_cgroup": double_slash_proc_cgroup,
            "dotdot_proc_cgroup": dotdot_proc_cgroup,
            "dot_proc_cgroup": dot_proc_cgroup,
            "trailing_slash_proc_cgroup": trailing_slash_proc_cgroup,
            "nonterminated_mountinfo_raw": nonterminated_mountinfo_raw,
            "leading_blank_mountinfo_raw": leading_blank_mountinfo_raw,
            "crlf_mountinfo_raw": crlf_mountinfo_raw,
            "mountinfo_without_access_mode": mountinfo_without_access_mode,
            "mountinfo_super_without_access_mode": (
                mountinfo_super_without_access_mode
            ),
            "malformed_known_mount_optional": malformed_known_mount_optional,
            "duplicate_known_mount_optional": duplicate_known_mount_optional,
            "misordered_known_mount_optional": (
                misordered_known_mount_optional
            ),
            "propagate_from_without_master": propagate_from_without_master,
            "propagate_from_equals_master": propagate_from_equals_master,
            "unknown_mount_option": unknown_mount_option,
            "misordered_producer_mount_options": (
                misordered_producer_mount_options
            ),
            "literal_hash_filesystem_type": literal_hash_filesystem_type,
            "unknown_escape_filesystem_type": (
                unknown_escape_filesystem_type
            ),
            "misordered_producer_super_options": (
                misordered_producer_super_options
            ),
            "fixed_super_option_after_filesystem_option": (
                fixed_super_option_after_filesystem_option
            ),
            "double_slash_mount_root": double_slash_mount_root,
            "dotdot_mount_root": dotdot_mount_root,
            "double_slash_mount_point": double_slash_mount_point,
            "dot_mount_point": dot_mount_point,
            "trailing_slash_mount_point": trailing_slash_mount_point,
            "hash_escape_in_mount_root": hash_escape_in_mount_root,
            "contradictory_cgroup_mode": contradictory_cgroup_mode,
            "unknown_field_errno": unknown_field_errno,
            "impossible_field_operation_errno": (
                impossible_field_operation_errno
            ),
            "impossible_proc_status_enoent": impossible_proc_status_enoent,
            "impossible_cpu_max_with_controller": (
                impossible_cpu_max_with_controller
            ),
            "impossible_memory_events_with_controller": (
                impossible_memory_events_with_controller
            ),
            "contradictory_os_release": contradictory_os_release,
            "duplicate_os_release_identity": duplicate_os_release_identity,
            "mismatched_os_release_raw": mismatched_os_release_raw,
            "contradictory_mountinfo_availability": (
                contradictory_mountinfo_availability
            ),
            "contradictory_read_field_availability": (
                contradictory_read_field_availability
            ),
            "impossible_runner_arch": impossible_runner_arch,
            "arbitrary_workflow": arbitrary_workflow,
            "impossible_image_date": impossible_image_date,
            "blocker_substitution": blocker_substitution,
            "error_bearing": error_bearing,
            "notice_drift": notice_drift,
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                evidence = _hosted_discovery_evidence()
                mutate(evidence)
                with self.assertRaises(probe.ProbeError):
                    probe.validate_discovery_evidence(evidence, SCHEMA_PATH)
                with tempfile.TemporaryDirectory() as raw_directory:
                    archive_path, _, _ = _write_discovery_zip(
                        Path(raw_directory), evidence
                    )
                    completed = subprocess.run(
                        _standalone_validator_argv(
                            validator_path, archive_path, evidence
                        ),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                self.assertNotEqual(
                    0,
                    completed.returncode,
                    completed.stdout.decode("utf-8", "replace"),
                )

    def test_operation_errno_domain_is_independent_of_validator_host(self):
        validator_path = _standalone_discovery_validator_path()
        validator_source = validator_path.read_text(encoding="utf-8")
        self.assertNotIn("errno.errorcode", validator_source)
        self.assertNotIn(
            "errno.errorcode", TOOL_PATH.read_text(encoding="utf-8")
        )

        evidence = _hosted_discovery_evidence()
        bpf_record = _refresh_discovery_record(evidence, "bpf_prog_query")
        bpf_record["value"].update(
            {
                "success": False,
                "errno": 1,
                "errno_name": "EPERM",
            }
        )
        _refresh_discovery_record(evidence, "bpf_prog_query")
        cgroup_record = _refresh_discovery_record(
            evidence, "cgroup_topology"
        )
        cgroup_record["value"]["controllers"] = ["memory", "pids"]
        cgroup_record["value"]["controllers_raw_base64"] = (
            probe._discovery_raw_base64(b"memory pids\n")
        )
        _refresh_discovery_record(evidence, "cgroup_topology")
        field_record = _refresh_discovery_record(evidence, "field_availability")
        optional_field = next(
            field
            for field in field_record["value"]["fields"]
            if field["name"] == "cpu.max"
        )
        optional_field["available"] = False
        optional_field["errno"] = 2
        _refresh_discovery_record(evidence, "field_availability")
        mount_record = _refresh_discovery_record(
            evidence, "mountinfo_topology"
        )
        mount_record["value"]["raw_base64"] = probe._discovery_raw_base64(
            b"21 1 0:20 / /sys/fs/cgroup rw,nosuid,nodev,noexec "
            b"- cgroup2 dev\\043name rw,nsdelegate\n"
        )
        mount_record["value"]["entries"][0]["mount_source"] = "dev#name"
        mount_record["value"]["raw_base64"] = probe._discovery_raw_base64(
            b"21 1 0:20 / /sys/fs/cgroup rw,nosuid,nodev,noexec "
            b"- fs\\043type dev\\043name rw,sync,lazytime,nsdelegate\n"
        )
        mount_entry = mount_record["value"]["entries"][0]
        mount_entry["fs_type"] = r"fs\043type"
        mount_entry["super_options"] = [
            "lazytime",
            "nsdelegate",
            "rw",
            "sync",
        ]
        _refresh_discovery_record(evidence, "mountinfo_topology")

        probe.validate_discovery_evidence(evidence, SCHEMA_PATH)
        with tempfile.TemporaryDirectory() as raw_directory:
            archive_path, _, _ = _write_discovery_zip(
                Path(raw_directory), evidence
            )
            completed = subprocess.run(
                _standalone_validator_argv(
                    validator_path, archive_path, evidence
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(
            0,
            completed.returncode,
            completed.stderr.decode("utf-8", "replace"),
        )

    def test_future_witness_declarations_cannot_become_effect_records(self):
        value = _discovery_evidence()
        self.assertTrue(
            all(not item["proof_eligible"] for item in value["future_witnesses"])
        )
        self.assertEqual(
            list(probe.EQUIVALENCE_CLASS_IDENTIFIERS),
            [item["id"] for item in value["future_witnesses"]],
        )
        overclaim = _discovery_evidence()
        overclaim["future_witnesses"][0]["proof_eligible"] = True
        self.assertDiscoveryInvalid(overclaim)

    def test_system_call_architectures_remains_blocked_with_or_without_abi(self):
        for present in (True, False):
            value = _discovery_evidence(abi_present=present)
            probe.validate_discovery_evidence(value, SCHEMA_PATH)
            self.assertIn(
                "SystemCallArchitectures",
                value["mandatory_effect_blockers"],
            )
            self.assertFalse(
                probe.candidate_run_succeeds(
                    cases=[_perfect_case(cid) for cid in probe.CASES],
                    requested_case_ids=probe.CASES,
                    errors=[],
                    witness_ok=True,
                    mandatory_blockers=value["mandatory_effect_blockers"],
                )
            )

    def test_gate1_namespace_and_success_overclaims_are_rejected(self):
        token = _discovery_evidence()
        token["errors"].append(
            {
                "code": "FORGED",
                "authority": "supervisor_observed",
                "detail": "GATE1_APPROVE",
            }
        )
        self.assertDiscoveryInvalid(token)

        success = _discovery_evidence()
        success["outcome"] = "SUCCESS"
        self.assertDiscoveryInvalid(success)


if __name__ == "__main__":
    unittest.main()
