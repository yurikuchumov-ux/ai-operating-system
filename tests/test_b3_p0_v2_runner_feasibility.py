"""Deterministic tests for the inert Gate 1 candidate surface."""

from __future__ import annotations

import ast
import copy
import io
import json
import os
import socket
import struct
import threading
import unittest
from itertools import product
from pathlib import Path
from unittest import mock

from tools import p0_v2_runner_probe as probe

try:
    import jsonschema

    HAVE_JSONSCHEMA = True
except ImportError:  # pragma: no cover - optional local dependency
    jsonschema = None
    HAVE_JSONSCHEMA = False


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github/workflows/p0-v2-runner-feasibility.yml"
SCHEMA_PATH = (
    REPO_ROOT
    / "contracts/schemas/p0-v2-runner-feasibility-evidence.v1.schema.json"
)
PROBE_PATH = REPO_ROOT / "tools/p0_v2_runner_probe.py"
OBSOLETE_SCHEMA_PATH = REPO_ROOT / probe.OBSOLETE_SCHEMA_PATH

EXPECTED_WORKFLOW = b"""name: P0 v2 runner feasibility candidate (inert)

on:
  workflow_call:

permissions: {}

jobs:
  inert-candidate:
    if: ${{ false }}
    permissions: {}
    runs-on: ubuntu-24.04
    steps:
      - name: Fail closed if GitHub evaluates the inert candidate workflow
        shell: bash
        run: exit 1
"""

HEX1 = "1" * 40
HEX2 = "2" * 40
HEX3 = "3" * 40
HEX4 = "4" * 40
DIGEST = "a" * 64
LABEL = f"g1v1-{HEX1}-1"


def candidate_path(path: str, index: int) -> dict:
    return {
        "path": path,
        "mode": "100644",
        "git_blob_sha": str(index + 5) * 40,
        "sha256": format(index + 10, "x") * 64,
    }


def context() -> dict:
    return {
        "context_version": "g1v1",
        "authorization": {
            "version": "g1v1",
            "phase": "1",
            "label": LABEL,
            "trusted_main_sha": HEX1,
        },
        "candidate": {
            "origin_base_sha": HEX2,
            "head_sha": HEX3,
            "parent_sha": HEX2,
            "tree_sha": HEX4,
            "repository": "yurikuchumov-ux/ai-operating-system",
            "repository_id": 1296950956,
            "head_repository": "yurikuchumov-ux/ai-operating-system",
            "head_repository_id": 1296950956,
            "owner_login": "yurikuchumov-ux",
            "owner_id": 299144523,
            "same_repository": True,
            "no_fork": True,
            "branch": "agent/issue-70-p0-v2-feasibility-gate1",
            "pr_number": 71,
            "paths": [
                candidate_path(path, index)
                for index, path in enumerate(probe.APPROVED_CANDIDATE_PATHS)
            ],
        },
        "control": {
            "repository": "yurikuchumov-ux/ai-operating-system",
            "repository_id": 1296950956,
            "owner_login": "yurikuchumov-ux",
            "owner_id": 299144523,
            "issue_number": 70,
            "issue_id": 123,
            "issue_node_id": "I_kwDO",
            "issue_state": "open",
            "issue_is_pull_request": False,
            "live_pr_base_sha": HEX2,
        },
        "event": {
            "name": "issues",
            "action": "labeled",
            "event_path_sha256": DIGEST,
            "issue_event_id": 1001,
            "issue_event_node_id": "LE_kwDO",
            "label_id": 1002,
            "label_node_id": "LA_kwDO",
            "label_name": LABEL,
            "label_color": "0e8a16",
            "label_description": None,
            "label_default": False,
            "created_at": "2026-07-28T10:00:00Z",
            "actor_login": "yurikuchumov-ux",
            "actor_id": 299144523,
            "triggering_actor_login": "yurikuchumov-ux",
            "triggering_actor_id": 299144523,
            "sender_login": "yurikuchumov-ux",
            "sender_id": 299144523,
            "run_id": 30362648987,
            "run_attempt": 1,
            "run_created_at": "2026-07-28T10:00:01.123Z",
            "boot_id": "12345678-1234-1234-1234-123456789abc",
        },
        "workflow": {
            "path": ".github/workflows/p0-v2-gate1-trusted-canary.yml",
            "ref": (
                "yurikuchumov-ux/ai-operating-system/"
                ".github/workflows/p0-v2-gate1-trusted-canary.yml@refs/heads/main"
            ),
            "sha": HEX1,
            "blob_sha": HEX4,
            "github_ref": "refs/heads/main",
            "github_workflow_sha": HEX1,
        },
        "digests": {
            "authorization_manifest": DIGEST,
            "controller": "b" * 64,
            "broker_protocol": "c" * 64,
            "candidate_probe": "d" * 64,
            "evidence_schema": "e" * 64,
            "synthetic_merge_tool": "f" * 64,
            "synthetic_merge_normalization": "0" * 64,
        },
        "snapshots": {
            "pre_acquisition_sha256": "1" * 64,
            "pre_broker_sha256": "2" * 64,
            "post_cleanup_sha256": None,
        },
        "synthetic_merge": {
            "sha": None,
            "ordered_parents": None,
            "tree_sha": None,
            "algorithm": None,
            "tool_version_sha256": None,
            "normalization_sha256": None,
            "construction_manifest_sha256": None,
            "conflict": None,
            "exact_tree_proof_sha256": None,
        },
        "staging": [
            {
                "name": "candidate-probe",
                "device": 1,
                "inode": 2,
                "size": 3,
                "mode": "0500",
                "link_count": 1,
                "sha256": "3" * 64,
            },
            {
                "name": "sealed-context",
                "device": 1,
                "inode": 3,
                "size": 4,
                "mode": "0400",
                "link_count": 1,
                "sha256": "4" * 64,
            },
        ],
        "replay": {
            "phase_consumed": False,
            "prior_phase_labels": [],
            "prior_run_ids": [],
            "overlapping_run": False,
            "sequence_sha256": "5" * 64,
        },
    }


def canonical_context(value: dict) -> bytes:
    return probe.canonical_json_bytes(value)


def final_evidence() -> dict:
    sealed = context()

    def request(index: int) -> dict:
        return {
            "method": "GET",
            "target": f"https://api.github.com/repositories/1296950956/items/{index}",
            "status": 200,
            "api_version": "2022-11-28",
            "media_type": "application/vnd.github+json",
            "page": index,
            "next_target": None,
            "body_base64": "e30=",
            "body_sha256": probe.sha256_bytes(b"{}"),
            "etag": None,
            "last_modified": None,
            "rate_limit_limit": 60,
            "rate_limit_remaining": 59,
            "rate_limit_reset": 1785236400,
            "retrieved_at": "2026-07-28T10:00:00Z",
        }

    def snapshot(name: str, marker: str) -> dict:
        return {
            "name": name,
            "requests": [request(index) for index in range(1, 7)],
            "raw_requests_sha256": marker * 64,
            "canonical_projection_sha256": marker * 64,
            "authorization_state_sha256": "9" * 64,
        }

    def staged_file(index: int) -> dict:
        digest = format(index + 10, "x") * 64
        return {
            "name": f"staged-{index}",
            "device": 1,
            "inode": index + 1,
            "size": index + 10,
            "mode": "0400",
            "link_count": 1,
            "sha256": digest,
            "source_sha256": digest,
            "readback_sha256": digest,
        }

    return {
        "schema_version": "2.0.0",
        "evidence_kind": "p0-v2-gate1-trusted-control-plane-evidence",
        "authority": "trusted_default_branch_control_plane",
        "outcome": "SUCCESS",
        "evidence_stage": "completed",
        "candidate_report_state": "complete",
        "authorization": sealed["authorization"],
        "candidate": sealed["candidate"],
        "control": sealed["control"],
        "event": sealed["event"],
        "workflow": sealed["workflow"],
        "digests": {
            **sealed["digests"],
            "sealed_context": "f" * 64,
            "recovery_journal": "8" * 64,
        },
        "synthetic_merge": sealed["synthetic_merge"],
        "snapshots": {
            "pre_acquisition": snapshot("pre_acquisition", "1"),
            "pre_broker": snapshot("pre_broker", "2"),
            "post_cleanup": snapshot("post_cleanup", "3"),
        },
        "staging": [staged_file(index) for index in range(6)],
        "broker": {
            "protocol_version": "g1-broker-v1",
            "instance_nonce_sha256": "4" * 64,
            "candidate_uid": 65534,
            "candidate_gid": 65534,
            "candidate_report_sha256": "5" * 64,
            "transcript_state": "complete",
            "transcript_sha256": "6" * 64,
            "accepted_request_count": 22,
            "completed_response_count": 22,
            "candidate_subtree_empty": True,
            "host_restored": True,
            "channel_closed": True,
            "isolation": {
                "no_supplementary_groups": True,
                "capabilities_empty": True,
                "no_new_privs": True,
                "no_setid_elevation": True,
                "private_pid": True,
                "private_mount": True,
                "private_ipc": True,
                "private_uts": True,
                "private_user": True,
                "private_network": True,
                "namespace_local_proc": True,
                "host_pid_hidden": True,
                "host_sockets_hidden": True,
                "credentials_absent": True,
                "command_files_absent": True,
                "writable_descriptors_absent": True,
                "loopback_disabled": True,
            },
        },
        "replay": sealed["replay"],
        "cancellation": {
            "requested": False,
            "ordinary": False,
            "force": False,
            "active_marker_sha256": None,
            "recovery_journal_sha256": "8" * 64,
            "trusted_finalizer_complete": True,
            "candidate_subtree_empty": True,
            "host_restored": True,
        },
        "artifact": {
            "manifest_sha256": "7" * 64,
            "archive_sha256": "8" * 64,
            "archive_size": 12345,
            "constructed_after_post_cleanup_snapshot": True,
            "upload_started_after_candidate_destruction": True,
        },
        "errors": [],
    }


def cancelled_final_evidence() -> dict:
    value = final_evidence()
    value["outcome"] = "ACTIONS_CANCELLED"
    value["evidence_stage"] = "cancelled_after_wait"
    value["candidate_report_state"] = "absent_due_to_cancellation"
    value["authorization"]["phase"] = "c"
    value["authorization"]["label"] = f"g1v1-{HEX1}-c"
    value["event"]["label_name"] = value["authorization"]["label"]
    value["replay"]["prior_phase_labels"] = [
        f"g1v1-{HEX1}-1",
        f"g1v1-{HEX1}-2",
        f"g1v1-{HEX1}-3",
    ]
    value["replay"]["prior_run_ids"] = [100, 101, 102]
    value["broker"].update(
        {
            "candidate_report_sha256": None,
            "transcript_state": "partial_due_to_cancellation",
            "accepted_request_count": 4,
            "completed_response_count": 3,
        }
    )
    value["cancellation"].update(
        {
            "requested": True,
            "ordinary": True,
            "active_marker_sha256": "9" * 64,
        }
    )
    return value


def pre_acquisition_failure_evidence() -> dict:
    value = final_evidence()
    value["outcome"] = "FAILED"
    value["evidence_stage"] = "pre_acquisition_rejected"
    value["candidate_report_state"] = "absent_before_candidate_start"
    value["snapshots"] = {
        "pre_acquisition": None,
        "pre_broker": None,
        "post_cleanup": None,
    }
    value["staging"] = None
    value["broker"] = None
    value["artifact"] = None
    value["cancellation"]["trusted_finalizer_complete"] = False
    value["errors"] = [
        {
            "code": "AUTHORIZATION_REJECTED",
            "detail_sha256": "a" * 64,
        }
    ]
    return value


def authorization_failure_evidence() -> dict:
    value = pre_acquisition_failure_evidence()
    value["evidence_stage"] = "authorization_rejected"
    return value


def pre_broker_failure_evidence() -> dict:
    value = pre_acquisition_failure_evidence()
    value["evidence_stage"] = "pre_broker_rejected"
    value["snapshots"]["pre_acquisition"] = final_evidence()["snapshots"][
        "pre_acquisition"
    ]
    return value


def broker_failed_evidence() -> dict:
    value = final_evidence()
    value["outcome"] = "FAILED"
    value["evidence_stage"] = "broker_failed"
    value["candidate_report_state"] = "absent_due_to_failure"
    value["snapshots"]["post_cleanup"] = None
    value["broker"].update(
        {
            "candidate_report_sha256": None,
            "transcript_state": "partial_due_to_failure",
            "accepted_request_count": 4,
            "completed_response_count": 3,
        }
    )
    value["artifact"] = None
    value["errors"] = [
        {
            "code": "BROKER_FAILED",
            "detail_sha256": "a" * 64,
        }
    ]
    return value


def cancellation_broker_failed_evidence() -> dict:
    value = broker_failed_evidence()
    value["authorization"]["phase"] = "c"
    value["authorization"]["label"] = f"g1v1-{HEX1}-c"
    value["event"]["label_name"] = value["authorization"]["label"]
    value["replay"]["prior_phase_labels"] = [
        f"g1v1-{HEX1}-1",
        f"g1v1-{HEX1}-2",
        f"g1v1-{HEX1}-3",
    ]
    value["replay"]["prior_run_ids"] = [100, 101, 102]
    value["cancellation"]["active_marker_sha256"] = "9" * 64
    return value


def complete_exchange_report_failure_evidence(phase: str = "1") -> dict:
    value = broker_failed_evidence()
    value["authorization"]["phase"] = phase
    value["authorization"]["label"] = f"g1v1-{HEX1}-{phase}"
    value["event"]["label_name"] = value["authorization"]["label"]
    value["broker"].update(
        {
            "accepted_request_count": 22,
            "completed_response_count": 22,
            "transcript_state": "complete",
        }
    )
    value["errors"][0]["code"] = "CANDIDATE_REPORT_FAILED"
    return value


def post_cleanup_snapshot_failure_evidence() -> dict:
    value = final_evidence()
    value["outcome"] = "FAILED"
    value["evidence_stage"] = "post_cleanup_snapshot_rejected"
    value["snapshots"]["post_cleanup"] = None
    value["artifact"] = None
    value["errors"] = [
        {
            "code": "POST_CLEANUP_SNAPSHOT_REJECTED",
            "detail_sha256": "a" * 64,
        }
    ]
    return value


def artifact_failure_evidence() -> dict:
    value = final_evidence()
    value["outcome"] = "FAILED"
    value["evidence_stage"] = "artifact_failed"
    value["artifact"] = None
    value["errors"] = [
        {
            "code": "ARTIFACT_FAILED",
            "detail_sha256": "a" * 64,
        }
    ]
    return value


def cancellation_cleanup_failure_evidence() -> dict:
    value = cancelled_final_evidence()
    value["outcome"] = "FAILED"
    value["evidence_stage"] = "cancellation_cleanup_failed"
    value["snapshots"]["post_cleanup"] = None
    value["artifact"] = None
    value["cancellation"]["trusted_finalizer_complete"] = False
    value["errors"] = [
        {
            "code": "CANCELLATION_CLEANUP_FAILED",
            "detail_sha256": "a" * 64,
        }
    ]
    return value


def cancellation_artifact_failure_evidence() -> dict:
    value = cancelled_final_evidence()
    value["outcome"] = "FAILED"
    value["evidence_stage"] = "cancellation_artifact_failed"
    value["artifact"] = None
    value["errors"] = [
        {
            "code": "CANCELLATION_ARTIFACT_FAILED",
            "detail_sha256": "a" * 64,
        }
    ]
    return value


def status_text(**overrides: str) -> str:
    fields = {
        "CapInh": "0000000000000000",
        "CapPrm": "0000000000000000",
        "CapEff": "0000000000000000",
        "CapBnd": "0000000000000000",
        "CapAmb": "0000000000000000",
        "NoNewPrivs": "1",
        "Seccomp": "2",
        "Groups": "",
        "NSpid": "91000 1",
    }
    fields.update(overrides)
    return "".join(f"{key}:\t{value}\n" for key, value in fields.items())


class WorkflowContractTests(unittest.TestCase):
    def test_workflow_is_exact_inert_stub(self) -> None:
        self.assertEqual(WORKFLOW_PATH.read_bytes(), EXPECTED_WORKFLOW)

    def test_workflow_has_only_workflow_call_and_empty_permissions(self) -> None:
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertEqual(text.count("workflow_call:"), 1)
        self.assertEqual(text.count("permissions: {}"), 2)
        self.assertEqual(text.count("if: ${{ false }}"), 1)
        self.assertEqual(text.count("run: exit 1"), 1)
        for forbidden in (
            "pull_request",
            "pull_request_target",
            "issues:",
            "push:",
            "schedule:",
            "workflow_dispatch:",
            "workflow_run:",
            "repository_dispatch:",
            "uses:",
            "checkout",
            "sudo",
            "python",
            "curl",
            "wget",
            "upload",
            "secrets:",
            "inputs:",
        ):
            self.assertNotIn(forbidden, text)

    def test_exact_bytes_make_yaml_ambiguity_fail_closed(self) -> None:
        mutations = (
            EXPECTED_WORKFLOW.replace(b"on:\n", b"on: &events\n", 1),
            EXPECTED_WORKFLOW.replace(b"permissions: {}\n", b"<<: *defaults\n", 1),
            EXPECTED_WORKFLOW.replace(
                b"workflow_call:\n", b"workflow_call:\n  pull_request:\n", 1
            ),
            EXPECTED_WORKFLOW.replace(b"${{ false }}", b"${{ 1 == 0 }}", 1),
            EXPECTED_WORKFLOW + b"jobs: {}\n",
        )
        for payload in mutations:
            with self.subTest(payload=payload[-40:]):
                self.assertNotEqual(payload, EXPECTED_WORKFLOW)


class SchemaContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = SCHEMA_PATH.read_bytes()
        cls.schema = probe.strict_json_loads(cls.raw, limit=2 * 1024 * 1024)

    def test_schema_is_canonical_path_and_closed(self) -> None:
        self.assertEqual(
            self.schema["$id"],
            (
                "https://github.com/yurikuchumov-ux/ai-operating-system/"
                "contracts/schemas/p0-v2-runner-feasibility-evidence.v1.schema.json"
            ),
        )
        self.assertFalse(self.schema["additionalProperties"])
        self.assertFalse(OBSOLETE_SCHEMA_PATH.exists())
        self.assertNotIn(probe.OBSOLETE_SCHEMA_PATH.encode("ascii"), self.raw)

    def test_schema_binds_three_snapshots_and_separated_bases(self) -> None:
        required = set(self.schema["required"])
        self.assertTrue(
            {
                "authorization",
                "candidate",
                "control",
                "event",
                "workflow",
                "synthetic_merge",
                "snapshots",
                "broker",
                "replay",
                "artifact",
            }
            <= required
        )
        snapshots = self.schema["$defs"]["stage_aware_snapshots"]["properties"]
        self.assertEqual(
            set(snapshots), {"pre_acquisition", "pre_broker", "post_cleanup"}
        )
        candidate_required = set(self.schema["$defs"]["candidate"]["required"])
        control_required = set(self.schema["$defs"]["control"]["required"])
        self.assertIn("origin_base_sha", candidate_required)
        self.assertIn("live_pr_base_sha", control_required)

    def test_schema_binds_exact_label_and_four_paths(self) -> None:
        label = self.schema["$defs"]["authorization"]["properties"]["label"]
        self.assertEqual(label["minLength"], 47)
        self.assertEqual(label["maxLength"], 47)
        self.assertEqual(label["pattern"], r"^g1v1-[0-9a-f]{40}-[123c]$")
        paths = self.schema["$defs"]["candidate"]["properties"]["paths"]
        self.assertEqual(paths["minItems"], 4)
        self.assertEqual(paths["maxItems"], 4)
        expected = [
            item["allOf"][1]["properties"]["path"]["const"]
            for item in paths["prefixItems"]
        ]
        self.assertEqual(tuple(expected), probe.APPROVED_CANDIDATE_PATHS)

    @unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema is optional")
    def test_schema_is_valid_draft_2020_12(self) -> None:
        jsonschema.Draft202012Validator.check_schema(self.schema)

    @unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema is optional")
    def test_complete_final_evidence_validates(self) -> None:
        jsonschema.Draft202012Validator(self.schema).validate(final_evidence())

    @unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema is optional")
    def test_truthful_cancelled_evidence_has_no_candidate_report(self) -> None:
        value = cancelled_final_evidence()
        self.assertIsNone(value["broker"]["candidate_report_sha256"])
        self.assertEqual(value["broker"]["accepted_request_count"], 4)
        self.assertEqual(value["broker"]["completed_response_count"], 3)
        jsonschema.Draft202012Validator(self.schema).validate(value)
        value["broker"]["candidate_report_sha256"] = "5" * 64
        self.assertTrue(
            list(jsonschema.Draft202012Validator(self.schema).iter_errors(value))
        )

    @unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema is optional")
    def test_outcome_conditioned_broker_counts_and_states_fail_closed(
        self,
    ) -> None:
        validator = jsonschema.Draft202012Validator(self.schema)
        mutations = (
            lambda value: value.update({"candidate_report_state": "complete"}),
            lambda value: value["broker"].update({"accepted_request_count": 5}),
            lambda value: value["broker"].update({"completed_response_count": 4}),
            lambda value: value["broker"].update({"transcript_state": "complete"}),
        )
        for mutation in mutations:
            value = cancelled_final_evidence()
            mutation(value)
            with self.subTest(mutation=mutation):
                self.assertTrue(list(validator.iter_errors(value)))

    @unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema is optional")
    def test_pre_acquisition_failure_has_no_broker_or_fabricated_artifact(
        self,
    ) -> None:
        value = pre_acquisition_failure_evidence()
        self.assertIsNone(value["staging"])
        self.assertIsNone(value["broker"])
        self.assertIsNone(value["artifact"])
        jsonschema.Draft202012Validator(self.schema).validate(value)
        value["errors"] = []
        self.assertTrue(
            list(jsonschema.Draft202012Validator(self.schema).iter_errors(value))
        )

    @unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema is optional")
    def test_failed_stage_vectors_validate_without_fabricated_evidence(
        self,
    ) -> None:
        validator = jsonschema.Draft202012Validator(self.schema)
        for value in (
            authorization_failure_evidence(),
            pre_acquisition_failure_evidence(),
            pre_broker_failure_evidence(),
            broker_failed_evidence(),
            cancellation_broker_failed_evidence(),
            complete_exchange_report_failure_evidence("1"),
            complete_exchange_report_failure_evidence("2"),
            complete_exchange_report_failure_evidence("3"),
            post_cleanup_snapshot_failure_evidence(),
            artifact_failure_evidence(),
            cancellation_cleanup_failure_evidence(),
            cancellation_artifact_failure_evidence(),
        ):
            with self.subTest(stage=value["evidence_stage"]):
                validator.validate(value)

    @unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema is optional")
    def test_failed_stage_boundaries_reject_fabricated_or_impossible_state(
        self,
    ) -> None:
        validator = jsonschema.Draft202012Validator(self.schema)

        broker_failed = broker_failed_evidence()
        broker_failed["broker"] = None
        self.assertFalse(validator.is_valid(broker_failed))
        broker_failed = broker_failed_evidence()
        broker_failed["broker"]["accepted_request_count"] = 1
        broker_failed["broker"]["completed_response_count"] = 2
        self.assertFalse(validator.is_valid(broker_failed))
        broker_failed = broker_failed_evidence()
        broker_failed["broker"]["accepted_request_count"] = 22
        broker_failed["broker"]["completed_response_count"] = 22
        broker_failed["broker"]["transcript_state"] = "partial_due_to_failure"
        self.assertFalse(validator.is_valid(broker_failed))
        broker_failed["broker"]["transcript_state"] = "complete"
        validator.validate(broker_failed)
        broker_failed["broker"]["completed_response_count"] = 21
        self.assertFalse(validator.is_valid(broker_failed))
        broker_failed["broker"]["transcript_state"] = "partial_due_to_failure"
        validator.validate(broker_failed)
        broker_failed["broker"]["completed_response_count"] = 20
        self.assertFalse(validator.is_valid(broker_failed))
        broker_failed["broker"]["transcript_state"] = "complete"
        self.assertFalse(validator.is_valid(broker_failed))
        broker_failed["broker"]["accepted_request_count"] = 21
        broker_failed["broker"]["completed_response_count"] = 21
        self.assertFalse(validator.is_valid(broker_failed))
        broker_failed["broker"]["accepted_request_count"] = 22
        broker_failed["broker"]["completed_response_count"] = 23
        self.assertFalse(validator.is_valid(broker_failed))

        complete_without_report = complete_exchange_report_failure_evidence()
        complete_without_report["broker"]["candidate_report_sha256"] = DIGEST
        self.assertFalse(validator.is_valid(complete_without_report))
        complete_without_report = complete_exchange_report_failure_evidence()
        complete_without_report["artifact"] = final_evidence()["artifact"]
        self.assertFalse(validator.is_valid(complete_without_report))
        complete_without_report = complete_exchange_report_failure_evidence()
        complete_without_report["snapshots"]["post_cleanup"] = final_evidence()[
            "snapshots"
        ]["post_cleanup"]
        self.assertFalse(validator.is_valid(complete_without_report))

        cancellation_complete = cancellation_broker_failed_evidence()
        cancellation_complete["broker"].update(
            {
                "accepted_request_count": 22,
                "completed_response_count": 22,
                "transcript_state": "complete",
            }
        )
        self.assertFalse(validator.is_valid(cancellation_complete))

        broker_failed = broker_failed_evidence()
        broker_failed["broker"]["accepted_request_count"] = 22
        broker_failed["broker"]["completed_response_count"] = 21
        validator.validate(broker_failed)

        for accepted, completed in ((5, 4), (4, 4), (22, 21)):
            broker_failed = cancellation_broker_failed_evidence()
            broker_failed["broker"]["accepted_request_count"] = accepted
            broker_failed["broker"]["completed_response_count"] = completed
            self.assertFalse(validator.is_valid(broker_failed))

        pre_broker = pre_broker_failure_evidence()
        pre_broker["staging"] = final_evidence()["staging"]
        self.assertFalse(validator.is_valid(pre_broker))
        pre_broker = pre_broker_failure_evidence()
        pre_broker["artifact"] = final_evidence()["artifact"]
        self.assertFalse(validator.is_valid(pre_broker))

        for original in (
            post_cleanup_snapshot_failure_evidence,
            artifact_failure_evidence,
        ):
            value = original()
            value["authorization"]["phase"] = "c"
            value["authorization"]["label"] = f"g1v1-{HEX1}-c"
            value["event"]["label_name"] = value["authorization"]["label"]
            self.assertFalse(validator.is_valid(value))

            value = original()
            value["cancellation"].update(
                {
                    "requested": True,
                    "ordinary": True,
                    "active_marker_sha256": DIGEST,
                }
            )
            self.assertFalse(validator.is_valid(value))

            for field in (
                "candidate_subtree_empty",
                "host_restored",
                "channel_closed",
            ):
                value = original()
                value["broker"][field] = False
                self.assertFalse(validator.is_valid(value))

        for original in (
            cancellation_cleanup_failure_evidence,
            cancellation_artifact_failure_evidence,
        ):
            value = original()
            value["cancellation"]["active_marker_sha256"] = None
            self.assertFalse(validator.is_valid(value))

            value = original()
            value["broker"]["host_restored"] = not value["cancellation"][
                "host_restored"
            ]
            self.assertFalse(validator.is_valid(value))

            value = original()
            value["broker"]["candidate_subtree_empty"] = not value[
                "cancellation"
            ]["candidate_subtree_empty"]
            self.assertFalse(validator.is_valid(value))

        for field in (
            "candidate_subtree_empty",
            "host_restored",
            "channel_closed",
        ):
            value = cancellation_artifact_failure_evidence()
            value["broker"][field] = False
            self.assertFalse(validator.is_valid(value))

    @unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema is optional")
    def test_failure_stages_close_cancellation_and_cleanup_state(self) -> None:
        validator = jsonschema.Draft202012Validator(self.schema)

        def normal_broker_failure(phase: str) -> dict:
            value = broker_failed_evidence()
            value["authorization"]["phase"] = phase
            value["authorization"]["label"] = f"g1v1-{HEX1}-{phase}"
            value["event"]["label_name"] = value["authorization"]["label"]
            return value

        cancellation_cases = (
            (
                authorization_failure_evidence(),
                (False, False, False, False, True, True),
            ),
            (
                pre_acquisition_failure_evidence(),
                (False, False, False, False, True, True),
            ),
            (
                pre_broker_failure_evidence(),
                (False, False, False, False, True, True),
            ),
            (
                normal_broker_failure("1"),
                (False, False, False, True, True, True),
            ),
            (
                normal_broker_failure("2"),
                (False, False, False, True, True, True),
            ),
            (
                normal_broker_failure("3"),
                (False, False, False, True, True, True),
            ),
            (
                cancellation_broker_failed_evidence(),
                (False, False, True, True, True, True),
            ),
        )
        cancellation_three_three = cancellation_broker_failed_evidence()
        cancellation_three_three["broker"].update(
            {
                "accepted_request_count": 3,
                "completed_response_count": 3,
            }
        )
        cancellation_cases += (
            (
                cancellation_three_three,
                (False, False, True, True, True, True),
            ),
        )

        for baseline, expected in cancellation_cases:
            for values in product((False, True), repeat=6):
                (
                    requested,
                    ordinary,
                    marker_present,
                    finalizer,
                    subtree,
                    host,
                ) = values
                value = copy.deepcopy(baseline)
                value["cancellation"].update(
                    {
                        "requested": requested,
                        "ordinary": ordinary,
                        "active_marker_sha256": DIGEST if marker_present else None,
                        "trusted_finalizer_complete": finalizer,
                        "candidate_subtree_empty": subtree,
                        "host_restored": host,
                    }
                )
                with self.subTest(
                    stage=value["evidence_stage"],
                    phase=value["authorization"]["phase"],
                    counts=(
                        None
                        if value["broker"] is None
                        else (
                            value["broker"]["accepted_request_count"],
                            value["broker"]["completed_response_count"],
                        )
                    ),
                    cancellation_values=values,
                ):
                    self.assertEqual(validator.is_valid(value), values == expected)

        marker_matrix = (
            (1, 0, (None,)),
            (1, 1, (None,)),
            (2, 1, (None,)),
            (2, 2, (None,)),
            (3, 2, (None, DIGEST)),
            (3, 3, (DIGEST,)),
            (4, 3, (DIGEST,)),
        )
        for accepted, completed, valid_markers in marker_matrix:
            for marker in (None, DIGEST):
                value = cancellation_broker_failed_evidence()
                value["broker"].update(
                    {
                        "accepted_request_count": accepted,
                        "completed_response_count": completed,
                    }
                )
                value["cancellation"]["active_marker_sha256"] = marker
                with self.subTest(
                    counts=(accepted, completed),
                    marker=marker,
                ):
                    self.assertEqual(
                        validator.is_valid(value),
                        marker in valid_markers,
                    )

        for factory in (
            broker_failed_evidence,
            cancellation_broker_failed_evidence,
        ):
            for field in (
                "candidate_subtree_empty",
                "host_restored",
                "channel_closed",
            ):
                value = factory()
                value["broker"][field] = False
                with self.subTest(factory=factory.__name__, broker_field=field):
                    self.assertFalse(validator.is_valid(value))

    @unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema is optional")
    def test_success_requires_consistent_finalizer_cleanup_state(self) -> None:
        validator = jsonschema.Draft202012Validator(self.schema)
        for field in ("candidate_subtree_empty", "host_restored"):
            value = final_evidence()
            value["cancellation"][field] = False
            self.assertFalse(validator.is_valid(value))

    @unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema is optional")
    def test_success_requires_complete_candidate_report_and_no_active_marker(
        self,
    ) -> None:
        validator = jsonschema.Draft202012Validator(self.schema)
        mutations = (
            lambda value: value.update(
                {"candidate_report_state": "absent_due_to_failure"}
            ),
            lambda value: value["broker"].update(
                {"candidate_report_sha256": None}
            ),
            lambda value: value["broker"].update({"accepted_request_count": 21}),
            lambda value: value["cancellation"].update(
                {"active_marker_sha256": "9" * 64}
            ),
        )
        for mutation in mutations:
            value = final_evidence()
            mutation(value)
            with self.subTest(mutation=mutation):
                self.assertTrue(list(validator.iter_errors(value)))

    @unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema is optional")
    def test_snapshot_name_and_unknown_fields_fail_closed(self) -> None:
        validator = jsonschema.Draft202012Validator(self.schema)
        mutations = (
            lambda value: value["snapshots"]["pre_broker"].update(
                {"name": "post_cleanup"}
            ),
            lambda value: value["event"].update({"delivery_guid": "invented"}),
            lambda value: value["candidate"]["paths"][0].update({"mode": "100755"}),
            lambda value: value["broker"]["isolation"].update(
                {"credentials_absent": False}
            ),
            lambda value: value["artifact"].update(
                {"constructed_after_post_cleanup_snapshot": False}
            ),
        )
        for mutation in mutations:
            value = final_evidence()
            mutation(value)
            with self.subTest(mutation=mutation):
                self.assertTrue(list(validator.iter_errors(value)))


class StaticCandidateBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = PROBE_PATH.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_candidate_has_no_process_or_privilege_modules(self) -> None:
        imported = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        self.assertTrue(
            {"subprocess", "ctypes", "resource", "fcntl", "signal", "tempfile"}
            .isdisjoint(imported)
        )

    def test_candidate_cannot_exec_fork_or_change_identity(self) -> None:
        forbidden = {
            "execv",
            "execve",
            "execvp",
            "execvpe",
            "fork",
            "forkpty",
            "kill",
            "posix_spawn",
            "posix_spawnp",
            "setgid",
            "setgroups",
            "setuid",
            "system",
        }
        called = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                function = node.func
                if isinstance(function, ast.Attribute):
                    called.add(function.attr)
                elif isinstance(function, ast.Name):
                    called.add(function.id)
        self.assertTrue(forbidden.isdisjoint(called), forbidden & called)

    def test_candidate_exposes_no_legacy_privileged_cli(self) -> None:
        for forbidden in (
            "argparse",
            '"supervisor"',
            '"finalize"',
            '"discover"',
            "systemctl",
            "systemd-run",
            "cgroup.kill",
            "core_pattern",
            "/usr/bin/sudo",
        ):
            self.assertNotIn(forbidden, self.source)

    def test_candidate_uses_fixed_descriptors_and_no_path_arguments(self) -> None:
        self.assertEqual(probe.CONTEXT_FD, 3)
        self.assertEqual(probe.PROTOCOL_FD, 4)
        with self.assertRaisesRegex(probe.CandidateError, "ARGUMENTS_FORBIDDEN"):
            probe.main(["--context", "/tmp/context"])


class StrictJsonTests(unittest.TestCase):
    def test_duplicate_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(probe.CandidateError, "JSON_DUPLICATE_KEY"):
            probe.strict_json_loads(b'{"x":1,"x":2}', limit=100)

    def test_float_nan_and_oversize_are_rejected(self) -> None:
        for payload in (b'{"x":1.0}', b'{"x":NaN}', b"{}"):
            with self.subTest(payload=payload):
                with self.assertRaises(probe.CandidateError):
                    probe.strict_json_loads(payload, limit=1)

    def test_canonical_json_is_ascii_sorted_and_stable(self) -> None:
        value = {"z": "\N{SNOWMAN}", "a": [1, True, None]}
        self.assertEqual(
            probe.canonical_json_bytes(value),
            b'{"a":[1,true,null],"z":"\\u2603"}',
        )

    def test_integer_outside_interoperable_range_is_rejected(self) -> None:
        with self.assertRaisesRegex(probe.CandidateError, "JSON_INTEGER_RANGE"):
            probe.strict_json_loads(b'{"x":9007199254740992}', limit=100)


class LabelAndContextTests(unittest.TestCase):
    def test_canonical_context_is_accepted(self) -> None:
        self.assertEqual(probe.validate_sealed_context(context()), context())

    def test_label_has_exact_git_sha1_grammar(self) -> None:
        self.assertEqual(probe.parse_label(LABEL), (HEX1, "1"))
        invalid = (
            f"g1v1-{'a' * 64}-1",
            f"g1v1-{HEX1}-pass-1",
            f"g1v1-{'a' * 40}-1".upper(),
            f"g1v1-{HEX1}-x",
            f"g1v1-{HEX1}-1 ",
            f"G1V1-{HEX1}-1",
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(probe.CandidateError):
                    probe.parse_label(value)

    def assert_context_rejected(self, mutation) -> None:
        value = context()
        mutation(value)
        with self.assertRaises(probe.CandidateError):
            probe.validate_sealed_context(value)

    def test_unknown_or_missing_fields_are_rejected_at_every_boundary(self) -> None:
        mutations = (
            lambda value: value.update({"extra": True}),
            lambda value: value["authorization"].pop("phase"),
            lambda value: value["candidate"].update({"extra": True}),
            lambda value: value["event"].update({"delivery_guid": "invented"}),
            lambda value: value["synthetic_merge"].update({"extra": None}),
            lambda value: value["replay"].update({"extra": False}),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_context_rejected(mutation)

    def test_authorization_event_workflow_and_attempt_mismatches_reject(self) -> None:
        mutations = (
            lambda value: value["authorization"].update({"phase": "2"}),
            lambda value: value["authorization"].update({"trusted_main_sha": HEX2}),
            lambda value: value["event"].update({"name": "pull_request"}),
            lambda value: value["event"].update({"action": "unlabeled"}),
            lambda value: value["event"].update({"label_name": "wrong"}),
            lambda value: value["event"].update({"actor_login": "attacker"}),
            lambda value: value["event"].update({"sender_id": 999}),
            lambda value: value["event"].update({"run_attempt": 2}),
            lambda value: value["workflow"].update({"github_ref": "refs/heads/dev"}),
            lambda value: value["workflow"].update({"github_workflow_sha": HEX2}),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_context_rejected(mutation)

    def test_fork_path_mode_and_repository_substitutions_reject(self) -> None:
        mutations = (
            lambda value: value["candidate"].update({"same_repository": False}),
            lambda value: value["candidate"].update({"no_fork": False}),
            lambda value: value["candidate"].update(
                {"head_repository": "attacker/fork"}
            ),
            lambda value: value["candidate"].update({"pr_number": 72}),
            lambda value: value["candidate"].update({"branch": "attacker"}),
            lambda value: value["candidate"]["paths"].reverse(),
            lambda value: value["candidate"]["paths"][0].update({"mode": "100755"}),
            lambda value: value["candidate"]["paths"][1].update(
                {"path": probe.OBSOLETE_SCHEMA_PATH}
            ),
            lambda value: value["control"].update({"repository_id": 999}),
            lambda value: value["control"].update({"issue_number": 71}),
            lambda value: value["control"].update({"issue_state": "closed"}),
            lambda value: value["control"].update({"issue_is_pull_request": True}),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_context_rejected(mutation)

    def test_synthetic_merge_is_all_null_or_complete(self) -> None:
        self.assert_context_rejected(
            lambda value: value["synthetic_merge"].update({"sha": HEX1})
        )
        value = context()
        value["synthetic_merge"] = {
            "sha": HEX1,
            "ordered_parents": [HEX1, HEX3],
            "tree_sha": HEX3,
            "algorithm": "git-merge-tree-write-tree-v1",
            "tool_version_sha256": "f" * 64,
            "normalization_sha256": "0" * 64,
            "construction_manifest_sha256": DIGEST,
            "conflict": False,
            "exact_tree_proof_sha256": DIGEST,
        }
        self.assertEqual(probe.validate_sealed_context(value), value)

    def test_conflicted_synthetic_merge_rejects_before_protocol(self) -> None:
        value = context()
        value["synthetic_merge"] = {
            "sha": HEX1,
            "ordered_parents": [HEX1, HEX3],
            "tree_sha": HEX3,
            "algorithm": "git-merge-tree-write-tree-v1",
            "tool_version_sha256": "f" * 64,
            "normalization_sha256": "0" * 64,
            "construction_manifest_sha256": DIGEST,
            "conflict": True,
            "exact_tree_proof_sha256": DIGEST,
        }
        protocol_read, protocol_write = os.pipe()
        try:
            with self.assertRaisesRegex(
                probe.CandidateError, "SYNTHETIC_MERGE_CONFLICT"
            ):
                probe.validate_sealed_context(value)
            os.set_blocking(protocol_read, False)
            with self.assertRaises(BlockingIOError):
                os.read(protocol_read, 1)
        finally:
            os.close(protocol_read)
            os.close(protocol_write)

    def test_synthetic_merge_algorithm_and_manifest_are_exact(self) -> None:
        value = context()
        value["synthetic_merge"] = {
            "sha": HEX1,
            "ordered_parents": [HEX1, HEX3],
            "tree_sha": HEX3,
            "algorithm": "git-merge-tree-write-tree-v1",
            "tool_version_sha256": "f" * 64,
            "normalization_sha256": "0" * 64,
            "construction_manifest_sha256": DIGEST,
            "conflict": False,
            "exact_tree_proof_sha256": DIGEST,
        }
        for mutation, error in (
            (
                lambda item: item.update({"algorithm": "ort"}),
                "SYNTHETIC_MERGE_ALGORITHM",
            ),
            (
                lambda item: item.update(
                    {"construction_manifest_sha256": "d" * 64}
                ),
                "SYNTHETIC_MERGE_MANIFEST",
            ),
            (
                lambda item: item.update(
                    {"ordered_parents": [HEX3, HEX1]}
                ),
                "SYNTHETIC_MERGE_PARENTS",
            ),
            (
                lambda item: item.update({"tool_version_sha256": "b" * 64}),
                "SYNTHETIC_MERGE_TOOL",
            ),
            (
                lambda item: item.update({"normalization_sha256": "c" * 64}),
                "SYNTHETIC_MERGE_NORMALIZATION",
            ),
        ):
            changed = copy.deepcopy(value)
            mutation(changed["synthetic_merge"])
            with self.subTest(error=error):
                with self.assertRaisesRegex(probe.CandidateError, error):
                    probe.validate_sealed_context(changed)

    def test_replay_overlap_current_run_and_current_phase_reject(self) -> None:
        mutations = (
            lambda value: value["replay"].update({"phase_consumed": True}),
            lambda value: value["replay"].update({"overlapping_run": True}),
            lambda value: value["replay"].update(
                {"prior_run_ids": [value["event"]["run_id"]]}
            ),
            lambda value: value["replay"].update(
                {"prior_phase_labels": [value["authorization"]["label"]]}
            ),
            lambda value: value["replay"].update({"prior_run_ids": [999]}),
            lambda value: value["staging"][0].update({"link_count": 2}),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_context_rejected(mutation)

    def test_prior_phase_and_run_sequences_are_exact(self) -> None:
        value = context()
        value["authorization"]["phase"] = "3"
        value["authorization"]["label"] = f"g1v1-{HEX1}-3"
        value["event"]["label_name"] = value["authorization"]["label"]
        value["replay"]["prior_phase_labels"] = [
            f"g1v1-{HEX1}-1",
            f"g1v1-{HEX1}-2",
        ]
        value["replay"]["prior_run_ids"] = [100, 101]
        self.assertEqual(probe.validate_sealed_context(value), value)
        value["replay"]["prior_phase_labels"].reverse()
        with self.assertRaisesRegex(probe.CandidateError, "REPLAY_PHASE_SEQUENCE"):
            probe.validate_sealed_context(value)

    def test_post_cleanup_snapshot_cannot_be_claimed_before_candidate(self) -> None:
        self.assert_context_rejected(
            lambda value: value["snapshots"].update(
                {"post_cleanup_sha256": "f" * 64}
            )
        )


class RuntimeIsolationTests(unittest.TestCase):
    def test_minimal_environment_is_required(self) -> None:
        probe.validate_environment(probe.ALLOWED_ENVIRONMENT)
        for name, value in (
            ("GITHUB_TOKEN", "secret"),
            ("GITHUB_OUTPUT", "/tmp/output"),
            ("ACTIONS_RUNTIME_TOKEN", "secret"),
            ("SSH_AUTH_SOCK", "/tmp/socket"),
            ("PYTHONPATH", "/tmp"),
            ("EXTRA", "value"),
        ):
            environment = dict(probe.ALLOWED_ENVIRONMENT)
            environment[name] = value
            with self.subTest(name=name):
                with self.assertRaises(probe.CandidateError):
                    probe.validate_environment(environment)

    def test_capabilities_namespaces_seccomp_and_groups_are_required(self) -> None:
        probe.validate_proc_status(status_text())
        mutations = (
            {"CapEff": "0000000000000001"},
            {"CapBnd": "0000000000000400"},
            {"NoNewPrivs": "0"},
            {"Seccomp": "0"},
            {"Groups": "100 101"},
            {"NSpid": "91000"},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(probe.CandidateError):
                    probe.validate_proc_status(status_text(**mutation))
        with self.assertRaisesRegex(probe.CandidateError, "PROC_STATUS_DUPLICATE"):
            probe.validate_proc_status(status_text() + "CapEff:\t0000000000000000\n")

    def test_only_fixed_context_protocol_and_capture_fds_are_allowed(self) -> None:
        valid = {
            0: "pipe:[1]",
            1: "pipe:[2]",
            2: "pipe:[3]",
            3: "pipe:[4]",
            4: "socket:[5]",
        }
        probe.validate_open_fds(valid)
        for mutation in (
            {**valid, 5: "socket:[6]"},
            {**valid, 3: "/tmp/context"},
            {**valid, 4: "pipe:[5]"},
            {**valid, 1: "/tmp/stdout"},
            {**valid, 0: "/tmp/stdin"},
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(probe.CandidateError):
                    probe.validate_open_fds(mutation)

    def test_root_execution_is_rejected_before_context_read(self) -> None:
        with mock.patch.object(os, "geteuid", return_value=0):
            with self.assertRaisesRegex(probe.CandidateError, "ROOT_EXECUTION"):
                probe.validate_runtime()


class ProtocolTests(unittest.TestCase):
    def test_operation_sequence_is_closed_and_phase_specific(self) -> None:
        normal = probe.operation_sequence("1", DIGEST)
        self.assertEqual(normal[0]["op"], "HELLO")
        self.assertEqual(normal[1]["op"], "PREFLIGHT")
        self.assertEqual(normal[-1]["op"], "FINISH")
        self.assertEqual(
            [item["case"] for item in normal if item["op"] == "RUN_CASE"],
            list(probe.NORMAL_CASES),
        )
        cancel = probe.operation_sequence("c", DIGEST)
        self.assertEqual(
            [(item["op"], item.get("case")) for item in cancel],
            [
                ("HELLO", None),
                ("PREFLIGHT", None),
                ("RUN_CASE", probe.CANCELLATION_CASE),
                ("WAIT_CANCELLATION", None),
            ],
        )
        for request in normal + cancel:
            self.assertTrue(
                set(request) in (
                    {"v", "seq", "op", "context_sha256"},
                    {"v", "seq", "op", "context_sha256", "case"},
                )
            )
            self.assertNotIn("path", request)
            self.assertNotIn("argv", request)
            self.assertNotIn("unit", request)
        with self.assertRaisesRegex(probe.CandidateError, "AUTHORIZATION_PHASE"):
            probe.operation_sequence("x", DIGEST)

    def test_response_rejects_unknown_replay_order_and_failure(self) -> None:
        request = probe.operation_sequence("1", DIGEST)[0]
        valid = {
            "v": probe.PROTOCOL_VERSION,
            "seq": 1,
            "op": "HELLO",
            "ok": True,
            "record_sha256": DIGEST,
        }
        self.assertEqual(probe.validate_response(valid, request), valid)
        mutations = (
            lambda value: value.update({"extra": True}),
            lambda value: value.update({"seq": 2}),
            lambda value: value.update({"seq": True}),
            lambda value: value.update({"op": "FINISH"}),
            lambda value: value.update({"ok": False}),
            lambda value: value.update({"record_sha256": "bad"}),
        )
        for mutation in mutations:
            value = dict(valid)
            mutation(value)
            with self.subTest(value=value):
                with self.assertRaises(probe.CandidateError):
                    probe.validate_response(value, request)

    def test_length_prefix_rejects_zero_and_oversize(self) -> None:
        for size in (0, probe.MAX_FRAME_BYTES + 1):
            read_fd, write_fd = os.pipe()
            try:
                os.write(write_fd, struct.pack(">I", size))
                with self.assertRaisesRegex(probe.CandidateError, "FRAME_LENGTH"):
                    probe.read_length_prefixed(
                        read_fd, maximum=probe.MAX_FRAME_BYTES
                    )
            finally:
                os.close(read_fd)
                os.close(write_fd)

    def test_end_to_end_client_uses_only_finite_protocol(self) -> None:
        value = context()
        payload = canonical_context(value)
        context_read, context_write = os.pipe()
        client_socket, broker_socket = socket.socketpair()
        output = io.BytesIO()
        requests = []
        errors = []

        def broker() -> None:
            try:
                for expected in probe.operation_sequence("1", probe.sha256_bytes(payload)):
                    request_payload = probe.read_length_prefixed(
                        broker_socket.fileno(), maximum=probe.MAX_FRAME_BYTES
                    )
                    request = probe.strict_json_loads(
                        request_payload, limit=probe.MAX_FRAME_BYTES
                    )
                    requests.append(request)
                    self.assertEqual(request, expected)
                    response = {
                        "v": probe.PROTOCOL_VERSION,
                        "seq": request["seq"],
                        "op": request["op"],
                        "ok": True,
                        "record_sha256": probe.sha256_bytes(request_payload),
                    }
                    probe.write_length_prefixed(
                        broker_socket.fileno(),
                        probe.canonical_json_bytes(response),
                        maximum=probe.MAX_FRAME_BYTES,
                    )
            except BaseException as exc:  # captured and asserted in parent
                errors.append(exc)
            finally:
                broker_socket.close()

        worker = threading.Thread(target=broker)
        worker.start()
        try:
            os.write(context_write, struct.pack(">I", len(payload)) + payload)
            os.close(context_write)
            report = probe.run_client(
                context_fd=context_read,
                protocol_fd=client_socket.fileno(),
                output=output,
                runtime={
                    "uid": 65534,
                    "gid": 65534,
                    "fd_targets_sha256": "6" * 64,
                    "environment_sha256": "7" * 64,
                },
            )
        finally:
            os.close(context_read)
            client_socket.close()
            worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(requests), 22)
        self.assertEqual(report["outcome"], "CANDIDATE_REPORT_COMPLETE")
        self.assertEqual(report["run_attempt"], 1)
        self.assertEqual(
            output.getvalue(), probe.canonical_json_bytes(report) + b"\n"
        )
        self.assertNotIn("SUCCESS", report.values())
        self.assertNotIn("APPROVE", output.getvalue().decode("ascii"))
        self.assertNotIn("GATE1_", output.getvalue().decode("ascii"))

    def test_complete_exchange_can_fail_before_candidate_report_bytes(self) -> None:
        class RejectingOutput:
            def write(self, payload: bytes) -> int:
                raise BrokenPipeError("candidate report output rejected")

            def flush(self) -> None:
                raise AssertionError("flush must not follow a rejected write")

        def reproduce(
            output: object,
            *,
            fail_report_build: bool,
        ) -> tuple[BaseException | None, list[dict], list[BaseException]]:
            value = context()
            payload = canonical_context(value)
            context_read, context_write = os.pipe()
            client_socket, broker_socket = socket.socketpair()
            requests: list[dict] = []
            errors: list[BaseException] = []

            def broker() -> None:
                try:
                    expected_operations = probe.operation_sequence(
                        "1", probe.sha256_bytes(payload)
                    )
                    for expected in expected_operations:
                        request_payload = probe.read_length_prefixed(
                            broker_socket.fileno(),
                            maximum=probe.MAX_FRAME_BYTES,
                        )
                        request = probe.strict_json_loads(
                            request_payload,
                            limit=probe.MAX_FRAME_BYTES,
                        )
                        self.assertEqual(request, expected)
                        requests.append(request)
                        response = {
                            "v": probe.PROTOCOL_VERSION,
                            "seq": request["seq"],
                            "op": request["op"],
                            "ok": True,
                            "record_sha256": probe.sha256_bytes(request_payload),
                        }
                        probe.write_length_prefixed(
                            broker_socket.fileno(),
                            probe.canonical_json_bytes(response),
                            maximum=probe.MAX_FRAME_BYTES,
                        )
                except BaseException as exc:  # captured and asserted in parent
                    errors.append(exc)
                finally:
                    broker_socket.close()

            worker = threading.Thread(target=broker)
            worker.start()
            caught = None
            try:
                os.write(context_write, struct.pack(">I", len(payload)) + payload)
                os.close(context_write)
                if fail_report_build:
                    with mock.patch.object(
                        probe,
                        "build_candidate_report",
                        side_effect=MemoryError("candidate report build failed"),
                    ):
                        probe.run_client(
                            context_fd=context_read,
                            protocol_fd=client_socket.fileno(),
                            output=output,
                            runtime={
                                "uid": 65534,
                                "gid": 65534,
                                "fd_targets_sha256": "6" * 64,
                                "environment_sha256": "7" * 64,
                            },
                        )
                else:
                    probe.run_client(
                        context_fd=context_read,
                        protocol_fd=client_socket.fileno(),
                        output=output,
                        runtime={
                            "uid": 65534,
                            "gid": 65534,
                            "fd_targets_sha256": "6" * 64,
                            "environment_sha256": "7" * 64,
                        },
                    )
            except BaseException as exc:
                caught = exc
            finally:
                os.close(context_read)
                client_socket.close()
                worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
            return caught, requests, errors

        output = io.BytesIO()
        caught, requests, errors = reproduce(output, fail_report_build=True)
        self.assertIsInstance(caught, MemoryError)
        self.assertEqual(errors, [])
        self.assertEqual(len(requests), 22)
        self.assertEqual(requests[-1]["op"], "FINISH")
        self.assertEqual(output.getvalue(), b"")

        caught, requests, errors = reproduce(
            RejectingOutput(),
            fail_report_build=False,
        )
        self.assertIsInstance(caught, BrokenPipeError)
        self.assertEqual(errors, [])
        self.assertEqual(len(requests), 22)
        self.assertEqual(requests[-1]["op"], "FINISH")

    def test_cancellation_closes_wait_without_candidate_report(self) -> None:
        value = context()
        value["authorization"]["phase"] = "c"
        value["authorization"]["label"] = f"g1v1-{HEX1}-c"
        value["event"]["label_name"] = value["authorization"]["label"]
        value["replay"]["prior_phase_labels"] = [
            f"g1v1-{HEX1}-1",
            f"g1v1-{HEX1}-2",
            f"g1v1-{HEX1}-3",
        ]
        value["replay"]["prior_run_ids"] = [100, 101, 102]
        payload = canonical_context(value)
        context_read, context_write = os.pipe()
        client_socket, broker_socket = socket.socketpair()
        output = io.BytesIO()
        requests = []
        errors = []

        def broker() -> None:
            try:
                expected_operations = probe.operation_sequence(
                    "c", probe.sha256_bytes(payload)
                )
                for expected in expected_operations:
                    request_payload = probe.read_length_prefixed(
                        broker_socket.fileno(), maximum=probe.MAX_FRAME_BYTES
                    )
                    request = probe.strict_json_loads(
                        request_payload, limit=probe.MAX_FRAME_BYTES
                    )
                    self.assertEqual(request, expected)
                    requests.append(request)
                    if request["op"] == "WAIT_CANCELLATION":
                        return
                    response = {
                        "v": probe.PROTOCOL_VERSION,
                        "seq": request["seq"],
                        "op": request["op"],
                        "ok": True,
                        "record_sha256": probe.sha256_bytes(request_payload),
                    }
                    probe.write_length_prefixed(
                        broker_socket.fileno(),
                        probe.canonical_json_bytes(response),
                        maximum=probe.MAX_FRAME_BYTES,
                    )
            except BaseException as exc:  # captured and asserted in parent
                errors.append(exc)
            finally:
                broker_socket.close()

        worker = threading.Thread(target=broker)
        worker.start()
        try:
            os.write(context_write, struct.pack(">I", len(payload)) + payload)
            os.close(context_write)
            with self.assertRaisesRegex(probe.CandidateError, "UNEXPECTED_EOF"):
                probe.run_client(
                    context_fd=context_read,
                    protocol_fd=client_socket.fileno(),
                    output=output,
                    runtime={
                        "uid": 65534,
                        "gid": 65534,
                        "fd_targets_sha256": "6" * 64,
                        "environment_sha256": "7" * 64,
                    },
                )
        finally:
            os.close(context_read)
            client_socket.close()
            worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(
            [request["op"] for request in requests],
            ["HELLO", "PREFLIGHT", "RUN_CASE", "WAIT_CANCELLATION"],
        )
        self.assertEqual(output.getvalue(), b"")

    def test_noncanonical_broker_response_is_rejected(self) -> None:
        value = context()
        payload = canonical_context(value)
        client_socket, broker_socket = socket.socketpair()

        def broker() -> None:
            request_payload = probe.read_length_prefixed(
                broker_socket.fileno(), maximum=probe.MAX_FRAME_BYTES
            )
            request = probe.strict_json_loads(
                request_payload, limit=probe.MAX_FRAME_BYTES
            )
            response = {
                "v": probe.PROTOCOL_VERSION,
                "seq": request["seq"],
                "op": request["op"],
                "ok": True,
                "record_sha256": DIGEST,
            }
            noncanonical = json.dumps(response, indent=2).encode("ascii")
            probe.write_length_prefixed(
                broker_socket.fileno(),
                noncanonical,
                maximum=probe.MAX_FRAME_BYTES,
            )
            broker_socket.close()

        worker = threading.Thread(target=broker)
        worker.start()
        try:
            with self.assertRaisesRegex(
                probe.CandidateError, "PROTOCOL_RESPONSE_NOT_CANONICAL"
            ):
                probe.exchange_protocol(client_socket.fileno(), value, payload)
        finally:
            client_socket.close()
            worker.join(timeout=5)

    def test_noncanonical_context_bytes_are_rejected(self) -> None:
        payload = json.dumps(context(), indent=2, sort_keys=True).encode("ascii")
        context_read, context_write = os.pipe()
        client_socket, broker_socket = socket.socketpair()
        try:
            os.write(context_write, struct.pack(">I", len(payload)) + payload)
            os.close(context_write)
            with self.assertRaisesRegex(
                probe.CandidateError, "SEALED_CONTEXT_NOT_CANONICAL"
            ):
                probe.run_client(
                    context_fd=context_read,
                    protocol_fd=client_socket.fileno(),
                    output=io.BytesIO(),
                    runtime={},
                )
        finally:
            os.close(context_read)
            client_socket.close()
            broker_socket.close()


if __name__ == "__main__":
    unittest.main()
