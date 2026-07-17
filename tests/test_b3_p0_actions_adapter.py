"""Deterministic tests for the Issue #29 P0 Actions adapter/check.

This suite is named `test_b3_*` on purpose: the immutable task's registered
required check (`repo.contracts.b3.tests`) discovers `tests/test_b3_*.py`, so
these tests run under the exact, workflow-controlled command whose process
exit code is the trusted AC-A1 evidence -- never an executor self-report or
an Actions job conclusion.

Coverage maps to the task's acceptance criteria:
  * AC-A1  the registered suite exits 0 (offline `run_suite` returns 0).
  * AC-A2  fixtures/p0/manifest.v1.json passes at rate 1.0 with every
           required positive/negative scenario present.
  * AC-A3  the accepted result declares the four required result artifacts
           with real (non-synthetic) hashes, and workflow-run-metadata
           carries the required provenance fields.
  * AC-A4  reviewer/executor lineage overlap fails closed; a new executor
           head invalidates a prior review.
  * AC-A5  the produced result/verification documents are schema-valid and
           the workflow enforces the required invariants and none of the
           forbidden capabilities.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from tools import p0_actions_adapter as adapter
from tools.p0_actions_adapter import (
    CODEX_LOCAL_BOOTSTRAP_ADAPTER,
    CODEX_EXECUTOR_ADAPTER,
    Decision,
    ISSUE_40_TASK_COMMIT,
    ISSUE_40_TASK_ID,
    PINNED_ADAPTER_ACTION,
    PINNED_CODEX_ACTION,
    PINNED_CODEX_CLI_VERSION,
    PINNED_CODEX_EFFORT,
    PINNED_CODEX_MODEL,
    PINNED_CODEX_PERMISSION_PROFILE,
    PINNED_CODEX_SAFETY_STRATEGY,
    PROVIDER_TRANSIENT_OUTPUT_PATH,
    VERIFIER_CHECK_CONTEXT,
    build_documents,
    changed_paths_within_scope,
    evaluate,
    is_verification_only,
    prohibited_transcript_tool_use,
    resolve_registered_check,
    resolve_workflow_executor_adapter,
    run_suite,
    transcript_tool_policy_failure,
    transcript_tool_use_names,
    validate_executor_adapter,
    validate_target_branch,
    validate_task_path,
    validate_task_ref,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "fixtures/p0/manifest.v1.json"
DOCUMENTS_DIR = REPO_ROOT / "fixtures/p0/documents"
WORKFLOW_PATH = REPO_ROOT / ".github/workflows/p0-actions-adapter.yml"
RESULT_SCHEMA_PATH = REPO_ROOT / "contracts/schemas/result.v1.schema.json"
VERIFICATION_SCHEMA_PATH = REPO_ROOT / "contracts/schemas/verification.v1.schema.json"
EXACT_ISSUE_40_TASK_SHA256 = "9bc65a850a53808d66042e726762d4ca15651c00196d8e11ed0fad7d3e04a286"
EXACT_ISSUE_40_TASK_B64 = "ewogICJzY2hlbWFfdmVyc2lvbiI6ICIxLjAuMCIsCiAgInRhc2tfaWQiOiAieXVyaWt1Y2h1bW92LXV4L2FpLW9wZXJhdGluZy1zeXN0ZW0jNDAiLAogICJyZXBvc2l0b3J5IjogInl1cmlrdWNodW1vdi11eC9haS1vcGVyYXRpbmctc3lzdGVtIiwKICAiaXNzdWVfbnVtYmVyIjogNDAsCiAgIm9iamVjdGl2ZSI6ICJCb290c3RyYXAgYSBzZWNvbmQgdHJ1dGhmdWwgYXV0aG9yIHBhdGggaW4gdGhlIGV4aXN0aW5nIFAwIEFjdGlvbnMgYWRhcHRlciBhZnRlciBTb25uZXQgZXhoYXVzdGVkIElzc3VlIDM5LiBTZWxlY3QgQ29kZXggb25seSB3aGVuIHRoZSBpbW11dGFibGUgdGFzayBkZWNsYXJlcyBleGVjdXRvci5hZGFwdGVyIG9wZW5haS1jb2RleC1hY3Rpb24uIFBpbiBvcGVuYWkvY29kZXgtYWN0aW9uIGF0IDUyZmUwMWVjNzBhNDJmNDU0YzlkMmViZDQ3NTk4ZjlmZDY4OTNkNTYsIG1vZGVsIGdwdC01LjMtY29kZXgsIGV4cGxpY2l0IGVmZm9ydCwgcGVybWlzc2lvbi1wcm9maWxlIDp3b3Jrc3BhY2UsIGFuZCBzYWZldHktc3RyYXRlZ3kgZHJvcC1zdWRvLiBLZWVwIHRoZSBleGVjdXRlIGpvYiByZWFkLW9ubHkgdG8gR2l0SHViIGFuZCBwcmVzZXJ2ZSBleGFjdC1iYXNlIGNoZWNrb3V0LCBzY29wZSBlbmZvcmNlbWVudCwgcmVnaXN0ZXJlZCBjaGVja3MsIGJpbmFyeSBwYXRjaCwgc2VwYXJhdGUgcHVibGlzaGVyLCBpbW11dGFibGUgZXZpZGVuY2UsIGluZGVwZW5kZW50IHJldmlldyBiaW5kaW5nIGFuZCBodW1hbiBtZXJnZS4gUmVjb3JkIHRydXRoZnVsIHJ1bi1ib3VuZCBDb2RleCBpZGVudGl0eSB3aXRob3V0IGludmVudGluZyBhIENsYXVkZSB0cmFuc2NyaXB0LiBQcmVzZXJ2ZSB0aGUgQ2xhdWRlIHBhdGggZm9yIHVucmVsYXRlZCB0YXNrcyBidXQgbmV2ZXIgcm91dGUgSXNzdWUgMzkgdG8gaXQgYWdhaW4uIEFkZCBkZXRlcm1pbmlzdGljIGZhbHNlLXN1Y2Nlc3MgYW5kIHNlY3VyaXR5IHJlZ3Jlc3Npb24gdGVzdHMuIERvIG5vdCBhZGQgYW4gb3JjaGVzdHJhdG9yIHNlcnZpY2UsIGRlcGxveW1lbnQsIHByb2R1Y3QgYmVoYXZpb3IsIG5ldyBzZWNyZXRzLCBhdXRvbWF0aWMgbWVyZ2UsIG9yIHBhdGhzIG91dHNpZGUgdGhlIGRlY2xhcmVkIHNjb3BlLiIsCiAgImNoYW5nZV9wb2xpY3kiOiB7CiAgICAiY2hhbmdlX3JlcXVpcmVkIjogdHJ1ZSwKICAgICJwb2xpY3lfZXhjZXB0aW9uX2lkIjogbnVsbCwKICAgICJub19jaGFuZ2UiOiB7CiAgICAgICJhbGxvd2VkIjogZmFsc2UsCiAgICAgICJyZWFzb25fY29kZXMiOiBbXSwKICAgICAgInJlcXVpcmVkX2V2aWRlbmNlX3R5cGVzIjogW10KICAgIH0KICB9LAogICJiYXNlX3JlZiI6ICJtYWluIiwKICAiYmFzZV9zaGEiOiAiNWMyOTU0NzJkMWM4MWU0ODg4OGZlNjRiYzFlMmM5MzI4YmJhMDNlOCIsCiAgImJyYW5jaCI6ICJhZ2VudC9pc3N1ZS00MC1jb2RleC1hY3Rpb25zLWJvb3RzdHJhcCIsCiAgImFsbG93ZWRfcGF0aHMiOiBbCiAgICAiLmdpdGh1Yi93b3JrZmxvd3MvcDAtYWN0aW9ucy1hZGFwdGVyLnltbCIsCiAgICAidG9vbHMvcDBfYWN0aW9uc19hZGFwdGVyLnB5IiwKICAgICJ0ZXN0cy90ZXN0X2IzX3AwX2FjdGlvbnNfYWRhcHRlci5weSIKICBdLAogICJkZW5pZWRfcGF0aHMiOiBbCiAgICAiLmFpL3Rhc2tzLyoqIiwKICAgICJBSV9PUy5tZCIsCiAgICAiUkVBRE1FLm1kIiwKICAgICJDSEFOR0VMT0cubWQiLAogICAgImNvbnRyYWN0cy8qKiIsCiAgICAiZG9jcy8qKiIsCiAgICAiZml4dHVyZXMvKioiLAogICAgInJlcXVpcmVtZW50cy0qLnR4dCIsCiAgICAic3RhbmRhcmRzLyoqIiwKICAgICJ0ZW1wbGF0ZXMvKioiLAogICAgInRlc3RzL3Rlc3RfYjBfY29udHJhY3RzLnB5IiwKICAgICJ0ZXN0cy90ZXN0X2IxX2ZpbmFsaXplci5weSIsCiAgICAidGVzdHMvdGVzdF9iMl92ZXJpZmllci5weSIsCiAgICAidGVzdHMvdGVzdF9iM190ZXJtaW5hbF9wcm9wYWdhdGlvbi5weSIsCiAgICAidG9vbHMvcHJvcGFnYXRlX2IzLnB5IgogIF0sCiAgInJpc2tfY2xhc3MiOiAiTDMiLAogICJleGVjdXRvciI6IHsKICAgICJhZGFwdGVyIjogIm9wZW5haS1jb2RleC1sb2NhbC1ib290c3RyYXAiLAogICAgInZlcnNpb24iOiAiY29kZXgtYXBwLTAxOWY1NWJhLTk4ZjUtNzBkMi04MzNkLTI4ZmE3NWNjNTY1OCIsCiAgICAibWF4X2F0dGVtcHRzIjogMywKICAgICJ0aW1lb3V0X3NlY29uZHMiOiAzNjAwCiAgfSwKICAiYWNjZXB0YW5jZV9jcml0ZXJpYSI6IFsKICAgIHsKICAgICAgImlkIjogIkFDLUNPREVYLTEiLAogICAgICAicHJlZGljYXRlX2lkIjogInByb2Nlc3MuZXhpdF9jb2RlLmVxdWFscyIsCiAgICAgICJwYXJhbWV0ZXJzIjogewogICAgICAgICJjb21wb25lbnQiOiAiaXNzdWUtNDAtY29kZXgtYWN0aW9ucy1hZGFwdGVyLXN1aXRlIiwKICAgICAgICAidmFsdWUiOiAwLAogICAgICAgICJ0cnVzdGVkX2V2aWRlbmNlX3NvdXJjZSI6ICJpbmRlcGVuZGVudF9wcm9jZXNzX2V4aXRfY29kZSIsCiAgICAgICAgImZvcmJpZGRlbl9zb3VyY2VzIjogWwogICAgICAgICAgImF1dGhvcl9zZWxmX3JlcG9ydCIsCiAgICAgICAgICAiYWN0aW9uc19qb2JfY29uY2x1c2lvbiIKICAgICAgICBdCiAgICAgIH0sCiAgICAgICJyZXF1aXJlZCI6IHRydWUsCiAgICAgICJsaW5rZWRfY2hlY2tzIjogWwogICAgICAgICJpc3N1ZS00MC1jb2RleC1hZGFwdGVyLXRlc3RzIgogICAgICBdCiAgICB9CiAgXSwKICAicmVxdWlyZWRfY2hlY2tzIjogWwogICAgewogICAgICAiaWQiOiAiaXNzdWUtNDAtY29kZXgtYWRhcHRlci10ZXN0cyIsCiAgICAgICJjb21tYW5kX2lkIjogInJlcG8uY29udHJhY3RzLmIzLnRlc3RzIiwKICAgICAgInJlcXVpcmVkIjogdHJ1ZSwKICAgICAgImV4cGVjdGVkX3Bvc3Rjb25kaXRpb25zIjogWwogICAgICAgIHsKICAgICAgICAgICJwcmVkaWNhdGVfaWQiOiAicHJvY2Vzcy5leGl0X2NvZGUuZXF1YWxzIiwKICAgICAgICAgICJwYXJhbWV0ZXJzIjogewogICAgICAgICAgICAidmFsdWUiOiAwCiAgICAgICAgICB9CiAgICAgICAgfQogICAgICBdCiAgICB9CiAgXSwKICAicmV2aWV3X3BvbGljeSI6IHsKICAgICJyZXZpZXdlcl9jbGFzcyI6ICJpbmRlcGVuZGVudC1lbmdpbmVlcmluZyIsCiAgICAicG9saWN5X2lkIjogInJldmlldy1pbmRlcGVuZGVuY2UudjEiLAogICAgImZvcmJpZGRlbl9saW5lYWdlX292ZXJsYXBzIjogWwogICAgICAiYWdlbnRfcnVudGltZV9pZCIsCiAgICAgICJjcmVkZW50aWFsX3ByaW5jaXBhbCIsCiAgICAgICJhdXRob3JlZF9jb21taXRzIgogICAgXSwKICAgICJtaW5pbXVtX2Rpc3RpbmN0X2h1bWFuX29wZXJhdG9ycyI6IDEKICB9LAogICJleHRlcm5hbF9zaWRlX2VmZmVjdHMiOiAib3duZXJfYXBwcm92ZWQiLAogICJjcmVhdGVkX2J5IjogImdpdGh1Yjp5dXJpa3VjaHVtb3YtdXgvY29kZXgtY29udHJvbC1wbGFuZSIsCiAgImNyZWF0ZWRfYXQiOiAiMjAyNi0wNy0xN1QwODozNjozOVoiCn0K"


def _load_exact_issue_40_task():
    """Offline byte-for-byte snapshot of immutable task commit 636748bb.

    The task lives on its control commit rather than the implementation
    branch, so the PR-triggered shallow checkout cannot git-show it. Keep the
    exact bytes and their SHA-256 here to make admission compatibility a
    deterministic, network-free regression rather than a source-token test.
    """
    raw = base64.b64decode(EXACT_ISSUE_40_TASK_B64)
    if hashlib.sha256(raw).hexdigest() != EXACT_ISSUE_40_TASK_SHA256:
        raise AssertionError("embedded Issue #40 task bytes do not match the immutable snapshot")
    return json.loads(raw)

# The original eight scenarios AC-A2 requires by name.
REQUIRED_SCENARIOS = {
    "reject-mutable-task-ref",
    "reject-invalid-task",
    "reject-base-sha-mismatch",
    "reject-target-branch-mismatch",
    "reject-missing-executor-evidence",
    "reject-self-review",
    "reject-post-review-head-change",
    "accept-bounded-executor-result",
    # Issue #32 correction: the four scenarios proving the live-canary
    # corrective fixes (AC-C2).
    "exclude-provider-transient-output",
    "prohibit-shell-tool-execution",
    "preserve-primary-scope-failure",
    "persist-observed-changed-paths-on-failure",
}

REQUIRED_RESULT_ARTIFACT_IDS = {
    "executor-transcript",
    "executor-manifest",
    "result-artifact",
    "verification-report",
    "workflow-run-metadata",
}

REQUIRED_PROVENANCE = {
    "workflow_run_id",
    "workflow_run_attempt",
    "execution_id",
    "subject_sha",
    "primary_terminal_reason",
    "observed_changed_paths",
    "task_commit",
}


def _tmp_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="p0-actions-test-"))


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _validator(path: Path) -> Draft202012Validator:
    return Draft202012Validator(_load(path), format_checker=FormatChecker())


class ManifestOracleTests(unittest.TestCase):
    """AC-A1 + AC-A2: the offline fixture suite is the deterministic oracle."""

    def test_suite_passes_at_rate_one(self) -> None:
        exit_code, report = run_suite(MANIFEST_PATH, workdir=_tmp_dir())
        self.assertEqual(0, exit_code)
        self.assertTrue(report["valid"])
        self.assertEqual(1.0, report["pass_rate"])
        self.assertFalse(report["authoritative_verifier"])
        self.assertEqual("P0", report["bootstrap_scope"])
        self.assertEqual(report["summary"]["failed"], 0)
        for fixture in report["fixtures"]:
            self.assertTrue(
                fixture["expectation_met"],
                "scenario {} did not match the oracle: {}".format(
                    fixture["id"], fixture["actual"]
                ),
            )

    def test_all_required_scenarios_present(self) -> None:
        manifest = _load(MANIFEST_PATH)
        ids = {fixture["id"] for fixture in manifest["fixtures"]}
        self.assertEqual(REQUIRED_SCENARIOS, ids)

    def test_positive_and_negative_scenarios_both_exist(self) -> None:
        manifest = _load(MANIFEST_PATH)
        accepted = [f for f in manifest["fixtures"] if f["expected"]["accepted"]]
        rejected = [f for f in manifest["fixtures"] if not f["expected"]["accepted"]]
        self.assertGreaterEqual(len(accepted), 1)
        self.assertGreaterEqual(len(rejected), 1)
        # Every rejection must fail the Check Run closed.
        for fixture in rejected:
            self.assertEqual("failure", fixture["expected"]["check_run_conclusion"])
        for fixture in accepted:
            self.assertEqual("success", fixture["expected"]["check_run_conclusion"])


class InputAdmissionTests(unittest.TestCase):
    """AC-A5 admission invariants: every workflow input is untrusted."""

    def test_task_ref_requires_full_lowercase_40_hex(self) -> None:
        self.assertIsNone(validate_task_ref("5033581665f759971f8a6c5875efd2be93c2b109"))
        self.assertEqual("mutable_task_ref", validate_task_ref("HEAD"))
        self.assertEqual("mutable_task_ref", validate_task_ref("main"))
        self.assertEqual("mutable_task_ref", validate_task_ref("5033581"))
        # Uppercase hex is rejected (must be canonical lowercase).
        self.assertEqual(
            "mutable_task_ref",
            validate_task_ref("5033581665F759971F8A6C5875EFD2BE93C2B109"),
        )
        self.assertEqual("mutable_task_ref", validate_task_ref(None))

    def test_task_path_allowlist_and_traversal_guard(self) -> None:
        self.assertIsNone(validate_task_path(".ai/tasks/20/issue-20-canary-task.v1.json"))
        self.assertEqual("task_path_not_allowlisted", validate_task_path("tools/evil.json"))
        self.assertEqual(
            "task_path_not_allowlisted",
            validate_task_path(".ai/tasks/../../etc/passwd.json"),
        )
        self.assertEqual(
            "task_path_not_allowlisted", validate_task_path("/ai/tasks/20/x.json")
        )
        self.assertEqual(
            "task_path_not_allowlisted", validate_task_path(".ai/tasks/20/x.yaml")
        )
        self.assertEqual("task_path_not_allowlisted", validate_task_path(None))

    def test_target_branch_must_be_agent_and_not_protected(self) -> None:
        self.assertIsNone(validate_target_branch("agent/issue-20-canary", "main"))
        self.assertEqual(
            "target_branch_mismatch", validate_target_branch("release/x", "main")
        )
        self.assertEqual("target_branch_protected", validate_target_branch("main", "main"))
        self.assertEqual(
            "target_branch_protected", validate_target_branch("master", "main")
        )
        # The repository's own default branch is protected even if it were
        # renamed away from main/master.
        self.assertEqual(
            "target_branch_protected",
            validate_target_branch("agent/trunk", "agent/trunk"),
        )

    def test_verification_only_mode_detection(self) -> None:
        self.assertTrue(is_verification_only("verify-only"))
        self.assertTrue(is_verification_only("verify_only"))
        self.assertFalse(is_verification_only("execute"))
        self.assertFalse(is_verification_only(None))


class ScopeTests(unittest.TestCase):
    def test_changed_paths_within_scope(self) -> None:
        allowed = ["src/canary/**"]
        denied = [".github/workflows/**", "contracts/schemas/**"]
        self.assertTrue(
            changed_paths_within_scope(["src/canary/hello.py"], allowed, denied)
        )
        self.assertFalse(
            changed_paths_within_scope(["tools/other.py"], allowed, denied)
        )
        self.assertFalse(
            changed_paths_within_scope(
                ["src/canary/x.py", ".github/workflows/p0.yml"], allowed, denied
            )
        )


class RegistryResolutionTests(unittest.TestCase):
    """The executor runs only registry-resolved argv, never interpolated
    task prose."""

    def test_resolves_registered_command(self) -> None:
        argv = resolve_registered_check("repo.contracts.b3.tests")
        self.assertEqual(
            ["python3", "-m", "unittest", "discover", "-s", "tests", "-p", "test_b3_*.py"],
            argv,
        )

    def test_p0_suite_command_is_registered(self) -> None:
        argv = resolve_registered_check("repo.p0.actions.suite")
        self.assertIn("tools/p0_actions_adapter.py", argv)

    def test_unregistered_command_fails_closed(self) -> None:
        with self.assertRaises(adapter.P0AdapterError):
            resolve_registered_check("repo.definitely.not.registered")
        # An arbitrary injected shell string is never a registered id.
        with self.assertRaises(adapter.P0AdapterError):
            resolve_registered_check("rm -rf / # not a registry id")


class ExecutionIdentityTests(unittest.TestCase):
    """AC-A3: a real session id is preserved; an executor id is never
    synthesized when the adapter claimed to run."""

    def test_real_session_preserved(self) -> None:
        signal = _load(DOCUMENTS_DIR / "executor-signal-accept.json")
        execution_id, source = adapter.resolve_execution_identity(signal)
        self.assertEqual(signal["execution_id"], execution_id)
        self.assertEqual("adapter_session", source)

    def test_missing_session_is_pipeline_derived_not_fabricated(self) -> None:
        signal = _load(DOCUMENTS_DIR / "executor-signal-missing-evidence.json")
        execution_id, source = adapter.resolve_execution_identity(signal)
        self.assertEqual("pipeline_derived", source)
        # Deterministic from real run facts, reproducible, and a valid uuid.
        import uuid as _uuid

        _uuid.UUID(execution_id)
        again, _ = adapter.resolve_execution_identity(signal)
        self.assertEqual(execution_id, again)

    def test_adapter_claimed_to_run_without_session_is_rejected(self) -> None:
        signal = _load(DOCUMENTS_DIR / "executor-signal-missing-evidence.json")
        self.assertEqual(
            "missing_executor_evidence", adapter.executor_evidence_failure(signal)
        )


class CodexActionEvidenceTests(unittest.TestCase):
    """Issue #40: Codex has truthful run-bound evidence, never a fabricated
    Claude session or transcript."""

    def _codex_case(self):
        task = _load(DOCUMENTS_DIR / "task-issue-20-canary.json")
        task["executor"]["adapter"] = CODEX_EXECUTOR_ADAPTER
        task["executor"]["version"] = PINNED_CODEX_CLI_VERSION
        signal = _load(DOCUMENTS_DIR / "executor-signal-accept.json")
        signal.update(
            {
                "adapter": CODEX_EXECUTOR_ADAPTER,
                "adapter_version": "codex-cli-{}".format(PINNED_CODEX_CLI_VERSION),
                "adapter_action": PINNED_CODEX_ACTION,
                "codex_cli_version": PINNED_CODEX_CLI_VERSION,
                "codex_model": PINNED_CODEX_MODEL,
                "codex_effort": PINNED_CODEX_EFFORT,
                "codex_permission_profile": PINNED_CODEX_PERMISSION_PROFILE,
                "codex_safety_strategy": PINNED_CODEX_SAFETY_STRATEGY,
                "execution_evidence_run_attempt": "1",
                "execution_file_content": None,
                "structured_output_raw": None,
                "transcript": None,
                "codex_final_message": "Implemented the bounded task.",
                "executor_identity": {
                    "operator_principal": "github:yurikuchumov-ux",
                    "agent_runtime_id": "openai-codex-action:run-9000000001",
                    "credential_principal": "openai:api-key:github-secret:OPENAI_API_KEY",
                    "delegation_parent": "issue-20-owner-decision",
                    "role": "author",
                },
            }
        )
        review = _load(DOCUMENTS_DIR / "review-accept.json")
        for overlap in review["eligibility"]["overlap_results"]:
            if overlap["field"] == "agent_runtime_id":
                overlap["author_values"] = [signal["executor_identity"]["agent_runtime_id"]]
            elif overlap["field"] == "credential_principal":
                overlap["author_values"] = [signal["executor_identity"]["credential_principal"]]
        inputs = {
            "task_commit": signal["executor_task_commit"],
            "task_path": signal["executor_task_path"],
            "target_branch": task["branch"],
            "default_branch": "main",
            "attempt": 1,
            "mode": "execute",
        }
        return inputs, task, signal, review

    def test_codex_run_is_accepted_without_claude_transcript(self) -> None:
        inputs, task, signal, review = self._codex_case()
        decision = evaluate(inputs, task, signal, review)
        self.assertTrue(decision.accepted, decision.failure_code)
        self.assertEqual("codex_action_run", decision.execution_id_source)
        import uuid as _uuid
        _uuid.UUID(decision.execution_id)

    def test_exact_issue_40_bootstrap_binding_resolves_to_codex_action(self) -> None:
        inputs, _, signal, review = self._codex_case()
        task = _load_exact_issue_40_task()
        self.assertEqual(ISSUE_40_TASK_ID, task["task_id"])
        self.assertEqual(CODEX_LOCAL_BOOTSTRAP_ADAPTER, task["executor"]["adapter"])
        signal["base_sha"] = task["base_sha"]
        signal["target_branch"] = task["branch"]
        signal["default_branch_head_before"] = task["base_sha"]
        signal["default_branch_head_after"] = task["base_sha"]
        signal["changed_files"] = ["tools/p0_actions_adapter.py"]
        signal["executor_task_commit"] = ISSUE_40_TASK_COMMIT
        signal["executor_task_path"] = ".ai/tasks/40/codex-actions-bootstrap-task.v1.json"
        inputs["task_commit"] = ISSUE_40_TASK_COMMIT
        inputs["task_path"] = signal["executor_task_path"]
        inputs["target_branch"] = task["branch"]
        review["task_id"] = ISSUE_40_TASK_ID
        review["eligibility"]["risk_class"] = "L3"

        self.assertIsNone(adapter.validate_task_document(task))
        self.assertIsNone(validate_executor_adapter(task))
        self.assertEqual(CODEX_EXECUTOR_ADAPTER, resolve_workflow_executor_adapter(task))
        decision = evaluate(inputs, task, signal, review)
        self.assertTrue(decision.accepted, decision.failure_code)

    def test_unknown_or_cross_issue_local_bootstrap_adapter_fails_closed(self) -> None:
        _, task, _, _ = self._codex_case()
        task["executor"]["adapter"] = "openai-codex-unknown"
        self.assertEqual("executor_adapter_unsupported", validate_executor_adapter(task))
        self.assertIsNone(resolve_workflow_executor_adapter(task))

        task["executor"]["adapter"] = CODEX_LOCAL_BOOTSTRAP_ADAPTER
        task["task_id"] = "yurikuchumov-ux/ai-operating-system#41"
        task["issue_number"] = 41
        self.assertEqual("executor_adapter_unsupported", validate_executor_adapter(task))
        self.assertIsNone(resolve_workflow_executor_adapter(task))

    def test_codex_policy_mismatch_fails_closed(self) -> None:
        inputs, task, signal, review = self._codex_case()
        signal["codex_safety_strategy"] = "unsafe"
        decision = evaluate(inputs, task, signal, review)
        self.assertFalse(decision.accepted)
        self.assertEqual("executor_adapter_mismatch", decision.failure_code)

    def test_manifest_executor_adapter_shape_uses_codex_policy(self) -> None:
        _, _, signal, _ = self._codex_case()
        manifest = dict(signal)
        manifest["executor_adapter"] = manifest.pop("adapter")
        self.assertIsNone(adapter.codex_action_evidence_failure(manifest))
        manifest["codex_model"] = "some-default-model"
        self.assertEqual(
            "executor_adapter_mismatch",
            adapter.codex_action_evidence_failure(manifest),
        )

    def test_codex_requires_positive_run_attempt_and_real_invocation(self) -> None:
        _, _, signal, _ = self._codex_case()
        signal["adapter_attempted"] = False
        self.assertEqual("missing_executor_evidence", adapter.executor_evidence_failure(signal))
        signal["adapter_attempted"] = True
        signal["execution_evidence_run_attempt"] = "0"
        self.assertEqual("missing_executor_evidence", adapter.executor_evidence_failure(signal))

    def test_task_and_signal_adapter_must_match(self) -> None:
        inputs, task, signal, review = self._codex_case()
        task["executor"]["adapter"] = "human-supervised-claude-code"
        decision = evaluate(inputs, task, signal, review)
        self.assertEqual("executor_adapter_mismatch", decision.failure_code)

    def test_issue_39_cannot_replay_a_fourth_claude_attempt(self) -> None:
        _, task, _, _ = self._codex_case()
        task["task_id"] = "yurikuchumov-ux/ai-operating-system#39"
        task["issue_number"] = 39
        task["executor"]["adapter"] = "human-supervised-claude-code"
        self.assertEqual("executor_attempts_exhausted", validate_executor_adapter(task))
        task["executor"]["adapter"] = CODEX_EXECUTOR_ADAPTER
        self.assertIsNone(validate_executor_adapter(task))


class TruthfulLiveSignalTests(unittest.TestCase):
    """Regression tests for the live false-success classes found after the
    first implementation commit."""

    def setUp(self) -> None:
        self.task = _load(DOCUMENTS_DIR / "task-issue-20-canary.json")
        self.signal = _load(DOCUMENTS_DIR / "executor-signal-accept.json")
        self.review = _load(DOCUMENTS_DIR / "review-accept.json")
        self.inputs = {
            "task_commit": "5033581665f759971f8a6c5875efd2be93c2b109",
            "task_path": ".ai/tasks/20/issue-20-canary-task.v1.json",
            "target_branch": "agent/issue-20-canary",
            "default_branch": "main",
            "attempt": 1,
            "mode": "execute",
            "execution_run_id": "9000000001",
        }

    def decide(self) -> Decision:
        return evaluate(self.inputs, self.task, self.signal, self.review)

    def test_real_observed_check_is_required(self) -> None:
        del self.signal["required_check"]
        self.assertEqual("required_check_missing", self.decide().failure_code)

    def test_nonzero_or_timed_out_check_fails_closed(self) -> None:
        self.signal["required_check"]["exit_code"] = 7
        self.assertEqual("required_check_failed", self.decide().failure_code)
        self.signal = _load(DOCUMENTS_DIR / "executor-signal-accept.json")
        self.signal["required_check"]["timed_out"] = True
        self.assertEqual("required_check_failed", self.decide().failure_code)

    def test_check_argv_and_subject_must_match_registry_and_head(self) -> None:
        self.signal["required_check"]["argv"] = ["sh", "-c", "true"]
        self.assertEqual("required_check_mismatch", self.decide().failure_code)
        self.signal = _load(DOCUMENTS_DIR / "executor-signal-accept.json")
        self.signal["required_check"]["subject_sha"] = "f" * 40
        self.assertEqual("required_check_mismatch", self.decide().failure_code)

    def test_adapter_outcome_and_transcript_are_terminal_evidence(self) -> None:
        self.signal["adapter_outcome"] = "failure"
        self.assertEqual("adapter_outcome_not_success", self.decide().failure_code)
        self.signal = _load(DOCUMENTS_DIR / "executor-signal-accept.json")
        self.signal["transcript"] = None
        self.assertEqual("missing_executor_transcript", self.decide().failure_code)

    def test_credential_separated_publication_must_be_proven(self) -> None:
        self.signal["publication_passed"] = False
        self.assertEqual("publication_not_verified", self.decide().failure_code)

    def test_executor_evidence_is_bound_to_task_and_verify_run(self) -> None:
        self.signal["executor_task_commit"] = "f" * 40
        self.assertEqual("execution_evidence_mismatch", self.decide().failure_code)
        self.signal = _load(DOCUMENTS_DIR / "executor-signal-accept.json")
        self.inputs["mode"] = "verify-only"
        self.inputs["execution_run_id"] = "123"
        self.assertEqual("execution_evidence_mismatch", self.decide().failure_code)

    def test_verification_only_still_checks_scope_and_nonempty_diff(self) -> None:
        self.inputs["mode"] = "verify-only"
        self.signal["changed_files"] = [".github/workflows/evil.yml"]
        self.assertEqual("changed_paths_not_allowed", self.decide().failure_code)
        self.signal = _load(DOCUMENTS_DIR / "executor-signal-accept.json")
        self.signal["changed_files"] = []
        self.signal["authored_commits"] = []
        self.assertEqual("empty_diff", self.decide().failure_code)

    def test_ref_history_and_exact_review_commit_are_required(self) -> None:
        self.signal["default_branch_head_after"] = "f" * 40
        self.assertEqual("ref_history_changed", self.decide().failure_code)
        self.signal = _load(DOCUMENTS_DIR / "executor-signal-accept.json")
        self.signal["review_attestation_commit"] = "main"
        self.assertEqual("review_binding_missing", self.decide().failure_code)

    def test_unsupported_acceptance_predicate_fails_closed(self) -> None:
        self.task["acceptance_criteria"][0]["predicate_id"] = "artifact.exists"
        self.assertEqual("unsupported_acceptance", self.decide().failure_code)

    def test_unsupported_required_check_postcondition_fails_closed(self) -> None:
        self.task["required_checks"][0]["expected_postconditions"][0]["parameters"]["value"] = 1
        self.assertEqual("unsupported_acceptance", self.decide().failure_code)

    def test_review_self_report_values_are_exactly_bound(self) -> None:
        self.review["eligibility"]["overlap_results"][0]["author_values"] = ["fabricated"]
        self.assertEqual("review_ineligible", self.decide().failure_code)

    def test_result_uses_observed_exit_and_log_evidence(self) -> None:
        decision = self.decide()
        docs = build_documents(
            decision,
            {
                "verification_id": "90000000-0000-4000-8000-0000000000bb",
                "evaluated_at": "2026-07-16T12:00:00Z",
                "verifier_identity": _load(DOCUMENTS_DIR / "verifier-identity.json"),
            },
            _tmp_dir(),
        )
        self.assertEqual(self.signal["required_check"]["exit_code"], docs["result"]["checks"][0]["exit_code"])
        self.assertEqual(["required-check-log"], docs["result"]["checks"][0]["evidence_artifact_ids"])
        self.assertIn("required-check-log", docs["artifact_ids"])


class AcceptedResultArtifactTests(unittest.TestCase):
    """AC-A3: the accepted result declares the four required artifacts with
    real hashes and full provenance."""

    def _accept_decision(self) -> Decision:
        task = _load(DOCUMENTS_DIR / "task-issue-20-canary.json")
        signal = _load(DOCUMENTS_DIR / "executor-signal-accept.json")
        # Issue #32 correction (AC-C3): the executor's own real manifest
        # bytes are a required, distinct evidence artifact. This is added
        # in-memory (never written back to the pinned fixture document, so
        # its sha256 stays exactly as recorded in the manifest) to prove
        # `build_documents` produces it whenever the trusted signal carries it.
        signal["executor_manifest_raw"] = json.dumps(
            {"adapter_outcome": "success", "postconditions_passed": True}, sort_keys=True
        )
        review = _load(DOCUMENTS_DIR / "review-accept.json")
        inputs = {
            "task_commit": "5033581665f759971f8a6c5875efd2be93c2b109",
            "task_path": ".ai/tasks/20/issue-20-canary-task.v1.json",
            "target_branch": "agent/issue-20-canary",
            "default_branch": "main",
            "attempt": 1,
            "mode": "execute",
        }
        return evaluate(inputs, task, signal, review)

    def test_required_artifacts_and_provenance(self) -> None:
        decision = self._accept_decision()
        self.assertTrue(decision.accepted)
        workdir = _tmp_dir()
        docs = build_documents(
            decision,
            {
                "verification_id": "90000000-0000-4000-8000-0000000000aa",
                "evaluated_at": "2026-07-16T12:00:00Z",
                "verifier_identity": _load(DOCUMENTS_DIR / "verifier-identity.json"),
            },
            workdir,
        )
        artifact_ids = {a["id"] for a in docs["result"]["artifacts"]}
        self.assertTrue(REQUIRED_RESULT_ARTIFACT_IDS.issubset(artifact_ids))
        self.assertTrue(REQUIRED_PROVENANCE.issubset(docs["metadata"].keys()))
        self.assertEqual(VERIFIER_CHECK_CONTEXT, docs["metadata"]["verifier_context"])
        # Every artifact hash is real: recompute it from the file on disk.
        for artifact in docs["result"]["artifacts"]:
            on_disk = adapter.sha256_file(workdir / artifact["path"])
            self.assertEqual(artifact["sha256"], on_disk)
            self.assertGreater(artifact["size_bytes"], 0)

    def test_check_run_conclusion_tracks_verification_only(self) -> None:
        decision = self._accept_decision()
        self.assertEqual("success", decision.check_run_conclusion)
        self.assertTrue(decision.accepted)


class ReviewIndependenceTests(unittest.TestCase):
    """AC-A4: independent review is bound to the exact subject SHA and must
    not overlap executor lineage; a new head invalidates the review."""

    def _evaluate(self, signal_name: str, review_name: str) -> Decision:
        task = _load(DOCUMENTS_DIR / "task-issue-20-canary.json")
        signal = _load(DOCUMENTS_DIR / signal_name)
        review = _load(DOCUMENTS_DIR / review_name)
        inputs = {
            "task_commit": "5033581665f759971f8a6c5875efd2be93c2b109",
            "task_path": ".ai/tasks/20/issue-20-canary-task.v1.json",
            "target_branch": "agent/issue-20-canary",
            "default_branch": "main",
            "attempt": 1,
            "mode": "execute",
        }
        return evaluate(inputs, task, signal, review)

    def test_self_lineage_review_fails_closed(self) -> None:
        decision = self._evaluate("executor-signal-accept.json", "review-self.json")
        self.assertFalse(decision.accepted)
        self.assertEqual("self_review", decision.failure_code)

    def test_new_head_invalidates_prior_review(self) -> None:
        decision = self._evaluate("executor-signal-new-head.json", "review-accept.json")
        self.assertFalse(decision.accepted)
        self.assertEqual("post_review_head_change", decision.failure_code)

    def test_missing_review_fails_closed(self) -> None:
        task = _load(DOCUMENTS_DIR / "task-issue-20-canary.json")
        signal = _load(DOCUMENTS_DIR / "executor-signal-accept.json")
        inputs = {
            "task_commit": "5033581665f759971f8a6c5875efd2be93c2b109",
            "task_path": ".ai/tasks/20/issue-20-canary-task.v1.json",
            "target_branch": "agent/issue-20-canary",
            "default_branch": "main",
            "attempt": 1,
            "mode": "execute",
        }
        decision = evaluate(inputs, task, signal, None)
        self.assertFalse(decision.accepted)
        self.assertEqual("reviewer_unavailable", decision.failure_code)
        self.assertEqual("blocked", decision.status)


class TranscriptToolUseTests(unittest.TestCase):
    """Issue #32 correction: the trusted transcript's own structural
    `tool_use.name` fields are independently re-verified against the
    edit-only allowlist -- never the provider's own claimed success."""

    def _events(self, *names: str, session_id: str = "70000000-0000-4000-8000-000000000001") -> str:
        events = [
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {"type": "tool_use", "id": "toolu_{}".format(i), "name": name, "input": {}}
                    ]
                },
            }
            for i, name in enumerate(names)
        ]
        events.append({"type": "result", "session_id": session_id})
        return json.dumps(events)

    def test_only_edit_only_tool_use_is_accepted(self) -> None:
        content = self._events("Read", "Edit", "Glob", "Grep", "Write")
        self.assertEqual(["Read", "Edit", "Glob", "Grep", "Write"], transcript_tool_use_names(content))
        self.assertIsNone(prohibited_transcript_tool_use(content))

    def test_bash_tool_use_is_rejected(self) -> None:
        content = self._events("Read", "Bash")
        self.assertEqual("Bash", prohibited_transcript_tool_use(content))

    def test_any_non_allowlisted_tool_is_rejected(self) -> None:
        for name in ("Bash", "WebFetch", "WebSearch", "Task", "NotebookEdit"):
            content = self._events(name)
            self.assertEqual(name, prohibited_transcript_tool_use(content))

    def test_missing_or_unparsable_transcript_is_not_coerced_into_a_violation(self) -> None:
        self.assertIsNone(prohibited_transcript_tool_use(None))
        self.assertIsNone(prohibited_transcript_tool_use(""))
        self.assertIsNone(prohibited_transcript_tool_use("{not json"))
        self.assertIsNone(prohibited_transcript_tool_use(json.dumps({"type": "result"})))

    def test_oversized_transcript_is_rejected_never_scanned(self) -> None:
        huge = self._events("Bash") + ("x" * (2 * 1024 * 1024))
        self.assertIsNone(transcript_tool_use_names(huge))
        self.assertIsNone(prohibited_transcript_tool_use(huge))

    def test_empty_array_is_unscannable_not_a_clean_scan(self) -> None:
        # A structurally valid but empty event array provides no positive
        # evidence that only allowed tools ran -- it must not be treated the
        # same as "scanned clean, zero tool_use found".
        self.assertIsNone(transcript_tool_use_names("[]"))
        self.assertIsNone(prohibited_transcript_tool_use("[]"))

    def test_non_empty_array_with_no_tool_use_events_is_scannable_and_clean(self) -> None:
        content = json.dumps([{"type": "result", "session_id": "70000000-0000-4000-8000-000000000001"}])
        self.assertEqual([], transcript_tool_use_names(content))
        self.assertIsNone(prohibited_transcript_tool_use(content))

    def test_event_count_over_the_bound_is_unscannable_not_a_truncated_scan(self) -> None:
        """Pass-3 correction: the whole admitted transcript must be
        examined. A transcript whose event count exceeds
        `_MAX_TRANSCRIPT_EVENTS_SCANNED`, with a real `Bash` call placed
        just past the old scan prefix, must never be silently truncated and
        treated as clean -- it must fail closed as unscannable."""
        bound = adapter._MAX_TRANSCRIPT_EVENTS_SCANNED
        events = [
            {
                "type": "assistant",
                "message": {"content": [{"type": "tool_use", "id": "toolu_pad", "name": "Read", "input": {}}]},
            }
            for _ in range(bound)
        ]
        events.append(
            {
                "type": "assistant",
                "message": {"content": [{"type": "tool_use", "id": "toolu_over", "name": "Bash", "input": {}}]},
            }
        )
        content = json.dumps(events)
        self.assertEqual(bound + 1, len(json.loads(content)))
        self.assertLess(len(content.encode("utf-8")), adapter.MAX_TRANSCRIPT_BYTES)
        self.assertIsNone(transcript_tool_use_names(content))
        self.assertIsNone(prohibited_transcript_tool_use(content))
        self.assertEqual("unscannable_executor_transcript", transcript_tool_policy_failure(content))

    def test_event_count_exactly_at_the_bound_is_still_fully_scanned(self) -> None:
        """Clean control: an event count exactly at the bound (not over it)
        is still scanned in full, including a violation in its final event."""
        bound = adapter._MAX_TRANSCRIPT_EVENTS_SCANNED
        events = [
            {
                "type": "assistant",
                "message": {"content": [{"type": "tool_use", "id": "toolu_pad", "name": "Read", "input": {}}]},
            }
            for _ in range(bound - 1)
        ]
        events.append(
            {
                "type": "assistant",
                "message": {"content": [{"type": "tool_use", "id": "toolu_last", "name": "Bash", "input": {}}]},
            }
        )
        content = json.dumps(events)
        self.assertEqual(bound, len(json.loads(content)))
        names = transcript_tool_use_names(content)
        self.assertIsNotNone(names)
        self.assertEqual("Bash", names[-1])
        self.assertEqual("Bash", prohibited_transcript_tool_use(content))

    def test_non_object_top_level_events_fail_closed(self) -> None:
        """Pass-3 correction: `[null]` and `[1]` are structurally valid JSON
        arrays but their events cannot be safely interpreted -- they must
        never be coerced into "no tool_use observed"."""
        for content in ("[null]", "[1]", json.dumps([None, {"type": "result"}]), json.dumps(["not-an-object"])):
            self.assertIsNone(transcript_tool_use_names(content), content)
            self.assertIsNone(prohibited_transcript_tool_use(content), content)
            self.assertEqual("unscannable_executor_transcript", transcript_tool_policy_failure(content), content)

    def test_tool_use_with_absent_non_string_or_empty_name_fails_closed(self) -> None:
        """Pass-3 correction: a real `tool_use` content block whose `name`
        cannot be safely identified (missing, non-string, or empty) must
        never be silently skipped -- an unidentifiable tool invocation is
        never treated as if it were absent."""
        bad_names = [
            {},  # name entirely absent
            {"name": 123},  # non-string
            {"name": ""},  # empty string
            {"name": None},  # explicit null
        ]
        for extra in bad_names:
            item = {"type": "tool_use", "id": "toolu_bad"}
            item.update(extra)
            content = json.dumps(
                [
                    {"type": "assistant", "message": {"content": [item]}},
                    {"type": "result", "session_id": "70000000-0000-4000-8000-000000000001"},
                ]
            )
            self.assertIsNone(transcript_tool_use_names(content), content)
            self.assertIsNone(prohibited_transcript_tool_use(content), content)
            self.assertEqual(
                "unscannable_executor_transcript", transcript_tool_policy_failure(content), content
            )

    def test_legitimate_non_tool_content_blocks_are_preserved(self) -> None:
        """Control: ordinary non-`tool_use` content blocks (e.g. `text`) and
        events with no `message`/`content` at all remain legitimate and do
        not trip the new structural checks."""
        content = json.dumps(
            [
                {"type": "assistant", "message": {"content": [{"type": "text", "text": "thinking..."}]}},
                {"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "toolu_1", "name": "Read", "input": {}}]}},
                {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": "ok", "is_error": False}]}},
                {"type": "result", "session_id": "70000000-0000-4000-8000-000000000001"},
            ]
        )
        self.assertEqual(["Read"], transcript_tool_use_names(content))
        self.assertIsNone(prohibited_transcript_tool_use(content))
        self.assertIsNone(transcript_tool_policy_failure(content))

    def test_evaluate_rejects_a_real_bash_call_even_when_every_other_signal_claims_success(self) -> None:
        task = _load(DOCUMENTS_DIR / "task-issue-20-canary.json")
        signal = _load(DOCUMENTS_DIR / "executor-signal-accept.json")
        review = _load(DOCUMENTS_DIR / "review-accept.json")
        signal["execution_file_content"] = self._events("Read", "Bash")
        inputs = {
            "task_commit": "5033581665f759971f8a6c5875efd2be93c2b109",
            "task_path": ".ai/tasks/20/issue-20-canary-task.v1.json",
            "target_branch": "agent/issue-20-canary",
            "default_branch": "main",
            "attempt": 1,
            "mode": "execute",
        }
        decision = evaluate(inputs, task, signal, review)
        self.assertFalse(decision.accepted)
        self.assertEqual("prohibited_tool_use", decision.failure_code)
        self.assertEqual("scope_violation", decision.terminal_reason)
        self.assertEqual("failure", decision.check_run_conclusion)


class MandatoryTranscriptScannabilityTests(unittest.TestCase):
    """Regression coverage for the independently-verified false-success
    class: `evaluate()` must never accept a run merely because
    `structured_output_raw` resolves a real session id -- the trusted
    structural transcript (`execution_file_content`) must itself be present,
    size-bounded, and a genuinely scannable non-empty JSON event array.
    Reproduces, against the otherwise-fully-valid accept signal, the exact
    four false-success cases independent verification found:
      1. the original non-array execution-file object;
      2. invalid JSON execution file plus a structured-output session id;
      3. missing execution file plus a structured-output session id;
      4. an empty array plus a structured-output session id.
    """

    VALID_STRUCTURED_OUTPUT = json.dumps(
        {"type": "result", "session_id": "80000000-0000-4000-8000-000000000099"}
    )

    def _otherwise_success_signal(self):
        return _load(DOCUMENTS_DIR / "executor-signal-accept.json")

    def _inputs(self):
        return {
            "task_commit": "5033581665f759971f8a6c5875efd2be93c2b109",
            "task_path": ".ai/tasks/20/issue-20-canary-task.v1.json",
            "target_branch": "agent/issue-20-canary",
            "default_branch": "main",
            "attempt": 1,
            "mode": "execute",
        }

    def _decide(self, signal):
        task = _load(DOCUMENTS_DIR / "task-issue-20-canary.json")
        review = _load(DOCUMENTS_DIR / "review-accept.json")
        return evaluate(self._inputs(), task, signal, review)

    def test_baseline_otherwise_success_signal_is_accepted(self) -> None:
        """Control: the unmodified, now-genuinely-scannable accept signal is
        still accepted -- proving the fix does not over-reject valid runs."""
        decision = self._decide(self._otherwise_success_signal())
        self.assertTrue(decision.accepted)
        self.assertIsNone(decision.failure_code)

    def test_original_non_array_execution_file_object_is_rejected(self) -> None:
        signal = self._otherwise_success_signal()
        signal["execution_file_content"] = json.dumps(
            {"type": "result", "session_id": "70000000-0000-4000-8000-000000000001"}
        )
        decision = self._decide(signal)
        self.assertFalse(decision.accepted)
        self.assertEqual("unscannable_executor_transcript", decision.failure_code)
        self.assertEqual("missing_artifact", decision.terminal_reason)
        self.assertEqual("failure", decision.check_run_conclusion)

    def test_invalid_json_execution_file_with_structured_output_session_is_rejected(self) -> None:
        signal = self._otherwise_success_signal()
        signal["execution_file_content"] = "{not valid json"
        signal["structured_output_raw"] = self.VALID_STRUCTURED_OUTPUT
        # Identity resolution still succeeds from structured_output_raw ...
        execution_id, source = adapter.resolve_execution_identity(signal)
        self.assertEqual("80000000-0000-4000-8000-000000000099", execution_id)
        self.assertEqual("adapter_session", source)
        # ... but that must never substitute for transcript tool-policy proof.
        decision = self._decide(signal)
        self.assertFalse(decision.accepted)
        self.assertEqual("unscannable_executor_transcript", decision.failure_code)

    def test_missing_execution_file_with_structured_output_session_is_rejected(self) -> None:
        signal = self._otherwise_success_signal()
        signal["execution_file_content"] = None
        signal["structured_output_raw"] = self.VALID_STRUCTURED_OUTPUT
        execution_id, source = adapter.resolve_execution_identity(signal)
        self.assertEqual("80000000-0000-4000-8000-000000000099", execution_id)
        self.assertEqual("adapter_session", source)
        decision = self._decide(signal)
        self.assertFalse(decision.accepted)
        self.assertEqual("unscannable_executor_transcript", decision.failure_code)

    def test_empty_array_execution_file_with_structured_output_session_is_rejected(self) -> None:
        signal = self._otherwise_success_signal()
        signal["execution_file_content"] = "[]"
        signal["structured_output_raw"] = self.VALID_STRUCTURED_OUTPUT
        execution_id, source = adapter.resolve_execution_identity(signal)
        self.assertEqual("80000000-0000-4000-8000-000000000099", execution_id)
        self.assertEqual("adapter_session", source)
        decision = self._decide(signal)
        self.assertFalse(decision.accepted)
        self.assertEqual("unscannable_executor_transcript", decision.failure_code)

    def test_valid_edit_only_event_array_passes_and_prohibited_tool_still_fails(self) -> None:
        clean = self._otherwise_success_signal()
        self.assertIsNone(transcript_tool_policy_failure(clean["execution_file_content"]))
        self.assertTrue(self._decide(clean).accepted)

        dirty = self._otherwise_success_signal()
        dirty["execution_file_content"] = json.dumps(
            [
                {
                    "type": "assistant",
                    "message": {
                        "content": [
                            {"type": "tool_use", "id": "toolu_x", "name": "Bash", "input": {}}
                        ]
                    },
                },
                {"type": "result", "session_id": "70000000-0000-4000-8000-000000000001"},
            ]
        )
        self.assertEqual("prohibited_tool_use", transcript_tool_policy_failure(dirty["execution_file_content"]))
        decision = self._decide(dirty)
        self.assertFalse(decision.accepted)
        self.assertEqual("prohibited_tool_use", decision.failure_code)

    def test_2001st_event_bash_bypass_is_rejected(self) -> None:
        """Pass-3 correction: an otherwise-success signal whose transcript
        has more events than `_MAX_TRANSCRIPT_EVENTS_SCANNED`, with a real
        `Bash` call placed past the old scan prefix, must be rejected as
        unscannable rather than silently accepted from a truncated scan."""
        bound = adapter._MAX_TRANSCRIPT_EVENTS_SCANNED
        events = [
            {
                "type": "assistant",
                "message": {"content": [{"type": "tool_use", "id": "toolu_pad", "name": "Read", "input": {}}]},
            }
            for _ in range(bound)
        ]
        events.append(
            {
                "type": "assistant",
                "message": {"content": [{"type": "tool_use", "id": "toolu_over", "name": "Bash", "input": {}}]},
            }
        )
        # A trailing result event carries the real session id so that
        # identity resolution succeeds independently of the tool-policy scan
        # -- proving the rejection below comes from the transcript check,
        # not from an unrelated missing-session-evidence failure.
        events.append({"type": "result", "session_id": "70000000-0000-4000-8000-000000000001"})
        signal = self._otherwise_success_signal()
        signal["execution_file_content"] = json.dumps(events)
        signal["structured_output_raw"] = json.dumps(
            {"type": "result", "session_id": "70000000-0000-4000-8000-000000000001"}
        )
        self.assertLess(len(signal["execution_file_content"].encode("utf-8")), adapter.MAX_TRANSCRIPT_BYTES)
        execution_id, source = adapter.resolve_execution_identity(signal)
        self.assertEqual("70000000-0000-4000-8000-000000000001", execution_id)
        self.assertEqual("adapter_session", source)
        decision = self._decide(signal)
        self.assertFalse(decision.accepted)
        self.assertEqual("unscannable_executor_transcript", decision.failure_code)
        self.assertEqual("missing_artifact", decision.terminal_reason)
        self.assertEqual("failure", decision.check_run_conclusion)

    def test_malformed_structural_events_are_rejected(self) -> None:
        """Pass-3 correction: `[null]`, `[1]`, and a `tool_use` block with a
        non-string `name` must never be accepted merely because
        `structured_output_raw` resolves a real session id."""
        for execution_file_content in (
            "[null]",
            "[1]",
            json.dumps(
                [
                    {
                        "type": "assistant",
                        "message": {
                            "content": [{"type": "tool_use", "id": "toolu_bad", "name": 123, "input": {}}]
                        },
                    }
                ]
            ),
        ):
            signal = self._otherwise_success_signal()
            signal["execution_file_content"] = execution_file_content
            signal["structured_output_raw"] = self.VALID_STRUCTURED_OUTPUT
            execution_id, source = adapter.resolve_execution_identity(signal)
            self.assertEqual("80000000-0000-4000-8000-000000000099", execution_id, execution_file_content)
            self.assertEqual("adapter_session", source, execution_file_content)
            decision = self._decide(signal)
            self.assertFalse(decision.accepted, execution_file_content)
            self.assertEqual(
                "unscannable_executor_transcript", decision.failure_code, execution_file_content
            )
            self.assertEqual("failure", decision.check_run_conclusion, execution_file_content)


class ProviderTransientIsolationTests(unittest.TestCase):
    """Issue #32 correction: the provider's own known transient
    (`output.txt`) must already be isolated upstream of `evaluate()`; its
    presence in the observed changed-file set is always treated as a scope
    violation here, never silently exempted -- so a task-created file
    smuggled at that exact path can never escape scope enforcement."""

    def _decide(self, changed_files):
        task = _load(DOCUMENTS_DIR / "task-issue-20-canary.json")
        signal = _load(DOCUMENTS_DIR / "executor-signal-accept.json")
        review = _load(DOCUMENTS_DIR / "review-accept.json")
        signal["changed_files"] = changed_files
        inputs = {
            "task_commit": "5033581665f759971f8a6c5875efd2be93c2b109",
            "task_path": ".ai/tasks/20/issue-20-canary-task.v1.json",
            "target_branch": "agent/issue-20-canary",
            "default_branch": "main",
            "attempt": 1,
            "mode": "execute",
        }
        return evaluate(inputs, task, signal, review)

    def test_clean_observed_changed_files_are_accepted(self) -> None:
        decision = self._decide(["src/canary/hello.py"])
        self.assertTrue(decision.accepted)

    def test_provider_transient_present_in_observed_changed_files_is_rejected(self) -> None:
        decision = self._decide([PROVIDER_TRANSIENT_OUTPUT_PATH, "src/canary/hello.py"])
        self.assertFalse(decision.accepted)
        self.assertEqual("changed_paths_not_allowed", decision.failure_code)
        self.assertEqual("scope_violation", decision.terminal_reason)

    def test_task_created_arbitrary_output_outside_allowed_paths_is_never_exempted(self) -> None:
        """The isolation is narrow: a real out-of-scope path that is *not*
        the exact provider transient is rejected exactly as before."""
        decision = self._decide(["not-allowed/arbitrary.txt"])
        self.assertFalse(decision.accepted)
        self.assertEqual("changed_paths_not_allowed", decision.failure_code)


class ExecutorManifestPrimaryFailurePrecedenceTests(unittest.TestCase):
    """Issue #32 correction: the executor manifest's own earliest recorded
    terminal failure takes precedence over every downstream check that
    assumes execution/publication proceeded, and neither the target branch
    nor an independent review is required to reach that decision."""

    def _base_signal(self):
        signal = _load(DOCUMENTS_DIR / "executor-signal-accept.json")
        signal["publication_passed"] = False
        signal["target_branch_head"] = None
        signal["default_branch_head_before"] = None
        signal["default_branch_head_after"] = None
        signal["executor_manifest_primary_failure"] = "changed_paths_not_allowed"
        return signal

    def _inputs(self):
        return {
            "task_commit": "5033581665f759971f8a6c5875efd2be93c2b109",
            "task_path": ".ai/tasks/20/issue-20-canary-task.v1.json",
            "target_branch": "agent/issue-20-canary",
            "default_branch": "main",
            "attempt": 1,
            "mode": "execute",
        }

    def test_primary_failure_wins_over_absent_target_branch_and_missing_review(self) -> None:
        task = _load(DOCUMENTS_DIR / "task-issue-20-canary.json")
        signal = self._base_signal()
        decision = evaluate(self._inputs(), task, signal, None)
        self.assertFalse(decision.accepted)
        self.assertEqual("changed_paths_not_allowed", decision.failure_code)
        self.assertEqual("scope_violation", decision.terminal_reason)
        self.assertEqual("failure", decision.check_run_conclusion)

    def test_unrecognized_manifest_failure_still_fails_closed(self) -> None:
        task = _load(DOCUMENTS_DIR / "task-issue-20-canary.json")
        signal = self._base_signal()
        signal["executor_manifest_primary_failure"] = "some_new_unknown_reason"
        decision = evaluate(self._inputs(), task, signal, None)
        self.assertFalse(decision.accepted)
        self.assertEqual("adapter_outcome_not_success", decision.failure_code)

    def test_control_integrity_failure_keeps_its_primary_reason(self) -> None:
        task = _load(DOCUMENTS_DIR / "task-issue-20-canary.json")
        signal = self._base_signal()
        signal["executor_manifest_primary_failure"] = "control_integrity_failed"
        decision = evaluate(self._inputs(), task, signal, None)
        self.assertFalse(decision.accepted)
        self.assertEqual("control_integrity_failed", decision.failure_code)
        self.assertEqual("ref_history_unverifiable", decision.terminal_reason)

    def test_success_path_is_unaffected_and_still_requires_branch_and_review(self) -> None:
        """No manifest primary failure recorded: the ordinary success path,
        including the exact target branch and an independent review, is
        required exactly as before this correction."""
        task = _load(DOCUMENTS_DIR / "task-issue-20-canary.json")
        signal = _load(DOCUMENTS_DIR / "executor-signal-accept.json")
        self.assertNotIn("executor_manifest_primary_failure", signal)
        decision_no_review = evaluate(self._inputs(), task, signal, None)
        self.assertFalse(decision_no_review.accepted)
        self.assertEqual("reviewer_unavailable", decision_no_review.failure_code)

        review = _load(DOCUMENTS_DIR / "review-accept.json")
        decision_accepted = evaluate(self._inputs(), task, signal, review)
        self.assertTrue(decision_accepted.accepted)


class ObservedChangedPathsPersistenceTests(unittest.TestCase):
    """Issue #32 correction: the exact observed changed-path list is
    persisted into `workflow-run-metadata` before every scope rejection, not
    just on success."""

    def test_observed_changed_paths_persist_on_a_scope_rejection(self) -> None:
        task = _load(DOCUMENTS_DIR / "task-issue-20-canary.json")
        signal = _load(DOCUMENTS_DIR / "executor-signal-accept.json")
        signal["publication_passed"] = False
        signal["executor_manifest_primary_failure"] = "changed_paths_not_allowed"
        signal["observed_changed_paths"] = [".github/workflows/p0-actions-adapter.yml", "output.txt"]
        inputs = {
            "task_commit": "5033581665f759971f8a6c5875efd2be93c2b109",
            "task_path": ".ai/tasks/20/issue-20-canary-task.v1.json",
            "target_branch": "agent/issue-20-canary",
            "default_branch": "main",
            "attempt": 1,
            "mode": "execute",
        }
        decision = evaluate(inputs, task, signal, None)
        self.assertFalse(decision.accepted)
        docs = build_documents(
            decision,
            {
                "verification_id": "90000000-0000-4000-8000-0000000000ee",
                "evaluated_at": "2026-07-16T12:00:00Z",
                "verifier_identity": _load(DOCUMENTS_DIR / "verifier-identity.json"),
            },
            _tmp_dir(),
        )
        self.assertEqual(
            [".github/workflows/p0-actions-adapter.yml", "output.txt"],
            docs["metadata"]["observed_changed_paths"],
        )
        self.assertEqual("scope_violation", docs["metadata"]["primary_terminal_reason"])

    def test_observed_changed_paths_falls_back_to_changed_files_when_absent(self) -> None:
        decision = evaluate(
            {
                "task_commit": "5033581665f759971f8a6c5875efd2be93c2b109",
                "task_path": ".ai/tasks/20/issue-20-canary-task.v1.json",
                "target_branch": "agent/issue-20-canary",
                "default_branch": "main",
                "attempt": 1,
                "mode": "execute",
            },
            _load(DOCUMENTS_DIR / "task-issue-20-canary.json"),
            _load(DOCUMENTS_DIR / "executor-signal-accept.json"),
            _load(DOCUMENTS_DIR / "review-accept.json"),
        )
        self.assertTrue(decision.accepted)
        docs = build_documents(
            decision,
            {
                "verification_id": "90000000-0000-4000-8000-0000000000ff",
                "evaluated_at": "2026-07-16T12:00:00Z",
                "verifier_identity": _load(DOCUMENTS_DIR / "verifier-identity.json"),
            },
            _tmp_dir(),
        )
        self.assertEqual(["src/canary/hello.py"], docs["metadata"]["observed_changed_paths"])


class ProducedDocumentSchemaTests(unittest.TestCase):
    """AC-A5: every produced result/verification document validates against
    the existing, unmodified contract schemas -- on success AND failure."""

    def test_every_fixture_produces_schema_valid_documents(self) -> None:
        result_validator = _validator(RESULT_SCHEMA_PATH)
        verification_validator = _validator(VERIFICATION_SCHEMA_PATH)
        manifest = _load(MANIFEST_PATH)
        workdir = _tmp_dir()
        for fixture in manifest["fixtures"]:
            report = adapter.run_fixture(fixture, DOCUMENTS_DIR.parent, workdir)
            self.assertEqual([], report["result_schema_errors"], fixture["id"])
            self.assertEqual([], report["verification_schema_errors"], fixture["id"])


class WorkflowInvariantTests(unittest.TestCase):
    """AC-A5: the workflow enforces the required invariants and declares none
    of the forbidden capabilities."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW_PATH.read_text(encoding="utf-8")
        # "Functional" YAML with comment lines removed, so documentation that
        # names an invariant/forbidden capability is never mistaken for a
        # declaration of it.
        cls.functional = "\n".join(
            line for line in cls.text.splitlines() if not line.lstrip().startswith("#")
        )

    def test_pinned_action_no_floating_tag(self) -> None:
        self.assertIn(PINNED_ADAPTER_ACTION, self.text)
        self.assertNotIn("claude-code-action@main", self.text)
        self.assertNotIn("claude-code-action@v", self.text)

    def test_codex_action_and_cli_are_exactly_pinned(self) -> None:
        self.assertIn("uses: {}".format(PINNED_CODEX_ACTION), self.text)
        self.assertNotIn("openai/codex-action@v", self.text)
        self.assertIn('codex-version: "{}"'.format(PINNED_CODEX_CLI_VERSION), self.text)
        self.assertIn("model: {}".format(PINNED_CODEX_MODEL), self.text)
        self.assertIn("effort: {}".format(PINNED_CODEX_EFFORT), self.text)

    def test_codex_security_profile_and_secret_boundary_are_exact(self) -> None:
        codex_step = self.text.split("- name: Codex edits the workspace", 1)[1].split(
            "- name: Preserve real adapter output", 1
        )[0]
        self.assertIn('permission-profile: "{}"'.format(PINNED_CODEX_PERMISSION_PROFILE), codex_step)
        self.assertIn("safety-strategy: {}".format(PINNED_CODEX_SAFETY_STRATEGY), codex_step)
        self.assertIn("openai-api-key: ${{ secrets.OPENAI_API_KEY }}", codex_step)
        self.assertNotIn("github-token:", codex_step)
        self.assertNotIn("github_token:", codex_step)
        self.assertNotIn("sandbox:", codex_step)
        execute_checkout = self.text.split("  execute:", 1)[1].split("  publish-target:", 1)[0]
        self.assertIn("persist-credentials: false", execute_checkout)

    def test_codex_is_selected_only_from_immutable_task_adapter(self) -> None:
        self.assertIn("executor_adapter: ${{ steps.bind.outputs.executor_adapter }}", self.text)
        self.assertIn("adapter.resolve_workflow_executor_adapter(task)", self.text)
        self.assertIn(
            "if: needs.admission.outputs.executor_adapter == 'openai-codex-action'",
            self.text,
        )
        self.assertIn(
            "if: needs.admission.outputs.executor_adapter == 'human-supervised-claude-code'",
            self.text,
        )

    def test_codex_has_run_evidence_without_fabricated_claude_transcript(self) -> None:
        self.assertIn("codex-final-message.txt", self.text)
        self.assertIn("adapter.codex_action_evidence_failure(manifest)", self.text)
        self.assertIn("execution_evidence_run_attempt", self.text)
        self.assertIn("openai-codex-action:run-", self.text)
        self.assertNotIn("executor-transcript.txt').write_text(codex_final", self.text)
        self.assertIn("shutil.rmtree(codex_control)", self.text)
        # output.txt is a known Claude action byproduct only. A Codex-created
        # output.txt must remain visible to the ordinary scope rejection.
        self.assertIn("if not is_codex and provider_transient.is_file():", self.text)

    def test_control_hash_failure_is_preserved_before_python_import(self) -> None:
        self.assertIn("control_integrity_failed=false", self.text)
        self.assertIn('d["postcondition_failure"]="control_integrity_failed"', self.text)
        self.assertIn('manifest.get(\'postcondition_failure\')', self.text)

    def test_workflow_dispatch_inputs_present(self) -> None:
        for token in ("workflow_dispatch", "task_commit", "task_path", "target_branch", "mode"):
            self.assertIn(token, self.text)

    def test_pull_request_never_runs_executor(self) -> None:
        # The executor job must be gated to workflow_dispatch only.
        self.assertIn("github.event_name == 'workflow_dispatch'", self.text)
        self.assertIn("github.event.inputs.mode == 'execute'", self.text)

    def test_pr_bootstrap_emits_exact_head_review_evidence(self) -> None:
        bootstrap = self.text.split("  bootstrap-tests:", 1)[1].split("  admission:", 1)[0]
        self.assertIn("ref: ${{ github.event.pull_request.head.sha || github.sha }}", bootstrap)
        self.assertIn("fetch-depth: 0", bootstrap)
        self.assertIn("persist-credentials: false", bootstrap)
        self.assertIn("Prepare cross-platform private temp root", bootstrap)
        self.assertIn("sudo install -d -m 1777 /private/tmp", bootstrap)
        self.assertIn("Verify exact immutable Issue 40 task routing regression", bootstrap)
        self.assertIn("Run full repository suite", bootstrap)
        self.assertIn("Parse workflow YAML independently", bootstrap)
        self.assertIn("Validate exact PR diff", bootstrap)
        self.assertIn("BASE_SHA: ${{ github.event.pull_request.base.sha }}", bootstrap)
        self.assertIn("HEAD_SHA: ${{ github.event.pull_request.head.sha }}", bootstrap)
        self.assertIn('test "$(git rev-parse HEAD)" = "$HEAD_SHA"', bootstrap)
        self.assertIn('git diff --check "$BASE_SHA..$HEAD_SHA"', bootstrap)

    def test_top_level_permissions_read_only(self) -> None:
        # The top-level permissions block grants only contents: read.
        top = self.text.split("jobs:", 1)[0]
        self.assertIn("permissions:\n  contents: read", top)

    def test_only_execute_job_has_contents_write(self) -> None:
        # Exactly one credential-separated publisher is granted write;
        # the Claude execution job remains repository read-only.
        self.assertEqual(1, self.functional.count("contents: write"))
        execute_section = self.text.split("  execute:", 1)[1].split("  publish-target:", 1)[0]
        self.assertNotIn("contents: write", execute_section)
        publisher_section = self.text.split("  publish-target:", 1)[1].split("  finalize-and-verify:", 1)[0]
        self.assertIn("contents: write", publisher_section)

    def test_least_privilege_no_broad_scopes(self) -> None:
        for forbidden in ("id-token:", "pull-requests: write", "packages: write", "deployments: write"):
            self.assertNotIn(forbidden, self.functional)

    def test_always_run_finalizer(self) -> None:
        self.assertIn("if: always()", self.text)
        self.assertIn("Finalize, independently verify, and publish Check Run", self.text)

    def test_verifier_owned_check_run(self) -> None:
        self.assertIn(VERIFIER_CHECK_CONTEXT, self.text)
        self.assertIn("VERIFIER_CHECK_CONTEXT", self.text)

    def test_clean_ephemeral_checkout_and_exact_base(self) -> None:
        self.assertIn("Clean ephemeral checkout at exact protected-main base SHA", self.text)
        self.assertIn("needs.admission.outputs.base_sha", self.text)

    def test_forbidden_capabilities_absent(self) -> None:
        functional = self.functional
        lowered = functional.lower()
        # No auto-merge API call ever.
        self.assertNotIn("merge_pull_request", lowered)
        # No deployment environment binding, no settings write.
        self.assertNotIn("environment:", lowered)
        self.assertNotIn("deployments:", lowered)
        # `gh pr merge` and `git push --force` may appear ONLY inside the
        # executor's disallowedTools denial list -- never as an enabled step.
        for token in ("gh pr merge", "git push --force", "push -f", "--force-with-lease"):
            for line in functional.splitlines():
                if token in line:
                    self.assertIn(
                        "disallowedTools",
                        line,
                        "'{}' appears outside a denial list: {}".format(token, line),
                    )

    def test_executor_has_explicit_non_shell_tool_allowlist(self) -> None:
        # Issue #32 correction: `--allowedTools` alone is never the deny
        # boundary. The bounded surface is declared with `--tools`, and
        # `--disallowedTools` is present as defense-in-depth explicitly
        # naming `Bash` -- and the workflow's own trusted transcript parser
        # (`transcript_tool_policy_failure`) is the real, independently
        # enforced boundary (asserted separately below).
        self.assertNotIn("--allowedTools", self.text)
        tools_match = re.search(r'--tools\s+"([^"]*)"', self.text)
        self.assertIsNotNone(tools_match, "expected an explicit --tools argument for the adapter step")
        self.assertEqual("Read,Edit,Write,Glob,Grep", tools_match.group(1))
        disallowed_match = re.search(r'--disallowedTools\s+"([^"]*)"', self.text)
        self.assertIsNotNone(disallowed_match, "expected defense-in-depth --disallowedTools")
        disallowed_tools = {t.strip() for t in disallowed_match.group(1).split(",")}
        self.assertIn("Bash", disallowed_tools)
        self.assertFalse(disallowed_tools & {"Read", "Edit", "Write", "Glob", "Grep"})

    def test_prohibited_transcript_tool_use_is_independently_verified(self) -> None:
        # The workflow never relies solely on the provider's own CLI flags:
        # it independently re-parses the real preserved transcript bytes for
        # any actual tool_use outside the edit-only allowlist, and requires
        # the transcript to be positively scannable at all (never treating a
        # missing/malformed/empty transcript as "no violation found"), in
        # both the execute job and the credential-separated publisher.
        self.assertEqual(2, self.text.count("adapter.transcript_tool_policy_failure(execution)"))
        self.assertEqual(2, self.text.count("reject(tool_policy_failure)"))
        self.assertNotIn("prohibited_transcript_tool_use(execution)", self.text)

    def test_provider_transient_output_is_isolated_narrowly(self) -> None:
        self.assertIn("Assert provider-owned transient output.txt is absent before invocation", self.text)
        self.assertIn("test ! -e output.txt", self.text)
        self.assertIn("PROVIDER_TRANSIENT_OUTPUT_PATH", self.text)
        self.assertIn("provider_transient.unlink()", self.text)

    def test_observed_changed_paths_persisted_before_scope_decisions(self) -> None:
        occurrences = self.text.count("manifest['observed_changed_paths'] = changed")
        self.assertGreaterEqual(occurrences, 2)
        self.assertIn("'observed_changed_paths': manifest.get('observed_changed_paths')", self.text)

    def test_executor_manifest_primary_failure_is_threaded_into_signal(self) -> None:
        self.assertIn("primary_failure = manifest.get('postcondition_failure') or manifest.get('publication_failure')", self.text)
        self.assertIn("'executor_manifest_primary_failure': primary_failure", self.text)

    def test_finalizer_falls_back_to_execute_job_evidence_when_publication_never_ran(self) -> None:
        self.assertIn("Download execute-job evidence when publication never ran (execute mode)", self.text)
        self.assertIn("Download execute-job evidence when publication never ran (verify-only mode)", self.text)
        self.assertIn("hashFiles('p0-adapter-output/manifest.json') == ''", self.text)

    def test_workflow_owns_check_commit_and_exact_target_push(self) -> None:
        self.assertIn("subprocess.run(argv", self.text)
        self.assertIn("HEAD:refs/heads/{}", self.text)
        self.assertIn("changed_paths_within_scope", self.text)
        self.assertIn("postconditions_passed", self.text)

    def test_verifier_reruns_check_on_detached_exact_subject(self) -> None:
        self.assertIn('git switch --detach "$subject"', self.text)
        self.assertGreaterEqual(self.text.count("workflow_controlled_process_exit_code"), 1)
        self.assertIn("required-check.log", self.text)

    def test_review_ref_is_validated_as_exact_commit_and_recorded(self) -> None:
        self.assertIn("validate_task_ref", self.text)
        self.assertIn("review-binding.json", self.text)
        self.assertIn("review_attestation_commit", self.text)

    def test_refuses_protected_branch_write(self) -> None:
        self.assertIn("Prove dispatch SHA is current protected default-branch head", self.text)
        self.assertIn("default_branch_head_after", self.text)
        self.assertIn("default_after != base", self.text)

    def _claude_args_block(self) -> str:
        # The claude_args YAML block-scalar value is every line more deeply
        # indented than the `claude_args:` key that begins with a `--` flag;
        # bounding on indentation (not just "any indented line") keeps this
        # from spilling into the following, less-indented workflow step.
        match = re.search(r"claude_args:\s*\|\n((?:[ \t]{12}--\S.*\n)+)", self.text)
        self.assertIsNotNone(match, "expected a claude_args block")
        return match.group(1)

    def test_claude_args_grant_exactly_the_narrow_control_directory(self) -> None:
        # Issue #35 correction: the pinned Claude invocation must read
        # /tmp/p0-control (task.json, allowed-paths.json, required-check.json)
        # through the CLI's own bounded --add-dir mechanism -- nothing wider.
        claude_args_block = self._claude_args_block()
        add_dir_matches = re.findall(r"--add-dir\s+(\S+)", claude_args_block)
        self.assertEqual(["/tmp/p0-control"], add_dir_matches)

    def test_claude_args_never_grant_broad_permission_bypass(self) -> None:
        claude_args_block = self._claude_args_block()
        forbidden_tokens = (
            "--dangerously-skip-permissions",
            "--permission-mode bypassPermissions",
            "bypassPermissions",
            "dangerously-skip-permissions",
        )
        for token in forbidden_tokens:
            self.assertNotIn(token, claude_args_block)
        # The only --add-dir grant is the exact /tmp/p0-control path (no
        # trailing slash, no wildcard, no additional directories appended).
        # Matched within a single line only: `\s` would otherwise cross the
        # newline into the following `--permission-mode` flag.
        add_dir_matches = re.findall(r"--add-dir(?:[ \t]+\S+)+", claude_args_block)
        for match in add_dir_matches:
            self.assertEqual("--add-dir /tmp/p0-control", match.strip())

    def test_edit_only_tool_surface_still_bounded_alongside_directory_grant(self) -> None:
        # The narrow directory grant must coexist with, not replace, the
        # existing edit-only --tools allowlist and Bash --disallowedTools
        # defense-in-depth already asserted above.
        tools_match = re.search(r'--tools\s+"([^"]*)"', self.text)
        self.assertIsNotNone(tools_match)
        self.assertEqual("Read,Edit,Write,Glob,Grep", tools_match.group(1))
        disallowed_match = re.search(r'--disallowedTools\s+"([^"]*)"', self.text)
        self.assertIsNotNone(disallowed_match)
        disallowed_tools = {t.strip() for t in disallowed_match.group(1).split(",")}
        self.assertIn("Bash", disallowed_tools)
        self.assertNotIn("--allowedTools", self.text)

    def test_claude_args_declare_exactly_accept_edits_permission_mode(self) -> None:
        # Issue #37 correction: the pinned Claude invocation must run under
        # the supported non-interactive `acceptEdits` permission mode so
        # bounded Read/Edit/Write/Glob/Grep operations are no longer denied
        # for want of interactive approval, without widening the tool
        # surface or granting a permission bypass.
        claude_args_block = self._claude_args_block()
        permission_mode_matches = re.findall(r"--permission-mode\s+(\S+)", claude_args_block)
        self.assertEqual(["acceptEdits"], permission_mode_matches)

    def test_claude_args_reject_any_other_or_duplicate_permission_mode(self) -> None:
        claude_args_block = self._claude_args_block()
        permission_mode_matches = re.findall(r"--permission-mode\s+(\S+)", claude_args_block)
        # Exactly one declaration, and it must be exactly "acceptEdits" --
        # never a duplicate, a different mode, or a bypass-equivalent value.
        self.assertEqual(1, len(permission_mode_matches))
        for forbidden_mode in ("bypassPermissions", "plan", "default", "acceptedits", "AcceptEdits"):
            self.assertNotEqual(forbidden_mode, permission_mode_matches[0])
        self.assertNotIn("bypassPermissions", claude_args_block)


if __name__ == "__main__":
    unittest.main()
