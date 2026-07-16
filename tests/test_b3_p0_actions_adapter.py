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

import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from tools import p0_actions_adapter as adapter
from tools.p0_actions_adapter import (
    Decision,
    PINNED_ADAPTER_ACTION,
    VERIFIER_CHECK_CONTEXT,
    build_documents,
    changed_paths_within_scope,
    evaluate,
    is_verification_only,
    resolve_registered_check,
    run_suite,
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

# The eight scenarios AC-A2 requires by name.
REQUIRED_SCENARIOS = {
    "reject-mutable-task-ref",
    "reject-invalid-task",
    "reject-base-sha-mismatch",
    "reject-target-branch-mismatch",
    "reject-missing-executor-evidence",
    "reject-self-review",
    "reject-post-review-head-change",
    "accept-bounded-executor-result",
}

REQUIRED_RESULT_ARTIFACT_IDS = {
    "executor-transcript",
    "result-artifact",
    "verification-report",
    "workflow-run-metadata",
}

REQUIRED_PROVENANCE = {
    "workflow_run_id",
    "workflow_run_attempt",
    "execution_id",
    "subject_sha",
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


class AcceptedResultArtifactTests(unittest.TestCase):
    """AC-A3: the accepted result declares the four required artifacts with
    real hashes and full provenance."""

    def _accept_decision(self) -> Decision:
        task = _load(DOCUMENTS_DIR / "task-issue-20-canary.json")
        signal = _load(DOCUMENTS_DIR / "executor-signal-accept.json")
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

    def test_workflow_dispatch_inputs_present(self) -> None:
        for token in ("workflow_dispatch", "task_commit", "task_path", "target_branch", "mode"):
            self.assertIn(token, self.text)

    def test_pull_request_never_runs_executor(self) -> None:
        # The executor job must be gated to workflow_dispatch only.
        self.assertIn("github.event_name == 'workflow_dispatch'", self.text)
        self.assertIn("mode != 'verify-only'", self.text)

    def test_top_level_permissions_read_only(self) -> None:
        # The top-level permissions block grants only contents: read.
        top = self.text.split("jobs:", 1)[0]
        self.assertIn("permissions:\n  contents: read", top)

    def test_only_execute_job_has_contents_write(self) -> None:
        # Exactly one job (the executor) is granted contents: write.
        self.assertEqual(1, self.functional.count("contents: write"))

    def test_least_privilege_no_broad_scopes(self) -> None:
        for forbidden in ("id-token:", "pull-requests: write", "packages: write", "deployments: write"):
            self.assertNotIn(forbidden, self.functional)

    def test_always_run_finalizer(self) -> None:
        self.assertIn("if: always()", self.text)
        self.assertIn("Finalize, verify, and publish Check Run", self.text)

    def test_verifier_owned_check_run(self) -> None:
        self.assertIn(VERIFIER_CHECK_CONTEXT, self.text)
        self.assertIn("VERIFIER_CHECK_CONTEXT", self.text)

    def test_clean_ephemeral_checkout_and_exact_base(self) -> None:
        self.assertIn("Clean ephemeral checkout at the exact protected-main base SHA", self.text)
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

    def test_executor_denies_dangerous_tools(self) -> None:
        # The pinned action is invoked with an explicit denial of force-push,
        # merge, and main/master writes.
        self.assertIn("disallowedTools", self.text)
        for denied in ("git push --force", "gh pr merge", "git push origin main"):
            self.assertIn(denied, self.text)

    def test_refuses_protected_branch_write(self) -> None:
        self.assertIn("refusing to write protected/default branch", self.text)


if __name__ == "__main__":
    unittest.main()
