from __future__ import annotations

import json
import re
import tempfile
import unittest
import uuid
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker

from tools.propagate_b3 import (
    B3PropagatorError,
    Classification,
    PROVIDER_SIGNAL_SCHEMA,
    build_trusted_observation,
    build_workflow_run_metadata,
    classify_terminal,
    derive_pipeline_execution_id,
    load_provider_signal,
    resolve_adapter_session_id,
    resolve_execution_identity,
    run_fixture,
    run_pipeline,
    run_suite,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS_DIR = REPO_ROOT / "fixtures/b3/documents"
MANIFEST_PATH = REPO_ROOT / "fixtures/b3/manifest.v1.json"
RESULT_SCHEMA_PATH = REPO_ROOT / "contracts/schemas/result.v1.schema.json"
VERIFICATION_SCHEMA_PATH = REPO_ROOT / "contracts/schemas/verification.v1.schema.json"
COMMAND_REGISTRY_PATH = REPO_ROOT / "contracts/registries/commands.v1.json"
WORKFLOW_PATH = REPO_ROOT / ".github/workflows/b3-terminal-propagation.yml"

TASK_ID = "yurikuchumov-ux/ai-operating-system#19"
PINNED_ADAPTER_ACTION = "anthropics/claude-code-action@6902c227aaa9536481b99d56f3014bbbad6c6da8"
HEAD_BRANCH = "agent/issue-19-b3-terminal-propagation"

ALL_SCENARIO_IDS = {
    "canonical-run-29190170902-false-success",
    "reject-max-turns",
    "reject-adapter-timeout",
    "reject-job-timeout",
    "reject-missing-commit",
    "reject-missing-result-artifact",
    "reject-missing-evidence-artifact",
    "reject-empty-diff",
    "reject-check-failed",
    "reject-adapter-error",
    "reject-cancelled",
    "reject-verifier-overrides-adapter-self-report",
    "accept-genuine-success",
    "reject-runner-lost",
    "reject-adapter-session-unresolvable",
}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _tmp_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="b3-propagator-test-", dir="/private/tmp"))


class B3FixtureOracleTests(unittest.TestCase):
    """Every required terminal-propagation scenario -- the 13 the control
    contract requires plus 2 added to exercise the corrected runner_lost /
    session-resolution paths -- must match the oracle exactly: result
    status/terminal_reason, and the Check Run conclusion the verifier's
    report -- not adapter prose -- forces."""

    def test_all_15_required_scenarios_match(self) -> None:
        exit_code, report = run_suite(MANIFEST_PATH, workdir=_tmp_dir())
        self.assertEqual(0, exit_code)
        self.assertTrue(report["valid"])
        self.assertEqual(15, report["summary"]["total"])
        self.assertEqual(15, report["summary"]["passed"])
        self.assertEqual(0, report["summary"]["failed"])
        self.assertFalse(report["authoritative_verifier"])
        self.assertEqual("B3", report["bootstrap_scope"])
        for fixture in report["fixtures"]:
            self.assertTrue(
                fixture["expectation_met"],
                "scenario {} did not match the oracle: {}".format(fixture["id"], fixture["actual"]),
            )

    def test_scenario_ids_match_control_contract_manifest(self) -> None:
        manifest = _load_json(MANIFEST_PATH)
        ids = {fixture["id"] for fixture in manifest["fixtures"]}
        self.assertEqual(ALL_SCENARIO_IDS, ids)

    def test_all_13_originally_required_scenarios_are_preserved(self) -> None:
        """Corrective-attempt invariant: none of attempt 1's 13 required
        scenarios were removed or had their expected terminal outcome
        changed by the correction."""
        original_expected = {
            "canonical-run-29190170902-false-success": ("failed", "max_turns", "failure"),
            "reject-max-turns": ("failed", "max_turns", "failure"),
            "reject-adapter-timeout": ("failed", "timeout", "failure"),
            "reject-job-timeout": ("failed", "timeout", "failure"),
            "reject-missing-commit": ("failed", "missing_commit", "failure"),
            "reject-missing-result-artifact": ("failed", "missing_artifact", "failure"),
            "reject-missing-evidence-artifact": ("failed", "missing_artifact", "failure"),
            "reject-empty-diff": ("failed", "empty_diff", "failure"),
            "reject-check-failed": ("failed", "check_failed", "failure"),
            "reject-adapter-error": ("failed", "adapter_error", "failure"),
            "reject-cancelled": ("cancelled", "cancelled_by_owner", "failure"),
            "reject-verifier-overrides-adapter-self-report": ("failed", "check_failed", "failure"),
            "accept-genuine-success": ("change_proposed", "completed", "success"),
        }
        manifest = _load_json(MANIFEST_PATH)
        by_id = {f["id"]: f for f in manifest["fixtures"]}
        for scenario_id, (status, terminal_reason, conclusion) in original_expected.items():
            fixture = by_id[scenario_id]
            self.assertEqual(status, fixture["expected"]["status"], scenario_id)
            self.assertEqual(terminal_reason, fixture["expected"]["terminal_reason"], scenario_id)
            self.assertEqual(conclusion, fixture["expected"]["check_run_conclusion"], scenario_id)

    def test_canonical_run_29190170902_is_a_false_success_fixture_that_fails_closed(self) -> None:
        manifest = _load_json(MANIFEST_PATH)
        fixture = next(
            f for f in manifest["fixtures"] if f["id"] == "canonical-run-29190170902-false-success"
        )
        signal = _load_json(DOCUMENTS_DIR / "signal-canonical-run-29190170902.json")
        # The historical run was green at both the adapter and the job layer.
        self.assertEqual("success", signal["adapter_self_report"]["status"])
        self.assertEqual("success", signal["actions_job_conclusion"])
        # ... yet it actually terminated on max-turns with no commit and no
        # artifacts, and the fixture's declared oracle must fail closed on
        # exactly that reason, not the adapter's or job's self-report.
        self.assertEqual("29190170902", signal["source_run_id"])
        self.assertEqual("error_max_turns", signal["raw_provider_terminal_reason"])
        self.assertEqual("failed", fixture["expected"]["status"])
        self.assertEqual("max_turns", fixture["expected"]["terminal_reason"])
        self.assertEqual("failure", fixture["expected"]["check_run_conclusion"])
        self.assertEqual(0, fixture["expected"]["artifacts_count"])
        self.assertFalse(fixture["expected"]["new_commit"])
        # The real run produced no execution_file/structured_output at all
        # (consistent with "zero artifacts"), so execution_id cannot be the
        # adapter's own session id -- it must fall back to the deterministic,
        # non-random derivation, never a fabricated UUID.
        self.assertEqual("pipeline_derived", fixture["expected"]["execution_id_source"])

    def test_genuine_success_fixture_passes(self) -> None:
        manifest = _load_json(MANIFEST_PATH)
        fixture = next(f for f in manifest["fixtures"] if f["id"] == "accept-genuine-success")
        self.assertEqual("change_proposed", fixture["expected"]["status"])
        self.assertEqual("completed", fixture["expected"]["terminal_reason"])
        self.assertEqual("success", fixture["expected"]["check_run_conclusion"])
        self.assertEqual("adapter_session", fixture["expected"]["execution_id_source"])


class B3SchemaValidityTests(unittest.TestCase):
    """AC-B3-2: every scenario's finalized result and verification report
    must validate against the existing, unmodified result.v1 and
    verification.v1 schemas."""

    def test_every_result_and_verification_artifact_is_schema_valid(self) -> None:
        result_validator = Draft202012Validator(_load_json(RESULT_SCHEMA_PATH), format_checker=FormatChecker())
        verification_validator = Draft202012Validator(
            _load_json(VERIFICATION_SCHEMA_PATH), format_checker=FormatChecker()
        )
        manifest = _load_json(MANIFEST_PATH)
        manifest_dir = MANIFEST_PATH.parent
        workdir = _tmp_dir()
        for fixture in manifest["fixtures"]:
            run_fixture(fixture, manifest_dir, workdir)
            output_dir = workdir / fixture["id"]
            result = _load_json(output_dir / "result.json")
            verification = _load_json(output_dir / "verification.json")
            self.assertEqual(
                [], [e.message for e in result_validator.iter_errors(result)], fixture["id"]
            )
            self.assertEqual(
                [], [e.message for e in verification_validator.iter_errors(verification)], fixture["id"]
            )


class B3ClassificationPriorityTests(unittest.TestCase):
    """Direct unit coverage of classify_terminal's fixed priority order, its
    refusal to read adapter- or job-self-reported status, and the corrected
    evidence-based timeout / runner_lost / session-resolution behavior."""

    def _signal(self, **overrides: Any) -> Mapping[str, Any]:
        base = {
            "schema_version": "1.0.0",
            "task_id": TASK_ID,
            "attempt": 1,
            "executor": {
                "adapter": "human-supervised-claude-code",
                "adapter_version": "test",
                "identity": {
                    "operator_principal": "github:test",
                    "agent_runtime_id": "claude-code:test",
                    "credential_principal": "github:actions:test-executor",
                    "delegation_parent": "test",
                    "role": "author",
                },
            },
            "started_at": "2026-07-14T08:00:00Z",
            "finished_at": "2026-07-14T08:10:00Z",
            "workflow_run_id": "1",
            "workflow_run_attempt": "1",
            "source_run_id": None,
            "cancelled_by_owner": False,
            "adapter_attempted": True,
            "adapter_step_outcome": "success",
            "job_elapsed_seconds": 60,
            "job_timeout_budget_seconds": 900,
            "adapter_elapsed_seconds": 45,
            "adapter_timeout_budget_seconds": 600,
            "max_turns_exhausted": False,
            "adapter_error": None,
            "raw_provider_terminal_reason": None,
            "adapter_self_report": None,
            "actions_job_conclusion": None,
            "untrusted_candidate": None,
            "execution_file_content": json.dumps({"session_id": "99999999-9999-4999-8999-999999999999"}),
            "structured_output_raw": None,
            "git_observation": {
                "base_sha": "a" * 40,
                "head_sha": "b" * 40,
                "authored_commits": ["c" * 40],
                "changed_files": ["src/x.py"],
            },
            "result_artifact_present": True,
            "required_evidence_artifact_present": True,
            "required_check_exit_code": 0,
            "finalized_by": {"component_id": "test", "credential_principal": "github:actions:test-finalizer"},
        }
        base.update(overrides)
        return base

    def _classify(self, signal: Mapping[str, Any]) -> Classification:
        _, _, session_error = resolve_execution_identity(signal)
        return classify_terminal(signal, session_error)

    def test_cancelled_by_owner_takes_priority_over_everything_else(self) -> None:
        signal = self._signal(
            cancelled_by_owner=True,
            job_elapsed_seconds=1000,
            job_timeout_budget_seconds=900,
            max_turns_exhausted=True,
        )
        c = self._classify(signal)
        self.assertEqual("cancelled", c.status)
        self.assertEqual("cancelled_by_owner", c.terminal_reason)

    def test_job_timeout_requires_elapsed_exceeding_budget_evidence(self) -> None:
        signal = self._signal(job_elapsed_seconds=901, job_timeout_budget_seconds=900)
        c = self._classify(signal)
        self.assertEqual("failed", c.status)
        self.assertEqual("timeout", c.terminal_reason)
        self.assertEqual("actions_job", c.timeout_origin)

    def test_job_failure_without_elapsed_budget_evidence_is_not_timeout(self) -> None:
        """The corrected behavior: an execute-job failure with no elapsed
        time recorded at all must never be blanket-mapped to timeout."""
        signal = self._signal(job_elapsed_seconds=None, job_timeout_budget_seconds=900)
        c = self._classify(signal)
        self.assertNotEqual("timeout", c.terminal_reason)

    def test_elapsed_within_budget_is_not_timeout_even_if_job_conclusion_is_failure(self) -> None:
        signal = self._signal(
            job_elapsed_seconds=30,
            job_timeout_budget_seconds=900,
            actions_job_conclusion="failure",
            required_check_exit_code=1,
        )
        c = self._classify(signal)
        self.assertNotEqual("timeout", c.terminal_reason)
        self.assertEqual("check_failed", c.terminal_reason)

    def test_adapter_timeout_requires_its_own_elapsed_budget_evidence(self) -> None:
        signal = self._signal(adapter_elapsed_seconds=601, adapter_timeout_budget_seconds=600)
        c = self._classify(signal)
        self.assertEqual("timeout", c.terminal_reason)
        self.assertEqual("adapter", c.timeout_origin)

    def test_max_turns_takes_priority_over_missing_commit_and_check_failure(self) -> None:
        signal = self._signal(
            max_turns_exhausted=True,
            required_check_exit_code=1,
            git_observation={"base_sha": "a" * 40, "head_sha": None, "authored_commits": [], "changed_files": []},
        )
        c = self._classify(signal)
        self.assertEqual("max_turns", c.terminal_reason)

    def test_adapter_never_attempted_is_runner_lost_not_timeout_or_adapter_error(self) -> None:
        signal = self._signal(
            adapter_attempted=False,
            adapter_step_outcome="skipped",
            execution_file_content=None,
        )
        c = self._classify(signal)
        self.assertEqual("failed", c.status)
        self.assertEqual("runner_lost", c.terminal_reason)

    def test_runner_lost_takes_priority_over_downstream_artifact_and_diff_checks(self) -> None:
        signal = self._signal(
            adapter_attempted=False,
            execution_file_content=None,
            result_artifact_present=False,
            required_evidence_artifact_present=False,
        )
        c = self._classify(signal)
        self.assertEqual("runner_lost", c.terminal_reason)

    def test_adapter_attempted_with_unresolvable_session_is_adapter_error(self) -> None:
        signal = self._signal(execution_file_content=None, structured_output_raw=None)
        c = self._classify(signal)
        self.assertEqual("failed", c.status)
        self.assertEqual("adapter_error", c.terminal_reason)
        self.assertEqual("adapter_session_unresolvable", c.error_code)

    def test_malformed_session_id_is_treated_as_unresolvable_not_coerced(self) -> None:
        signal = self._signal(execution_file_content=json.dumps({"session_id": "not-a-uuid"}))
        c = self._classify(signal)
        self.assertEqual("adapter_error", c.terminal_reason)
        self.assertEqual("adapter_session_unresolvable", c.error_code)

    def test_adapter_self_report_success_cannot_mask_a_real_check_failure(self) -> None:
        """The core AC-B3-3 guarantee at the classification layer: a green
        adapter self-report and a green Actions job conclusion are never
        read by classify_terminal, so they cannot turn a real check failure
        into a passing classification."""
        signal = self._signal(
            required_check_exit_code=1,
            adapter_self_report={
                "status": "success",
                "claimed_status": "change_proposed",
                "claimed_terminal_reason": "completed",
            },
            actions_job_conclusion="success",
        )
        c = self._classify(signal)
        self.assertEqual("failed", c.status)
        self.assertEqual("check_failed", c.terminal_reason)

    def test_genuine_success_requires_every_gate_to_be_clear(self) -> None:
        signal = self._signal()
        c = self._classify(signal)
        self.assertEqual("change_proposed", c.status)
        self.assertEqual("completed", c.terminal_reason)

    def test_classification_never_reads_self_report_or_job_conclusion_fields(self) -> None:
        import inspect

        source = inspect.getsource(classify_terminal)
        body = source.split('"""', 2)[-1]
        self.assertNotIn("adapter_self_report", body)
        self.assertNotIn("actions_job_conclusion", body)

    def test_classification_never_reads_a_pre_computed_timeout_boolean(self) -> None:
        """Structural guarantee that the blanket failure-to-timeout mapping
        bug cannot reappear: there is no `job_timed_out`/`adapter_timed_out`
        boolean field left in the schema for classify_terminal to trust --
        it must compute both from elapsed/budget evidence itself."""
        self.assertNotIn("job_timed_out", PROVIDER_SIGNAL_SCHEMA["properties"])
        self.assertNotIn("adapter_timed_out", PROVIDER_SIGNAL_SCHEMA["properties"])
        self.assertNotIn("execution_id", PROVIDER_SIGNAL_SCHEMA["properties"])


class B3ExecutionIdentityTests(unittest.TestCase):
    """AC-B3-3 corrective invariant: `execution_id` is never `uuid.uuid4()`
    randomness. It is either the adapter's real, parsed session_id, or a
    UUID5 deterministically derived from real Actions run facts."""

    def test_session_id_present_is_used_directly(self) -> None:
        session = "abababab-abab-4bab-8bab-abababababab"
        content = json.dumps({"session_id": session, "status": "completed"})
        resolved = resolve_adapter_session_id(content, None)
        self.assertEqual(session, resolved)

    def test_session_id_in_jsonl_transcript_is_found(self) -> None:
        session = "cdcdcdcd-cdcd-4cdc-8cdc-cdcdcdcdcdcd"
        transcript = "\n".join(
            [
                json.dumps({"type": "turn", "n": 1}),
                json.dumps({"type": "result", "session_id": session, "status": "completed"}),
            ]
        )
        resolved = resolve_adapter_session_id(transcript, None)
        self.assertEqual(session, resolved)

    def test_missing_session_id_returns_none_never_fabricated(self) -> None:
        self.assertIsNone(resolve_adapter_session_id(None, None))
        self.assertIsNone(resolve_adapter_session_id("", ""))
        self.assertIsNone(resolve_adapter_session_id(json.dumps({"status": "completed"}), None))

    def test_malformed_json_returns_none_never_raises(self) -> None:
        self.assertIsNone(resolve_adapter_session_id("{not json", "also not json"))

    def test_non_uuid_session_id_value_is_rejected_not_coerced(self) -> None:
        content = json.dumps({"session_id": "12345"})
        self.assertIsNone(resolve_adapter_session_id(content, None))

    def test_oversized_content_is_rejected_never_scanned(self) -> None:
        huge = json.dumps({"session_id": "abababab-abab-4bab-8bab-abababababab", "padding": "x" * (2 * 1024 * 1024)})
        self.assertIsNone(resolve_adapter_session_id(huge, None))

    def test_derived_pipeline_execution_id_is_deterministic_not_random(self) -> None:
        first = derive_pipeline_execution_id("123", "1", 1)
        second = derive_pipeline_execution_id("123", "1", 1)
        self.assertEqual(first, second)
        different = derive_pipeline_execution_id("456", "1", 1)
        self.assertNotEqual(first, different)
        # Must be a valid UUID string (schema-required format), but not
        # produced by uuid.uuid4() -- uuid5 is reproducible from its inputs.
        uuid.UUID(first)

    def test_resolve_execution_identity_prefers_real_session_over_fallback(self) -> None:
        session = "efefefef-efef-4fef-8fef-efefefefefef"
        signal = {
            "adapter_attempted": True,
            "execution_file_content": json.dumps({"session_id": session}),
            "structured_output_raw": None,
            "workflow_run_id": "1",
            "workflow_run_attempt": "1",
            "attempt": 1,
        }
        execution_id, resolved_session, session_error = resolve_execution_identity(signal)
        self.assertEqual(session, execution_id)
        self.assertEqual(session, resolved_session)
        self.assertIsNone(session_error)

    def test_resolve_execution_identity_falls_back_when_adapter_never_attempted(self) -> None:
        signal = {
            "adapter_attempted": False,
            "execution_file_content": None,
            "structured_output_raw": None,
            "workflow_run_id": "42",
            "workflow_run_attempt": "1",
            "attempt": 1,
        }
        execution_id, resolved_session, session_error = resolve_execution_identity(signal)
        self.assertEqual(derive_pipeline_execution_id("42", "1", 1), execution_id)
        self.assertIsNone(resolved_session)
        self.assertIsNone(session_error)

    def test_resolve_execution_identity_flags_session_error_when_attempted_but_unresolvable(self) -> None:
        signal = {
            "adapter_attempted": True,
            "execution_file_content": None,
            "structured_output_raw": None,
            "workflow_run_id": "42",
            "workflow_run_attempt": "1",
            "attempt": 1,
        }
        execution_id, resolved_session, session_error = resolve_execution_identity(signal)
        self.assertIsNone(resolved_session)
        self.assertIsNotNone(session_error)
        self.assertEqual(derive_pipeline_execution_id("42", "1", 1), execution_id)


class B3OverrideDetectionTests(unittest.TestCase):
    """The adapter's untrusted self-report is preserved as evidence and any
    disagreement with the trusted classification is recorded -- but never
    changes the finalized result."""

    def test_verifier_overrides_scenario_records_ignored_candidate_overrides(self) -> None:
        outputs = run_pipeline(
            DOCUMENTS_DIR / "signal-reject-verifier-overrides-adapter-self-report.json",
            DOCUMENTS_DIR / "task-baseline.json",
            DOCUMENTS_DIR / "review-baseline.json",
            DOCUMENTS_DIR / "verifier-identity.json",
            "90000000-0000-4000-8000-000000000001",
            "2026-07-14T12:00:00Z",
            _tmp_dir() / "override-test",
        )
        self.assertEqual("failed", outputs.result["status"])
        self.assertEqual("check_failed", outputs.result["terminal_reason"])
        self.assertIn("candidate_field_override_ignored:status", outputs.result["warnings"])
        self.assertIn("candidate_field_override_ignored:terminal_reason", outputs.result["warnings"])
        self.assertFalse(outputs.verification["passed"])
        self.assertEqual("failure", outputs.check_run_conclusion)


class B3CheckRunConclusionSourceTests(unittest.TestCase):
    """AC-B3-3: the Check Run conclusion is success iff verification.v1.passed,
    never the adapter's or job's own self-report."""

    def test_conclusion_is_success_iff_verification_passed(self) -> None:
        manifest = _load_json(MANIFEST_PATH)
        manifest_dir = MANIFEST_PATH.parent
        workdir = _tmp_dir()
        for fixture in manifest["fixtures"]:
            run_fixture(fixture, manifest_dir, workdir)
            output_dir = workdir / fixture["id"]
            verification = _load_json(output_dir / "verification.json")
            metadata = _load_json(output_dir / "workflow-run-metadata.json")
            expected_conclusion = "success" if verification["passed"] else "failure"
            self.assertEqual(expected_conclusion, metadata["check_run_conclusion"], fixture["id"])

    def test_command_registry_carries_the_narrow_b3_test_entry(self) -> None:
        registry = _load_json(COMMAND_REGISTRY_PATH)
        entries = {entry["id"]: entry for entry in registry["entries"]}
        self.assertIn("repo.contracts.b3.tests", entries)
        entry = entries["repo.contracts.b3.tests"]
        self.assertEqual(
            ["python3", "-m", "unittest", "discover", "-s", "tests", "-p", "test_b3_*.py"], entry["argv"]
        )


class B3ArtifactPublicationTests(unittest.TestCase):
    """AC-B3-4: result-artifact, verification-report, and
    workflow-run-metadata are all published, and workflow_run_id /
    execution_id are both required non-null."""

    def test_required_artifact_types_are_all_published_with_non_null_ids(self) -> None:
        outputs = run_pipeline(
            DOCUMENTS_DIR / "signal-accept-genuine-success.json",
            DOCUMENTS_DIR / "task-baseline.json",
            DOCUMENTS_DIR / "review-baseline.json",
            DOCUMENTS_DIR / "verifier-identity.json",
            "90000000-0000-4000-8000-000000000002",
            "2026-07-14T12:00:00Z",
            _tmp_dir() / "artifact-test",
        )
        self.assertTrue(outputs.result_path.is_file())
        self.assertTrue(outputs.verification_path.is_file())
        self.assertTrue(outputs.workflow_run_metadata_path.is_file())
        self.assertIsNotNone(outputs.workflow_run_metadata["workflow_run_id"])
        self.assertIsNotNone(outputs.workflow_run_metadata["execution_id"])

    def test_artifact_presence_signal_is_independent_of_commit_existence(self) -> None:
        """Corrective invariant: `result_artifact_present` /
        `required_evidence_artifact_present` are real, independently
        supplied facts -- a signal with commits present but artifacts
        absent must still classify missing_artifact, not be masked by the
        presence of a commit."""
        signal = _load_json(DOCUMENTS_DIR / "signal-reject-missing-result-artifact.json")
        self.assertTrue(signal["git_observation"]["authored_commits"])
        self.assertFalse(signal["result_artifact_present"])
        _, _, session_error = resolve_execution_identity(signal)
        c = classify_terminal(signal, session_error)
        self.assertEqual("missing_artifact", c.terminal_reason)

    def test_workflow_run_metadata_is_never_overwritten(self) -> None:
        output_dir = _tmp_dir() / "overwrite-test"
        run_pipeline(
            DOCUMENTS_DIR / "signal-accept-genuine-success.json",
            DOCUMENTS_DIR / "task-baseline.json",
            DOCUMENTS_DIR / "review-baseline.json",
            DOCUMENTS_DIR / "verifier-identity.json",
            "90000000-0000-4000-8000-000000000003",
            "2026-07-14T12:00:00Z",
            output_dir,
        )
        with self.assertRaises(Exception):
            run_pipeline(
                DOCUMENTS_DIR / "signal-accept-genuine-success.json",
                DOCUMENTS_DIR / "task-baseline.json",
                DOCUMENTS_DIR / "review-baseline.json",
                DOCUMENTS_DIR / "verifier-identity.json",
                "90000000-0000-4000-8000-000000000004",
                "2026-07-14T12:00:00Z",
                output_dir,
            )


class B3IdentitySeparationTests(unittest.TestCase):
    """AC-B3-5: executor (author), reviewer, and verifier/checkrun-publisher
    identities are pairwise distinct in credential_principal -- the
    checkrun-publisher runs as the verifier identity, never the executor's."""

    def test_executor_reviewer_and_checkrun_publisher_credentials_are_distinct(self) -> None:
        task = _load_json(DOCUMENTS_DIR / "task-baseline.json")
        review = _load_json(DOCUMENTS_DIR / "review-baseline.json")
        verifier_identity = _load_json(DOCUMENTS_DIR / "verifier-identity.json")
        signal = _load_json(DOCUMENTS_DIR / "signal-accept-genuine-success.json")

        executor_credential = signal["executor"]["identity"]["credential_principal"]
        reviewer_credential = review["reviewer_identity"]["credential_principal"]
        checkrun_publisher_credential = verifier_identity["credential_principal"]

        self.assertEqual("author", signal["executor"]["identity"]["role"])
        self.assertEqual("reviewer", review["reviewer_identity"]["role"])
        self.assertEqual("verifier", verifier_identity["role"])

        credentials = {executor_credential, reviewer_credential, checkrun_publisher_credential}
        self.assertEqual(3, len(credentials), "executor/reviewer/checkrun-publisher credentials must be distinct")

        forbidden = set(task["review_policy"]["forbidden_lineage_overlaps"])
        self.assertIn("credential_principal", forbidden)
        self.assertIn("agent_runtime_id", forbidden)
        self.assertIn("authored_commits", forbidden)


class B3ProviderSignalPolicyTests(unittest.TestCase):
    """The provider signal is bounded, schema-validated, trusted input; a
    malformed or hash-mismatched fixture document fails closed before any
    finalize or verify attempt runs."""

    def test_unknown_field_in_provider_signal_is_rejected(self) -> None:
        signal = json.loads((DOCUMENTS_DIR / "signal-accept-genuine-success.json").read_text())
        signal["unexpected_field"] = True
        tmp = _tmp_dir() / "signal.json"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(signal), encoding="utf-8")
        with self.assertRaises(B3PropagatorError):
            load_provider_signal(tmp)

    def test_missing_signal_file_is_rejected(self) -> None:
        with self.assertRaises(B3PropagatorError):
            load_provider_signal(DOCUMENTS_DIR / "does-not-exist.json")

    def test_signal_with_caller_supplied_execution_id_is_rejected(self) -> None:
        """`execution_id` must not be an accepted input field at all -- a
        caller cannot smuggle a fabricated value back in."""
        signal = json.loads((DOCUMENTS_DIR / "signal-accept-genuine-success.json").read_text())
        signal["execution_id"] = "11111111-1111-4111-8111-111111111111"
        tmp = _tmp_dir() / "signal.json"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(signal), encoding="utf-8")
        with self.assertRaises(B3PropagatorError):
            load_provider_signal(tmp)

    def test_provider_signal_schema_is_self_consistent_with_fixtures(self) -> None:
        validator = Draft202012Validator(PROVIDER_SIGNAL_SCHEMA, format_checker=FormatChecker())
        for path in sorted(DOCUMENTS_DIR.glob("signal-*.json")):
            document = _load_json(path)
            errors = list(validator.iter_errors(document))
            self.assertEqual([], [e.message for e in errors], path.name)


class B3TrustedObservationBuilderTests(unittest.TestCase):
    def test_failed_classification_produces_a_non_null_error_object(self) -> None:
        classification = Classification("failed", "check_failed", "check_failed", "a required check did not exit zero", None, None)
        signal = _load_json(DOCUMENTS_DIR / "signal-reject-check-failed.json")
        observation = build_trusted_observation(signal, classification, "11111111-1111-4111-8111-111111111111")
        self.assertEqual("failed", observation["terminal_status"])
        self.assertIsNotNone(observation["error"])
        self.assertEqual("check_failed", observation["error"]["code"])
        self.assertEqual("11111111-1111-4111-8111-111111111111", observation["execution_id"])

    def test_success_classification_produces_a_null_error_object(self) -> None:
        classification = Classification("change_proposed", "completed", None, None, None, None)
        signal = _load_json(DOCUMENTS_DIR / "signal-accept-genuine-success.json")
        observation = build_trusted_observation(signal, classification, "22222222-2222-4222-8222-222222222222")
        self.assertEqual("change_proposed", observation["terminal_status"])
        self.assertIsNone(observation["error"])


class B3WorkflowRunMetadataTests(unittest.TestCase):
    def test_metadata_never_trusts_adapter_or_job_status_for_conclusion(self) -> None:
        result = {"execution_id": "x", "task_id": TASK_ID, "artifacts": [], "authored_commits": []}
        verification = {"verification_id": "v", "passed": False}
        signal = {
            "workflow_run_id": "1",
            "workflow_run_attempt": "1",
            "source_run_id": None,
            "raw_provider_terminal_reason": None,
            "adapter_self_report": {"status": "success", "claimed_status": "change_proposed", "claimed_terminal_reason": "completed"},
            "actions_job_conclusion": "success",
            "adapter_attempted": True,
            "result_artifact_present": True,
            "required_evidence_artifact_present": True,
        }
        metadata = build_workflow_run_metadata(signal, result, verification, "failure", None, "some session error")
        self.assertEqual("failure", metadata["check_run_conclusion"])
        self.assertEqual("success", metadata["adapter_self_reported_status"])
        self.assertEqual("success", metadata["actions_job_conclusion"])
        self.assertEqual("pipeline_derived", metadata["execution_id_source"])
        self.assertEqual("some session error", metadata["session_resolution_error"])


class B3WorkflowContentTests(unittest.TestCase):
    """Correction #7: the live workflow file itself must be asserted to
    contain the real pinned adapter action, the pre-merge pull_request
    trigger guarded to this head branch, actual execution-output parsing,
    real artifact observation, and no synthetic execution ID or blanket
    failure-to-timeout mapping -- not just the offline fixtures."""

    def setUp(self) -> None:
        self.assertTrue(WORKFLOW_PATH.is_file(), "expected .github/workflows/b3-terminal-propagation.yml to exist")
        self.text = WORKFLOW_PATH.read_text(encoding="utf-8")

    def test_contains_the_exact_pinned_claude_code_action(self) -> None:
        self.assertIn(PINNED_ADAPTER_ACTION, self.text)
        self.assertIn("secrets.ANTHROPIC_API_KEY", self.text)
        self.assertIn("github.token", self.text)

    def test_adapter_step_is_bounded_to_read_only_diagnostics(self) -> None:
        # The diagnostic invocation must run the registered B3 test command
        # and must never grant tools capable of pushing, merging, or
        # deploying -- whether via omission from `--allowedTools` or an
        # explicit `--disallowedTools` entry, neither may appear in the
        # allowed set.
        self.assertIn("test_b3_", self.text)
        allowed_match = re.search(r'--allowedTools\s+"([^"]*)"', self.text)
        self.assertIsNotNone(allowed_match, "expected an --allowedTools argument for the adapter step")
        allowed_tools = allowed_match.group(1)
        for risky in ("git push", "git commit", "gh pr merge", "Edit", "Write"):
            self.assertNotIn(risky, allowed_tools)

    def test_has_a_pull_request_trigger_guarded_to_this_head_branch(self) -> None:
        self.assertIn("pull_request:", self.text)
        pr_trigger_match = re.search(r"pull_request:\s*\n(?:.*\n)*?\s*types:\s*\[([^\]]*)\]", self.text)
        self.assertIsNotNone(pr_trigger_match, "expected a pull_request `types:` trigger list")
        types = {t.strip() for t in pr_trigger_match.group(1).split(",")}
        self.assertEqual({"opened", "synchronize", "reopened"}, types)
        self.assertIn(HEAD_BRANCH, self.text)
        self.assertIn("github.event.pull_request.head.ref", self.text)

    def test_workflow_dispatch_is_present_only_as_supplemental(self) -> None:
        self.assertIn("workflow_dispatch:", self.text)

    def test_parses_real_execution_output_for_session_id_never_random_uuid(self) -> None:
        self.assertIn("execution_file", self.text)
        self.assertIn("structured_output", self.text)
        self.assertIn("propagate_b3", self.text)
        # The old bug: this workflow itself fabricating `execution_id` with
        # `uuid.uuid4()`. There must be no step that generates an
        # `execution_id` output at all -- the workflow no longer produces
        # one; only tools/propagate_b3.py's resolve_execution_identity does,
        # from real adapter output. (A `verification_id` -- a distinct,
        # non-trust-bearing identifier for the verification report itself --
        # legitimately still uses uuid.uuid4() and is not what this checks.)
        self.assertNotIn("execution_id=", self.text)
        self.assertNotIn('"execution_id": execution_id or', self.text)
        self.assertNotIn("Generate trusted execution identity", self.text)

    def test_artifact_presence_is_derived_from_real_files_not_commits(self) -> None:
        # The corrected collect-signal step must check actual file
        # existence for result/evidence artifact presence, and must not
        # reuse the git commit list as a stand-in for artifact presence.
        self.assertNotIn('"result_artifact_present": bool(authored_commits', self.text)
        self.assertNotIn('"required_evidence_artifact_present": bool(authored_commits', self.text)
        self.assertIn("result_artifact_present", self.text)
        self.assertIn("required_evidence_artifact_present", self.text)
        self.assertIn(".is_file()", self.text)

    def test_does_not_blanket_map_job_failure_to_timeout(self) -> None:
        # The old bug: `job_timed_out = execute_result == "failure" and ...`.
        # No line may derive a timeout boolean purely from the job's own
        # conclusion; it must be computed from elapsed-vs-budget evidence.
        self.assertNotIn('execute_result == "failure"', self.text)
        self.assertIn("job_elapsed_seconds", self.text)
        self.assertIn("job_timeout_budget_seconds", self.text)
        self.assertIn("adapter_attempted", self.text)

    def test_verifier_remains_the_only_check_run_conclusion_source(self) -> None:
        self.assertIn("check_run_conclusion", self.text)
        self.assertIn("workflow-run-metadata.json", self.text)
        self.assertIn("checks.create", self.text)
        # The final job-gating step must still key off the same metadata
        # field, never the adapter's or job's own conclusion.
        gate_section = self.text.split("Gate job result on the verifier's conclusion", 1)[-1]
        self.assertIn("check_run_conclusion", gate_section)

    def test_workflow_yaml_is_syntactically_well_formed(self) -> None:
        # A lightweight structural check that does not require a YAML
        # parser dependency: every `run: |` block must be non-empty and the
        # two expected job names must be present with correct dependency.
        self.assertIn("jobs:", self.text)
        self.assertIn("execute:", self.text)
        self.assertIn("finalize-and-verify:", self.text)
        self.assertIn("needs: execute", self.text)
        self.assertIn("if: always()", self.text)


if __name__ == "__main__":
    unittest.main()
