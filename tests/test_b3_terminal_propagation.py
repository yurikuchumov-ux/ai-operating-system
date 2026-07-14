from __future__ import annotations

import json
import tempfile
import unittest
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
    load_provider_signal,
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

TASK_ID = "yurikuchumov-ux/ai-operating-system#19"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _tmp_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="b3-propagator-test-", dir="/private/tmp"))


class B3FixtureOracleTests(unittest.TestCase):
    """Every required terminal-propagation scenario must match the control
    contract oracle exactly: result status/terminal_reason, and the Check
    Run conclusion the verifier's report -- not adapter prose -- forces."""

    def test_all_13_required_scenarios_match(self) -> None:
        exit_code, report = run_suite(MANIFEST_PATH, workdir=_tmp_dir())
        self.assertEqual(0, exit_code)
        self.assertTrue(report["valid"])
        self.assertEqual(13, report["summary"]["total"])
        self.assertEqual(13, report["summary"]["passed"])
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
        self.assertEqual(
            {
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
            },
            ids,
        )

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

    def test_genuine_success_fixture_passes(self) -> None:
        manifest = _load_json(MANIFEST_PATH)
        fixture = next(f for f in manifest["fixtures"] if f["id"] == "accept-genuine-success")
        self.assertEqual("change_proposed", fixture["expected"]["status"])
        self.assertEqual("completed", fixture["expected"]["terminal_reason"])
        self.assertEqual("success", fixture["expected"]["check_run_conclusion"])


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
    """Direct unit coverage of classify_terminal's fixed priority order and
    its refusal to read adapter- or job-self-reported status."""

    def _signal(self, **overrides: Any) -> Mapping[str, Any]:
        base = {
            "schema_version": "1.0.0",
            "task_id": TASK_ID,
            "execution_id": "70000000-0000-4000-8000-000000000099",
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
            "source_run_id": None,
            "cancelled_by_owner": False,
            "adapter_timed_out": False,
            "job_timed_out": False,
            "max_turns_exhausted": False,
            "adapter_error": None,
            "raw_provider_terminal_reason": None,
            "adapter_self_report": None,
            "actions_job_conclusion": None,
            "untrusted_candidate": None,
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

    def test_cancelled_by_owner_takes_priority_over_everything_else(self) -> None:
        signal = self._signal(cancelled_by_owner=True, job_timed_out=True, max_turns_exhausted=True)
        c = classify_terminal(signal)
        self.assertEqual("cancelled", c.status)
        self.assertEqual("cancelled_by_owner", c.terminal_reason)

    def test_job_timeout_takes_priority_over_adapter_timeout_and_max_turns(self) -> None:
        signal = self._signal(job_timed_out=True, adapter_timed_out=True, max_turns_exhausted=True)
        c = classify_terminal(signal)
        self.assertEqual("failed", c.status)
        self.assertEqual("timeout", c.terminal_reason)
        self.assertEqual("actions_job", c.timeout_origin)

    def test_max_turns_takes_priority_over_missing_commit_and_check_failure(self) -> None:
        signal = self._signal(
            max_turns_exhausted=True,
            required_check_exit_code=1,
            git_observation={"base_sha": "a" * 40, "head_sha": None, "authored_commits": [], "changed_files": []},
        )
        c = classify_terminal(signal)
        self.assertEqual("max_turns", c.terminal_reason)

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
        c = classify_terminal(signal)
        self.assertEqual("failed", c.status)
        self.assertEqual("check_failed", c.terminal_reason)

    def test_genuine_success_requires_every_gate_to_be_clear(self) -> None:
        signal = self._signal()
        c = classify_terminal(signal)
        self.assertEqual("change_proposed", c.status)
        self.assertEqual("completed", c.terminal_reason)

    def test_classification_never_reads_self_report_or_job_conclusion_fields(self) -> None:
        import inspect

        source = inspect.getsource(classify_terminal)
        body = source.split('"""', 2)[-1]
        self.assertNotIn("adapter_self_report", body)
        self.assertNotIn("actions_job_conclusion", body)


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
        observation = build_trusted_observation(signal, classification)
        self.assertEqual("failed", observation["terminal_status"])
        self.assertIsNotNone(observation["error"])
        self.assertEqual("check_failed", observation["error"]["code"])

    def test_success_classification_produces_a_null_error_object(self) -> None:
        classification = Classification("change_proposed", "completed", None, None, None, None)
        signal = _load_json(DOCUMENTS_DIR / "signal-accept-genuine-success.json")
        observation = build_trusted_observation(signal, classification)
        self.assertEqual("change_proposed", observation["terminal_status"])
        self.assertIsNone(observation["error"])


class B3WorkflowRunMetadataTests(unittest.TestCase):
    def test_metadata_never_trusts_adapter_or_job_status_for_conclusion(self) -> None:
        result = {"execution_id": "x", "task_id": TASK_ID, "artifacts": [], "authored_commits": []}
        verification = {"verification_id": "v", "passed": False}
        signal = {
            "workflow_run_id": "1",
            "source_run_id": None,
            "raw_provider_terminal_reason": None,
            "adapter_self_report": {"status": "success", "claimed_status": "change_proposed", "claimed_terminal_reason": "completed"},
            "actions_job_conclusion": "success",
        }
        metadata = build_workflow_run_metadata(signal, result, verification, "failure")
        self.assertEqual("failure", metadata["check_run_conclusion"])
        self.assertEqual("success", metadata["adapter_self_reported_status"])
        self.assertEqual("success", metadata["actions_job_conclusion"])


if __name__ == "__main__":
    unittest.main()
