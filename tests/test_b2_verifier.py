from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any, Mapping
from unittest import mock

from jsonschema import Draft202012Validator, FormatChecker

from tools.verify_b2 import (
    Invocation,
    VerifierInputError,
    _open_evidence_bytes,
    build_report,
    canonical_bytes,
    load_json,
    publish_report,
    run_fixture,
    run_suite,
    run_verification,
    validate_report_schema,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS_DIR = REPO_ROOT / "fixtures/b2/documents"
MANIFEST_PATH = REPO_ROOT / "fixtures/b2/manifest.v1.json"
VERIFICATION_SCHEMA_PATH = REPO_ROOT / "contracts/schemas/verification.v1.schema.json"

TASK_ID = "yurikuchumov-ux/ai-operating-system#18"
EXECUTION_ID = "22222222-2222-4222-8222-222222222222"
BASE_SHA = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"
HEAD_SHA = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1"


def _tmp_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="b2-verifier-test-", dir="/private/tmp"))


def _baseline_invocation() -> Invocation:
    identity = load_json(DOCUMENTS_DIR / "verifier-identity.json")
    return Invocation(
        verification_id="50000001-0000-4000-8000-000000000000",
        evaluated_at="2026-07-13T12:00:00Z",
        expected_task_id=TASK_ID,
        expected_execution_id=EXECUTION_ID,
        expected_base_sha=BASE_SHA,
        expected_subject_sha=HEAD_SHA,
        verifier_identity=identity,
    )


class B2FixtureOracleTests(unittest.TestCase):
    """Every scenario must match the external contract oracle: exit code,
    passed value, and exact failure-code set -- not executor prose."""

    def test_all_18_oracle_scenarios_match(self) -> None:
        exit_code, report = run_suite(MANIFEST_PATH, workdir=_tmp_dir())
        self.assertEqual(0, exit_code)
        self.assertTrue(report["valid"])
        self.assertEqual(18, report["summary"]["total"])
        self.assertEqual(18, report["summary"]["passed"])
        self.assertEqual(0, report["summary"]["failed"])
        self.assertFalse(report["authoritative_verifier"])
        self.assertEqual("B2", report["bootstrap_scope"])
        for fixture in report["fixtures"]:
            self.assertTrue(
                fixture["expectation_met"],
                "scenario {} did not match the oracle: {}".format(
                    fixture["id"], fixture["actual"]
                ),
            )

    def test_scenario_ids_match_contract_manifest(self) -> None:
        manifest = load_json(MANIFEST_PATH)
        ids = {fixture["id"] for fixture in manifest["fixtures"]}
        self.assertEqual(
            {
                "valid-change-approved",
                "reject-task-id-mismatch",
                "reject-execution-id-mismatch",
                "reject-base-sha-mismatch",
                "reject-head-sha-mismatch",
                "reject-scope-violation",
                "reject-empty-required-diff",
                "reject-required-check-failure",
                "reject-required-acceptance-failure",
                "reject-missing-artifact",
                "reject-artifact-hash-mismatch",
                "reject-unknown-predicate",
                "reject-unresolved-evidence-reference",
                "reject-review-subject-mismatch",
                "reject-review-lineage-conflict",
                "reject-review-ineligible",
                "reject-schema-invalid-input",
                "deterministic-repeat",
            },
            ids,
        )

    def test_every_report_is_schema_valid_verification_v1(self) -> None:
        validator = Draft202012Validator(
            load_json(VERIFICATION_SCHEMA_PATH), format_checker=FormatChecker()
        )
        manifest = load_json(MANIFEST_PATH)
        manifest_dir = MANIFEST_PATH.parent
        workdir = _tmp_dir()
        for fixture in manifest["fixtures"]:
            run_fixture(fixture, manifest_dir, workdir)
            output_dir = workdir / fixture["id"]
            for report_file in sorted(output_dir.glob("verification-*.json")):
                report = load_json(report_file)
                errors = list(validator.iter_errors(report))
                self.assertEqual(
                    [],
                    [error.message for error in errors],
                    "scenario {} produced a non-schema-valid report".format(fixture["id"]),
                )


class B2DeterminismTests(unittest.TestCase):
    def test_identical_trusted_input_is_byte_identical_across_runs(self) -> None:
        invocation = _baseline_invocation()
        _, first = run_verification(
            invocation,
            DOCUMENTS_DIR / "task-base.json",
            DOCUMENTS_DIR / "result-base.json",
            DOCUMENTS_DIR / "review-base.json",
            DOCUMENTS_DIR / "git-observation-base.json",
            DOCUMENTS_DIR / "evidence/good",
        )
        _, second = run_verification(
            invocation,
            DOCUMENTS_DIR / "task-base.json",
            DOCUMENTS_DIR / "result-base.json",
            DOCUMENTS_DIR / "review-base.json",
            DOCUMENTS_DIR / "git-observation-base.json",
            DOCUMENTS_DIR / "evidence/good",
        )
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertTrue(first["passed"])


class B2SemanticEvaluationTests(unittest.TestCase):
    def test_valid_change_evaluates_all_14_required_predicates(self) -> None:
        invocation = _baseline_invocation()
        _, report = run_verification(
            invocation,
            DOCUMENTS_DIR / "task-base.json",
            DOCUMENTS_DIR / "result-base.json",
            DOCUMENTS_DIR / "review-base.json",
            DOCUMENTS_DIR / "git-observation-base.json",
            DOCUMENTS_DIR / "evidence/good",
        )
        predicate_ids = [row["predicate_id"] for row in report["predicate_results"]]
        self.assertEqual(
            [
                "schema.instance.valid",
                "binding.task_id.equals",
                "binding.execution_id.equals",
                "git.base_sha.equals",
                "git.head_sha.equals",
                "git.changed_paths.allowed",
                "git.diff.non_empty",
                "process.exit_code.equals",
                "acceptance.required.passed",
                "artifact.exists",
                "artifact.sha256.matches",
                "review.subject_sha.equals",
                "review.eligibility.passed",
                "identity.lineage.no_overlap",
            ],
            predicate_ids,
        )
        self.assertTrue(all(row["passed"] for row in report["predicate_results"]))

    def test_schema_invalid_task_short_circuits_to_single_predicate_row(self) -> None:
        invocation = _baseline_invocation()
        _, report = run_verification(
            invocation,
            DOCUMENTS_DIR / "task-schema-invalid.json",
            DOCUMENTS_DIR / "result-base.json",
            DOCUMENTS_DIR / "review-base.json",
            DOCUMENTS_DIR / "git-observation-base.json",
            DOCUMENTS_DIR / "evidence/good",
        )
        self.assertFalse(report["passed"])
        self.assertEqual(1, len(report["predicate_results"]))
        self.assertEqual("schema.instance.valid", report["predicate_results"][0]["predicate_id"])
        self.assertEqual("schema_validation_failed", report["predicate_results"][0]["failure_code"])

    def test_missing_input_document_fails_closed_with_schema_validation_failed(self) -> None:
        invocation = _baseline_invocation()
        exit_code, report = run_verification(
            invocation,
            DOCUMENTS_DIR / "does-not-exist.json",
            DOCUMENTS_DIR / "result-base.json",
            DOCUMENTS_DIR / "review-base.json",
            DOCUMENTS_DIR / "git-observation-base.json",
            DOCUMENTS_DIR / "evidence/good",
        )
        self.assertEqual(1, exit_code)
        self.assertFalse(report["passed"])
        self.assertEqual(["schema_validation_failed"], [
            row["failure_code"] for row in report["predicate_results"] if row["failure_code"]
        ])
        validate_report_schema(report)


class B2EvidenceSecurityTests(unittest.TestCase):
    """Direct security/failure injection for the evidence-root trust boundary."""

    def test_symlinked_artifact_is_rejected(self) -> None:
        root = _tmp_dir()
        decoy = root / "decoy.txt"
        decoy.write_bytes(b"decoy bytes")
        (root / "linked.txt").symlink_to(decoy)
        with self.assertRaises(VerifierInputError):
            _open_evidence_bytes(root, "linked.txt")

    def test_path_escape_outside_evidence_root_is_rejected(self) -> None:
        root = _tmp_dir()
        (root / "inside").mkdir()
        outside = root.parent / "outside-secret.txt"
        outside.write_bytes(b"outside bytes")
        try:
            with self.assertRaises(VerifierInputError):
                _open_evidence_bytes(root, "../{}".format(outside.name))
        finally:
            outside.unlink()

    def test_absolute_path_is_rejected(self) -> None:
        root = _tmp_dir()
        target = root / "artifact.txt"
        target.write_bytes(b"data")
        with self.assertRaises(VerifierInputError):
            _open_evidence_bytes(root, "/etc/passwd")

    def test_non_regular_file_is_rejected(self) -> None:
        root = _tmp_dir()
        (root / "adir").mkdir()
        with self.assertRaises(VerifierInputError):
            _open_evidence_bytes(root, "adir")

    def test_intermediate_symlink_component_is_rejected(self) -> None:
        root = _tmp_dir()
        victim_dir = root / "victim"
        victim_dir.mkdir()
        (victim_dir / "secret.txt").write_bytes(b"secret bytes")
        (root / "link").symlink_to(victim_dir)
        with self.assertRaises(VerifierInputError):
            _open_evidence_bytes(root, "link/secret.txt")

    def test_missing_file_raises_file_not_found(self) -> None:
        root = _tmp_dir()
        with self.assertRaises(FileNotFoundError):
            _open_evidence_bytes(root, "missing.txt")

    def test_oversized_evidence_is_rejected(self) -> None:
        root = _tmp_dir()
        target = root / "big.bin"
        target.write_bytes(b"x" * (1024 * 1024 + 1))
        with self.assertRaises(VerifierInputError):
            _open_evidence_bytes(root, "big.bin")

    def test_mutation_during_read_is_detected(self) -> None:
        root = _tmp_dir()
        target = root / "mutating.txt"
        target.write_bytes(b"original bytes")
        real_fstat = os.fstat
        calls = {"count": 0}

        def flaky_fstat(fd):
            calls["count"] += 1
            result = real_fstat(fd)
            if calls["count"] == 2:
                # simulate a size change observed between the pre- and
                # post-read fstat calls
                return os.stat_result(
                    (
                        result.st_mode,
                        result.st_ino,
                        result.st_dev,
                        result.st_nlink,
                        result.st_uid,
                        result.st_gid,
                        result.st_size + 1,
                        int(result.st_atime),
                        int(result.st_mtime),
                        int(result.st_ctime),
                    )
                )
            return result

        with mock.patch("tools.verify_b2.os.fstat", side_effect=flaky_fstat):
            with self.assertRaises(VerifierInputError):
                _open_evidence_bytes(root, "mutating.txt")

    def test_rebinding_after_read_is_detected(self) -> None:
        root = _tmp_dir()
        target = root / "rebind.txt"
        replacement = root / "replacement.txt"
        target.write_bytes(b"same bytes")
        replacement.write_bytes(b"same bytes")
        replacement_stat = replacement.stat()
        with mock.patch("tools.verify_b2.os.stat", return_value=replacement_stat):
            with self.assertRaises(VerifierInputError):
                _open_evidence_bytes(root, "rebind.txt")

    def test_platform_without_no_follow_fails_closed(self) -> None:
        root = _tmp_dir()
        target = root / "no-no-follow.txt"
        target.write_bytes(b"data")
        with mock.patch.object(os, "O_NOFOLLOW", 0):
            with self.assertRaises(VerifierInputError):
                _open_evidence_bytes(root, "no-no-follow.txt")

    def test_valid_evidence_is_read_with_no_follow_flag(self) -> None:
        root = _tmp_dir()
        target = root / "good.txt"
        target.write_bytes(b"good bytes")
        real_open = os.open
        observed_flags = []

        def recording_open(path, flags, *args, **kwargs):
            observed_flags.append(flags)
            return real_open(path, flags, *args, **kwargs)

        with mock.patch("tools.verify_b2.os.open", side_effect=recording_open):
            data = _open_evidence_bytes(root, "good.txt")
        self.assertEqual(b"good bytes", data)
        # the second os.open call (the first opens the evidence-root
        # directory) must carry O_NOFOLLOW on the final component.
        self.assertEqual(2, len(observed_flags))
        self.assertEqual(os.O_NOFOLLOW, observed_flags[1] & os.O_NOFOLLOW)


class B2PublicationTests(unittest.TestCase):
    """Direct failure injection for output publication: never overwrite,
    never leave a partially written or missing-but-referenced final path."""

    @staticmethod
    def _staging_files(output_dir: Path):
        if not output_dir.exists():
            return []
        return sorted(output_dir.rglob("*.tmp"))

    def test_publish_never_overwrites_existing_output(self) -> None:
        output_dir = _tmp_dir()
        output_path = output_dir / "verification.json"
        publish_report(output_path, b'{"a":1}\n')
        original = output_path.read_bytes()
        with self.assertRaises(VerifierInputError):
            publish_report(output_path, b'{"a":2}\n')
        self.assertEqual(original, output_path.read_bytes())

    def test_write_failure_leaves_no_visible_output(self) -> None:
        output_dir = _tmp_dir()
        output_path = output_dir / "verification.json"
        with mock.patch(
            "tools.verify_b2.os.write", side_effect=OSError("simulated write failure")
        ):
            with self.assertRaises(VerifierInputError):
                publish_report(output_path, b'{"a":1}\n')
        self.assertFalse(output_path.exists())
        self.assertEqual([], self._staging_files(output_dir))

    def test_fsync_failure_leaves_no_visible_output(self) -> None:
        output_dir = _tmp_dir()
        output_path = output_dir / "verification.json"
        with mock.patch(
            "tools.verify_b2.os.fsync", side_effect=OSError("simulated fsync failure")
        ):
            with self.assertRaises(VerifierInputError):
                publish_report(output_path, b'{"a":1}\n')
        self.assertFalse(output_path.exists())
        self.assertEqual([], self._staging_files(output_dir))

    def test_link_failure_leaves_no_visible_output(self) -> None:
        output_dir = _tmp_dir()
        output_path = output_dir / "verification.json"
        with mock.patch(
            "tools.verify_b2.os.link", side_effect=OSError("simulated disk full")
        ):
            with self.assertRaises(VerifierInputError):
                publish_report(output_path, b'{"a":1}\n')
        self.assertFalse(output_path.exists())
        self.assertEqual([], self._staging_files(output_dir))

    def test_output_collision_with_pre_existing_unrelated_file_is_refused(self) -> None:
        output_dir = _tmp_dir()
        output_path = output_dir / "verification.json"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(b"pre-existing unrelated content")
        with self.assertRaises(VerifierInputError):
            publish_report(output_path, b'{"a":1}\n')
        self.assertEqual(b"pre-existing unrelated content", output_path.read_bytes())


def _write_json(path: Path, document: Mapping[str, Any]) -> Path:
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


class B2FalseSuccessRegressionTests(unittest.TestCase):
    """Attempt-1 evaluated these six inputs as passed=True / exit 0. Each must
    now fail closed with a concrete failure code -- not merely 'not pass'."""

    def setUp(self) -> None:
        self.workdir = _tmp_dir()
        self.task = load_json(DOCUMENTS_DIR / "task-base.json")
        self.result = load_json(DOCUMENTS_DIR / "result-base.json")
        self.review = load_json(DOCUMENTS_DIR / "review-base.json")
        self.git_observation = load_json(DOCUMENTS_DIR / "git-observation-base.json")
        self.evidence_root = DOCUMENTS_DIR / "evidence/good"

    def _run(self, task=None, result=None, review=None, git_observation=None):
        invocation = _baseline_invocation()
        return run_verification(
            invocation,
            _write_json(self.workdir / "task.json", task if task is not None else self.task),
            _write_json(self.workdir / "result.json", result if result is not None else self.result),
            _write_json(self.workdir / "review.json", review if review is not None else self.review),
            _write_json(
                self.workdir / "git-observation.json",
                git_observation if git_observation is not None else self.git_observation,
            ),
            self.evidence_root,
        )

    def _failure_codes(self, report) -> set:
        return {row["failure_code"] for row in report["predicate_results"] if row["failure_code"]}

    def test_1_unaccounted_denied_path_in_trusted_observation_is_scope_violation(self) -> None:
        git_observation = dict(self.git_observation)
        git_observation["changed_files"] = ["src/app.py", ".github/workflows/evil.yml"]
        exit_code, report = self._run(git_observation=git_observation)
        self.assertEqual(1, exit_code)
        self.assertFalse(report["passed"])
        self.assertIn("scope_violation", self._failure_codes(report))

    def test_2_result_base_sha_divergence_is_base_sha_mismatch(self) -> None:
        result = dict(self.result)
        result["base_sha"] = "9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f"
        exit_code, report = self._run(result=result)
        self.assertEqual(1, exit_code)
        self.assertFalse(report["passed"])
        self.assertIn("base_sha_mismatch", self._failure_codes(report))

    def test_3_review_task_id_divergence_is_task_id_mismatch(self) -> None:
        review = dict(self.review)
        review["task_id"] = "yurikuchumov-ux/ai-operating-system#99"
        exit_code, report = self._run(review=review)
        self.assertEqual(1, exit_code)
        self.assertFalse(report["passed"])
        self.assertIn("task_id_mismatch", self._failure_codes(report))

    def test_4_reviewer_executor_runtime_overlap_is_identity_conflict_despite_self_assertion(self) -> None:
        review = json.loads(json.dumps(self.review))
        review["reviewer_identity"]["agent_runtime_id"] = self.result["executor"]["identity"][
            "agent_runtime_id"
        ]
        # Self-asserts no overlap and eligible, even though the identities now
        # actually collide -- the verifier must not trust this assertion.
        for item in review["eligibility"]["overlap_results"]:
            if item["field"] == "agent_runtime_id":
                item["overlap"] = False
        review["eligibility"]["eligible"] = True
        exit_code, report = self._run(review=review)
        self.assertEqual(1, exit_code)
        self.assertFalse(report["passed"])
        self.assertIn("identity_conflict", self._failure_codes(report))

    def test_5_failed_terminal_status_cannot_verify_despite_green_checks(self) -> None:
        result = json.loads(json.dumps(self.result))
        result["status"] = "failed"
        result["terminal_reason"] = "check_failed"
        result["error"] = {"code": "check_failed", "message": "contract tests failed"}
        # checks and acceptance_results still claim success.
        exit_code, report = self._run(result=result)
        self.assertEqual(1, exit_code)
        self.assertFalse(report["passed"])
        self.assertIn("check_failed", self._failure_codes(report))

    def test_6_acceptance_result_parameters_diverge_from_criterion_is_acceptance_failed(self) -> None:
        result = json.loads(json.dumps(self.result))
        result["acceptance_results"][0]["parameters"] = {"value": 1}
        result["acceptance_results"][0]["passed"] = True
        exit_code, report = self._run(result=result)
        self.assertEqual(1, exit_code)
        self.assertFalse(report["passed"])
        self.assertIn("acceptance_failed", self._failure_codes(report))

    def test_authored_commits_diverge_from_trusted_observation_is_empty_diff(self) -> None:
        result = json.loads(json.dumps(self.result))
        result["authored_commits"] = ["ffffffffffffffffffffffffffffffffffffffff"]
        exit_code, report = self._run(result=result)
        self.assertEqual(1, exit_code)
        self.assertFalse(report["passed"])
        self.assertIn("empty_diff", self._failure_codes(report))

    def test_claimed_extra_path_not_in_trusted_observation_is_scope_violation(self) -> None:
        result = json.loads(json.dumps(self.result))
        result["changed_files"].append("src/not-observed.py")
        exit_code, report = self._run(result=result)
        self.assertEqual(1, exit_code)
        self.assertFalse(report["passed"])
        self.assertIn("scope_violation", self._failure_codes(report))

    def test_acceptance_result_evidence_diverging_from_linked_check_is_acceptance_failed(self) -> None:
        result = json.loads(json.dumps(self.result))
        result["acceptance_results"][0]["evidence_artifact_ids"] = []
        exit_code, report = self._run(result=result)
        self.assertEqual(1, exit_code)
        self.assertFalse(report["passed"])
        self.assertIn("acceptance_failed", self._failure_codes(report))

    def test_unknown_command_id_in_task_and_result_fails_closed(self) -> None:
        task = json.loads(json.dumps(self.task))
        result = json.loads(json.dumps(self.result))
        task["required_checks"][0]["command_id"] = "unknown.command"
        result["checks"][0]["command_id"] = "unknown.command"
        exit_code, report = self._run(task=task, result=result)
        self.assertEqual(1, exit_code)
        self.assertFalse(report["passed"])
        self.assertIn("check_failed", self._failure_codes(report))

    def test_eligible_true_with_nonempty_reason_codes_is_review_ineligible(self) -> None:
        review = json.loads(json.dumps(self.review))
        review["eligibility"]["eligible"] = True
        review["eligibility"]["reason_codes"] = ["self_asserted_warning"]
        exit_code, report = self._run(review=review)
        self.assertEqual(1, exit_code)
        self.assertFalse(report["passed"])
        self.assertIn("review_ineligible", self._failure_codes(report))


class B2ReportSchemaTests(unittest.TestCase):
    def test_build_report_is_schema_valid_for_a_failing_predicate(self) -> None:
        invocation = _baseline_invocation()
        from tools.verify_b2 import PredicateResult

        row = PredicateResult(
            "schema.instance.valid", False, {"errors": ["x"]}, (), "schema_validation_failed"
        )
        report = build_report(invocation, False, [row], [])
        validate_report_schema(report)
        self.assertFalse(report["passed"])
        self.assertEqual(invocation.expected_task_id, report["task_id"])
        self.assertEqual(invocation.verification_id, report["verification_id"])


if __name__ == "__main__":
    unittest.main()
