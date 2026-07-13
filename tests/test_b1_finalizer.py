from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from tools.finalize_b1 import (
    MAX_INPUT_BYTES,
    MAX_JSON_DEPTH,
    CandidateOutcome,
    FinalizerPolicyError,
    OverwriteRefused,
    build_result,
    canonical_bytes,
    detect_override_attempts,
    finalize,
    json_depth,
    load_candidate,
    load_json,
    load_trusted_observation,
    run_suite,
    validate_result_schema,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS_DIR = REPO_ROOT / "fixtures/b1/documents"
MANIFEST_PATH = REPO_ROOT / "fixtures/b1/manifest.v1.json"
RESULT_SCHEMA_PATH = REPO_ROOT / "contracts/schemas/result.v1.schema.json"


def _tmp_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="b1-finalizer-test-", dir="/private/tmp"))


class B1FinalizerFixtureSuiteTests(unittest.TestCase):
    def test_all_required_scenarios_pass(self) -> None:
        exit_code, report = run_suite(MANIFEST_PATH, workdir=_tmp_dir())
        self.assertEqual(0, exit_code)
        self.assertTrue(report["valid"])
        self.assertEqual(6, report["summary"]["total"])
        self.assertEqual(6, report["summary"]["passed"])
        self.assertEqual(0, report["summary"]["failed"])
        self.assertFalse(report["authoritative_verifier"])
        self.assertEqual("B1", report["bootstrap_scope"])
        fixture_ids = {fixture["id"] for fixture in report["fixtures"]}
        self.assertEqual(
            {
                "success",
                "executor-failure",
                "timeout",
                "malformed-candidate",
                "missing-candidate",
                "overwrite-refusal",
            },
            fixture_ids,
        )

    @staticmethod
    def _strip_workdir_paths(report: dict) -> dict:
        # `report.result_path` embeds the caller-chosen workdir, which is
        # intentionally a fresh directory per run_suite call. Everything else
        # (exit codes, status, terminal_reason, warnings, and the canonical
        # result's sha256) must still be byte-for-byte deterministic.
        stripped = copy.deepcopy(report)
        for fixture in stripped["fixtures"]:
            if fixture.get("report"):
                fixture["report"].pop("result_path", None)
            last_error = fixture["actual"].get("last_error")
            if last_error:
                fixture["actual"]["last_error"] = last_error.split(":", 1)[0]
        return stripped

    def test_suite_report_is_deterministic(self) -> None:
        first = run_suite(MANIFEST_PATH, workdir=_tmp_dir())
        second = run_suite(MANIFEST_PATH, workdir=_tmp_dir())
        self.assertEqual(
            json.dumps(self._strip_workdir_paths(first[1]), sort_keys=True),
            json.dumps(self._strip_workdir_paths(second[1]), sort_keys=True),
        )

    def test_success_executor_failure_timeout_are_schema_valid_result_v1(self) -> None:
        # This directly exercises AC-B1-2's three named scenarios against the
        # real contracts/schemas/result.v1.schema.json (not a local copy).
        validator = Draft202012Validator(
            load_json(RESULT_SCHEMA_PATH), format_checker=FormatChecker()
        )
        scenarios = {
            "success": ("observation-success.json", "candidate-success.json"),
            "executor-failure": (
                "observation-executor-failure.json",
                "candidate-executor-failure.json",
            ),
            "timeout": ("observation-timeout.json", "candidate-timeout-empty.json"),
        }
        workdir = _tmp_dir()
        for scenario, (observation_name, candidate_name) in scenarios.items():
            output_dir = workdir / scenario
            observation = DOCUMENTS_DIR / observation_name
            candidate = DOCUMENTS_DIR / candidate_name
            finalize(observation, candidate, output_dir)
            result = load_json(output_dir / "result.json")
            errors = list(validator.iter_errors(result))
            self.assertEqual([], [error.message for error in errors])


class B1FinalizerTrustBoundaryTests(unittest.TestCase):
    def test_candidate_cannot_override_trusted_fields(self) -> None:
        output_dir = _tmp_dir() / "trust-boundary"
        finalize(
            DOCUMENTS_DIR / "observation-success.json",
            DOCUMENTS_DIR / "candidate-success.json",
            output_dir,
        )
        result = load_json(output_dir / "result.json")
        # candidate-success.json claims status no_change_required, a foreign
        # task_id, a different head_sha, and an attacker-controlled
        # finalized_by/executor identity. None of that may leak into the
        # finalized result: trusted observation always wins.
        self.assertEqual("change_proposed", result["status"])
        self.assertEqual("yurikuchumov-ux/ai-operating-system#18", result["task_id"])
        self.assertEqual(
            "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", result["head_sha"]
        )
        self.assertEqual("b1-result-finalizer.v1", result["finalized_by"]["component_id"])
        self.assertEqual(
            "human-supervised-claude-code", result["executor"]["adapter"]
        )
        self.assertIn("candidate_field_override_ignored:status", result["warnings"])
        self.assertIn("candidate_field_override_ignored:head_sha", result["warnings"])
        self.assertIn("candidate_field_override_ignored:task_id", result["warnings"])
        self.assertIn("candidate_field_override_ignored:finalized_by", result["warnings"])
        self.assertIn("candidate_field_override_ignored:executor", result["warnings"])

    def test_candidate_raw_bytes_are_preserved_as_hash_addressed_evidence(self) -> None:
        output_dir = _tmp_dir() / "evidence"
        finalize(
            DOCUMENTS_DIR / "observation-success.json",
            DOCUMENTS_DIR / "candidate-success.json",
            output_dir,
        )
        result = load_json(output_dir / "result.json")
        raw = (DOCUMENTS_DIR / "candidate-success.json").read_bytes()
        import hashlib

        digest = hashlib.sha256(raw).hexdigest()
        artifact_ids = {artifact["id"]: artifact for artifact in result["artifacts"]}
        self.assertIn("candidate-raw", artifact_ids)
        self.assertEqual(digest, artifact_ids["candidate-raw"]["sha256"])
        evidence_path = output_dir / "evidence" / "{}.raw".format(digest)
        self.assertTrue(evidence_path.is_file())
        self.assertEqual(raw, evidence_path.read_bytes())

    def test_malformed_candidate_still_finalizes_one_valid_failed_result(self) -> None:
        output_dir = _tmp_dir() / "malformed"
        finalize(
            DOCUMENTS_DIR / "observation-malformed-candidate.json",
            DOCUMENTS_DIR / "candidate-malformed.raw",
            output_dir,
        )
        result = load_json(output_dir / "result.json")
        self.assertEqual("failed", result["status"])
        self.assertIn("candidate_malformed_json", result["warnings"])
        # the unparsable raw candidate is still preserved as evidence
        self.assertEqual(1, len(result["artifacts"]))

    def test_missing_candidate_still_finalizes_one_valid_failed_result(self) -> None:
        output_dir = _tmp_dir() / "missing"
        finalize(
            DOCUMENTS_DIR / "observation-missing-candidate.json",
            None,
            output_dir,
        )
        result = load_json(output_dir / "result.json")
        self.assertEqual("failed", result["status"])
        self.assertIn("candidate_missing", result["warnings"])
        self.assertEqual([], result["artifacts"])

    def test_empty_candidate_file_is_treated_as_a_distinct_fault(self) -> None:
        output_dir = _tmp_dir() / "timeout"
        finalize(
            DOCUMENTS_DIR / "observation-timeout.json",
            DOCUMENTS_DIR / "candidate-timeout-empty.json",
            output_dir,
        )
        result = load_json(output_dir / "result.json")
        self.assertEqual("failed", result["status"])
        self.assertEqual("timeout", result["terminal_reason"])
        self.assertIn("candidate_empty", result["warnings"])

    def test_observation_missing_required_field_fails_closed_without_writing_output(
        self,
    ) -> None:
        observation = json.loads(
            (DOCUMENTS_DIR / "observation-success.json").read_text()
        )
        del observation["git_observation"]["base_sha"]
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            tmp_path = Path(tmp)
            observation_path = tmp_path / "observation.json"
            observation_path.write_text(json.dumps(observation))
            output_dir = tmp_path / "out"
            with self.assertRaises(FinalizerPolicyError):
                finalize(observation_path, None, output_dir)
            self.assertFalse((output_dir / "result.json").exists())

    def test_observation_oversized_fails_closed(self) -> None:
        observation = json.loads(
            (DOCUMENTS_DIR / "observation-success.json").read_text()
        )
        observation["warnings"] = ["x" * (MAX_INPUT_BYTES + 1)]
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            tmp_path = Path(tmp)
            observation_path = tmp_path / "observation.json"
            observation_path.write_text(json.dumps(observation))
            with self.assertRaises(FinalizerPolicyError):
                load_trusted_observation(observation_path)

    def test_candidate_oversized_is_bounded_and_not_stored(self) -> None:
        observation = load_json(DOCUMENTS_DIR / "observation-success.json")
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            tmp_path = Path(tmp)
            candidate_path = tmp_path / "candidate.json"
            candidate_path.write_bytes(b'{"a":"' + b"x" * (MAX_INPUT_BYTES + 1) + b'"}')
            outcome = load_candidate(candidate_path, observation)
            self.assertEqual("oversized", outcome.fault)
            self.assertIsNone(outcome.raw)

    def test_candidate_excessive_depth_is_bounded(self) -> None:
        observation = load_json(DOCUMENTS_DIR / "observation-success.json")
        nested: dict = {"leaf": True}
        for _ in range(MAX_JSON_DEPTH + 4):
            nested = {"nested": nested}
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            tmp_path = Path(tmp)
            candidate_path = tmp_path / "candidate.json"
            candidate_path.write_text(json.dumps(nested))
            outcome = load_candidate(candidate_path, observation)
            self.assertEqual("too_deep", outcome.fault)

    def test_json_depth_helper(self) -> None:
        self.assertEqual(0, json_depth("flat"))
        self.assertEqual(1, json_depth({"a": 1}))
        self.assertEqual(2, json_depth({"a": {"b": 1}}))
        self.assertEqual(2, json_depth({"a": [1, 2]}))


class B1FinalizerExactlyOnceTests(unittest.TestCase):
    def test_second_finalize_into_same_output_dir_is_refused(self) -> None:
        output_dir = _tmp_dir() / "exactly-once"
        finalize(
            DOCUMENTS_DIR / "observation-success.json",
            DOCUMENTS_DIR / "candidate-success.json",
            output_dir,
        )
        original = (output_dir / "result.json").read_bytes()
        with self.assertRaises(OverwriteRefused):
            finalize(
                DOCUMENTS_DIR / "observation-executor-failure.json",
                DOCUMENTS_DIR / "candidate-executor-failure.json",
                output_dir,
            )
        # the original artifact is untouched by the refused second attempt
        self.assertEqual(original, (output_dir / "result.json").read_bytes())

    def test_canonical_json_is_deterministic_regardless_of_build_order(self) -> None:
        observation = load_json(DOCUMENTS_DIR / "observation-success.json")
        candidate = CandidateOutcome(raw=b"{}", parsed={}, fault=None)
        first = canonical_bytes(build_result(observation, candidate))
        second = canonical_bytes(build_result(copy.deepcopy(observation), candidate))
        self.assertEqual(first, second)
        self.assertNotIn(b" ", first.rstrip(b"\n"))

    def test_built_result_that_would_fail_schema_validation_is_rejected(self) -> None:
        observation = load_json(DOCUMENTS_DIR / "observation-success.json")
        candidate = CandidateOutcome(raw=None, parsed=None, fault=None)
        result = build_result(observation, candidate)
        result["status"] = "not-a-real-status"
        with self.assertRaises(FinalizerPolicyError):
            validate_result_schema(result)

    def test_detect_override_attempts_ignores_benign_candidate_fields(self) -> None:
        observation = load_json(DOCUMENTS_DIR / "observation-success.json")
        benign_candidate = {"summary": "no conflicting claims here"}
        self.assertEqual((), detect_override_attempts(observation, benign_candidate))


class B1FinalizerEvidenceBeforeResultTests(unittest.TestCase):
    """Regression coverage for the evidence-before-result publication invariant."""

    def test_evidence_storage_failure_prevents_result_publication(self) -> None:
        output_dir = _tmp_dir() / "evidence-before-result"
        output_dir.mkdir(parents=True)
        # Occupy the evidence path with a plain file so evidence storage
        # fails before result.json is ever written.
        (output_dir / "evidence").write_bytes(b"not a directory")
        with self.assertRaises(OSError):
            finalize(
                DOCUMENTS_DIR / "observation-success.json",
                DOCUMENTS_DIR / "candidate-success.json",
                output_dir,
            )
        self.assertFalse((output_dir / "result.json").exists())

    def test_conflicting_preexisting_evidence_fails_closed_without_publishing(
        self,
    ) -> None:
        output_dir = _tmp_dir() / "conflicting-evidence"
        raw = (DOCUMENTS_DIR / "candidate-success.json").read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        evidence_dir = output_dir / "evidence"
        evidence_dir.mkdir(parents=True)
        (evidence_dir / "{}.raw".format(digest)).write_bytes(b"tampered evidence content")
        with self.assertRaises(FinalizerPolicyError):
            finalize(
                DOCUMENTS_DIR / "observation-success.json",
                DOCUMENTS_DIR / "candidate-success.json",
                output_dir,
            )
        self.assertFalse((output_dir / "result.json").exists())

    def test_symlinked_preexisting_evidence_fails_closed_without_publishing(
        self,
    ) -> None:
        output_dir = _tmp_dir() / "symlinked-evidence"
        raw = (DOCUMENTS_DIR / "candidate-success.json").read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        evidence_dir = output_dir / "evidence"
        evidence_dir.mkdir(parents=True)
        decoy = output_dir / "decoy.raw"
        decoy.write_bytes(raw)
        (evidence_dir / "{}.raw".format(digest)).symlink_to(decoy)
        with self.assertRaises(FinalizerPolicyError):
            finalize(
                DOCUMENTS_DIR / "observation-success.json",
                DOCUMENTS_DIR / "candidate-success.json",
                output_dir,
            )
        self.assertFalse((output_dir / "result.json").exists())

    def test_non_regular_preexisting_evidence_fails_closed_without_publishing(
        self,
    ) -> None:
        output_dir = _tmp_dir() / "non-regular-evidence"
        raw = (DOCUMENTS_DIR / "candidate-success.json").read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        evidence_dir = output_dir / "evidence"
        evidence_dir.mkdir(parents=True)
        (evidence_dir / "{}.raw".format(digest)).mkdir()
        with self.assertRaises(FinalizerPolicyError):
            finalize(
                DOCUMENTS_DIR / "observation-success.json",
                DOCUMENTS_DIR / "candidate-success.json",
                output_dir,
            )
        self.assertFalse((output_dir / "result.json").exists())

    def test_matching_preexisting_evidence_is_accepted_and_result_publishes(
        self,
    ) -> None:
        output_dir = _tmp_dir() / "matching-evidence"
        raw = (DOCUMENTS_DIR / "candidate-success.json").read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        evidence_dir = output_dir / "evidence"
        evidence_dir.mkdir(parents=True)
        (evidence_dir / "{}.raw".format(digest)).write_bytes(raw)
        finalize(
            DOCUMENTS_DIR / "observation-success.json",
            DOCUMENTS_DIR / "candidate-success.json",
            output_dir,
        )
        self.assertTrue((output_dir / "result.json").exists())

    def test_repeat_attempt_against_existing_result_adds_no_new_evidence(
        self,
    ) -> None:
        output_dir = _tmp_dir() / "no-evidence-on-repeat"
        finalize(
            DOCUMENTS_DIR / "observation-success.json",
            DOCUMENTS_DIR / "candidate-success.json",
            output_dir,
        )
        evidence_before = sorted((output_dir / "evidence").iterdir())
        # A different observation/candidate pair hashes to different
        # evidence bytes; the refused repeat must not add that new evidence
        # even though it never conflicts with what is already on disk.
        with self.assertRaises(OverwriteRefused):
            finalize(
                DOCUMENTS_DIR / "observation-executor-failure.json",
                DOCUMENTS_DIR / "candidate-executor-failure.json",
                output_dir,
            )
        evidence_after = sorted((output_dir / "evidence").iterdir())
        self.assertEqual(evidence_before, evidence_after)


if __name__ == "__main__":
    unittest.main()
