from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from tools.validate_b0 import (
    MAX_FIXTURE_DOCUMENT_BYTES,
    MAX_FIXTURE_MUTATIONS,
    MAX_JSON_POINTER_DEPTH,
    ContractValidator,
    FixtureResourceLimitError,
    apply_fixture_mutation,
    load_json,
    registry_semantic_findings,
    required_fixture_coverage,
    run_suite,
    validate_fixture,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "fixtures/b0/manifest.v1.json"


class B0ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validator = ContractValidator()
        cls.manifest = load_json(MANIFEST_PATH)

    def test_all_declared_fixtures_match_expected_outcomes(self) -> None:
        exit_code, report = run_suite(MANIFEST_PATH)
        self.assertEqual(0, exit_code)
        self.assertTrue(report["valid"])
        self.assertEqual(25, report["summary"]["total"])
        self.assertEqual(25, report["summary"]["passed"])
        self.assertEqual(0, report["summary"]["failed"])
        self.assertEqual(13, report["coverage"]["required"])
        self.assertEqual([], report["coverage"]["missing"])
        self.assertEqual(13, len(report["coverage"]["covered"]))
        self.assertFalse(report["authoritative_verifier"])
        self.assertEqual("B0", report["bootstrap_scope"])

    def test_suite_report_is_deterministic(self) -> None:
        first = run_suite(MANIFEST_PATH)
        second = run_suite(MANIFEST_PATH)
        self.assertEqual(first, second)
        self.assertEqual(
            json.dumps(first[1], sort_keys=True),
            json.dumps(second[1], sort_keys=True),
        )

    def test_fixture_hash_mismatch_fails_closed(self) -> None:
        fixture = copy.deepcopy(self.manifest["fixtures"][0])
        fixture["documents"][0]["sha256"] = "0" * 64
        result = validate_fixture(self.validator, fixture, MANIFEST_PATH.parent)
        self.assertFalse(result["actual"]["valid"])
        self.assertIn("fixture_hash_mismatch", result["actual"]["error_codes"])
        self.assertFalse(result["expectation_met"])

    def test_missing_fixture_file_fails_closed(self) -> None:
        fixture = copy.deepcopy(self.manifest["fixtures"][0])
        fixture["documents"][0]["path"] = "documents/not-present.json"
        result = validate_fixture(self.validator, fixture, MANIFEST_PATH.parent)
        self.assertFalse(result["actual"]["valid"])
        self.assertIn("fixture_file_missing", result["actual"]["error_codes"])
        self.assertFalse(result["expectation_met"])

    def test_result_check_evidence_uses_direct_artifact_ids(self) -> None:
        result_schema = load_json(REPO_ROOT / "contracts/schemas/result.v1.schema.json")
        check_properties = result_schema["properties"]["checks"]["items"]["properties"]
        self.assertIn("evidence_artifact_ids", check_properties)
        self.assertNotIn("evidence_path", check_properties)

    def test_command_registry_uses_argv_arrays(self) -> None:
        registry = load_json(REPO_ROOT / "contracts/registries/commands.v1.json")
        for entry in registry["entries"]:
            self.assertIsInstance(entry["argv"], list)
            self.assertGreater(len(entry["argv"]), 0)
            self.assertTrue(all(isinstance(value, str) for value in entry["argv"]))

    def test_required_fixture_removal_fails_closed(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["fixtures"] = [
            fixture
            for fixture in manifest["fixtures"]
            if fixture["id"] != "reject-false-success"
        ]
        findings, coverage = required_fixture_coverage(self.validator, manifest)
        self.assertIn("required_fixture_missing", {item.code for item in findings})
        self.assertEqual(["reject-false-success"], coverage["missing"])

    def test_required_fixture_expectation_change_fails_closed(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        fixture = next(
            item for item in manifest["fixtures"] if item["id"] == "reject-false-success"
        )
        fixture["expected"]["error_codes"] = ["schema_validation_failed"]
        findings, _ = required_fixture_coverage(self.validator, manifest)
        self.assertIn(
            "required_fixture_expectation_mismatch", {item.code for item in findings}
        )

    def test_json_pointer_depth_is_bounded(self) -> None:
        mutation = {
            "document_type": "task",
            "op": "replace",
            "path": "/" + "/".join(["nested"] * (MAX_JSON_POINTER_DEPTH + 1)),
            "value": "x",
        }
        with self.assertRaises(FixtureResourceLimitError):
            apply_fixture_mutation({}, mutation)

    def test_mutated_document_size_is_bounded(self) -> None:
        mutation = {
            "document_type": "task",
            "op": "replace",
            "path": "/value",
            "value": "x" * (MAX_FIXTURE_DOCUMENT_BYTES + 1),
        }
        with self.assertRaises(FixtureResourceLimitError):
            apply_fixture_mutation({"value": "ok"}, mutation)

    def test_fixture_mutation_count_is_bounded(self) -> None:
        fixture = copy.deepcopy(self.manifest["fixtures"][0])
        fixture["mutations"] = [
            {
                "document_type": "task",
                "op": "replace",
                "path": "/objective",
                "value": "bounded",
            }
            for _ in range(MAX_FIXTURE_MUTATIONS + 1)
        ]
        result = validate_fixture(self.validator, fixture, MANIFEST_PATH.parent)
        self.assertIn("fixture_resource_limit_exceeded", result["actual"]["error_codes"])

    def test_registry_version_compatibility_is_explicit(self) -> None:
        registry = copy.deepcopy(
            load_json(REPO_ROOT / "contracts/registries/commands.v1.json")
        )
        registry["schema_version"] = "2.0.0"
        findings = registry_semantic_findings("command_registry", registry)
        self.assertIn("unsupported_registry_version", {item.code for item in findings})

    def test_duplicate_predicate_semantics_are_rejected(self) -> None:
        registry = copy.deepcopy(
            load_json(REPO_ROOT / "contracts/registries/predicates.v1.json")
        )
        duplicate = copy.deepcopy(registry["entries"][0])
        duplicate["id"] = "duplicate.predicate"
        registry["entries"].append(duplicate)
        findings = registry_semantic_findings("predicate_registry", registry)
        self.assertIn("duplicate_predicate_semantics", {item.code for item in findings})

    def test_duplicate_command_implementations_are_rejected(self) -> None:
        registry = copy.deepcopy(
            load_json(REPO_ROOT / "contracts/registries/commands.v1.json")
        )
        duplicate = copy.deepcopy(registry["entries"][0])
        duplicate["id"] = "duplicate.command"
        registry["entries"].append(duplicate)
        findings = registry_semantic_findings("command_registry", registry)
        self.assertIn(
            "duplicate_command_implementation", {item.code for item in findings}
        )


if __name__ == "__main__":
    unittest.main()
