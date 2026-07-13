from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from tools.validate_b0 import ContractValidator, load_json, run_suite, validate_fixture


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
        self.assertEqual(19, report["summary"]["total"])
        self.assertEqual(19, report["summary"]["passed"])
        self.assertEqual(0, report["summary"]["failed"])
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


if __name__ == "__main__":
    unittest.main()
