from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker

from tools.validate_canonical_repositories import (
    CanonicalRepositoryValidator,
    repository_semantic_findings,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "contracts/schemas/canonical-repositories.v1.schema.json"
REGISTRY_PATH = REPO_ROOT / "contracts/canonical-repositories.v1.json"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


class CanonicalRepositorySchemaTests(unittest.TestCase):
    """Test that the canonical repository schema is valid and includes required metadata."""

    def test_schema_is_valid_json_schema(self) -> None:
        """The schema must be a valid JSON Schema Draft 2020-12."""
        schema = _load_json(SCHEMA_PATH)
        Draft202012Validator.check_schema(schema)

    def test_schema_has_required_top_level_metadata(self) -> None:
        """The schema must include schema_version 1.0.0 as a required top-level field."""
        schema = _load_json(SCHEMA_PATH)
        self.assertIn("required", schema)
        self.assertIn("schema_version", schema["required"])
        self.assertIn("properties", schema)
        self.assertIn("schema_version", schema["properties"])
        self.assertEqual(schema["properties"]["schema_version"], {"const": "1.0.0"})

    def test_schema_has_registry_type_metadata(self) -> None:
        """The schema must include registry_type as canonical_repository."""
        schema = _load_json(SCHEMA_PATH)
        self.assertIn("registry_type", schema["required"])
        self.assertIn("registry_type", schema["properties"])
        self.assertEqual(
            schema["properties"]["registry_type"], {"const": "canonical_repository"}
        )

    def test_schema_requires_entries(self) -> None:
        """The schema must require entries array."""
        schema = _load_json(SCHEMA_PATH)
        self.assertIn("entries", schema["required"])

    def test_schema_defines_sha_as_lowercase_hex(self) -> None:
        """The schema must define SHA as lowercase hexadecimal pattern."""
        schema = _load_json(SCHEMA_PATH)
        self.assertIn("$defs", schema)
        self.assertIn("sha", schema["$defs"])
        sha_def = schema["$defs"]["sha"]
        self.assertEqual(sha_def["type"], "string")
        self.assertEqual(sha_def["pattern"], "^[0-9a-f]{40}$")


class CanonicalRepositoryRegistryTests(unittest.TestCase):
    """Test that the canonical repository registry is valid."""

    def test_registry_is_valid_json(self) -> None:
        """The registry must be valid JSON."""
        registry = _load_json(REGISTRY_PATH)
        self.assertIsInstance(registry, dict)

    def test_registry_has_schema_version(self) -> None:
        """The registry must include schema_version 1.0.0."""
        registry = _load_json(REGISTRY_PATH)
        self.assertEqual(registry.get("schema_version"), "1.0.0")

    def test_registry_has_registry_type(self) -> None:
        """The registry must include registry_type canonical_repository."""
        registry = _load_json(REGISTRY_PATH)
        self.assertEqual(registry.get("registry_type"), "canonical_repository")

    def test_registry_validates_against_schema(self) -> None:
        """The registry must validate against its schema."""
        schema = _load_json(SCHEMA_PATH)
        registry = _load_json(REGISTRY_PATH)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        errors = list(validator.iter_errors(registry))
        self.assertEqual(errors, [], f"Validation errors: {errors}")

    def test_registry_has_unique_ids(self) -> None:
        """All registry entry IDs must be unique."""
        registry = _load_json(REGISTRY_PATH)
        entries = registry.get("entries", [])
        ids = [entry.get("id") for entry in entries]
        self.assertEqual(len(ids), len(set(ids)), "Duplicate IDs found")

    def test_registry_has_unique_repository_specs(self) -> None:
        """All repository owner/name combinations must be unique."""
        registry = _load_json(REGISTRY_PATH)
        entries = registry.get("entries", [])
        repo_specs = [
            f"{entry.get('repository_owner')}/{entry.get('repository_name')}"
            for entry in entries
        ]
        self.assertEqual(
            len(repo_specs), len(set(repo_specs)), "Duplicate repository specs found"
        )


class CanonicalRepositoryValidatorTests(unittest.TestCase):
    """Test the canonical repository validator."""

    def setUp(self) -> None:
        self.validator = CanonicalRepositoryValidator()
        self.valid_registry = {
            "schema_version": "1.0.0",
            "registry_type": "canonical_repository",
            "entries": [
                {
                    "id": "canonical.example_repo",
                    "repository_owner": "example-org",
                    "repository_name": "example-repo",
                    "repository_sha": "abc123def456abc123def456abc123def456abc1",
                }
            ],
        }

    def test_valid_registry_passes(self) -> None:
        """A valid registry should produce no findings."""
        findings = self.validator.validate_document(self.valid_registry)
        self.assertEqual(findings, [])

    def test_missing_schema_version_fails(self) -> None:
        """Registry without schema_version should fail."""
        invalid = copy.deepcopy(self.valid_registry)
        del invalid["schema_version"]
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)
        codes = [f.code for f in findings]
        self.assertIn("schema_validation_failed", codes)

    def test_wrong_schema_version_fails(self) -> None:
        """Registry with wrong schema_version should fail."""
        invalid = copy.deepcopy(self.valid_registry)
        invalid["schema_version"] = "2.0.0"
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)
        codes = [f.code for f in findings]
        self.assertIn("unsupported_schema_version", codes)

    def test_duplicate_ids_fail(self) -> None:
        """Registry with duplicate IDs should fail."""
        invalid = copy.deepcopy(self.valid_registry)
        invalid["entries"].append(copy.deepcopy(invalid["entries"][0]))
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)
        codes = [f.code for f in findings]
        self.assertIn("duplicate_id", codes)

    def test_duplicate_repository_specs_fail(self) -> None:
        """Registry with duplicate repository specs should fail."""
        invalid = copy.deepcopy(self.valid_registry)
        duplicate_entry = copy.deepcopy(invalid["entries"][0])
        duplicate_entry["id"] = "canonical.example_repo_2"
        invalid["entries"].append(duplicate_entry)
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)
        codes = [f.code for f in findings]
        self.assertIn("duplicate_repository_specification", codes)

    def test_uppercase_sha_rejected_by_schema_validation(self) -> None:
        """Uppercase SHA characters should be rejected by schema validation, not semantic check.

        This test proves that uppercase/mixed-case SHA mutations are deterministically
        rejected by schema_validation_failed (the earliest production code path) rather
        than reaching the later repository_sha_not_lowercase semantic check.
        """
        invalid = copy.deepcopy(self.valid_registry)
        # Use uppercase SHA - this should fail schema validation pattern check
        invalid["entries"][0]["repository_sha"] = "ABC123DEF456ABC123DEF456ABC123DEF456ABC1"
        findings = self.validator.validate_document(invalid)

        # Assert that findings exist
        self.assertTrue(len(findings) > 0, "Expected validation to fail for uppercase SHA")

        # Assert that schema_validation_failed is the error code (earliest check)
        codes = [f.code for f in findings]
        self.assertIn("schema_validation_failed", codes,
                     "Uppercase SHA should fail at schema validation, not semantic check")

        # Assert that repository_sha_not_lowercase is NOT in the codes
        # (because we never reach the semantic check - schema validation fails first)
        self.assertNotIn("repository_sha_not_lowercase", codes,
                        "Should not reach semantic repository_sha_not_lowercase check")

    def test_mixed_case_sha_rejected_by_schema_validation(self) -> None:
        """Mixed-case SHA should be rejected by schema validation, not semantic check.

        This test proves the same deterministic behavior for mixed-case mutations.
        """
        invalid = copy.deepcopy(self.valid_registry)
        # Use mixed-case SHA
        invalid["entries"][0]["repository_sha"] = "aBc123DeF456aBc123DeF456aBc123DeF456aBc1"
        findings = self.validator.validate_document(invalid)

        self.assertTrue(len(findings) > 0)
        codes = [f.code for f in findings]
        self.assertIn("schema_validation_failed", codes)
        self.assertNotIn("repository_sha_not_lowercase", codes)

    def test_semantic_lowercase_check_still_exists(self) -> None:
        """The repository_sha_not_lowercase semantic check should still exist for completeness.

        While the schema pattern ^[0-9a-f]{40}$ already rejects non-lowercase SHAs,
        the semantic check provides defense in depth and clearer error messages.
        This test verifies the semantic check code path exists and works correctly
        when bypassing schema validation (e.g., in unit tests of the semantic layer).
        """
        # Create a document that would pass schema but test semantic check directly
        document = {
            "schema_version": "1.0.0",
            "registry_type": "canonical_repository",
            "entries": [
                {
                    "id": "canonical.test",
                    "repository_owner": "test",
                    "repository_name": "test",
                    "repository_sha": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                }
            ],
        }

        # Call semantic check directly
        findings = repository_semantic_findings(document)
        codes = [f.code for f in findings]
        self.assertIn("repository_sha_not_lowercase", codes,
                     "Semantic check should detect non-lowercase SHA")

    def test_short_sha_fails_schema_validation(self) -> None:
        """SHA with incorrect length should fail schema validation."""
        invalid = copy.deepcopy(self.valid_registry)
        invalid["entries"][0]["repository_sha"] = "abc123"  # Too short
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)
        codes = [f.code for f in findings]
        self.assertIn("schema_validation_failed", codes)

    def test_sha_with_invalid_characters_fails_schema_validation(self) -> None:
        """SHA with non-hex characters should fail schema validation."""
        invalid = copy.deepcopy(self.valid_registry)
        invalid["entries"][0]["repository_sha"] = "ghijklmnopqrstuvwxyzghijklmnopqrstuvwxy"
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)
        codes = [f.code for f in findings]
        self.assertIn("schema_validation_failed", codes)

    def test_invalid_registry_id_pattern_fails(self) -> None:
        """Registry ID must follow the pattern."""
        invalid = copy.deepcopy(self.valid_registry)
        invalid["entries"][0]["id"] = "InvalidId"  # Must be lowercase with separators
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)
        codes = [f.code for f in findings]
        self.assertIn("schema_validation_failed", codes)

    def test_empty_entries_fails(self) -> None:
        """Registry must have at least one entry."""
        invalid = copy.deepcopy(self.valid_registry)
        invalid["entries"] = []
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)
        codes = [f.code for f in findings]
        self.assertIn("schema_validation_failed", codes)

    def test_additional_properties_rejected(self) -> None:
        """Registry should not allow additional properties."""
        invalid = copy.deepcopy(self.valid_registry)
        invalid["extra_field"] = "not allowed"
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)
        codes = [f.code for f in findings]
        self.assertIn("schema_validation_failed", codes)

    def test_entry_additional_properties_rejected(self) -> None:
        """Entry should not allow additional properties."""
        invalid = copy.deepcopy(self.valid_registry)
        invalid["entries"][0]["extra_field"] = "not allowed"
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)
        codes = [f.code for f in findings]
        self.assertIn("schema_validation_failed", codes)


class CanonicalRepositoryAdversarialTests(unittest.TestCase):
    """Adversarial mutation tests to ensure fail-closed validation."""

    def setUp(self) -> None:
        self.validator = CanonicalRepositoryValidator()
        self.baseline = {
            "schema_version": "1.0.0",
            "registry_type": "canonical_repository",
            "entries": [
                {
                    "id": "canonical.test_repo",
                    "repository_owner": "test-owner",
                    "repository_name": "test-repo",
                    "repository_sha": "1234567890abcdef1234567890abcdef12345678",
                }
            ],
        }

    def test_null_schema_version_rejected(self) -> None:
        """Null schema_version should be rejected."""
        invalid = copy.deepcopy(self.baseline)
        invalid["schema_version"] = None
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)

    def test_null_registry_type_rejected(self) -> None:
        """Null registry_type should be rejected."""
        invalid = copy.deepcopy(self.baseline)
        invalid["registry_type"] = None
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)

    def test_null_entries_rejected(self) -> None:
        """Null entries should be rejected."""
        invalid = copy.deepcopy(self.baseline)
        invalid["entries"] = None
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)

    def test_null_entry_id_rejected(self) -> None:
        """Null entry ID should be rejected."""
        invalid = copy.deepcopy(self.baseline)
        invalid["entries"][0]["id"] = None
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)

    def test_null_repository_owner_rejected(self) -> None:
        """Null repository_owner should be rejected."""
        invalid = copy.deepcopy(self.baseline)
        invalid["entries"][0]["repository_owner"] = None
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)

    def test_null_repository_name_rejected(self) -> None:
        """Null repository_name should be rejected."""
        invalid = copy.deepcopy(self.baseline)
        invalid["entries"][0]["repository_name"] = None
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)

    def test_null_repository_sha_rejected(self) -> None:
        """Null repository_sha should be rejected."""
        invalid = copy.deepcopy(self.baseline)
        invalid["entries"][0]["repository_sha"] = None
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)

    def test_empty_string_id_rejected(self) -> None:
        """Empty string ID should be rejected."""
        invalid = copy.deepcopy(self.baseline)
        invalid["entries"][0]["id"] = ""
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)

    def test_empty_string_repository_owner_rejected(self) -> None:
        """Empty string repository_owner should be rejected."""
        invalid = copy.deepcopy(self.baseline)
        invalid["entries"][0]["repository_owner"] = ""
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)

    def test_empty_string_repository_name_rejected(self) -> None:
        """Empty string repository_name should be rejected."""
        invalid = copy.deepcopy(self.baseline)
        invalid["entries"][0]["repository_name"] = ""
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)

    def test_empty_string_repository_sha_rejected(self) -> None:
        """Empty string repository_sha should be rejected."""
        invalid = copy.deepcopy(self.baseline)
        invalid["entries"][0]["repository_sha"] = ""
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)

    def test_repository_owner_with_slash_rejected(self) -> None:
        """Repository owner with slash should be rejected."""
        invalid = copy.deepcopy(self.baseline)
        invalid["entries"][0]["repository_owner"] = "owner/with/slash"
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)

    def test_repository_name_with_slash_rejected(self) -> None:
        """Repository name with slash should be rejected."""
        invalid = copy.deepcopy(self.baseline)
        invalid["entries"][0]["repository_name"] = "name/with/slash"
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)

    def test_repository_owner_with_spaces_rejected(self) -> None:
        """Repository owner with spaces should be rejected."""
        invalid = copy.deepcopy(self.baseline)
        invalid["entries"][0]["repository_owner"] = "owner with spaces"
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)

    def test_repository_name_with_spaces_rejected(self) -> None:
        """Repository name with spaces should be rejected."""
        invalid = copy.deepcopy(self.baseline)
        invalid["entries"][0]["repository_name"] = "name with spaces"
        findings = self.validator.validate_document(invalid)
        self.assertTrue(len(findings) > 0)

    def test_valid_real_world_inputs_pass(self) -> None:
        """Valid real-world repository specifications should pass."""
        valid_cases = [
            {
                "id": "canonical.anthropics_claude_code",
                "repository_owner": "anthropics",
                "repository_name": "claude-code",
                "repository_sha": "abc123def456abc123def456abc123def456abc1",
            },
            {
                "id": "canonical.github_actions",
                "repository_owner": "actions",
                "repository_name": "checkout",
                "repository_sha": "0000000000000000000000000000000000000000",
            },
            {
                "id": "canonical.org_name_with_dots",
                "repository_owner": "org.with.dots",
                "repository_name": "repo-name",
                "repository_sha": "fedcba9876543210fedcba9876543210fedcba98",
            },
        ]

        for entry in valid_cases:
            registry = {
                "schema_version": "1.0.0",
                "registry_type": "canonical_repository",
                "entries": [entry],
            }
            findings = self.validator.validate_document(registry)
            self.assertEqual(
                findings, [], f"Valid entry should pass: {entry['id']}, findings: {findings}"
            )


if __name__ == "__main__":
    unittest.main()
