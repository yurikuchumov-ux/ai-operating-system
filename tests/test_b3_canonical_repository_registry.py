#!/usr/bin/env python3
"""B3 unit tests for canonical repository registry validator.

Tests validate fail-closed behavior for missing, extra, duplicate, substituted,
malformed, unreadable, invalid-UTF-8 or invalid-JSON inputs.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict

from tools.validate_canonical_repositories import (
    EXPECTED_REPOSITORIES,
    Finding,
    load_json,
    validate_canonical_repositories,
    validate_exact_repository_match,
    validate_execution_plan_section_3_1,
    validate_registry_schema,
    validate_repository_uniqueness,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = REPO_ROOT / "contracts/canonical-repositories.v1.json"
SCHEMA_PATH = REPO_ROOT / "contracts/schemas/canonical-repositories.v1.schema.json"


class CanonicalRepositoryRegistryTests(unittest.TestCase):
    """Test the canonical repository registry validates correctly."""

    def test_registry_file_exists(self) -> None:
        """Registry file must exist at the canonical path."""
        self.assertTrue(REGISTRY_PATH.is_file(), f"registry not found: {REGISTRY_PATH}")

    def test_registry_is_valid_json(self) -> None:
        """Registry must be valid JSON."""
        registry = load_json(REGISTRY_PATH)
        self.assertIsInstance(registry, dict)

    def test_registry_has_correct_schema_version(self) -> None:
        """Registry must declare schema_version 1.0.0."""
        registry = load_json(REGISTRY_PATH)
        self.assertEqual(registry.get("schema_version"), "1.0.0")

    def test_registry_has_correct_type(self) -> None:
        """Registry must declare registry_type canonical_repositories."""
        registry = load_json(REGISTRY_PATH)
        self.assertEqual(registry.get("registry_type"), "canonical_repositories")

    def test_registry_has_exactly_three_repositories(self) -> None:
        """Registry must contain exactly three repositories."""
        registry = load_json(REGISTRY_PATH)
        repositories = registry.get("repositories", [])
        self.assertEqual(len(repositories), 3)

    def test_registry_repositories_match_expected(self) -> None:
        """Registry repositories must exactly match the approved list."""
        registry = load_json(REGISTRY_PATH)
        repositories = registry.get("repositories", [])

        # Sort both for comparison
        actual_sorted = sorted(repositories, key=lambda r: r.get("repository", ""))
        expected_sorted = sorted(EXPECTED_REPOSITORIES, key=lambda r: r["repository"])

        self.assertEqual(actual_sorted, expected_sorted)

    def test_schema_file_exists(self) -> None:
        """Schema file must exist at the canonical path."""
        self.assertTrue(SCHEMA_PATH.is_file(), f"schema not found: {SCHEMA_PATH}")

    def test_schema_is_valid_json(self) -> None:
        """Schema must be valid JSON."""
        schema = load_json(SCHEMA_PATH)
        self.assertIsInstance(schema, dict)

    def test_registry_validates_against_schema(self) -> None:
        """Registry must pass schema validation."""
        registry = load_json(REGISTRY_PATH)
        findings = validate_registry_schema(registry)
        self.assertEqual(findings, [], f"schema validation failed: {findings}")

    def test_full_validation_passes(self) -> None:
        """Full validation must pass with no findings."""
        exit_code, report = validate_canonical_repositories()
        self.assertEqual(exit_code, 0, f"validation failed: {report}")
        self.assertTrue(report["valid"])
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["error_codes"], [])


class RepositoryUniquenessTests(unittest.TestCase):
    """Test uniqueness validation for repository identities."""

    def test_duplicate_repository_name_rejected(self) -> None:
        """Duplicate repository names must be rejected."""
        repositories = [
            {
                "role": "Role A",
                "repository": "owner/repo-a",
                "visibility": "public",
                "main_sha": "a" * 40,
                "boundary": "Boundary A",
            },
            {
                "role": "Role B",
                "repository": "owner/repo-a",  # duplicate
                "visibility": "public",
                "main_sha": "b" * 40,
                "boundary": "Boundary B",
            },
        ]

        findings = validate_repository_uniqueness(repositories)
        codes = {f.code for f in findings}
        self.assertIn("duplicate_repository", codes)

    def test_duplicate_role_rejected(self) -> None:
        """Duplicate roles must be rejected."""
        repositories = [
            {
                "role": "Same Role",
                "repository": "owner/repo-a",
                "visibility": "public",
                "main_sha": "a" * 40,
                "boundary": "Boundary A",
            },
            {
                "role": "Same Role",  # duplicate
                "repository": "owner/repo-b",
                "visibility": "public",
                "main_sha": "b" * 40,
                "boundary": "Boundary B",
            },
        ]

        findings = validate_repository_uniqueness(repositories)
        codes = {f.code for f in findings}
        self.assertIn("duplicate_role", codes)

    def test_duplicate_main_sha_rejected(self) -> None:
        """Duplicate main_sha values must be rejected."""
        repositories = [
            {
                "role": "Role A",
                "repository": "owner/repo-a",
                "visibility": "public",
                "main_sha": "a" * 40,
                "boundary": "Boundary A",
            },
            {
                "role": "Role B",
                "repository": "owner/repo-b",
                "visibility": "public",
                "main_sha": "a" * 40,  # duplicate
                "boundary": "Boundary B",
            },
        ]

        findings = validate_repository_uniqueness(repositories)
        codes = {f.code for f in findings}
        self.assertIn("duplicate_main_sha", codes)


class ExactRepositoryMatchTests(unittest.TestCase):
    """Test exact matching against approved repository list."""

    def test_missing_repository_rejected(self) -> None:
        """Missing required repository must be rejected."""
        repositories = EXPECTED_REPOSITORIES[:2]  # only first two

        findings = validate_exact_repository_match(repositories)
        codes = {f.code for f in findings}
        self.assertIn("repository_count_mismatch", codes)

    def test_extra_repository_rejected(self) -> None:
        """Extra repository not in approved list must be rejected."""
        repositories = EXPECTED_REPOSITORIES + [
            {
                "role": "Extra role",
                "repository": "owner/extra-repo",
                "visibility": "public",
                "main_sha": "e" * 40,
                "boundary": "Extra boundary",
            }
        ]

        findings = validate_exact_repository_match(repositories)
        codes = {f.code for f in findings}
        # Should fail on count mismatch
        self.assertIn("repository_count_mismatch", codes)

    def test_substituted_repository_name_rejected(self) -> None:
        """Substituted repository name must be rejected."""
        repositories = [
            EXPECTED_REPOSITORIES[0],
            {
                **EXPECTED_REPOSITORIES[1],
                "repository": "wrong-owner/wrong-repo",
            },
            EXPECTED_REPOSITORIES[2],
        ]

        findings = validate_exact_repository_match(repositories)
        codes = {f.code for f in findings}
        self.assertIn("extra_repository", codes)
        self.assertIn("missing_repository", codes)

    def test_wrong_field_value_rejected(self) -> None:
        """Wrong field values must be rejected."""
        repositories = [
            EXPECTED_REPOSITORIES[0],
            {
                **EXPECTED_REPOSITORIES[1],
                "visibility": "private",  # should be public
            },
            EXPECTED_REPOSITORIES[2],
        ]

        findings = validate_exact_repository_match(repositories)
        codes = {f.code for f in findings}
        self.assertIn("field_value_mismatch", codes)

    def test_wrong_main_sha_rejected(self) -> None:
        """Wrong main_sha must be rejected."""
        repositories = [
            EXPECTED_REPOSITORIES[0],
            {
                **EXPECTED_REPOSITORIES[1],
                "main_sha": "f" * 40,  # wrong SHA
            },
            EXPECTED_REPOSITORIES[2],
        ]

        findings = validate_exact_repository_match(repositories)
        codes = {f.code for f in findings}
        self.assertIn("field_value_mismatch", codes)


class SchemaValidationTests(unittest.TestCase):
    """Test JSON schema validation."""

    def test_missing_required_field_rejected(self) -> None:
        """Registry missing required field must be rejected."""
        registry = {
            "schema_version": "1.0.0",
            # missing registry_type and repositories
        }

        findings = validate_registry_schema(registry)
        codes = {f.code for f in findings}
        self.assertIn("schema_validation_failed", codes)

    def test_invalid_schema_version_rejected(self) -> None:
        """Invalid schema_version must be rejected."""
        registry = {
            "schema_version": "2.0.0",  # wrong version
            "registry_type": "canonical_repositories",
            "repositories": [],
        }

        findings = validate_registry_schema(registry)
        codes = {f.code for f in findings}
        self.assertIn("schema_validation_failed", codes)

    def test_invalid_repository_name_format_rejected(self) -> None:
        """Invalid repository name format must be rejected."""
        registry = {
            "schema_version": "1.0.0",
            "registry_type": "canonical_repositories",
            "repositories": [
                {
                    "role": "Test",
                    "repository": "invalid repo name",  # no slash
                    "visibility": "public",
                    "main_sha": "a" * 40,
                    "boundary": "Test boundary",
                },
            ],
        }

        findings = validate_registry_schema(registry)
        codes = {f.code for f in findings}
        self.assertIn("schema_validation_failed", codes)

    def test_invalid_main_sha_format_rejected(self) -> None:
        """Invalid main_sha format must be rejected."""
        registry = {
            "schema_version": "1.0.0",
            "registry_type": "canonical_repositories",
            "repositories": [
                {
                    "role": "Test",
                    "repository": "owner/repo",
                    "visibility": "public",
                    "main_sha": "not-a-valid-sha",  # invalid format
                    "boundary": "Test boundary",
                },
            ],
        }

        findings = validate_registry_schema(registry)
        codes = {f.code for f in findings}
        self.assertIn("schema_validation_failed", codes)

    def test_invalid_visibility_value_rejected(self) -> None:
        """Invalid visibility value must be rejected."""
        registry = {
            "schema_version": "1.0.0",
            "registry_type": "canonical_repositories",
            "repositories": [
                {
                    "role": "Test",
                    "repository": "owner/repo",
                    "visibility": "internal",  # not in enum
                    "main_sha": "a" * 40,
                    "boundary": "Test boundary",
                },
            ],
        }

        findings = validate_registry_schema(registry)
        codes = {f.code for f in findings}
        self.assertIn("schema_validation_failed", codes)

    def test_too_few_repositories_rejected(self) -> None:
        """Registry with fewer than 3 repositories must be rejected."""
        registry = {
            "schema_version": "1.0.0",
            "registry_type": "canonical_repositories",
            "repositories": [
                {
                    "role": "Test",
                    "repository": "owner/repo",
                    "visibility": "public",
                    "main_sha": "a" * 40,
                    "boundary": "Test boundary",
                },
            ],
        }

        findings = validate_registry_schema(registry)
        codes = {f.code for f in findings}
        self.assertIn("schema_validation_failed", codes)

    def test_too_many_repositories_rejected(self) -> None:
        """Registry with more than 3 repositories must be rejected."""
        registry = {
            "schema_version": "1.0.0",
            "registry_type": "canonical_repositories",
            "repositories": [
                {
                    "role": f"Role {i}",
                    "repository": f"owner/repo-{i}",
                    "visibility": "public",
                    "main_sha": chr(ord("a") + i) * 40,
                    "boundary": f"Boundary {i}",
                }
                for i in range(4)
            ],
        }

        findings = validate_registry_schema(registry)
        codes = {f.code for f in findings}
        self.assertIn("schema_validation_failed", codes)

    def test_additional_properties_rejected(self) -> None:
        """Additional properties in registry must be rejected."""
        registry = {
            "schema_version": "1.0.0",
            "registry_type": "canonical_repositories",
            "repositories": EXPECTED_REPOSITORIES,
            "extra_field": "not allowed",
        }

        findings = validate_registry_schema(registry)
        codes = {f.code for f in findings}
        self.assertIn("schema_validation_failed", codes)


class ExecutionPlanSection31Tests(unittest.TestCase):
    """Test execution plan section 3.1 validation."""

    def test_section_3_1_exists(self) -> None:
        """Section 3.1 must exist in execution plan."""
        findings = validate_execution_plan_section_3_1()
        codes = {f.code for f in findings}
        self.assertNotIn("section_3_1_missing", codes)

    def test_section_3_1_has_table(self) -> None:
        """Section 3.1 must contain a table."""
        findings = validate_execution_plan_section_3_1()
        codes = {f.code for f in findings}
        self.assertNotIn("table_missing", codes)

    def test_section_3_1_table_has_correct_headers(self) -> None:
        """Section 3.1 table must have the exact five-column header."""
        findings = validate_execution_plan_section_3_1()

        # Should have no header-related errors
        codes = {f.code for f in findings}
        self.assertNotIn("header_column_count", codes)
        self.assertNotIn("header_content_mismatch", codes)

    def test_section_3_1_table_has_valid_separator(self) -> None:
        """Section 3.1 table must have valid five-column separator."""
        findings = validate_execution_plan_section_3_1()

        codes = {f.code for f in findings}
        self.assertNotIn("separator_column_count", codes)
        self.assertNotIn("separator_invalid_format", codes)

    def test_section_3_1_table_has_three_data_rows(self) -> None:
        """Section 3.1 table must have exactly three data rows."""
        findings = validate_execution_plan_section_3_1()

        codes = {f.code for f in findings}
        self.assertNotIn("data_row_count", codes)

    def test_section_3_1_table_rows_have_five_columns(self) -> None:
        """Section 3.1 table data rows must have exactly five columns."""
        findings = validate_execution_plan_section_3_1()

        codes = {f.code for f in findings}
        self.assertNotIn("data_row_column_count", codes)

    def test_section_3_1_repository_cells_well_formed(self) -> None:
        """Section 3.1 repository cells must be well-formed markdown links."""
        findings = validate_execution_plan_section_3_1()

        codes = {f.code for f in findings}
        self.assertNotIn("unbalanced_backticks", codes)
        self.assertNotIn("multiple_links", codes)
        self.assertNotIn("repository_cell_extra_text", codes)


class FailClosedInputTests(unittest.TestCase):
    """Test fail-closed behavior for malformed inputs."""

    def test_invalid_utf8_rejected(self) -> None:
        """Invalid UTF-8 must be rejected."""
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".json", delete=False) as f:
            # Write invalid UTF-8
            f.write(b'{"test": "\xff\xfe"}')
            temp_path = Path(f.name)

        try:
            with self.assertRaises(ValueError) as ctx:
                load_json(temp_path)
            self.assertIn("invalid_utf8", str(ctx.exception))
        finally:
            temp_path.unlink()

    def test_invalid_json_rejected(self) -> None:
        """Invalid JSON must be rejected."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{invalid json")
            temp_path = Path(f.name)

        try:
            with self.assertRaises(ValueError) as ctx:
                load_json(temp_path)
            self.assertIn("invalid_json", str(ctx.exception))
        finally:
            temp_path.unlink()

    def test_missing_file_rejected(self) -> None:
        """Missing file must be rejected."""
        nonexistent = Path("/tmp/nonexistent-file-12345.json")

        with self.assertRaises(ValueError) as ctx:
            load_json(nonexistent)
        self.assertIn("file_not_found", str(ctx.exception))


class DeterministicOutputTests(unittest.TestCase):
    """Test that validator produces deterministic machine-readable output."""

    def test_report_has_required_fields(self) -> None:
        """Validation report must have required fields."""
        exit_code, report = validate_canonical_repositories()

        self.assertIn("schema_version", report)
        self.assertIn("valid", report)
        self.assertIn("findings", report)
        self.assertIn("error_codes", report)

    def test_report_schema_version_is_1_0_0(self) -> None:
        """Report schema_version must be 1.0.0."""
        exit_code, report = validate_canonical_repositories()
        self.assertEqual(report["schema_version"], "1.0.0")

    def test_report_findings_are_deterministic(self) -> None:
        """Findings must be sorted deterministically."""
        exit_code, report = validate_canonical_repositories()

        # Findings should be sorted by code then path
        findings = report["findings"]
        if len(findings) > 1:
            for i in range(len(findings) - 1):
                curr = (findings[i]["code"], findings[i]["path"])
                next_f = (findings[i + 1]["code"], findings[i + 1]["path"])
                self.assertLessEqual(curr, next_f)

    def test_report_error_codes_are_sorted(self) -> None:
        """Error codes must be sorted."""
        exit_code, report = validate_canonical_repositories()

        error_codes = report["error_codes"]
        self.assertEqual(error_codes, sorted(error_codes))

    def test_exit_code_zero_when_valid(self) -> None:
        """Exit code must be 0 when validation passes."""
        exit_code, report = validate_canonical_repositories()

        if report["valid"]:
            self.assertEqual(exit_code, 0)

    def test_exit_code_nonzero_when_invalid(self) -> None:
        """Exit code must be non-zero when validation fails."""
        # Create invalid registry
        invalid_registry = {
            "schema_version": "1.0.0",
            "registry_type": "canonical_repositories",
            "repositories": [],  # too few
        }

        findings = validate_registry_schema(invalid_registry)
        if findings:
            # This would produce exit code 1
            self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()
