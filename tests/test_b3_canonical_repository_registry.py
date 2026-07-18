#!/usr/bin/env python3
"""Tests for canonical repository registry and execution plan validation.

Tests invoke production behavior only. No source-text or whitespace assertions.
Coverage: valid plan, unique section, header, missing/extra rows, and exact
plan_*_mismatch codes.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = REPO_ROOT / "tools/validate_canonical_repositories.py"
REGISTRY_PATH = REPO_ROOT / "contracts/canonical-repositories.v1.json"
SCHEMA_PATH = REPO_ROOT / "contracts/schemas/canonical-repositories.v1.schema.json"
PLAN_PATH = REPO_ROOT / "docs/AI_DEVELOPMENT_STUDIO_EXECUTION_PLAN.md"


def run_validator(*args):
    """Run validator and return parsed JSON result."""
    result = subprocess.run(
        [sys.executable, str(VALIDATOR_PATH)] + list(args),
        capture_output=True,
        text=True,
    )
    try:
        return result.returncode, json.loads(result.stdout)
    except json.JSONDecodeError:
        return result.returncode, {"error": "invalid_json", "stdout": result.stdout}


class TestCanonicalRepositoryRegistry(unittest.TestCase):
    """Test canonical repository registry validation."""

    def test_valid_registry(self):
        """Test that the production registry is valid."""
        exit_code, output = run_validator("--registry", str(REGISTRY_PATH), "--schema", str(SCHEMA_PATH))
        self.assertEqual(exit_code, 0, f"Registry validation failed: {output}")
        self.assertTrue(output.get("valid"), f"Registry marked invalid: {output}")
        self.assertEqual(output.get("error_codes"), [])

    def test_registry_top_level_keys(self):
        """Test that registry has exactly schema_version and canonical_repositories keys."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({
                "schema_version": "1.0.0",
                "canonical_repositories": [],
                "$schema": "should-not-be-here"
            }, f)
            temp_path = f.name

        try:
            exit_code, output = run_validator("--registry", temp_path, "--schema", str(SCHEMA_PATH))
            self.assertEqual(exit_code, 1)
            self.assertIn("registry_invalid_top_keys", output.get("error_codes", []))
        finally:
            Path(temp_path).unlink()

    def test_registry_unsupported_version(self):
        """Test that unsupported schema version is rejected."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({
                "schema_version": "2.0.0",
                "canonical_repositories": []
            }, f)
            temp_path = f.name

        try:
            exit_code, output = run_validator("--registry", temp_path, "--schema", str(SCHEMA_PATH))
            self.assertEqual(exit_code, 1)
            self.assertIn("registry_unsupported_version", output.get("error_codes", []))
        finally:
            Path(temp_path).unlink()

    def test_registry_empty_repositories(self):
        """Test that empty repository array is rejected."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({
                "schema_version": "1.0.0",
                "canonical_repositories": []
            }, f)
            temp_path = f.name

        try:
            exit_code, output = run_validator("--registry", temp_path, "--schema", str(SCHEMA_PATH))
            self.assertEqual(exit_code, 1)
            self.assertIn("registry_empty_repositories", output.get("error_codes", []))
        finally:
            Path(temp_path).unlink()

    def test_registry_duplicate_full_name(self):
        """Test that duplicate full_name is detected."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({
                "schema_version": "1.0.0",
                "canonical_repositories": [
                    {
                        "name": "repo1",
                        "owner": "owner",
                        "full_name": "owner/repo",
                        "label": "governance",
                        "main_sha": "a" * 40
                    },
                    {
                        "name": "repo2",
                        "owner": "owner",
                        "full_name": "owner/repo",
                        "label": "template",
                        "main_sha": "b" * 40
                    }
                ]
            }, f)
            temp_path = f.name

        try:
            exit_code, output = run_validator("--registry", temp_path, "--schema", str(SCHEMA_PATH))
            self.assertEqual(exit_code, 1)
            self.assertIn("registry_duplicate_full_name", output.get("error_codes", []))
        finally:
            Path(temp_path).unlink()

    def test_registry_duplicate_label(self):
        """Test that duplicate label is detected."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({
                "schema_version": "1.0.0",
                "canonical_repositories": [
                    {
                        "name": "repo1",
                        "owner": "owner1",
                        "full_name": "owner1/repo1",
                        "label": "governance",
                        "main_sha": "a" * 40
                    },
                    {
                        "name": "repo2",
                        "owner": "owner2",
                        "full_name": "owner2/repo2",
                        "label": "governance",
                        "main_sha": "b" * 40
                    }
                ]
            }, f)
            temp_path = f.name

        try:
            exit_code, output = run_validator("--registry", temp_path, "--schema", str(SCHEMA_PATH))
            self.assertEqual(exit_code, 1)
            self.assertIn("registry_duplicate_label", output.get("error_codes", []))
        finally:
            Path(temp_path).unlink()

    def test_missing_registry_file(self):
        """Test handling of missing registry file."""
        exit_code, output = run_validator("--registry", "/nonexistent/file.json", "--schema", str(SCHEMA_PATH))
        self.assertEqual(exit_code, 1)
        self.assertIn("registry_file_not_found", output.get("error_codes", []))

    def test_malformed_registry_json(self):
        """Test handling of malformed JSON in registry."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{invalid json")
            temp_path = f.name

        try:
            exit_code, output = run_validator("--registry", temp_path, "--schema", str(SCHEMA_PATH))
            self.assertEqual(exit_code, 1)
            error_codes = output.get("error_codes", [])
            # Should have a JSON decode error
            self.assertTrue(any("json_decode_error" in code for code in error_codes))
        finally:
            Path(temp_path).unlink()

    def test_missing_jsonschema_reported(self):
        """Test that missing jsonschema dependency is reported in output."""
        exit_code, output = run_validator("--registry", str(REGISTRY_PATH), "--schema", str(SCHEMA_PATH))
        # Output should always indicate jsonschema availability
        self.assertIn("jsonschema_available", output)
        self.assertIsInstance(output["jsonschema_available"], bool)


class TestExecutionPlanValidation(unittest.TestCase):
    """Test execution plan validation against canonical registry."""

    def test_valid_plan(self):
        """Test that the production execution plan validates against registry."""
        exit_code, output = run_validator(
            "--registry", str(REGISTRY_PATH),
            "--schema", str(SCHEMA_PATH),
            "--plan", str(PLAN_PATH),
            "--check-plan"
        )
        self.assertEqual(exit_code, 0, f"Plan validation failed: {output}")
        self.assertTrue(output.get("valid"), f"Plan marked invalid: {output}")
        self.assertEqual(output.get("error_codes"), [])

    def test_plan_section_not_found(self):
        """Test detection of missing section 3.1."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write("# Some document\n\nNo section 3.1 here.\n")
            temp_plan = f.name

        try:
            exit_code, output = run_validator(
                "--registry", str(REGISTRY_PATH),
                "--schema", str(SCHEMA_PATH),
                "--plan", temp_plan,
                "--check-plan"
            )
            self.assertEqual(exit_code, 1)
            self.assertIn("plan_section_3_1_not_found", output.get("error_codes", []))
        finally:
            Path(temp_plan).unlink()

    def test_plan_table_header_not_found(self):
        """Test detection of missing table header in section 3.1."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write("### 3.1 Verified names and boundaries\n\nNo table here.\n")
            temp_plan = f.name

        try:
            exit_code, output = run_validator(
                "--registry", str(REGISTRY_PATH),
                "--schema", str(SCHEMA_PATH),
                "--plan", temp_plan,
                "--check-plan"
            )
            self.assertEqual(exit_code, 1)
            self.assertIn("plan_table_header_not_found", output.get("error_codes", []))
        finally:
            Path(temp_plan).unlink()

    def test_plan_missing_rows(self):
        """Test detection of missing repository rows in plan."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write("""### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance |
""")
            temp_plan = f.name

        try:
            exit_code, output = run_validator(
                "--registry", str(REGISTRY_PATH),
                "--schema", str(SCHEMA_PATH),
                "--plan", temp_plan,
                "--check-plan"
            )
            self.assertEqual(exit_code, 1)
            self.assertIn("plan_missing_rows", output.get("error_codes", []))
        finally:
            Path(temp_plan).unlink()

    def test_plan_extra_rows(self):
        """Test detection of extra repository rows in plan."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            # Create registry with only governance
            json.dump({
                "schema_version": "1.0.0",
                "canonical_repositories": [
                    {
                        "name": "ai-operating-system",
                        "owner": "yurikuchumov-ux",
                        "full_name": "yurikuchumov-ux/ai-operating-system",
                        "label": "governance",
                        "main_sha": "a36a8eefcdd06c56edeec93057a90c58a239cf22"
                    }
                ]
            }, f)
            temp_registry = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write("""### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal |
| Voice reference product | [`yurikuchumov-ux/-ai-development-studio`](https://github.com) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns product runtime |
""")
            temp_plan = f.name

        try:
            exit_code, output = run_validator(
                "--registry", temp_registry,
                "--schema", str(SCHEMA_PATH),
                "--plan", temp_plan,
                "--check-plan"
            )
            self.assertEqual(exit_code, 1)
            self.assertIn("plan_extra_rows", output.get("error_codes", []))
        finally:
            Path(temp_plan).unlink()
            Path(temp_registry).unlink()

    def test_plan_repo_name_mismatch(self):
        """Test detection of repository name mismatch."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write("""### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`wrong/repository-name`](https://github.com) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal |
| Voice reference product | [`yurikuchumov-ux/-ai-development-studio`](https://github.com) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns product runtime |
""")
            temp_plan = f.name

        try:
            exit_code, output = run_validator(
                "--registry", str(REGISTRY_PATH),
                "--schema", str(SCHEMA_PATH),
                "--plan", temp_plan,
                "--check-plan"
            )
            self.assertEqual(exit_code, 1)
            self.assertIn("plan_repo_name_mismatch", output.get("error_codes", []))
        finally:
            Path(temp_plan).unlink()

    def test_plan_sha_mismatch(self):
        """Test detection of SHA mismatch."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write("""### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com) | public | `0000000000000000000000000000000000000000` | owns governance |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal |
| Voice reference product | [`yurikuchumov-ux/-ai-development-studio`](https://github.com) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns product runtime |
""")
            temp_plan = f.name

        try:
            exit_code, output = run_validator(
                "--registry", str(REGISTRY_PATH),
                "--schema", str(SCHEMA_PATH),
                "--plan", temp_plan,
                "--check-plan"
            )
            self.assertEqual(exit_code, 1)
            self.assertIn("plan_sha_mismatch", output.get("error_codes", []))
        finally:
            Path(temp_plan).unlink()

    def test_plan_duplicate_label_row(self):
        """Test detection of duplicate label rows in plan."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write("""### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal |
| Voice reference product | [`yurikuchumov-ux/-ai-development-studio`](https://github.com) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns product runtime |
""")
            temp_plan = f.name

        try:
            exit_code, output = run_validator(
                "--registry", str(REGISTRY_PATH),
                "--schema", str(SCHEMA_PATH),
                "--plan", temp_plan,
                "--check-plan"
            )
            self.assertEqual(exit_code, 1)
            self.assertIn("plan_duplicate_label_row", output.get("error_codes", []))
        finally:
            Path(temp_plan).unlink()

    def test_missing_plan_file(self):
        """Test handling of missing plan file."""
        exit_code, output = run_validator(
            "--registry", str(REGISTRY_PATH),
            "--schema", str(SCHEMA_PATH),
            "--plan", "/nonexistent/plan.md",
            "--check-plan"
        )
        self.assertEqual(exit_code, 1)
        self.assertIn("plan_file_not_found", output.get("error_codes", []))

    def test_output_always_json(self):
        """Test that all validation scenarios emit valid JSON."""
        # Valid case
        exit_code, output = run_validator("--registry", str(REGISTRY_PATH))
        self.assertIsInstance(output, dict)
        self.assertIn("valid", output)
        self.assertIn("error_codes", output)

        # Invalid case
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{invalid")
            temp_path = f.name

        try:
            exit_code, output = run_validator("--registry", temp_path)
            self.assertIsInstance(output, dict)
            self.assertIn("error_codes", output)
        finally:
            Path(temp_path).unlink()


if __name__ == "__main__":
    unittest.main()
