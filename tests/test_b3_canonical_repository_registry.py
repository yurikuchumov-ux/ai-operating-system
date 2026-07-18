#!/usr/bin/env python3
"""Tests for canonical repository registry validation."""

import json
import unittest
from pathlib import Path
from typing import Any, Dict

# Import validator functions
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))

from validate_canonical_repositories import (
    ValidationError,
    load_json,
    validate_schema,
    validate_semantic_rules,
    validate_unicode,
)


class TestCanonicalRepositoryRegistry(unittest.TestCase):
    """Test canonical repository registry structure and validation."""

    @classmethod
    def setUpClass(cls):
        """Load registry and schema once for all tests."""
        repo_root = Path(__file__).parent.parent
        cls.registry_path = repo_root / "contracts" / "canonical-repositories.v1.json"
        cls.schema_path = repo_root / "contracts" / "schemas" / "canonical-repositories.v1.schema.json"

        cls.registry_data = load_json(cls.registry_path)
        cls.schema_data = load_json(cls.schema_path)

    def test_registry_file_exists(self):
        """Registry file must exist."""
        self.assertTrue(self.registry_path.exists())

    def test_schema_file_exists(self):
        """Schema file must exist."""
        self.assertTrue(self.schema_path.exists())

    def test_registry_is_valid_json(self):
        """Registry must be valid JSON."""
        self.assertIsInstance(self.registry_data, dict)

    def test_schema_is_valid_json(self):
        """Schema must be valid JSON."""
        self.assertIsInstance(self.schema_data, dict)

    def test_schema_version(self):
        """Registry must have schema_version 1.0.0."""
        self.assertEqual(self.registry_data["schema_version"], "1.0.0")

    def test_owner_field(self):
        """Registry must have owner field."""
        self.assertIn("owner", self.registry_data)
        self.assertEqual(self.registry_data["owner"], "yurikuchumov-ux")

    def test_repositories_field(self):
        """Registry must have repositories array."""
        self.assertIn("repositories", self.registry_data)
        self.assertIsInstance(self.registry_data["repositories"], list)

    def test_exactly_three_repositories(self):
        """Registry must contain exactly 3 repositories."""
        repos = self.registry_data["repositories"]
        self.assertEqual(len(repos), 3)

    def test_all_roles_present(self):
        """Registry must contain governance, template, and voice roles."""
        roles = {repo["role"] for repo in self.registry_data["repositories"]}
        self.assertEqual(roles, {"governance", "template", "voice"})

    def test_unique_roles(self):
        """All repository roles must be unique."""
        roles = [repo["role"] for repo in self.registry_data["repositories"]]
        self.assertEqual(len(roles), len(set(roles)))

    def test_unique_names(self):
        """All repository names must be unique."""
        names = [repo["name"] for repo in self.registry_data["repositories"]]
        self.assertEqual(len(names), len(set(names)))

    def test_unique_full_names(self):
        """All repository full_names must be unique."""
        full_names = [repo["full_name"] for repo in self.registry_data["repositories"]]
        self.assertEqual(len(full_names), len(set(full_names)))

    def test_unique_urls(self):
        """All repository URLs must be unique."""
        urls = [repo["url"] for repo in self.registry_data["repositories"]]
        self.assertEqual(len(urls), len(set(urls)))

    def test_governance_repository(self):
        """Governance repository must have correct values."""
        repo = next(r for r in self.registry_data["repositories"] if r["role"] == "governance")
        self.assertEqual(repo["name"], "ai-operating-system")
        self.assertEqual(repo["full_name"], "yurikuchumov-ux/ai-operating-system")
        self.assertEqual(repo["url"], "https://github.com/yurikuchumov-ux/ai-operating-system")
        self.assertEqual(repo["visibility"], "public")
        self.assertEqual(repo["main_sha"], "a36a8eefcdd06c56edeec93057a90c58a239cf22")
        self.assertIn("boundary", repo)

    def test_template_repository(self):
        """Template repository must have correct values."""
        repo = next(r for r in self.registry_data["repositories"] if r["role"] == "template")
        self.assertEqual(repo["name"], "ai-development-studio-template")
        self.assertEqual(repo["full_name"], "yurikuchumov-ux/ai-development-studio-template")
        self.assertEqual(repo["url"], "https://github.com/yurikuchumov-ux/ai-development-studio-template")
        self.assertEqual(repo["visibility"], "public")
        self.assertEqual(repo["main_sha"], "ec088bf2e95e048ce1f5b69d969542b516afbc8b")
        self.assertIn("boundary", repo)

    def test_voice_repository(self):
        """Voice repository must have correct values."""
        repo = next(r for r in self.registry_data["repositories"] if r["role"] == "voice")
        self.assertEqual(repo["name"], "-ai-development-studio")
        self.assertEqual(repo["full_name"], "yurikuchumov-ux/-ai-development-studio")
        self.assertEqual(repo["url"], "https://github.com/yurikuchumov-ux/-ai-development-studio")
        self.assertEqual(repo["visibility"], "private")
        self.assertEqual(repo["main_sha"], "f6550d4078ffccc952db269081619fdfe57e598c")
        self.assertIn("boundary", repo)

    def test_all_shas_valid_format(self):
        """All main_sha values must be 40-character lowercase hex."""
        for repo in self.registry_data["repositories"]:
            sha = repo["main_sha"]
            self.assertEqual(len(sha), 40)
            self.assertTrue(all(c in "0123456789abcdef" for c in sha))

    def test_all_urls_github_format(self):
        """All URLs must be GitHub URLs."""
        for repo in self.registry_data["repositories"]:
            url = repo["url"]
            self.assertTrue(url.startswith("https://github.com/"))

    def test_full_name_consistency(self):
        """full_name must match owner/name for all repositories."""
        owner = self.registry_data["owner"]
        for repo in self.registry_data["repositories"]:
            expected = f"{owner}/{repo['name']}"
            self.assertEqual(repo["full_name"], expected)

    def test_url_consistency(self):
        """URL must match GitHub URL pattern for all repositories."""
        owner = self.registry_data["owner"]
        for repo in self.registry_data["repositories"]:
            expected = f"https://github.com/{owner}/{repo['name']}"
            self.assertEqual(repo["url"], expected)

    def test_schema_validation_passes(self):
        """Registry must pass schema validation."""
        try:
            validate_schema(self.registry_data, self.schema_data)
        except ValidationError as e:
            self.fail(f"Schema validation failed: {e.message}")

    def test_semantic_validation_passes(self):
        """Registry must pass semantic validation."""
        try:
            validate_semantic_rules(self.registry_data)
        except ValidationError as e:
            self.fail(f"Semantic validation failed: {e.message}")

    def test_unicode_validation_passes(self):
        """Registry must pass Unicode validation."""
        try:
            validate_unicode(self.registry_data)
        except ValidationError as e:
            self.fail(f"Unicode validation failed: {e.message}")

    def test_missing_schema_version_fails(self):
        """Registry without schema_version must fail."""
        invalid_data = self.registry_data.copy()
        del invalid_data["schema_version"]
        with self.assertRaises(ValidationError) as ctx:
            validate_schema(invalid_data, self.schema_data)
        self.assertEqual(ctx.exception.code, "schema_validation_failed")

    def test_wrong_repository_count_fails(self):
        """Registry with wrong number of repositories must fail."""
        # Too few
        invalid_data = self.registry_data.copy()
        invalid_data["repositories"] = self.registry_data["repositories"][:2]
        with self.assertRaises(ValidationError) as ctx:
            validate_schema(invalid_data, self.schema_data)
        self.assertEqual(ctx.exception.code, "schema_validation_failed")

        # Too many
        invalid_data = self.registry_data.copy()
        invalid_data["repositories"] = self.registry_data["repositories"] + [
            self.registry_data["repositories"][0]
        ]
        with self.assertRaises(ValidationError) as ctx:
            validate_schema(invalid_data, self.schema_data)
        self.assertEqual(ctx.exception.code, "schema_validation_failed")

    def test_duplicate_role_fails(self):
        """Registry with duplicate roles must fail semantic validation."""
        invalid_data = self.registry_data.copy()
        repos = [repo.copy() for repo in self.registry_data["repositories"]]
        repos[1]["role"] = repos[0]["role"]  # Duplicate role
        repos[1]["name"] = "different-name"  # But different name
        repos[1]["full_name"] = f"{invalid_data['owner']}/different-name"
        repos[1]["url"] = f"https://github.com/{invalid_data['owner']}/different-name"
        invalid_data["repositories"] = repos

        with self.assertRaises(ValidationError) as ctx:
            validate_semantic_rules(invalid_data)
        self.assertEqual(ctx.exception.code, "semantic_validation_failed")

    def test_duplicate_name_fails(self):
        """Registry with duplicate names must fail semantic validation."""
        invalid_data = self.registry_data.copy()
        repos = [repo.copy() for repo in self.registry_data["repositories"]]
        repos[1]["name"] = repos[0]["name"]  # Duplicate name
        repos[1]["full_name"] = repos[0]["full_name"]
        repos[1]["url"] = repos[0]["url"]
        invalid_data["repositories"] = repos

        with self.assertRaises(ValidationError) as ctx:
            validate_semantic_rules(invalid_data)
        self.assertEqual(ctx.exception.code, "semantic_validation_failed")

    def test_inconsistent_full_name_fails(self):
        """Registry with inconsistent full_name must fail semantic validation."""
        invalid_data = self.registry_data.copy()
        repos = [repo.copy() for repo in self.registry_data["repositories"]]
        repos[0]["full_name"] = "wrong-owner/wrong-repo"
        invalid_data["repositories"] = repos

        with self.assertRaises(ValidationError) as ctx:
            validate_semantic_rules(invalid_data)
        self.assertEqual(ctx.exception.code, "semantic_validation_failed")

    def test_inconsistent_url_fails(self):
        """Registry with inconsistent URL must fail semantic validation."""
        invalid_data = self.registry_data.copy()
        repos = [repo.copy() for repo in self.registry_data["repositories"]]
        repos[0]["url"] = "https://github.com/wrong-owner/wrong-repo"
        invalid_data["repositories"] = repos

        with self.assertRaises(ValidationError) as ctx:
            validate_semantic_rules(invalid_data)
        self.assertEqual(ctx.exception.code, "semantic_validation_failed")

    def test_invalid_sha_format_fails(self):
        """Registry with invalid SHA format must fail schema validation."""
        invalid_data = self.registry_data.copy()
        repos = [repo.copy() for repo in self.registry_data["repositories"]]
        repos[0]["main_sha"] = "invalid"  # Too short
        invalid_data["repositories"] = repos

        with self.assertRaises(ValidationError) as ctx:
            validate_schema(invalid_data, self.schema_data)
        self.assertEqual(ctx.exception.code, "schema_validation_failed")

    def test_missing_required_field_fails(self):
        """Registry with missing required field must fail schema validation."""
        invalid_data = self.registry_data.copy()
        repos = [repo.copy() for repo in self.registry_data["repositories"]]
        del repos[0]["boundary"]
        invalid_data["repositories"] = repos

        with self.assertRaises(ValidationError) as ctx:
            validate_schema(invalid_data, self.schema_data)
        self.assertEqual(ctx.exception.code, "schema_validation_failed")

    def test_invalid_role_fails(self):
        """Registry with invalid role must fail schema validation."""
        invalid_data = self.registry_data.copy()
        repos = [repo.copy() for repo in self.registry_data["repositories"]]
        repos[0]["role"] = "invalid_role"
        invalid_data["repositories"] = repos

        with self.assertRaises(ValidationError) as ctx:
            validate_schema(invalid_data, self.schema_data)
        self.assertEqual(ctx.exception.code, "schema_validation_failed")

    def test_invalid_visibility_fails(self):
        """Registry with invalid visibility must fail schema validation."""
        invalid_data = self.registry_data.copy()
        repos = [repo.copy() for repo in self.registry_data["repositories"]]
        repos[0]["visibility"] = "invalid"
        invalid_data["repositories"] = repos

        with self.assertRaises(ValidationError) as ctx:
            validate_schema(invalid_data, self.schema_data)
        self.assertEqual(ctx.exception.code, "schema_validation_failed")

    def test_no_extra_repositories(self):
        """Registry must have no extra repositories beyond the three."""
        self.assertEqual(len(self.registry_data["repositories"]), 3)

    def test_no_missing_repositories(self):
        """Registry must have all three required repositories."""
        roles = {repo["role"] for repo in self.registry_data["repositories"]}
        self.assertEqual(roles, {"governance", "template", "voice"})


if __name__ == "__main__":
    unittest.main()
