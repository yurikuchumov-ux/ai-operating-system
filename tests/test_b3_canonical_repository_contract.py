"""Tests for canonical repository registry contract validation.

This module tests the canonical repository registry validation
against the v1 contract specification.
"""

import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.canonical_repository_registry import validate_registry


class TestCanonicalRepositoryContract(unittest.TestCase):
    """Test cases for canonical repository registry contract."""

    def setUp(self):
        """Load the committed contract files used by production."""
        repo_root = Path(__file__).resolve().parents[1]
        registry_path = repo_root / "contracts" / "canonical-repositories.v1.json"
        schema_path = repo_root / "contracts" / "schemas" / "canonical-repositories.v1.schema.json"
        self.canonical_registry = json.loads(registry_path.read_text(encoding="utf-8"))
        self.canonical_schema = json.loads(schema_path.read_text(encoding="utf-8"))

    def test_exact_canonical_document_returns_empty_list(self):
        """Test that the exact canonical document validates successfully."""
        result = validate_registry(self.canonical_registry, self.canonical_schema)
        self.assertEqual(result, [])

    def test_unique_noncanonical_label_fails_closed(self):
        """A unique but incorrect label is not canonical metadata."""
        registry = copy.deepcopy(self.canonical_registry)
        registry["canonical_repositories"][0]["label"] = "Changed governance label"
        self.assertEqual(validate_registry(registry, self.canonical_schema), ["schema_validation_failed"])

    def test_noncanonical_visibility_fails_closed(self):
        """Visibility is bound to the repository role."""
        registry = copy.deepcopy(self.canonical_registry)
        registry["canonical_repositories"][0]["visibility"] = "private"
        self.assertEqual(validate_registry(registry, self.canonical_schema), ["schema_validation_failed"])

    def test_noncanonical_boundary_fails_closed(self):
        """A changed ownership boundary is rejected."""
        registry = copy.deepcopy(self.canonical_registry)
        registry["canonical_repositories"][0]["boundary"] = "changed boundary"
        self.assertEqual(validate_registry(registry, self.canonical_schema), ["schema_validation_failed"])

    def test_swapped_visibility_fails_closed(self):
        """Swapping valid visibility values between canonical roles is rejected."""
        registry = copy.deepcopy(self.canonical_registry)
        registry["canonical_repositories"][0]["visibility"] = "private"
        registry["canonical_repositories"][2]["visibility"] = "public"
        self.assertEqual(validate_registry(registry, self.canonical_schema), ["schema_validation_failed"])

    def test_exact_top_level_keys_required(self):
        """Test that exact top-level keys are required."""
        # Missing schema_version
        registry = copy.deepcopy(self.canonical_registry)
        del registry["schema_version"]
        result = validate_registry(registry, self.canonical_schema)
        self.assertEqual(result, ["schema_validation_failed"])

        # Missing canonical_repositories
        registry = copy.deepcopy(self.canonical_registry)
        del registry["canonical_repositories"]
        result = validate_registry(registry, self.canonical_schema)
        self.assertEqual(result, ["schema_validation_failed"])

    def test_alternative_shape_rejected(self):
        """Test that alternative top-level keys like registry_type and entries are rejected."""
        # Using registry_type instead of schema_version
        registry = {
            "registry_type": "canonical",
            "entries": self.canonical_registry["canonical_repositories"]
        }
        result = validate_registry(registry, self.canonical_schema)
        self.assertEqual(result, ["schema_validation_failed"])

    def test_missing_entry_returns_schema_validation_failed(self):
        """Test that missing an entry returns schema_validation_failed."""
        registry = copy.deepcopy(self.canonical_registry)
        registry["canonical_repositories"] = registry["canonical_repositories"][:2]
        result = validate_registry(registry, self.canonical_schema)
        self.assertEqual(result, ["schema_validation_failed"])

    def test_extra_entry_returns_schema_validation_failed(self):
        """Test that adding an extra entry returns schema_validation_failed."""
        registry = copy.deepcopy(self.canonical_registry)
        extra_entry = {
            "role": "governance",
            "label": "Extra repo",
            "owner": "yurikuchumov-ux",
            "name": "extra-repo",
            "full_name": "yurikuchumov-ux/extra-repo",
            "url": "https://github.com/yurikuchumov-ux/extra-repo",
            "visibility": "public",
            "boundary": "extra"
        }
        registry["canonical_repositories"].append(extra_entry)
        result = validate_registry(registry, self.canonical_schema)
        self.assertEqual(result, ["schema_validation_failed"])

    def test_unknown_owner_includes_canonical_owner_unknown(self):
        """Test that a relation-consistent unknown owner includes canonical_owner_unknown."""
        registry = copy.deepcopy(self.canonical_registry)
        registry["canonical_repositories"][0]["owner"] = "unknown-owner"
        registry["canonical_repositories"][0]["full_name"] = "unknown-owner/ai-operating-system"
        registry["canonical_repositories"][0]["url"] = "https://github.com/unknown-owner/ai-operating-system"
        result = validate_registry(registry, self.canonical_schema)
        self.assertIn("canonical_owner_unknown", result)

    def test_unknown_repository_includes_canonical_repository_unknown(self):
        """Test that a relation-consistent unknown name includes canonical_repository_unknown."""
        registry = copy.deepcopy(self.canonical_registry)
        registry["canonical_repositories"][0]["name"] = "unknown-repo"
        registry["canonical_repositories"][0]["full_name"] = "yurikuchumov-ux/unknown-repo"
        registry["canonical_repositories"][0]["url"] = "https://github.com/yurikuchumov-ux/unknown-repo"
        result = validate_registry(registry, self.canonical_schema)
        self.assertIn("canonical_repository_unknown", result)

    def test_role_mismatch_includes_canonical_repository_role_mismatch(self):
        """Test that swapping canonical names between roles includes canonical_repository_role_mismatch."""
        registry = copy.deepcopy(self.canonical_registry)
        # Swap governance and template repos
        registry["canonical_repositories"][0]["name"] = "ai-development-studio-template"
        registry["canonical_repositories"][0]["full_name"] = "yurikuchumov-ux/ai-development-studio-template"
        registry["canonical_repositories"][0]["url"] = "https://github.com/yurikuchumov-ux/ai-development-studio-template"

        registry["canonical_repositories"][1]["name"] = "ai-operating-system"
        registry["canonical_repositories"][1]["full_name"] = "yurikuchumov-ux/ai-operating-system"
        registry["canonical_repositories"][1]["url"] = "https://github.com/yurikuchumov-ux/ai-operating-system"

        result = validate_registry(registry, self.canonical_schema)
        self.assertIn("canonical_repository_role_mismatch", result)

    def test_duplicate_role(self):
        """Test that duplicate role returns duplicate_role error code."""
        registry = copy.deepcopy(self.canonical_registry)
        # Keep role-bound metadata schema-valid so semantic duplicate detection runs.
        first = registry["canonical_repositories"][0]
        second = registry["canonical_repositories"][1]
        second["role"] = "governance"
        second["label"] = first["label"]
        second["visibility"] = first["visibility"]
        second["boundary"] = first["boundary"]
        result = validate_registry(registry, self.canonical_schema)
        self.assertIn("duplicate_role", result)

    def test_duplicate_label(self):
        """Test that duplicate label returns duplicate_label error code."""
        registry = copy.deepcopy(self.canonical_registry)
        # Align role-bound metadata with governance so schema validation passes
        # and the production semantic duplicate-label path is exercised.
        first = registry["canonical_repositories"][0]
        second = registry["canonical_repositories"][1]
        second["role"] = "governance"
        second["label"] = first["label"]
        second["visibility"] = first["visibility"]
        second["boundary"] = first["boundary"]
        result = validate_registry(registry, self.canonical_schema)
        self.assertIn("duplicate_label", result)

    def test_duplicate_full_name(self):
        """Test that duplicate full_name returns duplicate_full_name error code."""
        registry = copy.deepcopy(self.canonical_registry)
        registry["canonical_repositories"][1]["full_name"] = registry["canonical_repositories"][0]["full_name"]
        result = validate_registry(registry, self.canonical_schema)
        self.assertIn("duplicate_full_name", result)

    def test_duplicate_url(self):
        """Test that duplicate url returns duplicate_url error code."""
        registry = copy.deepcopy(self.canonical_registry)
        registry["canonical_repositories"][1]["url"] = registry["canonical_repositories"][0]["url"]
        result = validate_registry(registry, self.canonical_schema)
        self.assertIn("duplicate_url", result)

    def test_full_name_mismatch(self):
        """Test that full_name mismatch returns full_name_mismatch error code."""
        registry = copy.deepcopy(self.canonical_registry)
        registry["canonical_repositories"][0]["full_name"] = "wrong/format"
        result = validate_registry(registry, self.canonical_schema)
        self.assertIn("full_name_mismatch", result)

    def test_url_mismatch(self):
        """Test that url mismatch returns url_mismatch error code."""
        registry = copy.deepcopy(self.canonical_registry)
        registry["canonical_repositories"][0]["url"] = "https://example.com/wrong"
        result = validate_registry(registry, self.canonical_schema)
        self.assertIn("url_mismatch", result)

    def test_mutable_field_returns_schema_validation_failed(self):
        """Test that mutable main_sha returns schema_validation_failed because additional properties are forbidden."""
        registry = copy.deepcopy(self.canonical_registry)
        registry["canonical_repositories"][0]["main_sha"] = "abc123"
        result = validate_registry(registry, self.canonical_schema)
        self.assertEqual(result, ["schema_validation_failed"])

    def test_malformed_registry_returns_schema_validation_failed(self):
        """Test that malformed registry returns schema_validation_failed."""
        malformed_registry = {
            "schema_version": "1.0.0",
            "canonical_repositories": "not-an-array"
        }
        result = validate_registry(malformed_registry, self.canonical_schema)
        self.assertEqual(result, ["schema_validation_failed"])

    def test_invalid_schema_type_returns_schema_definition_invalid(self):
        """Test that actually invalid schema type 42 returns schema_definition_invalid."""
        invalid_schema = {"type": 42}
        result = validate_registry(self.canonical_registry, invalid_schema)
        self.assertEqual(result, ["schema_definition_invalid"])

    def test_strict_versus_permissive_schema(self):
        """Test strict versus permissive supplied schema proves the schema argument is used."""
        # Permissive schema allows additional properties
        permissive_schema = copy.deepcopy(self.canonical_schema)
        permissive_schema["additionalProperties"] = True
        permissive_schema["properties"]["canonical_repositories"]["items"]["additionalProperties"] = True

        # Registry with additional property
        registry = copy.deepcopy(self.canonical_registry)
        registry["canonical_repositories"][0]["extra_field"] = "value"

        # With strict schema, should fail
        result_strict = validate_registry(registry, self.canonical_schema)
        self.assertEqual(result_strict, ["schema_validation_failed"])

        # With permissive schema, should pass schema validation
        result_permissive = validate_registry(registry, permissive_schema)
        # Note: semantic validation still runs, but schema validation passes
        self.assertNotEqual(result_permissive, ["schema_validation_failed"])

    def test_jsonschema_dependency_missing(self):
        """Test real production lazy import interception returns exactly jsonschema_dependency_missing."""
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "jsonschema":
                raise ModuleNotFoundError(f"No module named '{name}'")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            result = validate_registry(self.canonical_registry, self.canonical_schema)
            self.assertEqual(result, ["jsonschema_dependency_missing"])


if __name__ == "__main__":
    unittest.main()
