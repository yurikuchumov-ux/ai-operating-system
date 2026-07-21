"""Tests for canonical repository registry contract validation.

This module tests the canonical repository registry validation
against the v1 contract specification.
"""

import copy
import json
import unittest
from unittest.mock import patch

from tools.canonical_repository_registry import validate_registry


class TestCanonicalRepositoryContract(unittest.TestCase):
    """Test cases for canonical repository registry contract."""

    def setUp(self):
        """Set up test fixtures."""
        # Exact canonical document
        self.canonical_registry = {
            "schema_version": "1.0.0",
            "canonical_repositories": [
                {
                    "role": "governance",
                    "label": "Governance and shared contracts",
                    "owner": "yurikuchumov-ux",
                    "name": "ai-operating-system",
                    "full_name": "yurikuchumov-ux/ai-operating-system",
                    "url": "https://github.com/yurikuchumov-ux/ai-operating-system",
                    "visibility": "public",
                    "boundary": "owns governance, schemas, reusable workflows and evidence contracts"
                },
                {
                    "role": "template",
                    "label": "Compliant repository fixture",
                    "owner": "yurikuchumov-ux",
                    "name": "ai-development-studio-template",
                    "full_name": "yurikuchumov-ux/ai-development-studio-template",
                    "url": "https://github.com/yurikuchumov-ux/ai-development-studio-template",
                    "visibility": "public",
                    "boundary": "owns the minimal downstream skeleton and repeatability tests"
                },
                {
                    "role": "platform",
                    "label": "AI Development Studio platform",
                    "owner": "yurikuchumov-ux",
                    "name": "-ai-development-studio",
                    "full_name": "yurikuchumov-ux/-ai-development-studio",
                    "url": "https://github.com/yurikuchumov-ux/-ai-development-studio",
                    "visibility": "private",
                    "boundary": "owns the automated agentic software-development platform runtime and platform delivery"
                }
            ]
        }

        # Exact canonical schema
        self.canonical_schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://github.com/yurikuchumov-ux/ai-operating-system/contracts/schemas/canonical-repositories.v1.schema.json",
            "title": "Canonical Repositories Registry v1",
            "description": "Immutable registry of canonical repositories defining governance, template and platform roles",
            "type": "object",
            "required": ["schema_version", "canonical_repositories"],
            "additionalProperties": False,
            "properties": {
                "schema_version": {
                    "type": "string",
                    "const": "1.0.0"
                },
                "canonical_repositories": {
                    "type": "array",
                    "minItems": 3,
                    "maxItems": 3,
                    "uniqueItems": True,
                    "items": {
                        "type": "object",
                        "required": [
                            "role",
                            "label",
                            "owner",
                            "name",
                            "full_name",
                            "url",
                            "visibility",
                            "boundary"
                        ],
                        "additionalProperties": False,
                        "properties": {
                            "role": {
                                "type": "string",
                                "enum": ["governance", "template", "platform"]
                            },
                            "label": {
                                "type": "string"
                            },
                            "owner": {
                                "type": "string"
                            },
                            "name": {
                                "type": "string"
                            },
                            "full_name": {
                                "type": "string"
                            },
                            "url": {
                                "type": "string",
                                "format": "uri"
                            },
                            "visibility": {
                                "type": "string",
                                "enum": ["public", "private"]
                            },
                            "boundary": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        }

    def test_exact_canonical_document_returns_empty_list(self):
        """Test that the exact canonical document validates successfully."""
        result = validate_registry(self.canonical_registry, self.canonical_schema)
        self.assertEqual(result, [])

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
        # Change second entry to have same role as first
        registry["canonical_repositories"][1]["role"] = "governance"
        result = validate_registry(registry, self.canonical_schema)
        self.assertIn("duplicate_role", result)

    def test_duplicate_label(self):
        """Test that duplicate label returns duplicate_label error code."""
        registry = copy.deepcopy(self.canonical_registry)
        registry["canonical_repositories"][1]["label"] = registry["canonical_repositories"][0]["label"]
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
