#!/usr/bin/env python3
"""Validate canonical repository registry against schema and semantic rules."""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


class ValidationError(Exception):
    """Validation failure with specific error code."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


def load_json(path: Path) -> Dict[str, Any]:
    """Load and parse JSON file."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ValidationError("json_parse_error", f"Invalid JSON in {path}: {e}")
    except IOError as e:
        raise ValidationError("io_error", f"Cannot read {path}: {e}")


def validate_schema(data: Dict[str, Any], schema: Dict[str, Any]) -> None:
    """Validate data against JSON schema."""
    try:
        import jsonschema
        jsonschema.validate(instance=data, schema=schema)
    except ImportError:
        # Fallback to basic validation if jsonschema not available
        _basic_schema_validation(data, schema)
    except Exception as e:
        raise ValidationError("schema_validation_failed", str(e))


def _basic_schema_validation(data: Dict[str, Any], schema: Dict[str, Any]) -> None:
    """Basic schema validation without jsonschema library."""
    # Check required top-level fields
    required = schema.get("required", [])
    for field in required:
        if field not in data:
            raise ValidationError(
                "schema_validation_failed",
                f"Missing required field: {field}"
            )

    # Validate schema_version
    if "schema_version" in data:
        if data["schema_version"] != "1.0.0":
            raise ValidationError(
                "schema_validation_failed",
                f"Invalid schema_version: {data['schema_version']}"
            )

    # Validate repositories
    repos = data.get("repositories", [])
    if not isinstance(repos, list):
        raise ValidationError(
            "schema_validation_failed",
            "repositories must be an array"
        )

    if len(repos) != 3:
        raise ValidationError(
            "schema_validation_failed",
            f"repositories must contain exactly 3 entries, found {len(repos)}"
        )

    # Validate each repository entry
    required_repo_fields = ["role", "name", "full_name", "url", "visibility", "main_sha", "boundary"]
    valid_roles = {"governance", "template", "voice"}
    valid_visibilities = {"public", "private"}

    for i, repo in enumerate(repos):
        if not isinstance(repo, dict):
            raise ValidationError(
                "schema_validation_failed",
                f"Repository entry {i} must be an object"
            )

        for field in required_repo_fields:
            if field not in repo:
                raise ValidationError(
                    "schema_validation_failed",
                    f"Repository entry {i} missing required field: {field}"
                )

        # Validate role
        if repo["role"] not in valid_roles:
            raise ValidationError(
                "schema_validation_failed",
                f"Repository entry {i} has invalid role: {repo['role']}"
            )

        # Validate visibility
        if repo["visibility"] not in valid_visibilities:
            raise ValidationError(
                "schema_validation_failed",
                f"Repository entry {i} has invalid visibility: {repo['visibility']}"
            )

        # Validate main_sha format (40 lowercase hex characters)
        sha = repo["main_sha"]
        if not isinstance(sha, str) or len(sha) != 40:
            raise ValidationError(
                "schema_validation_failed",
                f"Repository entry {i} has invalid main_sha length"
            )
        if not all(c in "0123456789abcdef" for c in sha):
            raise ValidationError(
                "schema_validation_failed",
                f"Repository entry {i} has invalid main_sha format"
            )

        # Validate URL format
        url = repo["url"]
        if not isinstance(url, str) or not url.startswith("https://github.com/"):
            raise ValidationError(
                "schema_validation_failed",
                f"Repository entry {i} has invalid URL"
            )


def validate_semantic_rules(data: Dict[str, Any]) -> None:
    """Validate semantic rules beyond schema structure."""
    repos = data["repositories"]

    # Check for unique roles
    roles = [repo["role"] for repo in repos]
    if len(roles) != len(set(roles)):
        raise ValidationError(
            "semantic_validation_failed",
            "Duplicate roles found"
        )

    # Check for unique names
    names = [repo["name"] for repo in repos]
    if len(names) != len(set(names)):
        raise ValidationError(
            "semantic_validation_failed",
            "Duplicate repository names found"
        )

    # Check for unique full_names
    full_names = [repo["full_name"] for repo in repos]
    if len(full_names) != len(set(full_names)):
        raise ValidationError(
            "semantic_validation_failed",
            "Duplicate full_name values found"
        )

    # Check for unique URLs
    urls = [repo["url"] for repo in repos]
    if len(urls) != len(set(urls)):
        raise ValidationError(
            "semantic_validation_failed",
            "Duplicate URL values found"
        )

    # Validate consistency between owner, name, full_name, and url
    owner = data["owner"]
    for repo in repos:
        expected_full_name = f"{owner}/{repo['name']}"
        if repo["full_name"] != expected_full_name:
            raise ValidationError(
                "semantic_validation_failed",
                f"Repository {repo['name']}: full_name '{repo['full_name']}' "
                f"does not match owner/name '{expected_full_name}'"
            )

        expected_url = f"https://github.com/{owner}/{repo['name']}"
        if repo["url"] != expected_url:
            raise ValidationError(
                "semantic_validation_failed",
                f"Repository {repo['name']}: url '{repo['url']}' "
                f"does not match expected '{expected_url}'"
            )


def validate_unicode(data: Dict[str, Any]) -> None:
    """Validate that all string data is valid Unicode."""
    def check_string(value: Any, path: str) -> None:
        if isinstance(value, str):
            try:
                value.encode('utf-8')
            except UnicodeEncodeError as e:
                raise ValidationError(
                    "unicode_error",
                    f"Invalid Unicode at {path}: {e}"
                )
        elif isinstance(value, dict):
            for key, val in value.items():
                check_string(val, f"{path}.{key}")
        elif isinstance(value, list):
            for i, val in enumerate(value):
                check_string(val, f"{path}[{i}]")

    check_string(data, "root")


def main() -> int:
    """Main validation entry point."""
    repo_root = Path(__file__).parent.parent
    registry_path = repo_root / "contracts" / "canonical-repositories.v1.json"
    schema_path = repo_root / "contracts" / "schemas" / "canonical-repositories.v1.schema.json"

    try:
        # Load files
        registry_data = load_json(registry_path)
        schema_data = load_json(schema_path)

        # Validate Unicode
        validate_unicode(registry_data)

        # Validate against schema
        validate_schema(registry_data, schema_data)

        # Validate semantic rules
        validate_semantic_rules(registry_data)

        print("✓ Canonical repository registry validation passed")
        return 0

    except ValidationError as e:
        print(f"✗ Validation failed: {e.code}", file=sys.stderr)
        print(f"  {e.message}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"✗ Unexpected error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
