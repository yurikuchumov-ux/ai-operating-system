"""Canonical repository registry validator.

This module provides validation for the canonical repositories registry
against its JSON Schema and semantic constraints.
"""

from typing import List


def _import_jsonschema():
    """Lazy import helper for jsonschema dependency.

    Returns:
        The jsonschema module.

    Raises:
        ModuleNotFoundError: If jsonschema is not installed.
    """
    import jsonschema
    return jsonschema


def validate_registry(registry, schema) -> List[str]:
    """Validate the canonical repositories registry.

    Args:
        registry: The registry document to validate.
        schema: The JSON Schema to validate against.

    Returns:
        A sorted list of unique error codes. Empty list indicates success.

    Error codes:
        - jsonschema_dependency_missing: jsonschema package not available
        - schema_definition_invalid: The schema itself is invalid
        - schema_validation_failed: The registry fails schema validation
        - canonical_owner_unknown: Unknown owner in a repository entry
        - canonical_repository_unknown: Unknown repository name
        - canonical_repository_role_mismatch: Repository assigned wrong role
        - full_name_mismatch: full_name does not match owner/name
        - url_mismatch: url does not match expected format
        - duplicate_role: Multiple entries with same role
        - duplicate_label: Multiple entries with same label
        - duplicate_full_name: Multiple entries with same full_name
        - duplicate_url: Multiple entries with same url
    """
    errors = []

    # Step 1: Dependency check - lazy import jsonschema
    try:
        jsonschema = _import_jsonschema()
    except ModuleNotFoundError:
        return ["jsonschema_dependency_missing"]

    # Step 2: Schema definition validation
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
    except (jsonschema.SchemaError, jsonschema.exceptions.SchemaError):
        return ["schema_definition_invalid"]
    except Exception:
        return ["schema_definition_invalid"]

    # Step 3: Schema instance validation
    try:
        validator = jsonschema.Draft202012Validator(
            schema,
            format_checker=jsonschema.FormatChecker()
        )
        validation_errors = list(validator.iter_errors(registry))
        if validation_errors:
            return ["schema_validation_failed"]
    except Exception:
        return ["schema_validation_failed"]

    # Step 4: Semantic validation (only after schema passes)

    # Canonical repository definitions
    CANONICAL_REPOS = {
        ("yurikuchumov-ux", "ai-operating-system"): "governance",
        ("yurikuchumov-ux", "ai-development-studio-template"): "template",
        ("yurikuchumov-ux", "-ai-development-studio"): "platform",
    }

    CANONICAL_OWNERS = {"yurikuchumov-ux"}
    CANONICAL_NAMES = {
        "ai-operating-system",
        "ai-development-studio-template",
        "-ai-development-studio"
    }

    # Get canonical_repositories array
    if not isinstance(registry, dict):
        return errors

    canonical_repositories = registry.get("canonical_repositories", [])
    if not isinstance(canonical_repositories, list):
        return errors

    # Track duplicates
    seen_roles = set()
    seen_labels = set()
    seen_full_names = set()
    seen_urls = set()

    for entry in canonical_repositories:
        if not isinstance(entry, dict):
            continue

        role = entry.get("role")
        label = entry.get("label")
        owner = entry.get("owner")
        name = entry.get("name")
        full_name = entry.get("full_name")
        url = entry.get("url")

        # Check for unknown owner
        if owner not in CANONICAL_OWNERS:
            if "canonical_owner_unknown" not in errors:
                errors.append("canonical_owner_unknown")

        # Check for unknown repository name
        if name not in CANONICAL_NAMES:
            if "canonical_repository_unknown" not in errors:
                errors.append("canonical_repository_unknown")

        # Check for role mismatch
        expected_role = CANONICAL_REPOS.get((owner, name))
        if expected_role and role != expected_role:
            if "canonical_repository_role_mismatch" not in errors:
                errors.append("canonical_repository_role_mismatch")

        # Check full_name matches owner/name
        expected_full_name = f"{owner}/{name}"
        if full_name != expected_full_name:
            if "full_name_mismatch" not in errors:
                errors.append("full_name_mismatch")

        # Check url matches expected format
        expected_url = f"https://github.com/{owner}/{name}"
        if url != expected_url:
            if "url_mismatch" not in errors:
                errors.append("url_mismatch")

        # Check for duplicate role
        if role:
            if role in seen_roles:
                if "duplicate_role" not in errors:
                    errors.append("duplicate_role")
            seen_roles.add(role)

        # Check for duplicate label
        if label:
            if label in seen_labels:
                if "duplicate_label" not in errors:
                    errors.append("duplicate_label")
            seen_labels.add(label)

        # Check for duplicate full_name
        if full_name:
            if full_name in seen_full_names:
                if "duplicate_full_name" not in errors:
                    errors.append("duplicate_full_name")
            seen_full_names.add(full_name)

        # Check for duplicate url
        if url:
            if url in seen_urls:
                if "duplicate_url" not in errors:
                    errors.append("duplicate_url")
            seen_urls.add(url)

    # Return sorted unique error codes
    return sorted(list(set(errors)))
