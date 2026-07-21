#!/usr/bin/env python3
"""Canonical repository registry semantic validator.

This module validates the stable canonical repository identity contract.
It performs registry-internal semantic validation beyond JSON Schema.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping


def validate_registry(registry: Mapping[str, Any], schema: Mapping[str, Any]) -> List[str]:
    """Validate canonical repository registry semantics.

    Args:
        registry: The canonical repository registry document
        schema: The JSON Schema for validation (used for reference)

    Returns:
        Deterministically ordered list of stable error codes.
        Empty list means valid.
    """
    errors: List[str] = []

    # Check for required top-level keys
    if "schema_version" not in registry:
        errors.append("missing_schema_version")
    if "canonical_repositories" not in registry:
        errors.append("missing_canonical_repositories")
        return sorted(errors)

    repositories = registry["canonical_repositories"]

    if not isinstance(repositories, list):
        errors.append("canonical_repositories_not_array")
        return sorted(errors)

    # Check for mutable fields that are forbidden
    forbidden_mutable_fields = ["main_sha", "head_sha", "run_id", "execution_id"]
    for idx, repo in enumerate(repositories):
        if not isinstance(repo, dict):
            continue
        for field in forbidden_mutable_fields:
            if field in repo:
                errors.append(f"forbidden_mutable_field_{field}")

    # Validate semantic relations
    seen_roles: Dict[str, int] = {}
    seen_labels: Dict[str, int] = {}
    seen_full_names: Dict[str, int] = {}
    seen_urls: Dict[str, int] = {}

    for idx, repo in enumerate(repositories):
        if not isinstance(repo, dict):
            continue

        # Check role uniqueness
        role = repo.get("role")
        if role is not None:
            if role in seen_roles:
                errors.append("duplicate_role")
            seen_roles[role] = idx

        # Check label uniqueness
        label = repo.get("label")
        if label is not None:
            if label in seen_labels:
                errors.append("duplicate_label")
            seen_labels[label] = idx

        # Check full_name uniqueness
        full_name = repo.get("full_name")
        if full_name is not None:
            if full_name in seen_full_names:
                errors.append("duplicate_full_name")
            seen_full_names[full_name] = idx

        # Check url uniqueness
        url = repo.get("url")
        if url is not None:
            if url in seen_urls:
                errors.append("duplicate_url")
            seen_urls[url] = idx

        # Validate full_name equals owner/name
        owner = repo.get("owner")
        name = repo.get("name")
        if owner is not None and name is not None and full_name is not None:
            expected_full_name = f"{owner}/{name}"
            if full_name != expected_full_name:
                errors.append("full_name_mismatch")

        # Validate url equals https://github.com/full_name
        if full_name is not None and url is not None:
            expected_url = f"https://github.com/{full_name}"
            if url != expected_url:
                errors.append("url_mismatch")

    # Return deterministically ordered unique error codes
    return sorted(set(errors))
