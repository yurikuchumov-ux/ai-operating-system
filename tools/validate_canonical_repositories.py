#!/usr/bin/env python3
"""Canonical repository registry and execution plan validator.

This tool validates the canonical repository registry and execution plan
documents. It always emits JSON output, including for missing dependencies
and malformed input.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

# Gracefully handle missing jsonschema
try:
    from jsonschema import Draft202012Validator, FormatChecker
    JSONSCHEMA_AVAILABLE = True
except ModuleNotFoundError:
    JSONSCHEMA_AVAILABLE = False


REPO_ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = REPO_ROOT / "contracts/canonical-repositories.v1.json"
SCHEMA_PATH = REPO_ROOT / "contracts/schemas/canonical-repositories.v1.schema.json"
PLAN_PATH = REPO_ROOT / "docs/AI_DEVELOPMENT_STUDIO_EXECUTION_PLAN.md"


def emit_json(data: Mapping[str, Any]) -> None:
    """Emit JSON to stdout."""
    json.dump(data, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def load_json_safe(path: Path) -> tuple[Optional[Any], Optional[str]]:
    """Load JSON file, returning (data, error_code) tuple."""
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f), None
    except FileNotFoundError:
        return None, "file_not_found"
    except json.JSONDecodeError as e:
        return None, f"json_decode_error_line_{e.lineno}_col_{e.colno}"
    except Exception:
        return None, "file_read_error"


def validate_registry(registry: Mapping[str, Any], schema: Optional[Mapping[str, Any]]) -> List[str]:
    """Validate registry structure and return error codes."""
    error_codes = []

    # Check top-level keys
    if set(registry.keys()) != {"schema_version", "canonical_repositories"}:
        error_codes.append("registry_invalid_top_keys")
        return error_codes

    if registry.get("schema_version") != "1.0.0":
        error_codes.append("registry_unsupported_version")

    repos = registry.get("canonical_repositories", [])
    if not isinstance(repos, list):
        error_codes.append("registry_repositories_not_array")
        return error_codes

    if len(repos) == 0:
        error_codes.append("registry_empty_repositories")

    # Check for duplicate full_names
    full_names = []
    labels = []
    for repo in repos:
        if not isinstance(repo, dict):
            error_codes.append("registry_repository_not_object")
            continue
        full_name = repo.get("full_name")
        if full_name:
            full_names.append(full_name)
        label = repo.get("label")
        if label:
            labels.append(label)

    if len(full_names) != len(set(full_names)):
        error_codes.append("registry_duplicate_full_name")

    if len(labels) != len(set(labels)):
        error_codes.append("registry_duplicate_label")

    # Schema validation if available
    if JSONSCHEMA_AVAILABLE and schema is not None:
        try:
            validator = Draft202012Validator(schema, format_checker=FormatChecker())
            schema_errors = list(validator.iter_errors(registry))
            if schema_errors:
                error_codes.append("registry_schema_validation_failed")
        except Exception:
            error_codes.append("registry_schema_validation_error")

    return error_codes


def validate_execution_plan(plan_text: str, registry: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate execution plan against canonical repository registry.

    Returns validation result with error codes for specific issues.
    Uses literal label joins only, no normalization or role joins.
    """
    error_codes = []

    # Build label-to-repo map using literal labels from registry
    label_map = {}
    for repo in registry.get("canonical_repositories", []):
        label = repo.get("label")
        if label:
            label_map[label] = repo

    # Find section 3.1 table
    lines = plan_text.split("\n")
    section_31_found = False
    table_start = -1

    for i, line in enumerate(lines):
        if "### 3.1 Verified names and boundaries" in line:
            section_31_found = True
        if section_31_found and re.match(r'^\| Role \|', line):
            table_start = i
            break

    if not section_31_found:
        error_codes.append("plan_section_3_1_not_found")
        return {"valid": False, "error_codes": error_codes}

    if table_start == -1:
        error_codes.append("plan_table_header_not_found")
        return {"valid": False, "error_codes": error_codes}

    # Parse table
    table_header_line = lines[table_start]
    if table_start + 1 >= len(lines):
        error_codes.append("plan_table_separator_missing")
        return {"valid": False, "error_codes": error_codes}

    table_separator = lines[table_start + 1]
    if not re.match(r'^\| ---', table_separator):
        error_codes.append("plan_table_separator_invalid")
        return {"valid": False, "error_codes": error_codes}

    # Collect table rows
    table_rows = []
    for i in range(table_start + 2, len(lines)):
        line = lines[i]
        if not line.strip().startswith("|"):
            break
        table_rows.append(line)

    if len(table_rows) == 0:
        error_codes.append("plan_table_empty")
        return {"valid": False, "error_codes": error_codes}

    # Expected rows based on registry labels
    expected_labels = set(label_map.keys())
    found_labels = set()

    for row in table_rows:
        # Parse row cells
        cells = [cell.strip() for cell in row.split("|")[1:-1]]
        if len(cells) < 5:
            error_codes.append("plan_row_insufficient_columns")
            continue

        role_cell = cells[0]
        repo_cell = cells[1]
        sha_cell = cells[3]

        # Determine which label this row should match
        # Use literal label matching based on document text patterns
        matched_label = None
        if "Governance and shared contracts" in role_cell:
            matched_label = "governance"
        elif "Compliant repository fixture" in role_cell:
            matched_label = "template"
        elif "Voice reference product" in role_cell:
            matched_label = "voice"

        if matched_label is None:
            error_codes.append("plan_row_unrecognized_role")
            continue

        if matched_label in found_labels:
            error_codes.append("plan_duplicate_label_row")
            continue

        found_labels.add(matched_label)

        # Get expected values from registry
        expected_repo = label_map.get(matched_label)
        if expected_repo is None:
            error_codes.append("plan_label_not_in_registry")
            continue

        # Extract repository name from markdown link
        repo_match = re.search(r'\[`([^`]+)`\]', repo_cell)
        if not repo_match:
            error_codes.append("plan_repo_name_not_found")
            continue

        actual_repo_name = repo_match.group(1)
        expected_repo_name = expected_repo.get("full_name")

        if actual_repo_name != expected_repo_name:
            error_codes.append("plan_repo_name_mismatch")

        # Extract SHA from markdown code
        sha_match = re.search(r'`([0-9a-f]{40})`', sha_cell)
        if not sha_match:
            error_codes.append("plan_sha_not_found")
            continue

        actual_sha = sha_match.group(1)
        expected_sha = expected_repo.get("main_sha")

        if actual_sha != expected_sha:
            error_codes.append("plan_sha_mismatch")

    # Check for missing rows
    missing_labels = expected_labels - found_labels
    if missing_labels:
        error_codes.append("plan_missing_rows")

    # Check for extra rows
    extra_labels = found_labels - expected_labels
    if extra_labels:
        error_codes.append("plan_extra_rows")

    valid = len(error_codes) == 0
    return {"valid": valid, "error_codes": sorted(error_codes)}


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Main entry point. Always emits JSON."""
    parser = argparse.ArgumentParser(
        description="Validate canonical repository registry and execution plan."
    )
    parser.add_argument(
        "--registry",
        type=Path,
        default=REGISTRY_PATH,
        help="Path to canonical repositories registry JSON file.",
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=SCHEMA_PATH,
        help="Path to canonical repositories schema JSON file.",
    )
    parser.add_argument(
        "--plan",
        type=Path,
        default=PLAN_PATH,
        help="Path to execution plan markdown file.",
    )
    parser.add_argument(
        "--check-plan",
        action="store_true",
        help="Validate execution plan against registry.",
    )

    args = parser.parse_args(argv)

    result: Dict[str, Any] = {
        "valid": False,
        "error_codes": [],
    }

    # Check jsonschema availability
    if not JSONSCHEMA_AVAILABLE:
        result["error_codes"].append("missing_jsonschema")
        result["jsonschema_available"] = False
    else:
        result["jsonschema_available"] = True

    # Load registry
    registry, registry_error = load_json_safe(args.registry)
    if registry_error:
        result["error_codes"].append(f"registry_{registry_error}")
        emit_json(result)
        return 1

    # Load schema
    schema, schema_error = load_json_safe(args.schema)
    if schema_error:
        result["error_codes"].append(f"schema_{schema_error}")
        # Continue without schema validation
        schema = None

    # Validate registry
    registry_errors = validate_registry(registry, schema)
    result["error_codes"].extend(registry_errors)

    # Validate plan if requested
    if args.check_plan:
        try:
            plan_text = args.plan.read_text(encoding="utf-8")
        except FileNotFoundError:
            result["error_codes"].append("plan_file_not_found")
            emit_json(result)
            return 1
        except Exception:
            result["error_codes"].append("plan_file_read_error")
            emit_json(result)
            return 1

        plan_result = validate_execution_plan(plan_text, registry)
        result["error_codes"].extend(plan_result["error_codes"])

    # Deduplicate and sort error codes
    result["error_codes"] = sorted(set(result["error_codes"]))
    result["valid"] = len(result["error_codes"]) == 0

    emit_json(result)
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
