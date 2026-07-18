#!/usr/bin/env python3
"""Validate canonical repositories registry against plan."""

import argparse
import json
import re
import sys
from pathlib import Path


def validate_execution_plan(plan_text, registry):
    """Validate execution plan against registry.

    Returns dict with 'valid' bool and optional 'errors' list.
    """
    errors = []

    # Find section heading
    section_heading = "### 3.1 Verified names and boundaries"
    section_count = plan_text.count(section_heading)

    if section_count == 0:
        errors.append({"code": "plan_missing_section", "message": "Section not found"})
        return {"valid": False, "errors": errors}
    elif section_count > 1:
        errors.append({"code": "plan_duplicate_section", "message": "Duplicate section found"})
        return {"valid": False, "errors": errors}

    # Extract table from section
    section_start = plan_text.index(section_heading)
    remaining_text = plan_text[section_start:]

    # Find the header
    expected_header = "| Role | Canonical repository | Visibility | `main` SHA | Boundary |"
    if expected_header not in remaining_text:
        errors.append({"code": "plan_header_mutation", "message": "Header does not match expected format"})
        return {"valid": False, "errors": errors}

    # Extract table rows (between header separator and next section or end)
    header_pos = remaining_text.index(expected_header)
    table_start = remaining_text.index("\n", header_pos + len(expected_header))
    table_start = remaining_text.index("\n", table_start + 1)  # Skip separator line

    # Find end of table (next ## or ### or end of file)
    next_section = len(remaining_text)
    for marker in ["\n## ", "\n### ", "\n**"]:
        pos = remaining_text.find(marker, table_start)
        if pos != -1 and pos < next_section:
            next_section = pos

    table_section = remaining_text[table_start:next_section].strip()

    # Parse table rows
    plan_rows = []
    for line in table_section.split("\n"):
        line = line.strip()
        if not line or not line.startswith("|"):
            continue

        # Parse row
        parts = [p.strip() for p in line.split("|")[1:-1]]  # Remove empty first/last from split
        if len(parts) == 5:
            # Extract repository link from markdown
            repo_match = re.search(r'\[`([^`]+)`\]\(([^)]+)\)', parts[1])
            if repo_match:
                full_name = repo_match.group(1)
                url = repo_match.group(2)

                plan_rows.append({
                    "label": parts[0],
                    "full_name": full_name,
                    "url": url,
                    "visibility": parts[2],
                    "main_sha": parts[3].strip("`"),
                    "boundary": parts[4]
                })

    # Check row count
    if len(plan_rows) != 3:
        if len(plan_rows) < 3:
            errors.append({"code": "plan_missing_row", "message": f"Expected 3 rows, found {len(plan_rows)}"})
        else:
            errors.append({"code": "plan_extra_row", "message": f"Expected 3 rows, found {len(plan_rows)}"})
        return {"valid": False, "errors": errors}

    # Match plan rows to registry entries by label
    registry_by_label = {entry["label"]: entry for entry in registry["canonical_repositories"]}

    for plan_row in plan_rows:
        label = plan_row["label"]

        if label not in registry_by_label:
            errors.append({"code": "plan_missing_row", "message": f"Label '{label}' not found in registry"})
            continue

        registry_entry = registry_by_label[label]

        # Compare fields
        if plan_row["full_name"] != registry_entry["full_name"]:
            errors.append({
                "code": "plan_full_name_mismatch",
                "label": label,
                "expected": registry_entry["full_name"],
                "actual": plan_row["full_name"]
            })

        if plan_row["url"] != registry_entry["url"]:
            errors.append({
                "code": "plan_url_mismatch",
                "label": label,
                "expected": registry_entry["url"],
                "actual": plan_row["url"]
            })

        if plan_row["visibility"] != registry_entry["visibility"]:
            errors.append({
                "code": "plan_visibility_mismatch",
                "label": label,
                "expected": registry_entry["visibility"],
                "actual": plan_row["visibility"]
            })

        if plan_row["main_sha"] != registry_entry["main_sha"]:
            errors.append({
                "code": "plan_main_sha_mismatch",
                "label": label,
                "expected": registry_entry["main_sha"],
                "actual": plan_row["main_sha"]
            })

        if plan_row["boundary"] != registry_entry["boundary"]:
            errors.append({
                "code": "plan_boundary_mismatch",
                "label": label,
                "expected": registry_entry["boundary"],
                "actual": plan_row["boundary"]
            })

    if errors:
        return {"valid": False, "errors": errors}

    return {"valid": True}


def validate_registry_schema(registry, schema):
    """Validate registry against schema using jsonschema."""
    try:
        import jsonschema
    except ImportError:
        return {
            "valid": False,
            "errors": [{"code": "missing_jsonschema", "message": "jsonschema module not available"}]
        }

    try:
        jsonschema.validate(instance=registry, schema=schema)
    except jsonschema.ValidationError as e:
        return {
            "valid": False,
            "errors": [{"code": "schema_validation_failed", "message": str(e)}]
        }

    return {"valid": True}


def validate_uniqueness(registry):
    """Validate uniqueness constraints."""
    errors = []

    repos = registry["canonical_repositories"]

    # Check roles unique
    roles = [r["role"] for r in repos]
    if len(roles) != len(set(roles)):
        errors.append({"code": "roles_not_unique", "message": "Roles must be unique"})

    # Check labels unique
    labels = [r["label"] for r in repos]
    if len(labels) != len(set(labels)):
        errors.append({"code": "labels_not_unique", "message": "Labels must be unique"})

    # Check full_names unique
    full_names = [r["full_name"] for r in repos]
    if len(full_names) != len(set(full_names)):
        errors.append({"code": "full_names_not_unique", "message": "Full names must be unique"})

    if errors:
        return {"valid": False, "errors": errors}

    return {"valid": True}


def main():
    parser = argparse.ArgumentParser(description="Validate canonical repositories registry")
    parser.add_argument("--registry", type=str, help="Path to registry JSON file")
    parser.add_argument("--schema", type=str, help="Path to schema JSON file")
    parser.add_argument("--plan", type=str, help="Path to execution plan markdown file")

    args = parser.parse_args()

    # Default inputs
    default_registry = "contracts/canonical-repositories.v1.json"
    default_schema = "contracts/schemas/canonical-repositories.v1.schema.json"
    default_plan = "docs/AI_DEVELOPMENT_STUDIO_EXECUTION_PLAN.md"

    registry_path = args.registry or default_registry
    schema_path = args.schema or default_schema
    plan_path = args.plan or default_plan

    result = {
        "valid": True,
        "registry_path": registry_path,
        "schema_path": schema_path,
        "plan_path": plan_path,
        "validations": {}
    }

    # Load registry
    try:
        with open(registry_path, "r") as f:
            registry = json.load(f)
    except FileNotFoundError:
        result["valid"] = False
        result["error"] = {"code": "registry_not_found", "path": registry_path}
        print(json.dumps(result))
        return 1
    except json.JSONDecodeError as e:
        result["valid"] = False
        result["error"] = {"code": "registry_invalid_json", "message": str(e)}
        print(json.dumps(result))
        return 1

    # Load schema
    try:
        with open(schema_path, "r") as f:
            schema = json.load(f)
    except FileNotFoundError:
        result["valid"] = False
        result["error"] = {"code": "schema_not_found", "path": schema_path}
        print(json.dumps(result))
        return 1
    except json.JSONDecodeError as e:
        result["valid"] = False
        result["error"] = {"code": "schema_invalid_json", "message": str(e)}
        print(json.dumps(result))
        return 1

    # Validate schema
    schema_result = validate_registry_schema(registry, schema)
    result["validations"]["schema"] = schema_result
    if not schema_result["valid"]:
        result["valid"] = False

    # Validate uniqueness
    uniqueness_result = validate_uniqueness(registry)
    result["validations"]["uniqueness"] = uniqueness_result
    if not uniqueness_result["valid"]:
        result["valid"] = False

    # Load and validate plan
    try:
        with open(plan_path, "r") as f:
            plan_text = f.read()
    except FileNotFoundError:
        result["valid"] = False
        result["error"] = {"code": "plan_not_found", "path": plan_path}
        print(json.dumps(result))
        return 1

    plan_result = validate_execution_plan(plan_text, registry)
    result["validations"]["plan"] = plan_result
    if not plan_result["valid"]:
        result["valid"] = False

    # Output JSON result
    print(json.dumps(result))

    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
