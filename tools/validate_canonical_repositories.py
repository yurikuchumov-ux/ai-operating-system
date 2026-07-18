#!/usr/bin/env python3
"""
Canonical Repository Registry Validator

Validates the canonical repository registry against its JSON Schema and checks
the execution plan document for consistency with the registry.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class JSONArgumentParser(argparse.ArgumentParser):
    """Fail closed with the validator's machine-readable output contract."""

    def error(self, message: str) -> None:
        print(json.dumps({"valid": False, "errors": ["argparse_error"]}))
        raise SystemExit(2)


def load_json_file(path: Path) -> Dict[str, Any]:
    """Load and parse a JSON file."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"error": "file_not_found", "path": str(path)}
    except PermissionError:
        return {"error": "permission_denied", "path": str(path)}
    except IsADirectoryError:
        return {"error": "is_directory", "path": str(path)}
    except UnicodeDecodeError:
        return {"error": "unicode_decode_error", "path": str(path)}
    except json.JSONDecodeError as e:
        return {"error": "json_decode_error", "path": str(path), "message": str(e)}


def load_plan_file(path: Path) -> Optional[str]:
    """Load a plan markdown file."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return None
    except PermissionError:
        return None
    except IsADirectoryError:
        return None
    except UnicodeDecodeError:
        return None


def validate_registry_structure(registry: Dict[str, Any]) -> Optional[str]:
    """Validate basic registry structure before schema validation."""
    if "error" in registry:
        return registry["error"]

    if not isinstance(registry, dict):
        return "invalid_registry_structure"

    if "schema_version" not in registry or "canonical_repositories" not in registry:
        return "invalid_registry_structure"

    if not isinstance(registry.get("canonical_repositories"), list):
        return "invalid_registry_structure"

    return None


def validate_semantic_relations(registry: Dict[str, Any]) -> List[str]:
    """Validate semantic relations between fields."""
    errors = []

    repos = registry.get("canonical_repositories", [])

    for repo in repos:
        # Check full_name equals owner/name
        expected_full_name = f"{repo['owner']}/{repo['name']}"
        if repo['full_name'] != expected_full_name:
            errors.append("registry_semantic_owner_name_mismatch")
            break

        # Check url equals https://github.com/full_name
        expected_url = f"https://github.com/{repo['full_name']}"
        if repo['url'] != expected_url:
            errors.append("registry_semantic_url_mismatch")
            break

    return errors


def validate_uniqueness(registry: Dict[str, Any]) -> List[str]:
    """Validate uniqueness constraints."""
    errors = []

    repos = registry.get("canonical_repositories", [])

    # Check role uniqueness
    roles = [repo['role'] for repo in repos]
    if len(roles) != len(set(roles)):
        errors.append("registry_duplicate_role")

    # Check label uniqueness
    labels = [repo['label'] for repo in repos]
    if len(labels) != len(set(labels)):
        errors.append("registry_duplicate_label")

    # Check full_name uniqueness
    full_names = [repo['full_name'] for repo in repos]
    if len(full_names) != len(set(full_names)):
        errors.append("registry_duplicate_full_name")

    return errors


def validate_execution_plan(plan_text: str, registry: Dict[str, Any]) -> List[str]:
    """Validate execution plan against registry."""
    errors = []

    # Find the section "### 3.1 Verified names and boundaries"
    section_pattern = r'^### 3\.1 Verified names and boundaries$'
    sections = list(re.finditer(section_pattern, plan_text, re.MULTILINE))

    if len(sections) == 0:
        errors.append("plan_missing_section")
        return errors

    if len(sections) > 1:
        errors.append("plan_duplicate_section")
        return errors

    # Extract the table
    section_start = sections[0].end()

    # Find the next section or end of document
    next_section = re.search(r'\n### ', plan_text[section_start:])
    if next_section:
        section_end = section_start + next_section.start()
    else:
        section_end = len(plan_text)

    section_text = plan_text[section_start:section_end]

    # Find table header
    header_pattern = r'^\| Role \| Canonical repository \| Visibility \| `main` SHA \| Boundary \|$'
    header_match = re.search(header_pattern, section_text, re.MULTILINE)

    if not header_match:
        errors.append("plan_header_mutation")
        return errors

    # Extract table rows (skip the separator line)
    table_start = header_match.end()
    lines = section_text[table_start:].split('\n')

    # Skip separator line
    if len(lines) > 1 and '---' in lines[1]:
        lines = lines[2:]
    else:
        lines = lines[1:]

    # Parse table rows
    plan_rows = []
    for line in lines:
        line = line.strip()
        if not line or not line.startswith('|'):
            break

        parts = [p.strip() for p in line.split('|')]
        # Filter out empty parts from leading/trailing |
        parts = [p for p in parts if p]

        if len(parts) >= 5:
            plan_rows.append({
                'label': parts[0],
                'repository': parts[1],
                'visibility': parts[2],
                'main_sha': parts[3],
                'boundary': parts[4]
            })

    # Get registry entries
    registry_entries = {entry['label']: entry for entry in registry.get('canonical_repositories', [])}

    # Check for duplicate labels in plan
    plan_labels = [row['label'] for row in plan_rows]
    if len(plan_labels) != len(set(plan_labels)):
        errors.append("plan_duplicate_label_substitution")
        return errors

    # Check label set equality
    registry_labels = set(registry_entries.keys())
    plan_label_set = set(plan_labels)

    if registry_labels != plan_label_set:
        missing_in_plan = registry_labels - plan_label_set
        extra_in_plan = plan_label_set - registry_labels

        if missing_in_plan:
            errors.append("plan_missing_row")
        if extra_in_plan:
            errors.append("plan_extra_row")

        return errors

    # Validate each row against registry
    for row in plan_rows:
        label = row['label']
        if label not in registry_entries:
            continue

        entry = registry_entries[label]

        # Extract full_name from repository link
        # Format: [`full_name`](url)
        repo_match = re.search(r'\[`([^`]+)`\]\(([^)]+)\)', row['repository'])
        if not repo_match:
            errors.append("plan_repository_format_error")
            continue

        plan_full_name = repo_match.group(1)
        plan_url = repo_match.group(2)

        # Count repository links in row
        link_count = len(re.findall(r'\[`[^`]+`\]\([^)]+\)', row['repository']))
        if link_count != 1:
            errors.append("plan_repository_link_count_error")
            continue

        # Compare fields
        if plan_full_name != entry['full_name']:
            errors.append("plan_full_name_mismatch")
            break

        if plan_url != entry['url']:
            errors.append("plan_url_mismatch")
            break

        # Extract main_sha from backticks
        sha_match = re.search(r'`([^`]+)`', row['main_sha'])
        if sha_match:
            plan_sha = sha_match.group(1)
        else:
            plan_sha = row['main_sha']

        if plan_sha != entry['main_sha']:
            errors.append("plan_main_sha_mismatch")
            break

        if row['visibility'] != entry['visibility']:
            errors.append("plan_visibility_mismatch")
            break

        if row['boundary'] != entry['boundary']:
            errors.append("plan_boundary_mismatch")
            break

    return errors


def main() -> int:
    """Main entry point."""
    parser = JSONArgumentParser(
        description='Validate canonical repository registry',
        add_help=False,
    )
    parser.add_argument(
        '--registry',
        type=Path,
        default=Path('contracts/canonical-repositories.v1.json'),
        help='Path to registry JSON file'
    )
    parser.add_argument(
        '--schema',
        type=Path,
        default=Path('contracts/schemas/canonical-repositories.v1.schema.json'),
        help='Path to schema JSON file'
    )
    parser.add_argument(
        '--plan',
        type=Path,
        default=Path('docs/AI_DEVELOPMENT_STUDIO_EXECUTION_PLAN.md'),
        help='Path to execution plan markdown file'
    )

    args = parser.parse_args()

    # Load registry
    registry = load_json_file(args.registry)

    # Check for registry loading errors
    if "error" in registry:
        result = {
            "valid": False,
            "errors": [registry["error"]]
        }
        print(json.dumps(result))
        return 1

    # Validate basic structure
    structure_error = validate_registry_structure(registry)
    if structure_error:
        result = {
            "valid": False,
            "errors": [structure_error]
        }
        print(json.dumps(result))
        return 1

    # Load schema
    schema = load_json_file(args.schema)

    # Check for schema loading errors
    if "error" in schema:
        result = {
            "valid": False,
            "errors": [schema["error"]]
        }
        print(json.dumps(result))
        return 1

    # Validate against schema
    try:
        import jsonschema
    except ImportError:
        result = {
            "valid": False,
            "errors": ["missing_jsonschema"]
        }
        print(json.dumps(result))
        return 1

    try:
        jsonschema.validate(instance=registry, schema=schema)
    except jsonschema.exceptions.SchemaError as e:
        result = {
            "valid": False,
            "errors": ["schema_error"]
        }
        print(json.dumps(result))
        return 1
    except jsonschema.exceptions.ValidationError as e:
        result = {
            "valid": False,
            "errors": ["registry_schema_validation_failed"]
        }
        print(json.dumps(result))
        return 1

    errors = []

    # Validate semantic relations
    semantic_errors = validate_semantic_relations(registry)
    errors.extend(semantic_errors)

    # Validate uniqueness
    uniqueness_errors = validate_uniqueness(registry)
    errors.extend(uniqueness_errors)

    # Load and validate plan
    plan_text = load_plan_file(args.plan)
    if plan_text is None:
        result = {
            "valid": False,
            "errors": ["plan_not_found"]
        }
        print(json.dumps(result))
        return 1

    plan_errors = validate_execution_plan(plan_text, registry)
    errors.extend(plan_errors)

    # Return result
    if errors:
        result = {
            "valid": False,
            "errors": errors
        }
        print(json.dumps(result))
        return 1
    else:
        result = {
            "valid": True,
            "errors": []
        }
        print(json.dumps(result))
        return 0


if __name__ == '__main__':
    sys.exit(main())
