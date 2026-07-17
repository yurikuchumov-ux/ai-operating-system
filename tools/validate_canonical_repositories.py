#!/usr/bin/env python3
"""Fail-closed offline validator for canonical-repository registry.

This tool validates only the canonical-repositories.v1.json registry and
execution-plan section 3.1. It emits deterministic machine-readable failures
for missing, extra, duplicate, substituted, malformed, unreadable, invalid-UTF-8
or invalid-JSON inputs.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ModuleNotFoundError as exc:  # pragma: no cover
    raise SystemExit(
        "missing dependency: install requirements-b0.txt before validation"
    ) from exc


REPO_ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = REPO_ROOT / "contracts/canonical-repositories.v1.json"
SCHEMA_PATH = REPO_ROOT / "contracts/schemas/canonical-repositories.v1.schema.json"
EXECUTION_PLAN_PATH = REPO_ROOT / "docs/AI_DEVELOPMENT_STUDIO_EXECUTION_PLAN.md"

# The three owner-approved identities with unique exact fields
EXPECTED_REPOSITORIES = [
    {
        "role": "Governance and shared contracts",
        "repository": "yurikuchumov-ux/ai-operating-system",
        "visibility": "public",
        "main_sha": "a36a8eefcdd06c56edeec93057a90c58a239cf22",
        "boundary": "owns governance, schemas, reusable workflows and evidence contracts",
    },
    {
        "role": "Compliant repository fixture",
        "repository": "yurikuchumov-ux/ai-development-studio-template",
        "visibility": "public",
        "main_sha": "ec088bf2e95e048ce1f5b69d969542b516afbc8b",
        "boundary": "owns the minimal downstream skeleton and repeatability tests",
    },
    {
        "role": "Voice reference product",
        "repository": "yurikuchumov-ux/-ai-development-studio",
        "visibility": "private",
        "main_sha": "f6550d4078ffccc952db269081619fdfe57e598c",
        "boundary": "owns product runtime, domain tests and product deployment",
    },
]


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    message: str

    def as_dict(self) -> Dict[str, str]:
        return {
            "code": self.code,
            "path": self.path,
            "message": self.message,
        }


def load_json(path: Path) -> Any:
    """Load JSON with fail-closed error handling."""
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        raise ValueError(f"file_not_found: {path}")
    except UnicodeDecodeError as exc:
        raise ValueError(f"invalid_utf8: {path} at position {exc.start}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid_json: {path} at line {exc.lineno} column {exc.colno}")


def validate_registry_schema(registry: Mapping[str, Any]) -> List[Finding]:
    """Validate registry against JSON schema."""
    findings: List[Finding] = []

    try:
        schema = load_json(SCHEMA_PATH)
    except ValueError as exc:
        return [Finding("schema_load_failed", "$", str(exc))]

    try:
        Draft202012Validator.check_schema(schema)
    except Exception as exc:
        return [Finding("schema_invalid", "$", str(exc))]

    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    for error in sorted(
        validator.iter_errors(registry),
        key=lambda e: (list(e.absolute_path), e.validator, e.message),
    ):
        path_parts = ["$"] + [str(p) for p in error.absolute_path]
        path = ".".join(path_parts)
        findings.append(Finding("schema_validation_failed", path, error.message))

    return findings


def validate_repository_uniqueness(repositories: List[Mapping[str, Any]]) -> List[Finding]:
    """Validate that all repository identities are unique."""
    findings: List[Finding] = []
    seen_repos: Dict[str, int] = {}
    seen_roles: Dict[str, int] = {}
    seen_shas: Dict[str, int] = {}

    for idx, repo in enumerate(repositories):
        repo_name = repo.get("repository", "")
        role = repo.get("role", "")
        sha = repo.get("main_sha", "")

        if repo_name in seen_repos:
            findings.append(
                Finding(
                    "duplicate_repository",
                    f"$.repositories[{idx}].repository",
                    f"duplicate repository: {repo_name}",
                )
            )
        seen_repos[repo_name] = idx

        if role in seen_roles:
            findings.append(
                Finding(
                    "duplicate_role",
                    f"$.repositories[{idx}].role",
                    f"duplicate role: {role}",
                )
            )
        seen_roles[role] = idx

        if sha and sha in seen_shas:
            findings.append(
                Finding(
                    "duplicate_main_sha",
                    f"$.repositories[{idx}].main_sha",
                    f"duplicate main_sha: {sha}",
                )
            )
        seen_shas[sha] = idx

    return findings


def validate_exact_repository_match(repositories: List[Mapping[str, Any]]) -> List[Finding]:
    """Validate exact match with expected repositories (fail-closed)."""
    findings: List[Finding] = []

    if len(repositories) != len(EXPECTED_REPOSITORIES):
        findings.append(
            Finding(
                "repository_count_mismatch",
                "$.repositories",
                f"expected exactly {len(EXPECTED_REPOSITORIES)} repositories, got {len(repositories)}",
            )
        )
        return findings

    # Build lookup by repository name
    actual_by_name = {repo.get("repository"): repo for repo in repositories}
    expected_by_name = {repo["repository"]: repo for repo in EXPECTED_REPOSITORIES}

    # Check for missing repositories
    for expected_repo in EXPECTED_REPOSITORIES:
        repo_name = expected_repo["repository"]
        if repo_name not in actual_by_name:
            findings.append(
                Finding(
                    "missing_repository",
                    "$.repositories",
                    f"missing required repository: {repo_name}",
                )
            )

    # Check for extra repositories
    for repo_name in actual_by_name:
        if repo_name not in expected_by_name:
            findings.append(
                Finding(
                    "extra_repository",
                    "$.repositories",
                    f"extra repository not in approved list: {repo_name}",
                )
            )

    # Check exact field matches for approved repositories
    for idx, actual_repo in enumerate(repositories):
        repo_name = actual_repo.get("repository")
        if repo_name not in expected_by_name:
            continue

        expected_repo = expected_by_name[repo_name]

        for field in ["role", "repository", "visibility", "main_sha", "boundary"]:
            expected_value = expected_repo[field]
            actual_value = actual_repo.get(field)

            if actual_value != expected_value:
                findings.append(
                    Finding(
                        "field_value_mismatch",
                        f"$.repositories[{idx}].{field}",
                        f"expected '{expected_value}', got '{actual_value}'",
                    )
                )

    return findings


def validate_execution_plan_section_3_1() -> List[Finding]:
    """Validate execution plan section 3.1 table structure and content."""
    findings: List[Finding] = []

    try:
        plan_content = EXECUTION_PLAN_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        return [Finding("execution_plan_not_found", "$", str(EXECUTION_PLAN_PATH))]
    except UnicodeDecodeError as exc:
        return [Finding("execution_plan_invalid_utf8", "$", f"position {exc.start}")]

    # Find section 3.1
    section_3_1_match = re.search(
        r"^### 3\.1 Verified names and boundaries\s*\n(.*?)(?=^###|\Z)",
        plan_content,
        re.MULTILINE | re.DOTALL,
    )

    if not section_3_1_match:
        return [Finding("section_3_1_missing", "$", "section 3.1 not found in execution plan")]

    section_content = section_3_1_match.group(1)

    # Validate exactly one table
    table_matches = re.findall(
        r"^\|[^\n]+\|$",
        section_content,
        re.MULTILINE,
    )

    if not table_matches:
        findings.append(Finding("table_missing", "section_3.1", "no table found in section 3.1"))
        return findings

    # Extract the table
    table_lines = []
    in_table = False
    for line in section_content.split("\n"):
        if line.strip().startswith("|"):
            table_lines.append(line)
            in_table = True
        elif in_table and not line.strip().startswith("|"):
            break

    if len(table_lines) < 3:
        findings.append(
            Finding(
                "table_incomplete",
                "section_3.1",
                f"table must have header, separator, and data rows; got {len(table_lines)} lines",
            )
        )
        return findings

    # Validate header (exact five columns)
    header = table_lines[0]
    header_cells = [cell.strip() for cell in header.split("|")]
    # Remove empty first/last cells from split
    header_cells = [c for c in header_cells if c]

    expected_headers = ["Role", "Canonical repository", "Visibility", "`main` SHA", "Boundary"]

    if len(header_cells) != 5:
        findings.append(
            Finding(
                "header_column_count",
                "section_3.1.table.header",
                f"expected exactly 5 columns, got {len(header_cells)}",
            )
        )

    if header_cells != expected_headers:
        findings.append(
            Finding(
                "header_content_mismatch",
                "section_3.1.table.header",
                f"header does not match expected: {expected_headers}",
            )
        )

    # Validate separator (exactly five columns with valid separator pattern)
    separator = table_lines[1]
    sep_cells = [cell.strip() for cell in separator.split("|")]
    sep_cells = [c for c in sep_cells if c]

    if len(sep_cells) != 5:
        findings.append(
            Finding(
                "separator_column_count",
                "section_3.1.table.separator",
                f"expected exactly 5 columns in separator, got {len(sep_cells)}",
            )
        )

    for idx, cell in enumerate(sep_cells):
        if not re.match(r"^:?-+:?$", cell):
            findings.append(
                Finding(
                    "separator_invalid_format",
                    f"section_3.1.table.separator[{idx}]",
                    f"invalid separator format: {cell}",
                )
            )

    # Validate data rows (exactly 3 rows with 5 columns each)
    data_rows = table_lines[2:]

    if len(data_rows) != 3:
        findings.append(
            Finding(
                "data_row_count",
                "section_3.1.table",
                f"expected exactly 3 data rows, got {len(data_rows)}",
            )
        )

    for row_idx, row in enumerate(data_rows):
        cells = [cell.strip() for cell in row.split("|")]
        cells = [c for c in cells if c]

        if len(cells) != 5:
            findings.append(
                Finding(
                    "data_row_column_count",
                    f"section_3.1.table.row[{row_idx}]",
                    f"expected exactly 5 cells, got {len(cells)}",
                )
            )

    # Validate repository cell format (column 1, 0-indexed)
    for row_idx, row in enumerate(data_rows):
        cells = [cell.strip() for cell in row.split("|")]
        cells = [c for c in cells if c]

        if len(cells) < 2:
            continue

        repo_cell = cells[1]

        # Must be exactly one markdown link with paired backticks or none
        # Reject unbalanced backticks, prefix/suffix text, multiple links

        # Check for unbalanced backticks
        backtick_count = repo_cell.count("`")
        if backtick_count % 2 != 0:
            findings.append(
                Finding(
                    "unbalanced_backticks",
                    f"section_3.1.table.row[{row_idx}].repository",
                    f"unbalanced backticks in repository cell",
                )
            )

        # Extract markdown links
        link_pattern = r"\[([^\]]+)\]\(([^)]+)\)"
        links = re.findall(link_pattern, repo_cell)

        if len(links) > 1:
            findings.append(
                Finding(
                    "multiple_links",
                    f"section_3.1.table.row[{row_idx}].repository",
                    f"repository cell must contain at most one markdown link, got {len(links)}",
                )
            )

        if len(links) == 1:
            # Validate that backticks are paired around link text
            link_text, link_url = links[0]

            # Check for prefix/suffix text outside the link
            # The cell should only contain the markdown link (and optional backticks)
            expected_patterns = [
                f"[`{link_text}`]({link_url})",
                f"[{link_text}]({link_url})",
            ]

            if repo_cell not in expected_patterns:
                # Check if there's extra text
                link_full = f"[{link_text}]({link_url})"
                link_full_backtick = f"[`{link_text}`]({link_url})"

                if link_full not in repo_cell and link_full_backtick not in repo_cell:
                    findings.append(
                        Finding(
                            "malformed_repository_link",
                            f"section_3.1.table.row[{row_idx}].repository",
                            f"repository cell contains unexpected format",
                        )
                    )
                elif repo_cell != link_full and repo_cell != link_full_backtick:
                    findings.append(
                        Finding(
                            "repository_cell_extra_text",
                            f"section_3.1.table.row[{row_idx}].repository",
                            f"repository cell contains prefix/suffix text",
                        )
                    )

    return findings


def validate_canonical_repositories() -> Tuple[int, Dict[str, Any]]:
    """Main validation function."""
    findings: List[Finding] = []

    # Load registry
    try:
        registry = load_json(REGISTRY_PATH)
    except ValueError as exc:
        findings.append(Finding("registry_load_failed", "$", str(exc)))
        report = {
            "schema_version": "1.0.0",
            "valid": False,
            "findings": [f.as_dict() for f in findings],
            "error_codes": sorted({f.code for f in findings}),
        }
        return 1, report

    # Schema validation
    findings.extend(validate_registry_schema(registry))
    if findings:
        report = {
            "schema_version": "1.0.0",
            "valid": False,
            "findings": [f.as_dict() for f in findings],
            "error_codes": sorted({f.code for f in findings}),
        }
        return 1, report

    # Repository validation
    repositories = registry.get("repositories", [])
    findings.extend(validate_repository_uniqueness(repositories))
    findings.extend(validate_exact_repository_match(repositories))

    # Execution plan validation
    findings.extend(validate_execution_plan_section_3_1())

    findings = sorted(findings, key=lambda f: (f.code, f.path))
    valid = len(findings) == 0

    report = {
        "schema_version": "1.0.0",
        "valid": valid,
        "findings": [f.as_dict() for f in findings],
        "error_codes": sorted({f.code for f in findings}),
    }

    return (0 if valid else 1), report


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point."""
    exit_code, report = validate_canonical_repositories()
    json.dump(report, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
