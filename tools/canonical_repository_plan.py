from __future__ import annotations

from dataclasses import dataclass
from typing import Any


SECTION_3_1_START = "## 3. Canonical repository inventory"
SECTION_3_1_HEADER = "### 3.1 Verified names and boundaries"
EXPECTED_HEADER = "| Role | Canonical repository | Visibility | `main` SHA | Boundary |"
EXPECTED_SEPARATOR = "| --- | --- | --- | --- | --- |"
EXPECTED_ROW_COUNT = 3

ERROR_INVALID_PLAN_INPUT = "invalid_plan_input"
ERROR_INVALID_REGISTRY_INPUT = "invalid_registry_input"
ERROR_SECTION_NOT_FOUND = "section_3_1_not_found"
ERROR_SECTION_DUPLICATE = "section_3_1_duplicate"
ERROR_PLAN_HEADER_MISMATCH = "plan_header_mismatch"
ERROR_PLAN_SEPARATOR_MISMATCH = "plan_separator_mismatch"
ERROR_PLAN_ROW_COUNT_MISMATCH = "plan_row_column_count_mismatch"
ERROR_PLAN_ROW_REPOSITORY_URL_COUNT = "plan_row_repository_url_count_mismatch"
ERROR_PLAN_ROW_REPOSITORY_PREFIX = "plan_row_repository_prefix_mismatch"
ERROR_PLAN_ROW_REPOSITORY_SUFFIX = "plan_row_repository_suffix_mismatch"
ERROR_PLAN_ROW_REPOSITORY_FULL_NAME = "plan_row_repository_full_name_mismatch"
ERROR_PLAN_ROW_REPOSITORY_URL = "plan_row_repository_url_mismatch"
ERROR_PLAN_ROW_ROLE_DUPLICATE = "plan_row_role_duplicate"
ERROR_PLAN_ROW_ROLE_SET = "plan_row_role_set_mismatch"
ERROR_PLAN_ROW_VISIBILITY = "plan_row_visibility_mismatch"
ERROR_PLAN_ROW_BOUNDARY = "plan_row_boundary_mismatch"
ERROR_PLAN_ROW_SHA = "plan_row_sha_mismatch"

REPOSITORY_URL_PREFIX = "[`"
REPOSITORY_URL_MIDDLE = "`](https://github.com/"
REPOSITORY_URL_SUFFIX = ")"


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    code: str | None = None


def _is_valid_sha40_lower_hex(value: str) -> bool:
    if len(value) != 40:
        return False
    for char in value:
        if char not in "0123456789abcdef":
            return False
    return True


def _extract_section_3_1_lines(plan_markdown: str) -> ValidationResult | list[str]:
    lines = plan_markdown.splitlines()
    section_positions: list[int] = []
    for index, line in enumerate(lines):
        if line == SECTION_3_1_HEADER:
            section_positions.append(index)

    if not section_positions:
        return ValidationResult(False, ERROR_SECTION_NOT_FOUND)
    if len(section_positions) > 1:
        return ValidationResult(False, ERROR_SECTION_DUPLICATE)

    start = section_positions[0] + 1
    end = len(lines)
    for index in range(start, len(lines)):
        line = lines[index]
        if line.startswith("## ") and index > section_positions[0]:
            end = index
            break

    return lines[start:end]


def _validate_registry(registry: Any) -> ValidationResult | dict[str, dict[str, str]]:
    if not isinstance(registry, list):
        return ValidationResult(False, ERROR_INVALID_REGISTRY_INPUT)

    by_label: dict[str, dict[str, str]] = {}
    required_keys = {"label", "full_name", "url", "visibility", "main_sha", "boundary"}

    for entry in registry:
        if not isinstance(entry, dict):
            return ValidationResult(False, ERROR_INVALID_REGISTRY_INPUT)

        if set(entry.keys()) != required_keys:
            return ValidationResult(False, ERROR_INVALID_REGISTRY_INPUT)

        for key in required_keys:
            value = entry[key]
            if not isinstance(value, str):
                return ValidationResult(False, ERROR_INVALID_REGISTRY_INPUT)
            if key == "label" and value == "":
                return ValidationResult(False, ERROR_INVALID_REGISTRY_INPUT)

        label = entry["label"]
        if label in by_label:
            return ValidationResult(False, ERROR_INVALID_REGISTRY_INPUT)

        if not _is_valid_sha40_lower_hex(entry["main_sha"]):
            return ValidationResult(False, ERROR_INVALID_REGISTRY_INPUT)

        by_label[label] = entry

    return by_label


def _parse_repository_cell(cell: str) -> ValidationResult | tuple[str, str]:
    if not cell.startswith(REPOSITORY_URL_PREFIX):
        return ValidationResult(False, ERROR_PLAN_ROW_REPOSITORY_PREFIX)
    if not cell.endswith(REPOSITORY_URL_SUFFIX):
        return ValidationResult(False, ERROR_PLAN_ROW_REPOSITORY_SUFFIX)

    middle_index = cell.find(REPOSITORY_URL_MIDDLE)
    if middle_index < 0:
        return ValidationResult(False, ERROR_PLAN_ROW_REPOSITORY_PREFIX)

    full_name = cell[len(REPOSITORY_URL_PREFIX):middle_index]
    url_start = middle_index + len(REPOSITORY_URL_MIDDLE)
    url_end = len(cell) - 1
    url_name = cell[url_start:url_end]

    url = f"https://github.com/{url_name}"
    return full_name, url


def validate_canonical_repository_plan(plan_markdown: Any, registry: Any) -> ValidationResult:
    if not isinstance(plan_markdown, str):
        return ValidationResult(False, ERROR_INVALID_PLAN_INPUT)

    registry_result = _validate_registry(registry)
    if isinstance(registry_result, ValidationResult):
        return registry_result
    registry_by_label = registry_result

    section_lines_result = _extract_section_3_1_lines(plan_markdown)
    if isinstance(section_lines_result, ValidationResult):
        return section_lines_result
    section_lines = section_lines_result

    table_lines = [line for line in section_lines if line.startswith("|")]
    if len(table_lines) < 2:
        return ValidationResult(False, ERROR_PLAN_HEADER_MISMATCH)

    if table_lines[0] != EXPECTED_HEADER:
        return ValidationResult(False, ERROR_PLAN_HEADER_MISMATCH)
    if table_lines[1] != EXPECTED_SEPARATOR:
        return ValidationResult(False, ERROR_PLAN_SEPARATOR_MISMATCH)

    data_rows = table_lines[2:]
    if len(data_rows) != EXPECTED_ROW_COUNT:
        return ValidationResult(False, ERROR_PLAN_ROW_COUNT_MISMATCH)

    seen_roles: set[str] = set()
    expected_roles = set(registry_by_label.keys())

    for row in data_rows:
        if row.count("|") != 6:
            return ValidationResult(False, ERROR_PLAN_ROW_COUNT_MISMATCH)

        if not row.startswith("| ") or not row.endswith(" |"):
            return ValidationResult(False, ERROR_PLAN_ROW_COUNT_MISMATCH)

        raw_cells = row[2:-2].split(" | ")
        if len(raw_cells) != 5:
            return ValidationResult(False, ERROR_PLAN_ROW_COUNT_MISMATCH)

        role, repository_cell, visibility, sha_cell, boundary = raw_cells

        if role in seen_roles:
            return ValidationResult(False, ERROR_PLAN_ROW_ROLE_DUPLICATE)
        seen_roles.add(role)

        if role not in registry_by_label:
            return ValidationResult(False, ERROR_PLAN_ROW_ROLE_SET)

        expected_entry = registry_by_label[role]

        if repository_cell.count("https://github.com/") != 1:
            return ValidationResult(False, ERROR_PLAN_ROW_REPOSITORY_URL_COUNT)

        parsed_repo = _parse_repository_cell(repository_cell)
        if isinstance(parsed_repo, ValidationResult):
            return parsed_repo
        full_name, url = parsed_repo

        if full_name != expected_entry["full_name"]:
            return ValidationResult(False, ERROR_PLAN_ROW_REPOSITORY_FULL_NAME)
        if url != expected_entry["url"]:
            return ValidationResult(False, ERROR_PLAN_ROW_REPOSITORY_URL)

        if visibility != expected_entry["visibility"]:
            return ValidationResult(False, ERROR_PLAN_ROW_VISIBILITY)

        if not (sha_cell.startswith("`") and sha_cell.endswith("`")):
            return ValidationResult(False, ERROR_PLAN_ROW_SHA)
        sha_value = sha_cell[1:-1]
        if not _is_valid_sha40_lower_hex(sha_value):
            return ValidationResult(False, ERROR_PLAN_ROW_SHA)
        if sha_value != expected_entry["main_sha"]:
            return ValidationResult(False, ERROR_PLAN_ROW_SHA)

        if boundary != expected_entry["boundary"]:
            return ValidationResult(False, ERROR_PLAN_ROW_BOUNDARY)

    if seen_roles != expected_roles:
        return ValidationResult(False, ERROR_PLAN_ROW_ROLE_SET)

    return ValidationResult(True, None)
