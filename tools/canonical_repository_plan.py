"""Validate the bounded raw-source Section 3.1 repository inventory."""

import re
from typing import Any, Dict, List, Optional, Tuple


SECTION_SENTINEL = "### 3.1 Verified names and boundaries"
TABLE_HEADER = "| Role | Canonical repository | Visibility | `main` SHA | Boundary |"
TABLE_SEPARATOR = "| --- | --- | --- | --- | --- |"

_SENTINEL_VARIANT = re.compile(
    r"^(#{1,6}) 3\.1 Verified names and boundaries(.*)$"
)
_REPOSITORY_URL_TOKEN = re.compile(
    r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
    r"(?![A-Za-z0-9_.~/%?#-])"
)
_REPOSITORY_CELL = re.compile(
    r"^\[`([^`\]\n]+)`\]\("
    r"(https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
    r"\)$"
)
_SHA_CELL = re.compile(r"^`[0-9a-f]{40}`$")
_REGISTRY_FIELDS = ("label", "full_name", "url", "visibility", "boundary")


def _registry_by_label(
    registry: Any,
) -> Optional[Dict[str, Dict[str, str]]]:
    if not isinstance(registry, dict):
        return None
    repositories = registry.get("canonical_repositories")
    if not isinstance(repositories, list):
        return None

    result: Dict[str, Dict[str, str]] = {}
    for entry in repositories:
        if not isinstance(entry, dict):
            return None
        if any(not isinstance(entry.get(field), str) for field in _REGISTRY_FIELDS):
            return None
        label = entry["label"]
        if not label or label in result:
            return None
        result[label] = entry
    return result


def _sentinel_index(lines: List[str]) -> Tuple[Optional[int], List[str]]:
    exact = [index for index, line in enumerate(lines) if line == SECTION_SENTINEL]
    if len(exact) > 1:
        return None, ["plan_section_duplicate"]

    wrong_level = False
    suffixed = False
    for line in lines:
        match = _SENTINEL_VARIANT.fullmatch(line)
        if not match or line == SECTION_SENTINEL:
            continue
        if match.group(1) == "###":
            suffixed = True
        else:
            wrong_level = True
    if wrong_level:
        return None, ["plan_section_wrong_level"]
    if suffixed:
        return None, ["plan_section_heading_suffix"]
    if not exact:
        return None, ["plan_section_missing"]
    return exact[0], []


def _parse_raw_row(row: str) -> Tuple[Optional[List[str]], Optional[str]]:
    if not row.startswith("|") or not row.endswith("|"):
        return None, "plan_row_column_count_mismatch"
    raw_cells = row[1:-1].split("|")
    if len(raw_cells) != 5:
        return None, "plan_row_column_count_mismatch"

    cells: List[str] = []
    for raw_cell in raw_cells:
        if len(raw_cell) < 2 or raw_cell[0] != " " or raw_cell[-1] != " ":
            return None, "plan_row_column_count_mismatch"
        cell = raw_cell[1:-1]
        if (cell and cell[0].isspace()) or (cell and cell[-1].isspace()):
            return None, "plan_row_column_count_mismatch"
        cells.append(cell)
    if row != "| " + " | ".join(cells) + " |":
        return None, "plan_row_column_count_mismatch"
    return cells, None


def validate_execution_plan(plan_text: Any, registry: Any) -> List[str]:
    """Return deterministic errors for the declared raw-source grammar.

    The input is deliberately not interpreted as CommonMark, GFM, or HTML.
    This pure stage-B function validates one contiguous source-line block.
    """
    if not isinstance(plan_text, str):
        return ["plan_input_invalid"]
    registry_entries = _registry_by_label(registry)
    if registry_entries is None:
        return ["registry_input_invalid"]

    lines = plan_text.splitlines()
    sentinel, sentinel_errors = _sentinel_index(lines)
    if sentinel_errors:
        return sentinel_errors
    assert sentinel is not None

    if sentinel + 3 >= len(lines) or lines[sentinel + 1] != "":
        return ["plan_header_mismatch"]
    if lines[sentinel + 2] != TABLE_HEADER:
        return ["plan_header_mismatch"]
    if lines[sentinel + 3] != TABLE_SEPARATOR:
        return ["plan_separator_mismatch"]

    row_start = sentinel + 4
    row_end = row_start + 3
    if row_end > len(lines):
        return ["plan_row_count_mismatch"]
    rows = lines[row_start:row_end]
    if any(not row.startswith("|") for row in rows):
        return ["plan_row_count_mismatch"]
    if row_end < len(lines) and lines[row_end].startswith("|"):
        return ["plan_row_count_mismatch"]

    parsed_rows: List[List[str]] = []
    for row in rows:
        cells, row_error = _parse_raw_row(row)
        if row_error:
            return [row_error]
        assert cells is not None

        tokens = list(_REPOSITORY_URL_TOKEN.finditer(row))
        if len(tokens) != 1:
            return ["plan_repository_link_count_mismatch"]
        tokens_by_cell = [
            len(list(_REPOSITORY_URL_TOKEN.finditer(cell))) for cell in cells
        ]
        if tokens_by_cell != [0, 1, 0, 0, 0]:
            return ["plan_repository_link_outside_repository_cell"]
        parsed_rows.append(cells)

    labels = [cells[0] for cells in parsed_rows]
    if len(labels) != len(set(labels)):
        return ["plan_duplicate_label"]
    if set(labels) != set(registry_entries):
        return ["plan_label_set_mismatch"]

    errors = set()
    for role, repository_cell, visibility, sha_cell, boundary in parsed_rows:
        expected = registry_entries[role]
        repository = _REPOSITORY_CELL.fullmatch(repository_cell)
        if repository is None or repository.group(1) != expected["full_name"]:
            errors.add("plan_full_name_mismatch")
        elif repository.group(2) != expected["url"]:
            errors.add("plan_url_mismatch")
        if visibility != expected["visibility"]:
            errors.add("plan_visibility_mismatch")
        if not _SHA_CELL.fullmatch(sha_cell):
            errors.add("plan_main_sha_invalid")
        if boundary != expected["boundary"]:
            errors.add("plan_boundary_mismatch")
    return sorted(errors)
