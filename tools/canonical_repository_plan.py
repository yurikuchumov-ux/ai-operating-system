"""Validate the governed Section 3.1 repository inventory."""

import re
from typing import Any, Dict, List, Optional, Tuple


SECTION_HEADING = "### 3.1 Verified names and boundaries"
TABLE_HEADER = "| Role | Canonical repository | Visibility | `main` SHA | Boundary |"
TABLE_SEPARATOR = "| --- | --- | --- | --- | --- |"

_HEADING_VARIANT = re.compile(
    r"^(#{1,6}) 3\.1 Verified names and boundaries(.*)$"
)
_GITHUB_REPOSITORY_LINK = re.compile(
    r"\[[^\]\n]*\]\("
    r"(https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
    r"\)"
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
    """Return a validated label lookup or ``None`` for an invalid input."""
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


def _section_index(lines: List[str]) -> Tuple[Optional[int], List[str]]:
    """Locate the exact section and classify near-match headings."""
    exact = [index for index, line in enumerate(lines) if line == SECTION_HEADING]
    if len(exact) > 1:
        return None, ["plan_section_duplicate"]

    wrong_level = False
    suffixed = False
    for line in lines:
        match = _HEADING_VARIANT.fullmatch(line)
        if not match or line == SECTION_HEADING:
            continue
        if match.group(1) != "###":
            wrong_level = True
        else:
            suffixed = True

    if wrong_level:
        return None, ["plan_section_wrong_level"]
    if suffixed:
        return None, ["plan_section_heading_suffix"]
    if not exact:
        return None, ["plan_section_missing"]
    return exact[0], []


def _section_end(lines: List[str], start: int) -> int:
    """Return the next level 1-3 heading or end of document."""
    for index in range(start, len(lines)):
        if re.match(r"^#{1,3}(?: |$)", lines[index]):
            return index
    return len(lines)


def _parse_row(row: str) -> Tuple[Optional[List[str]], Optional[str]]:
    """Parse one raw row without dropping or normalizing interior cells."""
    if not row.startswith("|") or not row.endswith("|"):
        return None, "plan_row_column_count_mismatch"
    raw_cells = row[1:-1].split("|")
    if len(raw_cells) != 5:
        return None, "plan_row_column_count_mismatch"

    # The governed table uses exactly one padding space around every cell.
    # Reconstructing the raw line makes that requirement explicit and keeps
    # whitespace from becoming an accidental normalization channel.
    cells = [cell.strip() for cell in raw_cells]
    if row != "| " + " | ".join(cells) + " |":
        return None, "plan_row_column_count_mismatch"
    return cells, None


def validate_execution_plan(plan_text: Any, registry: Any) -> List[str]:
    """Return sorted deterministic errors for the governed inventory.

    This is a pure stage-B validator: it accepts already-loaded values and
    performs no argument parsing, file access, or error presentation.
    """
    if not isinstance(plan_text, str):
        return ["plan_input_invalid"]

    registry_entries = _registry_by_label(registry)
    if registry_entries is None:
        return ["registry_input_invalid"]

    lines = plan_text.splitlines()
    heading_index, heading_errors = _section_index(lines)
    if heading_errors:
        return heading_errors
    assert heading_index is not None

    end = _section_end(lines, heading_index + 1)
    cursor = heading_index + 1
    while cursor < end and lines[cursor] == "":
        cursor += 1

    if cursor >= end or lines[cursor] != TABLE_HEADER:
        return ["plan_header_mismatch"]
    cursor += 1
    if cursor >= end or lines[cursor] != TABLE_SEPARATOR:
        return ["plan_separator_mismatch"]
    cursor += 1

    rows: List[str] = []
    while cursor < end and lines[cursor].startswith("|"):
        rows.append(lines[cursor])
        cursor += 1

    # No second table fragment may be hidden after prose or a blank line in
    # the governed section.
    trailing_table_rows = any(line.startswith("|") for line in lines[cursor:end])
    if len(rows) != 3 or trailing_table_rows:
        return ["plan_row_count_mismatch"]

    parsed_rows: List[List[str]] = []
    for row in rows:
        cells, row_error = _parse_row(row)
        if row_error:
            return [row_error]
        assert cells is not None

        links = list(_GITHUB_REPOSITORY_LINK.finditer(row))
        if len(links) != 1:
            return ["plan_repository_link_count_mismatch"]

        links_by_cell = [
            len(list(_GITHUB_REPOSITORY_LINK.finditer(cell))) for cell in cells
        ]
        if links_by_cell != [0, 1, 0, 0, 0]:
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
        match = _REPOSITORY_CELL.fullmatch(repository_cell)
        if match is None:
            errors.add("plan_full_name_mismatch")
        else:
            full_name = match.group(1)
            url = match.group(2)
            if full_name != expected["full_name"]:
                errors.add("plan_full_name_mismatch")
            if url != expected["url"]:
                errors.add("plan_url_mismatch")

        if visibility != expected["visibility"]:
            errors.add("plan_visibility_mismatch")
        if not _SHA_CELL.fullmatch(sha_cell):
            errors.add("plan_main_sha_invalid")
        if boundary != expected["boundary"]:
            errors.add("plan_boundary_mismatch")

    return sorted(errors)
