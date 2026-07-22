"""Bounded raw-source grammar validator for Section 3.1 execution plan inventory.

This module validates the exact raw-source structure of the execution plan's
canonical repository inventory against the stage-A registry. It operates
entirely on raw source lines without parsing CommonMark, GFM, HTML blocks,
fenced code, blockquotes, reference links or making claims about renderer output.
"""

from typing import List, Dict, Any


def validate_execution_plan(plan_text: str, registry: Dict[str, Any]) -> List[str]:
    """Validate execution plan inventory against the canonical repository registry.

    Args:
        plan_text: The raw execution plan document text
        registry: The stage-A canonical repository registry (must be used)

    Returns:
        Empty list on success, or sorted unique stable error codes on failure
    """
    errors = set()

    # Validate input types
    if not isinstance(plan_text, str):
        errors.add("PLAN_NOT_STRING")
        return sorted(errors)

    if not isinstance(registry, dict):
        errors.add("REGISTRY_NOT_DICT")
        return sorted(errors)

    if "canonical_repositories" not in registry:
        errors.add("REGISTRY_MISSING_CANONICAL_REPOSITORIES")
        return sorted(errors)

    if not isinstance(registry["canonical_repositories"], list):
        errors.add("REGISTRY_CANONICAL_REPOSITORIES_NOT_LIST")
        return sorted(errors)

    # Extract registry entries indexed by label
    registry_by_label = {}
    for entry in registry["canonical_repositories"]:
        if not isinstance(entry, dict):
            errors.add("REGISTRY_ENTRY_NOT_DICT")
            continue

        label = entry.get("label")
        if not isinstance(label, str):
            errors.add("REGISTRY_LABEL_NOT_STRING")
            continue

        registry_by_label[label] = entry

    if errors:
        return sorted(errors)

    # Split into lines for raw source processing
    lines = plan_text.split('\n')

    # Find the sentinel
    sentinel = "### 3.1 Verified names and boundaries"
    sentinel_indices = [i for i, line in enumerate(lines) if line == sentinel]

    if len(sentinel_indices) == 0:
        errors.add("SENTINEL_MISSING")
        return sorted(errors)

    if len(sentinel_indices) > 1:
        errors.add("SENTINEL_DUPLICATE")
        return sorted(errors)

    sentinel_idx = sentinel_indices[0]

    # Validate the exact contiguous structure after sentinel
    expected_blank = ""
    expected_header = "| Role | Canonical repository | Visibility | `main` SHA | Boundary |"
    expected_separator = "| --- | --- | --- | --- | --- |"

    # Check we have enough lines after sentinel
    if sentinel_idx + 4 > len(lines):
        errors.add("INSUFFICIENT_LINES_AFTER_SENTINEL")
        return sorted(errors)

    # Validate blank line
    if lines[sentinel_idx + 1] != expected_blank:
        errors.add("BLANK_LINE_INVALID")

    # Validate header line
    if lines[sentinel_idx + 2] != expected_header:
        errors.add("HEADER_LINE_INVALID")

    # Validate separator line
    if lines[sentinel_idx + 3] != expected_separator:
        errors.add("SEPARATOR_LINE_INVALID")

    if errors:
        return sorted(errors)

    # Extract the three data rows
    data_row_start = sentinel_idx + 4

    if data_row_start + 3 > len(lines):
        errors.add("INSUFFICIENT_DATA_ROWS")
        return sorted(errors)

    data_rows = []
    for i in range(3):
        row = lines[data_row_start + i]
        data_rows.append(row)

    # Check for forbidden fourth contiguous pipe row
    if data_row_start + 3 < len(lines):
        fourth_line = lines[data_row_start + 3]
        if fourth_line.startswith('|'):
            errors.add("FOURTH_CONTIGUOUS_PIPE_ROW_FORBIDDEN")
            return sorted(errors)

    # Validate each data row structure and content
    plan_labels = set()

    for row_idx, row in enumerate(data_rows):
        # Check row starts and ends with pipe
        if not row.startswith('|') or not row.endswith('|'):
            errors.add("ROW_DELIMITER_INVALID")
            continue

        # Split by pipe and remove first/last empty elements
        parts = row.split('|')
        if len(parts) < 2:
            errors.add("ROW_STRUCTURE_INVALID")
            continue

        # Remove leading and trailing empty strings from split
        parts = parts[1:-1]

        # Check for exactly 5 interior cells
        if len(parts) != 5:
            if len(parts) < 5:
                errors.add("ROW_TOO_FEW_CELLS")
            else:
                errors.add("ROW_TOO_MANY_CELLS")
            continue

        # Extract cells (strip only the one mandatory padding space on each side)
        role_cell = parts[0]
        repo_cell = parts[1]
        visibility_cell = parts[2]
        sha_cell = parts[3]
        boundary_cell = parts[4]

        # Check padding: each cell should have exactly one space on each side
        # The cells as split include the padding spaces
        for part_idx, part in enumerate(parts):
            if len(part) < 2:
                errors.add("CELL_PADDING_INVALID")
                break
            if not part.startswith(' ') or not part.endswith(' '):
                errors.add("CELL_PADDING_INVALID")
                break

        # Extract actual content (removing the single padding space)
        role = role_cell.strip()
        repo = repo_cell.strip()
        visibility = visibility_cell.strip()
        sha = sha_cell.strip()
        boundary = boundary_cell.strip()

        # Check for duplicate role
        if role in plan_labels:
            errors.add("ROLE_DUPLICATE")
        plan_labels.add(role)

        # Check role exists in registry
        if role not in registry_by_label:
            errors.add("ROLE_NOT_IN_REGISTRY")
            continue

        reg_entry = registry_by_label[role]

        # Validate repository URL token appears exactly once in the full raw row
        expected_url = reg_entry.get("url", "")
        if not isinstance(expected_url, str):
            errors.add("REGISTRY_URL_NOT_STRING")
            continue

        # Count occurrences of the exact URL in the raw row
        url_count = row.count(expected_url)
        if url_count != 1:
            if url_count == 0:
                errors.add("REPOSITORY_URL_MISSING")
            else:
                errors.add("REPOSITORY_URL_DUPLICATE")

        # Validate repository cell format: [`full_name`](url)
        expected_full_name = reg_entry.get("full_name", "")
        if not isinstance(expected_full_name, str):
            errors.add("REGISTRY_FULL_NAME_NOT_STRING")
            continue

        expected_repo_cell = f"[`{expected_full_name}`]({expected_url})"
        if repo != expected_repo_cell:
            errors.add("REPOSITORY_CELL_INVALID")

        # Validate visibility
        expected_visibility = reg_entry.get("visibility", "")
        if not isinstance(expected_visibility, str):
            errors.add("REGISTRY_VISIBILITY_NOT_STRING")
            continue

        if visibility != expected_visibility:
            errors.add("VISIBILITY_MISMATCH")

        # Validate boundary
        expected_boundary = reg_entry.get("boundary", "")
        if not isinstance(expected_boundary, str):
            errors.add("REGISTRY_BOUNDARY_NOT_STRING")
            continue

        if boundary != expected_boundary:
            errors.add("BOUNDARY_MISMATCH")

        # Validate SHA format: backticks and 40 lowercase hex characters
        if not sha.startswith('`') or not sha.endswith('`'):
            errors.add("SHA_BACKTICKS_MISSING")
            continue

        sha_value = sha[1:-1]
        if len(sha_value) != 40:
            errors.add("SHA_LENGTH_INVALID")
            continue

        # Check all characters are lowercase hex (0-9a-f)
        if not all(c in '0123456789abcdef' for c in sha_value):
            errors.add("SHA_FORMAT_INVALID")

    # Check that plan labels match registry labels exactly
    registry_labels = set(registry_by_label.keys())
    if plan_labels != registry_labels:
        if plan_labels - registry_labels:
            errors.add("PLAN_LABELS_NOT_IN_REGISTRY")
        if registry_labels - plan_labels:
            errors.add("REGISTRY_LABELS_NOT_IN_PLAN")

    return sorted(errors)
