"""
Canonical repository plan validator for Section 3.1 inventory binding.

This module validates the "3.1 Verified names and boundaries" section of the
AI Development Studio execution plan against the canonical repository registry.
"""

import re
from typing import List, Dict, Any


def validate_execution_plan(plan_text: Any, registry: Any) -> List[str]:
    """
    Validate the execution plan Section 3.1 against the canonical repository registry.

    Args:
        plan_text: The execution plan text (must be a string)
        registry: The canonical repository registry (must be a dict with canonical_repositories list)

    Returns:
        List of error codes, sorted and unique. Empty list means validation passed.
    """
    errors = set()

    # Validate inputs
    if not isinstance(plan_text, str):
        errors.add("plan_input_invalid")
        return sorted(errors)

    if not isinstance(registry, dict):
        errors.add("registry_input_invalid")
        return sorted(errors)

    if "canonical_repositories" not in registry:
        errors.add("registry_input_invalid")
        return sorted(errors)

    if not isinstance(registry["canonical_repositories"], list):
        errors.add("registry_input_invalid")
        return sorted(errors)

    # Build registry lookups by label (first column / Role cell)
    registry_by_label = {}
    for repo in registry["canonical_repositories"]:
        label = repo.get("label", "")
        registry_by_label[label] = repo

    # Find Section 3.1
    lines = plan_text.split('\n')
    section_heading = "### 3.1 Verified names and boundaries"

    # Find all occurrences and classify them
    exact_matches = []
    wrong_level_matches = []
    suffixed_matches = []

    for i, line in enumerate(lines):
        # Check for exact match first
        if line == section_heading:
            exact_matches.append(i)
        # Check for headings with "3.1 Verified names and boundaries" at different levels or with suffixes
        else:
            # Match any heading level with this text
            match = re.match(r'^(#{1,6})\s+3\.1\s+Verified names and boundaries(\s*)(.*)$', line)
            if match:
                level_marker = match.group(1)
                trailing_space = match.group(2)
                suffix = match.group(3)

                # Wrong level: anything other than ### (level 3)
                if level_marker != '###':
                    wrong_level_matches.append(i)
                # Suffix: level 3 but has additional text after a space
                elif suffix:
                    suffixed_matches.append(i)

    # Error detection: wrong level takes precedence over missing
    if wrong_level_matches:
        errors.add("plan_section_wrong_level")
        return sorted(errors)

    # Error detection: suffix
    if suffixed_matches:
        errors.add("plan_section_heading_suffix")
        return sorted(errors)

    # Error detection: missing section
    if not exact_matches:
        errors.add("plan_section_missing")
        return sorted(errors)

    # Error detection: duplicate section
    if len(exact_matches) > 1:
        errors.add("plan_section_duplicate")
        return sorted(errors)

    # Parse the section
    section_start = exact_matches[0] + 1

    # Find section end (next heading of level 1, 2, or 3, or end of document)
    section_end = len(lines)
    for i in range(section_start, len(lines)):
        if re.match(r'^#{1,3}\s+', lines[i]):
            section_end = i
            break

    section_lines = lines[section_start:section_end]

    # Find the table
    expected_header = "| Role | Canonical repository | Visibility | `main` SHA | Boundary |"
    expected_separator = "| --- | --- | --- | --- | --- |"

    header_idx = None
    separator_idx = None

    for i, line in enumerate(section_lines):
        if line.strip() == expected_header.strip():
            header_idx = i
        elif line.strip() == expected_separator.strip():
            separator_idx = i

    if header_idx is None or section_lines[header_idx].strip() != expected_header.strip():
        errors.add("plan_header_mismatch")
        return sorted(errors)

    if separator_idx is None or section_lines[separator_idx].strip() != expected_separator.strip():
        errors.add("plan_separator_mismatch")
        return sorted(errors)

    # Parse data rows
    data_start = separator_idx + 1
    data_rows = []

    for i in range(data_start, len(section_lines)):
        line = section_lines[i].strip()
        if not line or not line.startswith('|'):
            break
        data_rows.append(line)

    # Check row count
    if len(data_rows) != 3:
        errors.add("plan_row_count_mismatch")
        return sorted(errors)

    # Parse and validate each row
    plan_labels = []

    for row in data_rows:
        # Parse cells - need to handle markdown links
        # Split by | but be careful with content
        cells = [cell.strip() for cell in row.split('|')]
        # Remove empty first and last elements from splitting
        cells = [c for c in cells if c]

        # Check cell count (must be exactly 5)
        if len(cells) != 5:
            errors.add("plan_row_column_count_mismatch")
            continue

        # Count repository links in the complete raw row
        github_link_pattern = r'\[`[^`]+`\]\(https://github\.com/[^)]+\)'
        repo_links = re.findall(github_link_pattern, row)

        if len(repo_links) != 1:
            errors.add("plan_repository_link_count_mismatch")
            continue

        # Check that the repository link is in the second cell (index 1)
        repo_link_in_second_cell = github_link_pattern in cells[1] or re.search(github_link_pattern, cells[1])
        if not re.search(github_link_pattern, cells[1]):
            errors.add("plan_repository_link_outside_repository_cell")
            continue

        role_cell = cells[0]
        repository_cell = cells[1]
        visibility_cell = cells[2]
        sha_cell = cells[3]
        boundary_cell = cells[4]

        # Extract repository full_name from link
        link_match = re.search(r'\[`([^`]+)`\]\(https://github\.com/([^)]+)\)', repository_cell)
        if not link_match:
            continue

        plan_full_name = link_match.group(1)
        plan_url = f"https://github.com/{link_match.group(2)}"

        # Use role_cell as the label for registry lookup
        plan_label = role_cell
        plan_labels.append(plan_label)

        # Look up in registry by label
        if plan_label not in registry_by_label:
            errors.add("plan_label_set_mismatch")
            continue

        registry_entry = registry_by_label[plan_label]

        # Validate full_name
        if plan_full_name != registry_entry.get("full_name"):
            errors.add("plan_full_name_mismatch")

        # Validate URL
        if plan_url != registry_entry.get("url"):
            errors.add("plan_url_mismatch")

        # Validate visibility
        if visibility_cell != registry_entry.get("visibility"):
            errors.add("plan_visibility_mismatch")

        # Validate boundary
        if boundary_cell != registry_entry.get("boundary"):
            errors.add("plan_boundary_mismatch")

        # Validate SHA format
        # Strip exactly one pair of backticks
        sha_value = sha_cell
        if sha_value.startswith('`') and sha_value.endswith('`'):
            sha_value = sha_value[1:-1]

        # Validate with regex: lowercase hex, exactly 40 characters
        if not re.fullmatch(r'[0-9a-f]{40}', sha_value):
            errors.add("plan_main_sha_invalid")

    # Check for duplicate labels
    if len(plan_labels) != len(set(plan_labels)):
        errors.add("plan_duplicate_label")

    # Check label set match
    registry_labels = set(registry_by_label.keys())
    plan_label_set = set(plan_labels)

    if plan_label_set != registry_labels:
        errors.add("plan_label_set_mismatch")

    return sorted(errors)
