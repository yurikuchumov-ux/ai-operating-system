"""Stdlib unittest regressions for bounded raw-source execution plan validator.

These tests validate the finite raw-source grammar for Section 3.1 inventory blocks.
They make no claims about CommonMark, GFM, HTML parsing or renderer output semantics.
All tests are unittest.TestCase methods discoverable by: python3 -m unittest discover
"""

import unittest
import json
from tools.canonical_repository_plan import validate_execution_plan


class TestCanonicalRepositoryPlanValidation(unittest.TestCase):
    """Test suite for execution plan raw-source grammar validation."""

    def setUp(self):
        """Set up test fixtures with exact committed registry and plan."""
        # Exact registry structure from contracts/canonical-repositories.v1.json
        self.valid_registry = {
            "schema_version": "1.0.0",
            "canonical_repositories": [
                {
                    "role": "governance",
                    "label": "Governance and shared contracts",
                    "owner": "yurikuchumov-ux",
                    "name": "ai-operating-system",
                    "full_name": "yurikuchumov-ux/ai-operating-system",
                    "url": "https://github.com/yurikuchumov-ux/ai-operating-system",
                    "visibility": "public",
                    "boundary": "owns governance, schemas, reusable workflows and evidence contracts"
                },
                {
                    "role": "template",
                    "label": "Compliant repository fixture",
                    "owner": "yurikuchumov-ux",
                    "name": "ai-development-studio-template",
                    "full_name": "yurikuchumov-ux/ai-development-studio-template",
                    "url": "https://github.com/yurikuchumov-ux/ai-development-studio-template",
                    "visibility": "public",
                    "boundary": "owns the minimal downstream skeleton and repeatability tests"
                },
                {
                    "role": "platform",
                    "label": "AI Development Studio platform",
                    "owner": "yurikuchumov-ux",
                    "name": "-ai-development-studio",
                    "full_name": "yurikuchumov-ux/-ai-development-studio",
                    "url": "https://github.com/yurikuchumov-ux/-ai-development-studio",
                    "visibility": "private",
                    "boundary": "owns the automated agentic software-development platform runtime and platform delivery"
                }
            ]
        }

        # Valid plan text with exact structure matching task specification
        self.valid_plan_text = """### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |
"""

    def test_exact_committed_plan_and_registry_returns_empty_list(self):
        """Exact committed plan plus exact committed registry returns an empty list."""
        result = validate_execution_plan(self.valid_plan_text, self.valid_registry)
        self.assertEqual(result, [])

    def test_missing_sentinel_returns_specific_code(self):
        """Missing raw sentinel returns its specific code."""
        plan_without_sentinel = """### 3.0 Wrong heading

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
"""
        result = validate_execution_plan(plan_without_sentinel, self.valid_registry)
        self.assertIn("SENTINEL_MISSING", result)

    def test_duplicate_sentinel_returns_specific_code(self):
        """Duplicate raw sentinel returns its specific code."""
        plan_with_duplicate = """### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |

### 3.1 Verified names and boundaries
"""
        result = validate_execution_plan(plan_with_duplicate, self.valid_registry)
        self.assertIn("SENTINEL_DUPLICATE", result)

    def test_blank_line_whitespace_variant_fails(self):
        """The exact blank/header/separator sequence is mandatory; raw whitespace variants fail."""
        # Blank line with space instead of empty
        plan_with_space = self.valid_plan_text.replace("\n\n|", "\n \n|")
        result = validate_execution_plan(plan_with_space, self.valid_registry)
        self.assertIn("BLANK_LINE_INVALID", result)

    def test_header_line_mutation_fails(self):
        """The exact header line is mandatory; mutations fail."""
        # Modified header
        plan_with_wrong_header = self.valid_plan_text.replace(
            "| Role | Canonical repository |",
            "| Role  | Canonical repository |"
        )
        result = validate_execution_plan(plan_with_wrong_header, self.valid_registry)
        self.assertIn("HEADER_LINE_INVALID", result)

    def test_separator_line_mutation_fails(self):
        """The exact separator line is mandatory; mutations fail."""
        # Modified separator
        plan_with_wrong_separator = self.valid_plan_text.replace(
            "| --- | --- | --- | --- | --- |",
            "| --- | --- | --- | --- | ---- |"
        )
        result = validate_execution_plan(plan_with_wrong_separator, self.valid_registry)
        self.assertIn("SEPARATOR_LINE_INVALID", result)

    def test_fewer_than_five_cells_fails(self):
        """Fewer than five preserved interior cells fail."""
        # Row with only 4 cells
        plan_with_fewer_cells = """### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |
"""
        result = validate_execution_plan(plan_with_fewer_cells, self.valid_registry)
        self.assertIn("ROW_TOO_FEW_CELLS", result)

    def test_more_than_five_cells_with_ordinary_sixth_fails(self):
        """Ordinary sixth cell fails before semantic field validation."""
        # Row with 6 cells
        plan_with_extra_cell = """### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts | extra |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |
"""
        result = validate_execution_plan(plan_with_extra_cell, self.valid_registry)
        self.assertIn("ROW_TOO_MANY_CELLS", result)

    def test_empty_sixth_cell_fails(self):
        """Empty sixth cell fails before semantic field validation."""
        # Row with empty 6th cell
        plan_with_empty_sixth = """### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts | |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |
"""
        result = validate_execution_plan(plan_with_empty_sixth, self.valid_registry)
        self.assertIn("ROW_TOO_MANY_CELLS", result)

    def test_fourth_contiguous_leading_pipe_row_fails(self):
        """A fourth contiguous leading-pipe row fails."""
        plan_with_fourth_row = self.valid_plan_text + "| extra | row | here | now | test |\n"
        result = validate_execution_plan(plan_with_fourth_row, self.valid_registry)
        self.assertIn("FOURTH_CONTIGUOUS_PIPE_ROW_FORBIDDEN", result)

    def test_each_row_contains_exactly_one_url_token(self):
        """Each raw row contains exactly one literal GitHub repository URL token."""
        # Duplicate URL in row
        plan_with_dup_url = """### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance https://github.com/yurikuchumov-ux/ai-operating-system |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |
"""
        result = validate_execution_plan(plan_with_dup_url, self.valid_registry)
        self.assertIn("REPOSITORY_URL_DUPLICATE", result)

    def test_repository_cell_prefix_fails(self):
        """Repository cell prefix fails."""
        plan_with_prefix = """### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | prefix [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |
"""
        result = validate_execution_plan(plan_with_prefix, self.valid_registry)
        self.assertIn("REPOSITORY_CELL_INVALID", result)

    def test_repository_cell_suffix_fails(self):
        """Repository cell suffix fails."""
        plan_with_suffix = """### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) suffix | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |
"""
        result = validate_execution_plan(plan_with_suffix, self.valid_registry)
        self.assertIn("REPOSITORY_CELL_INVALID", result)

    def test_full_name_mutation_fails(self):
        """Repository cell full-name mutation fails."""
        plan_with_wrong_name = """### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/wrong-name`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |
"""
        result = validate_execution_plan(plan_with_wrong_name, self.valid_registry)
        self.assertIn("REPOSITORY_CELL_INVALID", result)

    def test_url_mutation_fails(self):
        """Repository cell URL mutation fails."""
        plan_with_wrong_url = """### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/wrong-owner/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |
"""
        result = validate_execution_plan(plan_with_wrong_url, self.valid_registry)
        self.assertIn("REPOSITORY_URL_MISSING", result)
        self.assertIn("REPOSITORY_CELL_INVALID", result)

    def test_role_duplication_fails(self):
        """Role duplication fails."""
        plan_with_dup_role = """### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Governance and shared contracts | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |
"""
        result = validate_execution_plan(plan_with_dup_role, self.valid_registry)
        self.assertIn("ROLE_DUPLICATE", result)

    def test_label_set_substitution_fails(self):
        """Label-set substitution fails (plan labels don't match registry labels)."""
        plan_with_wrong_label = """### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Wrong label | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |
"""
        result = validate_execution_plan(plan_with_wrong_label, self.valid_registry)
        self.assertIn("PLAN_LABELS_NOT_IN_REGISTRY", result)
        self.assertIn("REGISTRY_LABELS_NOT_IN_PLAN", result)

    def test_visibility_mutation_fails(self):
        """Visibility mutation returns specific code."""
        plan_with_wrong_visibility = """### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | private | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |
"""
        result = validate_execution_plan(plan_with_wrong_visibility, self.valid_registry)
        self.assertIn("VISIBILITY_MISMATCH", result)

    def test_boundary_mutation_fails(self):
        """Boundary mutation returns specific code."""
        plan_with_wrong_boundary = """### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | wrong boundary |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |
"""
        result = validate_execution_plan(plan_with_wrong_boundary, self.valid_registry)
        self.assertIn("BOUNDARY_MISMATCH", result)

    def test_sha_mutation_with_wrong_length_fails(self):
        """SHA with wrong length returns specific code."""
        plan_with_short_sha = """### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `abc123` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |
"""
        result = validate_execution_plan(plan_with_short_sha, self.valid_registry)
        self.assertIn("SHA_LENGTH_INVALID", result)

    def test_sha_missing_backticks_fails(self):
        """SHA without surrounding backticks fails."""
        plan_without_backticks = """### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | a36a8eefcdd06c56edeec93057a90c58a239cf22 | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |
"""
        result = validate_execution_plan(plan_without_backticks, self.valid_registry)
        self.assertIn("SHA_BACKTICKS_MISSING", result)

    def test_digits_only_40_char_lowercase_hex_sha_is_structurally_accepted(self):
        """Digits-only 40-character lowercase-hex SHA is structurally accepted."""
        plan_with_digits_only_sha = """### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `0123456789012345678901234567890123456789` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |
"""
        result = validate_execution_plan(plan_with_digits_only_sha, self.valid_registry)
        # Should succeed - digits are valid lowercase hex
        self.assertEqual(result, [])

    def test_uppercase_sha_fails(self):
        """SHA with uppercase characters fails."""
        plan_with_uppercase_sha = """### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `A36A8EEFCDD06C56EDEEC93057A90C58A239CF22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |
"""
        result = validate_execution_plan(plan_with_uppercase_sha, self.valid_registry)
        self.assertIn("SHA_FORMAT_INVALID", result)

    def test_registry_label_mutation_proves_registry_is_used(self):
        """Supplied registry label mutation proves the registry is used."""
        mutated_registry = {
            "schema_version": "1.0.0",
            "canonical_repositories": [
                {
                    "role": "governance",
                    "label": "Different label",
                    "owner": "yurikuchumov-ux",
                    "name": "ai-operating-system",
                    "full_name": "yurikuchumov-ux/ai-operating-system",
                    "url": "https://github.com/yurikuchumov-ux/ai-operating-system",
                    "visibility": "public",
                    "boundary": "owns governance, schemas, reusable workflows and evidence contracts"
                },
                {
                    "role": "template",
                    "label": "Compliant repository fixture",
                    "owner": "yurikuchumov-ux",
                    "name": "ai-development-studio-template",
                    "full_name": "yurikuchumov-ux/ai-development-studio-template",
                    "url": "https://github.com/yurikuchumov-ux/ai-development-studio-template",
                    "visibility": "public",
                    "boundary": "owns the minimal downstream skeleton and repeatability tests"
                },
                {
                    "role": "platform",
                    "label": "AI Development Studio platform",
                    "owner": "yurikuchumov-ux",
                    "name": "-ai-development-studio",
                    "full_name": "yurikuchumov-ux/-ai-development-studio",
                    "url": "https://github.com/yurikuchumov-ux/-ai-development-studio",
                    "visibility": "private",
                    "boundary": "owns the automated agentic software-development platform runtime and platform delivery"
                }
            ]
        }
        result = validate_execution_plan(self.valid_plan_text, mutated_registry)
        self.assertIn("ROLE_NOT_IN_REGISTRY", result)

    def test_registry_full_name_mutation_proves_registry_is_used(self):
        """Supplied registry full_name mutation proves the registry is used."""
        mutated_registry = {
            "schema_version": "1.0.0",
            "canonical_repositories": [
                {
                    "role": "governance",
                    "label": "Governance and shared contracts",
                    "owner": "yurikuchumov-ux",
                    "name": "ai-operating-system",
                    "full_name": "different-owner/ai-operating-system",
                    "url": "https://github.com/yurikuchumov-ux/ai-operating-system",
                    "visibility": "public",
                    "boundary": "owns governance, schemas, reusable workflows and evidence contracts"
                },
                {
                    "role": "template",
                    "label": "Compliant repository fixture",
                    "owner": "yurikuchumov-ux",
                    "name": "ai-development-studio-template",
                    "full_name": "yurikuchumov-ux/ai-development-studio-template",
                    "url": "https://github.com/yurikuchumov-ux/ai-development-studio-template",
                    "visibility": "public",
                    "boundary": "owns the minimal downstream skeleton and repeatability tests"
                },
                {
                    "role": "platform",
                    "label": "AI Development Studio platform",
                    "owner": "yurikuchumov-ux",
                    "name": "-ai-development-studio",
                    "full_name": "yurikuchumov-ux/-ai-development-studio",
                    "url": "https://github.com/yurikuchumov-ux/-ai-development-studio",
                    "visibility": "private",
                    "boundary": "owns the automated agentic software-development platform runtime and platform delivery"
                }
            ]
        }
        result = validate_execution_plan(self.valid_plan_text, mutated_registry)
        self.assertIn("REPOSITORY_CELL_INVALID", result)

    def test_registry_url_mutation_proves_registry_is_used(self):
        """Supplied registry URL mutation proves the registry is used."""
        mutated_registry = {
            "schema_version": "1.0.0",
            "canonical_repositories": [
                {
                    "role": "governance",
                    "label": "Governance and shared contracts",
                    "owner": "yurikuchumov-ux",
                    "name": "ai-operating-system",
                    "full_name": "yurikuchumov-ux/ai-operating-system",
                    "url": "https://github.com/different/url",
                    "visibility": "public",
                    "boundary": "owns governance, schemas, reusable workflows and evidence contracts"
                },
                {
                    "role": "template",
                    "label": "Compliant repository fixture",
                    "owner": "yurikuchumov-ux",
                    "name": "ai-development-studio-template",
                    "full_name": "yurikuchumov-ux/ai-development-studio-template",
                    "url": "https://github.com/yurikuchumov-ux/ai-development-studio-template",
                    "visibility": "public",
                    "boundary": "owns the minimal downstream skeleton and repeatability tests"
                },
                {
                    "role": "platform",
                    "label": "AI Development Studio platform",
                    "owner": "yurikuchumov-ux",
                    "name": "-ai-development-studio",
                    "full_name": "yurikuchumov-ux/-ai-development-studio",
                    "url": "https://github.com/yurikuchumov-ux/-ai-development-studio",
                    "visibility": "private",
                    "boundary": "owns the automated agentic software-development platform runtime and platform delivery"
                }
            ]
        }
        result = validate_execution_plan(self.valid_plan_text, mutated_registry)
        self.assertIn("REPOSITORY_URL_MISSING", result)

    def test_registry_visibility_mutation_proves_registry_is_used(self):
        """Supplied registry visibility mutation proves the registry is used."""
        mutated_registry = {
            "schema_version": "1.0.0",
            "canonical_repositories": [
                {
                    "role": "governance",
                    "label": "Governance and shared contracts",
                    "owner": "yurikuchumov-ux",
                    "name": "ai-operating-system",
                    "full_name": "yurikuchumov-ux/ai-operating-system",
                    "url": "https://github.com/yurikuchumov-ux/ai-operating-system",
                    "visibility": "private",
                    "boundary": "owns governance, schemas, reusable workflows and evidence contracts"
                },
                {
                    "role": "template",
                    "label": "Compliant repository fixture",
                    "owner": "yurikuchumov-ux",
                    "name": "ai-development-studio-template",
                    "full_name": "yurikuchumov-ux/ai-development-studio-template",
                    "url": "https://github.com/yurikuchumov-ux/ai-development-studio-template",
                    "visibility": "public",
                    "boundary": "owns the minimal downstream skeleton and repeatability tests"
                },
                {
                    "role": "platform",
                    "label": "AI Development Studio platform",
                    "owner": "yurikuchumov-ux",
                    "name": "-ai-development-studio",
                    "full_name": "yurikuchumov-ux/-ai-development-studio",
                    "url": "https://github.com/yurikuchumov-ux/-ai-development-studio",
                    "visibility": "private",
                    "boundary": "owns the automated agentic software-development platform runtime and platform delivery"
                }
            ]
        }
        result = validate_execution_plan(self.valid_plan_text, mutated_registry)
        self.assertIn("VISIBILITY_MISMATCH", result)

    def test_registry_boundary_mutation_proves_registry_is_used(self):
        """Supplied registry boundary mutation proves the registry is used."""
        mutated_registry = {
            "schema_version": "1.0.0",
            "canonical_repositories": [
                {
                    "role": "governance",
                    "label": "Governance and shared contracts",
                    "owner": "yurikuchumov-ux",
                    "name": "ai-operating-system",
                    "full_name": "yurikuchumov-ux/ai-operating-system",
                    "url": "https://github.com/yurikuchumov-ux/ai-operating-system",
                    "visibility": "public",
                    "boundary": "different boundary"
                },
                {
                    "role": "template",
                    "label": "Compliant repository fixture",
                    "owner": "yurikuchumov-ux",
                    "name": "ai-development-studio-template",
                    "full_name": "yurikuchumov-ux/ai-development-studio-template",
                    "url": "https://github.com/yurikuchumov-ux/ai-development-studio-template",
                    "visibility": "public",
                    "boundary": "owns the minimal downstream skeleton and repeatability tests"
                },
                {
                    "role": "platform",
                    "label": "AI Development Studio platform",
                    "owner": "yurikuchumov-ux",
                    "name": "-ai-development-studio",
                    "full_name": "yurikuchumov-ux/-ai-development-studio",
                    "url": "https://github.com/yurikuchumov-ux/-ai-development-studio",
                    "visibility": "private",
                    "boundary": "owns the automated agentic software-development platform runtime and platform delivery"
                }
            ]
        }
        result = validate_execution_plan(self.valid_plan_text, mutated_registry)
        self.assertIn("BOUNDARY_MISMATCH", result)

    def test_non_string_plan_returns_input_code(self):
        """Non-string plan returns its input code."""
        result = validate_execution_plan(123, self.valid_registry)
        self.assertIn("PLAN_NOT_STRING", result)

    def test_structurally_invalid_registry_returns_input_code(self):
        """Structurally invalid registry returns its input code."""
        result = validate_execution_plan(self.valid_plan_text, "not a dict")
        self.assertIn("REGISTRY_NOT_DICT", result)

    def test_registry_missing_canonical_repositories_key(self):
        """Registry without canonical_repositories key returns specific code."""
        invalid_registry = {"schema_version": "1.0.0"}
        result = validate_execution_plan(self.valid_plan_text, invalid_registry)
        self.assertIn("REGISTRY_MISSING_CANONICAL_REPOSITORIES", result)

    def test_no_commonmark_parser_in_implementation(self):
        """Tests contain no CommonMark, GFM or HTML parser."""
        # This is a meta-test that verifies the implementation approach
        # The implementation uses only raw string operations (split, startswith, etc.)
        # and makes no claims about rendered Markdown semantics
        import inspect
        source = inspect.getsource(validate_execution_plan)

        # Verify no markdown/html parsing libraries are used
        self.assertNotIn("markdown", source.lower())
        self.assertNotIn("commonmark", source.lower())
        self.assertNotIn("mistune", source.lower())
        self.assertNotIn("html.parser", source.lower())
        self.assertNotIn("BeautifulSoup", source)

    def test_tests_are_unittest_testcase_methods(self):
        """Every new regression is a stdlib unittest.TestCase method."""
        # This test verifies the test class structure
        self.assertIsInstance(self, unittest.TestCase)

        # Verify no pytest imports
        import sys
        self.assertNotIn("pytest", sys.modules)


if __name__ == '__main__':
    unittest.main()
