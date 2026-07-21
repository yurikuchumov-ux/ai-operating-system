"""
Tests for canonical repository plan validation (Section 3.1 inventory binding).
"""

import unittest
import json
from tools.canonical_repository_plan import validate_execution_plan


class TestCanonicalRepositoryPlan(unittest.TestCase):
    """Test suite for validate_execution_plan function."""

    def setUp(self):
        """Set up test fixtures."""
        # Load the canonical registry
        with open('contracts/canonical-repositories.v1.json', 'r') as f:
            self.registry = json.load(f)

        # Load the actual execution plan document
        with open('docs/AI_DEVELOPMENT_STUDIO_EXECUTION_PLAN.md', 'r') as f:
            self.valid_plan = f.read()

    def test_valid_plan_returns_empty_list(self):
        """Valid plan with exact registry match returns empty error list."""
        result = validate_execution_plan(self.valid_plan, self.registry)
        self.assertEqual(result, [])

    def test_plan_input_invalid(self):
        """Non-string plan input returns plan_input_invalid."""
        result = validate_execution_plan(123, self.registry)
        self.assertEqual(result, ["plan_input_invalid"])

        result = validate_execution_plan(None, self.registry)
        self.assertEqual(result, ["plan_input_invalid"])

        result = validate_execution_plan(['list'], self.registry)
        self.assertEqual(result, ["plan_input_invalid"])

    def test_registry_input_invalid_non_dict(self):
        """Non-dict registry returns registry_input_invalid."""
        result = validate_execution_plan(self.valid_plan, "string")
        self.assertEqual(result, ["registry_input_invalid"])

        result = validate_execution_plan(self.valid_plan, [])
        self.assertEqual(result, ["registry_input_invalid"])

    def test_registry_input_invalid_missing_key(self):
        """Registry without canonical_repositories key returns registry_input_invalid."""
        result = validate_execution_plan(self.valid_plan, {})
        self.assertEqual(result, ["registry_input_invalid"])

        result = validate_execution_plan(self.valid_plan, {"other_key": []})
        self.assertEqual(result, ["registry_input_invalid"])

    def test_registry_input_invalid_non_list(self):
        """Registry with non-list canonical_repositories returns registry_input_invalid."""
        result = validate_execution_plan(self.valid_plan, {"canonical_repositories": "string"})
        self.assertEqual(result, ["registry_input_invalid"])

        result = validate_execution_plan(self.valid_plan, {"canonical_repositories": {}})
        self.assertEqual(result, ["registry_input_invalid"])

    def test_plan_section_missing(self):
        """Plan without Section 3.1 returns plan_section_missing."""
        plan = """# AI Development Studio execution plan

## 3. Canonical repository inventory

### 3.2 Branch and protection baseline
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertEqual(result, ["plan_section_missing"])

    def test_plan_section_duplicate(self):
        """Plan with duplicate 3.1 headings returns plan_section_duplicate."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |

### 3.1 Verified names and boundaries

Something else
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertEqual(result, ["plan_section_duplicate"])

    def test_plan_section_wrong_level(self):
        """Section heading at wrong level returns plan_section_wrong_level."""
        plan = """# AI Development Studio execution plan

#### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |

### 3.2 Next section
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertEqual(result, ["plan_section_wrong_level"])

    def test_plan_section_heading_suffix(self):
        """Exact level heading with suffix returns plan_section_heading_suffix."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries (modified)

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertEqual(result, ["plan_section_heading_suffix"])

    def test_plan_header_mismatch(self):
        """Mutated or extra header column returns plan_header_mismatch."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertIn("plan_header_mismatch", result)

    def test_plan_header_mismatch_extra_column(self):
        """Extra header column returns plan_header_mismatch."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary | Extra |
| --- | --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts | extra |
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertIn("plan_header_mismatch", result)

    def test_plan_separator_mismatch(self):
        """Mutated separator returns plan_separator_mismatch."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertIn("plan_separator_mismatch", result)

    def test_plan_row_count_mismatch_missing_row(self):
        """Missing data row returns plan_row_count_mismatch."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |

### 3.2 Next section
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertIn("plan_row_count_mismatch", result)

    def test_plan_row_count_mismatch_extra_row(self):
        """Extra data row returns plan_row_count_mismatch."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |
| Extra row | [`yurikuchumov-ux/extra`](https://github.com/yurikuchumov-ux/extra) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | extra boundary |

### 3.2 Next section
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertIn("plan_row_count_mismatch", result)

    def test_plan_row_count_mismatch_duplicated_row(self):
        """Duplicated data row returns plan_row_count_mismatch."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |

### 3.2 Next section
"""
        result = validate_execution_plan(plan, self.registry)
        # This should trigger plan_row_count_mismatch (4 rows instead of 3)
        self.assertIn("plan_row_count_mismatch", result)

    def test_plan_label_set_mismatch_substituted_row(self):
        """Substituted row returns plan_label_set_mismatch."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Substituted label | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |

### 3.2 Next section
"""
        result = validate_execution_plan(plan, self.registry)
        # Row count is correct (3), but label set doesn't match
        self.assertIn("plan_label_set_mismatch", result)

    def test_plan_row_column_count_mismatch_fewer_cells(self):
        """Data row with fewer than 5 cells returns plan_row_column_count_mismatch."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |

### 3.2 Next section
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertIn("plan_row_column_count_mismatch", result)

    def test_plan_row_column_count_mismatch_more_cells(self):
        """Data row with more than 5 cells returns plan_row_column_count_mismatch."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts | extra cell |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |

### 3.2 Next section
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertIn("plan_row_column_count_mismatch", result)

    def test_plan_repository_link_count_mismatch_zero_links(self):
        """Row with zero repository links returns plan_repository_link_count_mismatch."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | yurikuchumov-ux/ai-operating-system | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |

### 3.2 Next section
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertIn("plan_repository_link_count_mismatch", result)

    def test_plan_repository_link_count_mismatch_two_links(self):
        """Row with two repository links returns plan_repository_link_count_mismatch."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) [`yurikuchumov-ux/extra`](https://github.com/yurikuchumov-ux/extra) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |

### 3.2 Next section
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertIn("plan_repository_link_count_mismatch", result)

    def test_plan_repository_link_outside_repository_cell(self):
        """Repository link outside second cell returns plan_repository_link_outside_repository_cell."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | Governance and shared contracts | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |

### 3.2 Next section
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertIn("plan_repository_link_outside_repository_cell", result)

    def test_plan_label_set_mismatch(self):
        """Mismatched label set returns plan_label_set_mismatch."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Wrong label | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |

### 3.2 Next section
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertIn("plan_label_set_mismatch", result)

    def test_plan_duplicate_label(self):
        """Duplicate role cell returns plan_duplicate_label."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Governance and shared contracts | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |

### 3.2 Next section
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertIn("plan_duplicate_label", result)

    def test_plan_full_name_mismatch(self):
        """Repository link label mutation returns plan_full_name_mismatch."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`wrong/name`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |

### 3.2 Next section
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertIn("plan_full_name_mismatch", result)

    def test_plan_url_mismatch(self):
        """Repository URL mutation returns plan_url_mismatch."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/wrong/url) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |

### 3.2 Next section
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertIn("plan_url_mismatch", result)

    def test_plan_visibility_mismatch(self):
        """Visibility mutation returns plan_visibility_mismatch."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | private | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |

### 3.2 Next section
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertIn("plan_visibility_mismatch", result)

    def test_plan_boundary_mismatch(self):
        """Boundary mutation returns plan_boundary_mismatch."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | wrong boundary |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |

### 3.2 Next section
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertIn("plan_boundary_mismatch", result)

    def test_plan_main_sha_invalid_uppercase(self):
        """Uppercase SHA returns plan_main_sha_invalid."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `A36A8EEFCDD06C56EDEEC93057A90C58A239CF22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |

### 3.2 Next section
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertIn("plan_main_sha_invalid", result)

    def test_plan_main_sha_invalid_non_hex(self):
        """Non-hex SHA returns plan_main_sha_invalid."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `g36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |

### 3.2 Next section
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertIn("plan_main_sha_invalid", result)

    def test_plan_main_sha_invalid_wrong_length(self):
        """Wrong-length SHA returns plan_main_sha_invalid."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |

### 3.2 Next section
"""
        result = validate_execution_plan(plan, self.registry)
        self.assertIn("plan_main_sha_invalid", result)

    def test_plan_main_sha_digits_only_accepted(self):
        """Digits-only 40-character SHA is accepted structurally."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `0123456789012345678901234567890123456789` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |

### 3.2 Next section
"""
        result = validate_execution_plan(plan, self.registry)
        # Should pass - digits-only is valid hex
        self.assertEqual(result, [])

    def test_registry_label_mutation_proves_registry_used(self):
        """Registry label mutation returns plan_label_set_mismatch."""
        mutated_registry = {
            "schema_version": "1.0.0",
            "canonical_repositories": [
                {
                    "role": "governance",
                    "label": "Wrong Label",
                    "owner": "yurikuchumov-ux",
                    "name": "ai-operating-system",
                    "full_name": "yurikuchumov-ux/ai-operating-system",
                    "url": "https://github.com/yurikuchumov-ux/ai-operating-system",
                    "visibility": "public",
                    "boundary": "owns governance, schemas, reusable workflows and evidence contracts"
                },
                self.registry["canonical_repositories"][1],
                self.registry["canonical_repositories"][2]
            ]
        }
        result = validate_execution_plan(self.valid_plan, mutated_registry)
        self.assertIn("plan_label_set_mismatch", result)

    def test_registry_url_mutation_proves_registry_used(self):
        """Registry URL mutation returns plan_url_mismatch."""
        mutated_registry = {
            "schema_version": "1.0.0",
            "canonical_repositories": [
                {
                    "role": "governance",
                    "label": "Governance and shared contracts",
                    "owner": "yurikuchumov-ux",
                    "name": "ai-operating-system",
                    "full_name": "yurikuchumov-ux/ai-operating-system",
                    "url": "https://github.com/wrong/url",
                    "visibility": "public",
                    "boundary": "owns governance, schemas, reusable workflows and evidence contracts"
                },
                self.registry["canonical_repositories"][1],
                self.registry["canonical_repositories"][2]
            ]
        }
        result = validate_execution_plan(self.valid_plan, mutated_registry)
        self.assertIn("plan_url_mismatch", result)

    def test_registry_visibility_mutation_proves_registry_used(self):
        """Registry visibility mutation returns plan_visibility_mismatch."""
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
                self.registry["canonical_repositories"][1],
                self.registry["canonical_repositories"][2]
            ]
        }
        result = validate_execution_plan(self.valid_plan, mutated_registry)
        self.assertIn("plan_visibility_mismatch", result)

    def test_registry_boundary_mutation_proves_registry_used(self):
        """Registry boundary mutation returns plan_boundary_mismatch."""
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
                    "boundary": "wrong boundary"
                },
                self.registry["canonical_repositories"][1],
                self.registry["canonical_repositories"][2]
            ]
        }
        result = validate_execution_plan(self.valid_plan, mutated_registry)
        self.assertIn("plan_boundary_mismatch", result)

    def test_sixth_cell_with_ordinary_text_fails(self):
        """A sixth ordinary cell cannot pass - plan_row_column_count_mismatch."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary | Extra |
| --- | --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts | extra |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests | extra |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery | extra |

### 3.2 Next section
"""
        result = validate_execution_plan(plan, self.registry)
        # Should fail due to column count mismatch - header also has 6 columns
        self.assertIn("plan_header_mismatch", result)

    def test_sixth_cell_with_repository_link_fails(self):
        """A sixth rogue repository-link cell cannot pass."""
        plan = """# AI Development Studio execution plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts | [`rogue/link`](https://github.com/rogue/link) |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |

### 3.2 Next section
"""
        result = validate_execution_plan(plan, self.registry)
        # Should detect either column count mismatch or repository link count mismatch
        self.assertTrue(
            "plan_row_column_count_mismatch" in result or "plan_repository_link_count_mismatch" in result,
            f"Expected column or link count error, got: {result}"
        )


if __name__ == '__main__':
    unittest.main()
