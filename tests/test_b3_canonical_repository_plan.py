import unittest

from tools.canonical_repository_plan import (
    ERROR_INVALID_PLAN_INPUT,
    ERROR_INVALID_REGISTRY_INPUT,
    ERROR_PLAN_HEADER_MISMATCH,
    ERROR_PLAN_ROW_BOUNDARY,
    ERROR_PLAN_ROW_COUNT_MISMATCH,
    ERROR_PLAN_ROW_REPOSITORY_FULL_NAME,
    ERROR_PLAN_ROW_REPOSITORY_PREFIX,
    ERROR_PLAN_ROW_REPOSITORY_SUFFIX,
    ERROR_PLAN_ROW_REPOSITORY_URL,
    ERROR_PLAN_ROW_REPOSITORY_URL_COUNT,
    ERROR_PLAN_ROW_ROLE_DUPLICATE,
    ERROR_PLAN_ROW_ROLE_SET,
    ERROR_PLAN_ROW_SHA,
    ERROR_PLAN_ROW_VISIBILITY,
    ERROR_PLAN_SEPARATOR_MISMATCH,
    ERROR_SECTION_DUPLICATE,
    ERROR_SECTION_NOT_FOUND,
    validate_canonical_repository_plan,
)


VALID_REGISTRY = [
    {
        "label": "Governance and shared contracts",
        "full_name": "yurikuchumov-ux/ai-operating-system",
        "url": "https://github.com/yurikuchumov-ux/ai-operating-system",
        "visibility": "public",
        "main_sha": "a36a8eefcdd06c56edeec93057a90c58a239cf22",
        "boundary": "owns governance, schemas, reusable workflows and evidence contracts",
    },
    {
        "label": "Compliant repository fixture",
        "full_name": "yurikuchumov-ux/ai-development-studio-template",
        "url": "https://github.com/yurikuchumov-ux/ai-development-studio-template",
        "visibility": "public",
        "main_sha": "ec088bf2e95e048ce1f5b69d969542b516afbc8b",
        "boundary": "owns the minimal downstream skeleton and repeatability tests",
    },
    {
        "label": "AI Development Studio platform",
        "full_name": "yurikuchumov-ux/-ai-development-studio",
        "url": "https://github.com/yurikuchumov-ux/-ai-development-studio",
        "visibility": "private",
        "main_sha": "f6550d4078ffccc952db269081619fdfe57e598c",
        "boundary": "owns the automated agentic software-development platform runtime and platform delivery",
    },
]


VALID_PLAN = """# AI Development Studio execution plan

## 3. Canonical repository inventory

### 3.1 Verified names and boundaries
| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| AI Development Studio platform | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns the automated agentic software-development platform runtime and platform delivery |

## 4. Next section
"""


class CanonicalRepositoryPlanTests(unittest.TestCase):
    def test_valid_plan_and_registry(self) -> None:
        result = validate_canonical_repository_plan(VALID_PLAN, VALID_REGISTRY)
        self.assertTrue(result.ok)
        self.assertIsNone(result.code)

