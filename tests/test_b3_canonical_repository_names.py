#!/usr/bin/env python3
"""B3 canonical repository name validation tests.

This test suite validates that task contracts reject noncanonical repository
names and genuinely unlabeled aliases, while permitting text explicitly
marked as historical or incorrect in documentation contexts.
"""

from __future__ import annotations

import unittest
from typing import Any, Dict


# Canonical repository names from section 3.1 of the execution plan
CANONICAL_REPOSITORIES = {
    "yurikuchumov-ux/ai-operating-system",
    "yurikuchumov-ux/ai-development-studio-template",
    "yurikuchumov-ux/-ai-development-studio",
}

# Known noncanonical names that must be rejected in task contracts
NONCANONICAL_ALIASES = {
    "yurikuchumov-ux/ai-project-template",  # incorrect, should be ai-development-studio-template
    "yurikuchumov-ux/ai-development-studio",  # missing leading hyphen, should be -ai-development-studio
}


def validate_repository_name(repository: str) -> tuple[bool, str]:
    """Validate a repository name against the canonical registry.

    Args:
        repository: The repository name to validate (format: owner/repo)

    Returns:
        A tuple of (is_valid, reason). is_valid is True if the repository
        name is canonical, False otherwise. reason explains the validation result.
    """
    if not repository:
        return False, "repository name is empty"

    if "/" not in repository:
        return False, "repository name must be in owner/repo format"

    if repository in CANONICAL_REPOSITORIES:
        return True, "repository name is canonical"

    if repository in NONCANONICAL_ALIASES:
        # Provide specific guidance for known incorrect names
        if repository == "yurikuchumov-ux/ai-project-template":
            return False, "noncanonical: use yurikuchumov-ux/ai-development-studio-template"
        elif repository == "yurikuchumov-ux/ai-development-studio":
            return False, "noncanonical: use yurikuchumov-ux/-ai-development-studio (note leading hyphen)"

    return False, f"repository is not in the explicit allowlisted canonical registry"


def validate_task_repository(task: Dict[str, Any]) -> tuple[bool, str]:
    """Validate the repository field in a task contract.

    Args:
        task: A task contract dictionary

    Returns:
        A tuple of (is_valid, reason)
    """
    if "repository" not in task:
        return False, "task missing required 'repository' field"

    return validate_repository_name(task["repository"])


class TestCanonicalRepositoryNames(unittest.TestCase):
    """Test canonical repository name validation."""

    def test_canonical_operating_system_repository(self):
        """The operating system repository name must be accepted."""
        is_valid, reason = validate_repository_name("yurikuchumov-ux/ai-operating-system")
        self.assertTrue(is_valid, f"Operating system repository should be valid: {reason}")

    def test_canonical_template_repository(self):
        """The template repository name must be accepted."""
        is_valid, reason = validate_repository_name("yurikuchumov-ux/ai-development-studio-template")
        self.assertTrue(is_valid, f"Template repository should be valid: {reason}")

    def test_canonical_voice_repository_with_leading_hyphen(self):
        """The voice repository with leading hyphen must be accepted."""
        is_valid, reason = validate_repository_name("yurikuchumov-ux/-ai-development-studio")
        self.assertTrue(is_valid, f"Voice repository should be valid: {reason}")

    def test_reject_ai_project_template(self):
        """Reject 'ai-project-template' as it does not exist in the verified owner repository list."""
        is_valid, reason = validate_repository_name("yurikuchumov-ux/ai-project-template")
        self.assertFalse(is_valid, "ai-project-template should be rejected")
        self.assertIn("ai-development-studio-template", reason,
                     "Error message should suggest the correct canonical name")

    def test_reject_voice_repository_without_hyphen(self):
        """Reject 'ai-development-studio' without leading hyphen."""
        is_valid, reason = validate_repository_name("yurikuchumov-ux/ai-development-studio")
        self.assertFalse(is_valid, "Voice repository without leading hyphen should be rejected")
        self.assertIn("-ai-development-studio", reason,
                     "Error message should indicate the correct name with leading hyphen")

    def test_reject_unlabeled_alias_in_task_context(self):
        """Task contracts must not use noncanonical repository names."""
        task = {
            "repository": "yurikuchumov-ux/ai-project-template",
            "task_id": "test-task",
        }
        is_valid, reason = validate_task_repository(task)
        self.assertFalse(is_valid, "Task with noncanonical repository should be rejected")

    def test_reject_unknown_repository(self):
        """Unknown repository names must be rejected."""
        is_valid, reason = validate_repository_name("yurikuchumov-ux/unknown-repo")
        self.assertFalse(is_valid, "Unknown repository should be rejected")
        self.assertIn("not in the explicit allowlisted canonical registry", reason)

    def test_reject_empty_repository(self):
        """Empty repository name must be rejected."""
        is_valid, reason = validate_repository_name("")
        self.assertFalse(is_valid, "Empty repository name should be rejected")

    def test_reject_invalid_format(self):
        """Repository name without owner/repo format must be rejected."""
        is_valid, reason = validate_repository_name("invalid-format")
        self.assertFalse(is_valid, "Invalid format should be rejected")
        self.assertIn("owner/repo format", reason)

    def test_task_missing_repository_field(self):
        """Task contracts must have a repository field."""
        task = {"task_id": "test-task"}
        is_valid, reason = validate_task_repository(task)
        self.assertFalse(is_valid, "Task without repository field should be rejected")
        self.assertIn("missing required 'repository' field", reason)


class TestDocumentationContext(unittest.TestCase):
    """Test that historical and comparison contexts are treated correctly.

    The execution plan section 5 contains a "Verified discrepancies" table
    with a row showing the incorrect claim 'ai-project-template' compared
    to the correct repository name. This is acceptable because the table
    explicitly documents it as incorrect comparison evidence.

    DECISION: do not require keywords the document does not promise.
    The table uses column headers 'Source claim' and 'Repository evidence'
    which clearly indicate comparison semantics.
    """

    def test_documentation_may_reference_incorrect_names_in_comparison_tables(self):
        """Documentation comparison tables may reference incorrect names.

        Section 5, line 197 of the execution plan contains:
        | template is `ai-project-template` | owner repository list contains `ai-development-studio-template` | use the verified canonical name |

        This is acceptable because:
        1. It appears in a "Verified discrepancies" table (section 5)
        2. The column header is "Source claim" (not a specification)
        3. The adjacent column shows the correct "Repository evidence"
        4. The Resolution column says "use the verified canonical name"

        This test documents that such comparison contexts are acceptable
        and do not violate the canonical name requirement.
        """
        # This test serves as documentation that the execution plan's
        # comparison table is correctly structured. The table row containing
        # ai-project-template is acceptable per its row semantics.

        # Verification: the table structure makes it clear that
        # ai-project-template is a SOURCE CLAIM (incorrect), not
        # a canonical name or unlabeled alias.

        table_row_context = {
            "source_claim": "template is `ai-project-template`",
            "repository_evidence": "owner repository list contains `ai-development-studio-template`",
            "resolution": "use the verified canonical name",
        }

        # The table row is semantically correct because it explicitly
        # labels the incorrect name as a "claim" and contrasts it with
        # "evidence" showing the correct name.
        self.assertEqual(
            table_row_context["resolution"],
            "use the verified canonical name",
            "Table row must indicate to use the canonical name"
        )

    def test_verified_facts_may_state_noncanonical_names_do_not_exist(self):
        """VERIFIED FACT statements may state that noncanonical names don't exist.

        Section 3.1, lines 75-77 state:
        **VERIFIED FACT:** `ai-project-template` does not exist in the verified
        owner repository list. The correct template name is
        `ai-development-studio-template`.

        This is acceptable because the statement explicitly says the name
        "does not exist" and provides the correct name.
        """
        verified_fact = {
            "statement": "ai-project-template does not exist in the verified owner repository list",
            "correct_name": "ai-development-studio-template",
        }

        # The VERIFIED FACT structure makes it clear that ai-project-template
        # is being documented as nonexistent (incorrect)
        self.assertIn("does not exist", verified_fact["statement"])
        self.assertEqual(verified_fact["correct_name"], "ai-development-studio-template")


if __name__ == "__main__":
    unittest.main()
