from __future__ import annotations

import re
from pathlib import Path

CANONICAL_REPOS = (
    "yurikuchumov-ux/ai-operating-system",
    "yurikuchumov-ux/ai-development-studio-template",
    "yurikuchumov-ux/-ai-development-studio",
)

CANONICAL_URLS = tuple(f"https://github.com/{name}" for name in CANONICAL_REPOS)

LEGACY_ALIAS = "yurikuchumov-ux/ai-development-studio"
LEGACY_ALIAS_URL = f"https://github.com/{LEGACY_ALIAS}"

UNKNOWN_OWNER_REPO_PATTERN = re.compile(
    r"https://github\.com/(?!yurikuchumov-ux/)([^\s)]+)"
)

REPO_TOKEN_BOUNDARY = re.compile(
    r"(?<![A-Za-z0-9-])"
    + re.escape("yurikuchumov-ux/ai-development-studio")
    + r"(?![A-Za-z0-9-])"
)

PLAN_PATH = Path("docs/AI_DEVELOPMENT_STUDIO_EXECUTION_PLAN.md")


def _plan_text() -> str:
    return PLAN_PATH.read_text(encoding="utf-8")


def _line_contexts(text: str, needle: str) -> list[str]:
    return [line.strip().lower() for line in text.splitlines() if needle in line]


def _is_explicitly_legacy_context(line: str) -> bool:
    return any(
        marker in line
        for marker in (
            "legacy",
            "historical",
            "incorrect",
            "discrep",
            "without the hyphen",
            "not the canonical",
            "resolution",
        )
    )


def test_b3_plan_contains_exact_canonical_inventory_names_and_urls() -> None:
    text = _plan_text()

    for name in CANONICAL_REPOS:
        assert name in text, f"missing canonical repository name: {name}"

    for url in CANONICAL_URLS:
        assert url in text, f"missing canonical repository URL: {url}"


def test_b3_template_name_is_not_matched_as_ai_development_studio_alias() -> None:
    text = _plan_text()

    assert "yurikuchumov-ux/ai-development-studio-template" in text

    alias_hits = REPO_TOKEN_BOUNDARY.findall(text)
    assert alias_hits, "expected at least one explicit alias mention for boundary coverage"

    contexts = _line_contexts(text, LEGACY_ALIAS)
    assert contexts, "expected alias line context for classification"
    assert all(_is_explicitly_legacy_context(line) for line in contexts), (
        "legacy alias must only appear in explicitly historical/incorrect/discrepancy contexts"
    )


def test_b3_rejects_noncanonical_github_owner_urls() -> None:
    text = _plan_text()

    noncanonical_matches = UNKNOWN_OWNER_REPO_PATTERN.findall(text)
    assert not noncanonical_matches, (
        "found noncanonical GitHub repository URL owner(s): "
        + ", ".join(sorted(set(noncanonical_matches)))
    )


def test_b3_legacy_alias_url_appears_only_in_discrepancy_context() -> None:
    text = _plan_text()

    contexts = _line_contexts(text, LEGACY_ALIAS_URL)
    assert contexts, "expected legacy alias URL reference for discrepancy classification"
    assert all(_is_explicitly_legacy_context(line) for line in contexts), (
        "legacy alias URL must only appear in explicitly historical/incorrect/discrepancy contexts"
    )
