"""Tests for canonical repository registry validation."""

import json
import subprocess
import tempfile
from pathlib import Path


def run_validator(registry_path=None, schema_path=None, plan_path=None):
    """Run validator and return parsed JSON output."""
    cmd = ["python3", "tools/validate_canonical_repositories.py"]

    if registry_path:
        cmd.extend(["--registry", str(registry_path)])
    if schema_path:
        cmd.extend(["--schema", str(schema_path)])
    if plan_path:
        cmd.extend(["--plan", str(plan_path)])

    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout), result.returncode


def test_plan_registry_equality():
    """Test that plan and registry are equal."""
    output, exit_code = run_validator()

    assert exit_code == 0, f"Validator failed with exit code {exit_code}"
    assert output["valid"] is True, f"Validation failed: {output}"
    assert "plan" in output["validations"], "Plan validation not found"
    assert output["validations"]["plan"]["valid"] is True, \
        f"Plan validation failed: {output['validations']['plan']}"


def test_plan_missing_row():
    """Test detection of missing row in plan."""
    # Create temporary plan with missing row
    plan_content = """# Test Plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |

"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        f.write(plan_content)
        temp_plan = f.name

    try:
        output, exit_code = run_validator(plan_path=temp_plan)

        assert exit_code != 0, "Validator should fail for missing row"
        assert output["valid"] is False, "Validation should fail"
        assert "plan" in output["validations"], "Plan validation not found"
        assert output["validations"]["plan"]["valid"] is False, "Plan should be invalid"

        errors = output["validations"]["plan"]["errors"]
        assert any(e["code"] == "plan_missing_row" for e in errors), \
            f"Expected plan_missing_row error, got: {errors}"
    finally:
        Path(temp_plan).unlink()


def test_plan_extra_row():
    """Test detection of extra row in plan."""
    # Create temporary plan with extra row
    plan_content = """# Test Plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| Voice reference product | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns product runtime, domain tests and product deployment |
| Extra row | [`owner/repo`](https://github.com/owner/repo) | public | `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` | extra boundary |

"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        f.write(plan_content)
        temp_plan = f.name

    try:
        output, exit_code = run_validator(plan_path=temp_plan)

        assert exit_code != 0, "Validator should fail for extra row"
        assert output["valid"] is False, "Validation should fail"
        assert "plan" in output["validations"], "Plan validation not found"
        assert output["validations"]["plan"]["valid"] is False, "Plan should be invalid"

        errors = output["validations"]["plan"]["errors"]
        assert any(e["code"] == "plan_extra_row" for e in errors), \
            f"Expected plan_extra_row error, got: {errors}"
    finally:
        Path(temp_plan).unlink()


def test_plan_url_mismatch():
    """Test detection of URL mismatch."""
    # Create temporary plan with wrong URL
    plan_content = """# Test Plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/wrong/url) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| Voice reference product | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns product runtime, domain tests and product deployment |

"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        f.write(plan_content)
        temp_plan = f.name

    try:
        output, exit_code = run_validator(plan_path=temp_plan)

        assert exit_code != 0, "Validator should fail for URL mismatch"
        assert output["valid"] is False, "Validation should fail"
        assert "plan" in output["validations"], "Plan validation not found"
        assert output["validations"]["plan"]["valid"] is False, "Plan should be invalid"

        errors = output["validations"]["plan"]["errors"]
        assert any(e["code"] == "plan_url_mismatch" for e in errors), \
            f"Expected plan_url_mismatch error, got: {errors}"
    finally:
        Path(temp_plan).unlink()


def test_plan_duplicate_section():
    """Test detection of duplicate section."""
    # Create temporary plan with duplicate section
    plan_content = """# Test Plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| Voice reference product | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns product runtime, domain tests and product deployment |

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |

"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        f.write(plan_content)
        temp_plan = f.name

    try:
        output, exit_code = run_validator(plan_path=temp_plan)

        assert exit_code != 0, "Validator should fail for duplicate section"
        assert output["valid"] is False, "Validation should fail"
        assert "plan" in output["validations"], "Plan validation not found"
        assert output["validations"]["plan"]["valid"] is False, "Plan should be invalid"

        errors = output["validations"]["plan"]["errors"]
        assert any(e["code"] == "plan_duplicate_section" for e in errors), \
            f"Expected plan_duplicate_section error, got: {errors}"
    finally:
        Path(temp_plan).unlink()


def test_plan_header_mutation():
    """Test detection of header mutation."""
    # Create temporary plan with wrong header
    plan_content = """# Test Plan

### 3.1 Verified names and boundaries

| Role | Repository | Visibility | SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| Voice reference product | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns product runtime, domain tests and product deployment |

"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        f.write(plan_content)
        temp_plan = f.name

    try:
        output, exit_code = run_validator(plan_path=temp_plan)

        assert exit_code != 0, "Validator should fail for header mutation"
        assert output["valid"] is False, "Validation should fail"
        assert "plan" in output["validations"], "Plan validation not found"
        assert output["validations"]["plan"]["valid"] is False, "Plan should be invalid"

        errors = output["validations"]["plan"]["errors"]
        assert any(e["code"] == "plan_header_mutation" for e in errors), \
            f"Expected plan_header_mutation error, got: {errors}"
    finally:
        Path(temp_plan).unlink()


def test_unreadable_input_json():
    """Test handling of unreadable/malformed input JSON."""
    # Create temporary invalid JSON file
    invalid_json = "{ invalid json content"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(invalid_json)
        temp_registry = f.name

    try:
        output, exit_code = run_validator(registry_path=temp_registry)

        assert exit_code != 0, "Validator should fail for invalid JSON"
        assert output["valid"] is False, "Validation should fail"
        assert "error" in output, "Error should be reported"
        assert output["error"]["code"] == "registry_invalid_json", \
            f"Expected registry_invalid_json error, got: {output['error']}"
    finally:
        Path(temp_registry).unlink()
