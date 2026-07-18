#!/usr/bin/env python3
"""
Test suite for canonical repository registry validation.

All tests are unittest.TestCase methods to ensure discovery by:
    python3 -m unittest discover -s tests -p test_b3_*.py
"""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


class TestCanonicalRepositoryRegistry(unittest.TestCase):
    """Test canonical repository registry validation."""

    def setUp(self):
        """Set up test fixtures."""
        self.registry_path = Path('contracts/canonical-repositories.v1.json')
        self.schema_path = Path('contracts/schemas/canonical-repositories.v1.schema.json')
        self.plan_path = Path('docs/AI_DEVELOPMENT_STUDIO_EXECUTION_PLAN.md')

        # Load canonical registry
        with open(self.registry_path, 'r') as f:
            self.canonical_registry = json.load(f)

    def _run_validator(self, registry=None, schema=None, plan=None):
        """Run the validator with optional overrides."""
        cmd = ['python3', 'tools/validate_canonical_repositories.py']

        if registry is not None:
            cmd.extend(['--registry', str(registry)])
        if schema is not None:
            cmd.extend(['--schema', str(schema)])
        if plan is not None:
            cmd.extend(['--plan', str(plan)])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )

        return result.returncode, json.loads(result.stdout)

    def test_exact_registry_entries(self):
        """Test that registry contains exactly the specified entries."""
        repos = self.canonical_registry['canonical_repositories']

        self.assertEqual(len(repos), 3)

        # Check governance entry
        governance = next(r for r in repos if r['role'] == 'governance')
        self.assertEqual(governance['label'], 'Governance and shared contracts')
        self.assertEqual(governance['owner'], 'yurikuchumov-ux')
        self.assertEqual(governance['name'], 'ai-operating-system')
        self.assertEqual(governance['full_name'], 'yurikuchumov-ux/ai-operating-system')
        self.assertEqual(governance['url'], 'https://github.com/yurikuchumov-ux/ai-operating-system')
        self.assertEqual(governance['visibility'], 'public')
        self.assertEqual(governance['main_sha'], 'a36a8eefcdd06c56edeec93057a90c58a239cf22')
        self.assertEqual(governance['boundary'], 'owns governance, schemas, reusable workflows and evidence contracts')

        # Check template entry
        template = next(r for r in repos if r['role'] == 'template')
        self.assertEqual(template['label'], 'Compliant repository fixture')
        self.assertEqual(template['owner'], 'yurikuchumov-ux')
        self.assertEqual(template['name'], 'ai-development-studio-template')
        self.assertEqual(template['full_name'], 'yurikuchumov-ux/ai-development-studio-template')
        self.assertEqual(template['url'], 'https://github.com/yurikuchumov-ux/ai-development-studio-template')
        self.assertEqual(template['visibility'], 'public')
        self.assertEqual(template['main_sha'], 'ec088bf2e95e048ce1f5b69d969542b516afbc8b')
        self.assertEqual(template['boundary'], 'owns the minimal downstream skeleton and repeatability tests')

        # Check voice entry
        voice = next(r for r in repos if r['role'] == 'voice')
        self.assertEqual(voice['label'], 'Voice reference product')
        self.assertEqual(voice['owner'], 'yurikuchumov-ux')
        self.assertEqual(voice['name'], '-ai-development-studio')
        self.assertEqual(voice['full_name'], 'yurikuchumov-ux/-ai-development-studio')
        self.assertEqual(voice['url'], 'https://github.com/yurikuchumov-ux/-ai-development-studio')
        self.assertEqual(voice['visibility'], 'private')
        self.assertEqual(voice['main_sha'], 'f6550d4078ffccc952db269081619fdfe57e598c')
        self.assertEqual(voice['boundary'], 'owns product runtime, domain tests and product deployment')

    def test_plan_registry_equality(self):
        """Test that plan and registry are consistent."""
        exit_code, output = self._run_validator()
        self.assertEqual(exit_code, 0)
        self.assertTrue(output['valid'])
        self.assertEqual(output['errors'], [])

    def test_plan_missing_row(self):
        """Test detection of missing row in plan."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write("""# Plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
""")
            plan_path = Path(f.name)

        try:
            exit_code, output = self._run_validator(plan=plan_path)
            self.assertNotEqual(exit_code, 0)
            self.assertFalse(output['valid'])
            self.assertIn('plan_missing_row', output['errors'])
        finally:
            plan_path.unlink()

    def test_plan_extra_row(self):
        """Test detection of extra row in plan."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write("""# Plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| Voice reference product | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns product runtime, domain tests and product deployment |
| Extra label | [`owner/repo`](https://github.com/owner/repo) | public | `0000000000000000000000000000000000000000` | extra boundary |
""")
            plan_path = Path(f.name)

        try:
            exit_code, output = self._run_validator(plan=plan_path)
            self.assertNotEqual(exit_code, 0)
            self.assertFalse(output['valid'])
            self.assertIn('plan_extra_row', output['errors'])
        finally:
            plan_path.unlink()

    def test_plan_url_mismatch(self):
        """Test detection of URL mismatch in plan."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write("""# Plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/wrong/url) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| Voice reference product | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns product runtime, domain tests and product deployment |
""")
            plan_path = Path(f.name)

        try:
            exit_code, output = self._run_validator(plan=plan_path)
            self.assertNotEqual(exit_code, 0)
            self.assertFalse(output['valid'])
            self.assertIn('plan_url_mismatch', output['errors'])
        finally:
            plan_path.unlink()

    def test_plan_duplicate_section(self):
        """Test detection of duplicate section in plan."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write("""# Plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| Voice reference product | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns product runtime, domain tests and product deployment |

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
""")
            plan_path = Path(f.name)

        try:
            exit_code, output = self._run_validator(plan=plan_path)
            self.assertNotEqual(exit_code, 0)
            self.assertFalse(output['valid'])
            self.assertIn('plan_duplicate_section', output['errors'])
        finally:
            plan_path.unlink()

    def test_plan_header_mutation(self):
        """Test detection of header mutation in plan."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write("""# Plan

### 3.1 Verified names and boundaries

| Different | Header | Format | Here | Now |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
""")
            plan_path = Path(f.name)

        try:
            exit_code, output = self._run_validator(plan=plan_path)
            self.assertNotEqual(exit_code, 0)
            self.assertFalse(output['valid'])
            self.assertIn('plan_header_mutation', output['errors'])
        finally:
            plan_path.unlink()

    def test_plan_duplicate_label_substitution(self):
        """Test detection of duplicate label in plan."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write("""# Plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Governance and shared contracts | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| Voice reference product | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns product runtime, domain tests and product deployment |
""")
            plan_path = Path(f.name)

        try:
            exit_code, output = self._run_validator(plan=plan_path)
            self.assertNotEqual(exit_code, 0)
            self.assertFalse(output['valid'])
            self.assertIn('plan_duplicate_label_substitution', output['errors'])
        finally:
            plan_path.unlink()

    def test_one_repository_link_per_row(self):
        """Test that each plan row has exactly one repository link."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write("""# Plan

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) [`extra/link`](https://github.com/extra/link) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| Voice reference product | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns product runtime, domain tests and product deployment |
""")
            plan_path = Path(f.name)

        try:
            exit_code, output = self._run_validator(plan=plan_path)
            self.assertNotEqual(exit_code, 0)
            self.assertFalse(output['valid'])
            self.assertIn('plan_repository_link_count_error', output['errors'])
        finally:
            plan_path.unlink()

    def test_registry_semantic_owner_name_mismatch(self):
        """Test detection of owner/name mismatch in registry."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            bad_registry = self.canonical_registry.copy()
            bad_registry['canonical_repositories'][0]['full_name'] = 'wrong/name'
            json.dump(bad_registry, f)
            registry_path = Path(f.name)

        try:
            exit_code, output = self._run_validator(registry=registry_path)
            self.assertNotEqual(exit_code, 0)
            self.assertFalse(output['valid'])
            self.assertIn('registry_semantic_owner_name_mismatch', output['errors'])
        finally:
            registry_path.unlink()

    def test_registry_directory_input_json(self):
        """Test that directory input for registry produces error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dir_path = Path(tmpdir)
            exit_code, output = self._run_validator(registry=dir_path)
            self.assertNotEqual(exit_code, 0)
            self.assertFalse(output['valid'])
            self.assertIn('is_directory', output['errors'])

    def test_schema_directory_input_json(self):
        """Test that directory input for schema produces error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dir_path = Path(tmpdir)
            exit_code, output = self._run_validator(schema=dir_path)
            self.assertNotEqual(exit_code, 0)
            self.assertFalse(output['valid'])
            self.assertIn('is_directory', output['errors'])

    def test_plan_directory_input_json(self):
        """Test that directory input for plan produces error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dir_path = Path(tmpdir)
            exit_code, output = self._run_validator(plan=dir_path)
            self.assertNotEqual(exit_code, 0)
            self.assertFalse(output['valid'])
            self.assertIn('plan_not_found', output['errors'])

    def test_unreadable_input_json(self):
        """Test that nonexistent input file produces error."""
        nonexistent = Path('/nonexistent/path/to/file.json')
        exit_code, output = self._run_validator(registry=nonexistent)
        self.assertNotEqual(exit_code, 0)
        self.assertFalse(output['valid'])
        self.assertIn('file_not_found', output['errors'])

    def test_missing_jsonschema_json(self):
        """Test that missing jsonschema dependency produces error."""
        # Create a test script that runs the validator in an environment without jsonschema
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("""#!/usr/bin/env python3
import sys
import builtins

# Block jsonschema import
_original_import = builtins.__import__

def _mock_import(name, *args, **kwargs):
    if name == 'jsonschema' or name.startswith('jsonschema.'):
        raise ImportError(f"No module named '{name}'")
    return _original_import(name, *args, **kwargs)

builtins.__import__ = _mock_import

# Now run the validator
exec(open('tools/validate_canonical_repositories.py').read(), {'__name__': '__main__'})
""")
            test_script = Path(f.name)

        try:
            result = subprocess.run(
                ['python3', str(test_script)],
                capture_output=True,
                text=True
            )
            output = json.loads(result.stdout)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output['valid'])
            self.assertIn('missing_jsonschema', output['errors'])
        finally:
            test_script.unlink()


if __name__ == '__main__':
    unittest.main()
