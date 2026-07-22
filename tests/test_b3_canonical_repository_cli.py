"""Regression tests for the canonical repository validation CLI."""

from __future__ import annotations

import builtins
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


class _SubprocessHarness:
    def __init__(self, script: Path, repo_root: Path) -> None:
        self.script = script
        self.repo_root = repo_root

    def run(
        self,
        arguments: list[str] | None = None,
        cwd: Path | None = None,
        environment: dict[str, str] | None = None,
    ) -> tuple[int, str, str]:
        completed = subprocess.run(
            [sys.executable, str(self.script), *(arguments or [])],
            cwd=str(cwd or self.repo_root),
            capture_output=True,
            check=False,
            env=environment,
            text=True,
            timeout=10,
        )
        return completed.returncode, completed.stdout, completed.stderr


class _InProcessHarness:
    def __init__(self, script: Path) -> None:
        module_name = "_issue65_canonical_repository_cli_under_test"
        spec = importlib.util.spec_from_file_location(module_name, script)
        if spec is None or spec.loader is None:
            raise RuntimeError("could not load production CLI")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.module = module

    def run(self, arguments: list[str] | None = None) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = self.module.main(arguments or [])
        return exit_code, stdout.getvalue(), stderr.getvalue()


class CanonicalRepositoryCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.script = cls.repo_root / "tools" / "validate_canonical_repositories.py"
        cls.registry = cls.repo_root / "contracts" / "canonical-repositories.v1.json"
        cls.schema = (
            cls.repo_root
            / "contracts"
            / "schemas"
            / "canonical-repositories.v1.schema.json"
        )
        cls.plan = cls.repo_root / "docs" / "AI_DEVELOPMENT_STUDIO_EXECUTION_PLAN.md"
        cls.registry_bytes = cls.registry.read_bytes()
        cls.schema_bytes = cls.schema.read_bytes()
        cls.plan_bytes = cls.plan.read_bytes()
        cls.subprocess_cli = _SubprocessHarness(cls.script, cls.repo_root)
        cls.in_process_cli = _InProcessHarness(cls.script)

    def assert_result(
        self,
        observed: tuple[int, str, str],
        exit_code: int,
        errors: list[str],
    ) -> None:
        actual_exit, stdout, stderr = observed
        expected = json.dumps(
            {"errors": sorted(set(errors)), "valid": not errors},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ) + "\n"
        self.assertEqual(actual_exit, exit_code)
        self.assertEqual(stdout, expected)
        self.assertEqual(stderr, "")
        self.assertEqual(stdout.count("\n"), 1)
        self.assertEqual(set(json.loads(stdout)), {"errors", "valid"})

    @contextlib.contextmanager
    def _exact_validator_modules(self):
        cli = self.in_process_cli.module
        registry_module = cli._load_repo_module(cli._REGISTRY_VALIDATOR)
        plan_module = cli._load_repo_module(cli._PLAN_VALIDATOR)

        def controlled_loader(path: Path):
            resolved = path.resolve()
            if resolved == cli._REGISTRY_VALIDATOR.resolve():
                return registry_module
            if resolved == cli._PLAN_VALIDATOR.resolve():
                return plan_module
            raise AssertionError(f"unexpected validator path: {path}")

        with patch.object(cli, "_load_repo_module", side_effect=controlled_loader):
            yield registry_module, plan_module

    def _canonical_copies(self, root: Path) -> tuple[Path, Path, Path]:
        registry = root / "registry.json"
        schema = root / "schema.json"
        plan = root / "plan.md"
        registry.write_bytes(self.registry_bytes)
        schema.write_bytes(self.schema_bytes)
        plan.write_bytes(self.plan_bytes)
        return registry, schema, plan

    def test_defaults_succeed_from_repository_root(self) -> None:
        self.assert_result(self.subprocess_cli.run(), 0, [])

    def test_defaults_succeed_from_different_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.assert_result(
                self.subprocess_cli.run(cwd=Path(temporary)),
                0,
                [],
            )

    def test_argument_failure_matrix(self) -> None:
        cases = {
            "positional": ["positional"],
            "single_dash": ["-r", "value"],
            "unknown": ["--unknown", "value"],
            "abbreviated": ["--reg", "value"],
            "missing_registry": ["--registry"],
            "missing_schema": ["--schema"],
            "missing_plan": ["--plan"],
            "option_as_value": ["--registry", "--schema", "value"],
            "empty_registry": ["--registry="],
            "empty_schema": ["--schema="],
            "empty_plan": ["--plan="],
            "option_as_equals_value": ["--registry=--schema"],
            "extra_equals_value": ["--registry==value"],
            "repeat_space": ["--registry", "one", "--registry", "two"],
            "repeat_equals": ["--schema=one", "--schema=two"],
            "repeat_mixed": ["--plan", "one", "--plan=two"],
        }
        for label, arguments in cases.items():
            with self.subTest(label=label):
                self.assert_result(
                    self.subprocess_cli.run(arguments),
                    2,
                    ["cli_argument_invalid"],
                )

    def test_override_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            registry, schema, plan = self._canonical_copies(Path(temporary))
            cases = {
                "registry_space": ["--registry", str(registry)],
                "schema_equals": [f"--schema={schema}"],
                "plan_space": ["--plan", str(plan)],
                "all": [
                    f"--registry={registry}",
                    "--schema",
                    str(schema),
                    f"--plan={plan}",
                ],
            }
            for label, arguments in cases.items():
                with self.subTest(label=label):
                    self.assert_result(self.subprocess_cli.run(arguments), 0, [])

    def test_missing_file_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing"
            cases = (
                ("registry", ["--registry", str(missing)], "registry_file_missing"),
                ("schema", ["--schema", str(missing)], "schema_file_missing"),
                ("plan", ["--plan", str(missing)], "plan_file_missing"),
            )
            for label, arguments, error in cases:
                with self.subTest(label=label):
                    self.assert_result(self.subprocess_cli.run(arguments), 1, [error])

    def test_directory_file_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            cases = (
                ("registry", ["--registry", str(directory)], "registry_file_is_directory"),
                ("schema", ["--schema", str(directory)], "schema_file_is_directory"),
                ("plan", ["--plan", str(directory)], "plan_file_is_directory"),
            )
            for label, arguments, error in cases:
                with self.subTest(label=label):
                    self.assert_result(self.subprocess_cli.run(arguments), 1, [error])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO requires POSIX")
    def test_special_file_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fifo = Path(temporary) / "input.fifo"
            os.mkfifo(fifo)
            for kind, option, error in (
                ("registry", "--registry", "registry_file_unreadable"),
                ("schema", "--schema", "schema_file_unreadable"),
                ("plan", "--plan", "plan_file_unreadable"),
            ):
                with self.subTest(kind=kind):
                    self.assert_result(
                        self.subprocess_cli.run([option, str(fifo)]),
                        1,
                        [error],
                    )

    def test_invalid_utf8_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            invalid = Path(temporary) / "invalid"
            invalid.write_bytes(b"\xff\xfe")
            cases = (
                ("registry", ["--registry", str(invalid)], "registry_file_unicode_invalid"),
                ("schema", ["--schema", str(invalid)], "schema_file_unicode_invalid"),
                ("plan", ["--plan", str(invalid)], "plan_file_unicode_invalid"),
            )
            for label, arguments, error in cases:
                with self.subTest(label=label):
                    self.assert_result(self.subprocess_cli.run(arguments), 1, [error])

    def test_malformed_json_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            malformed = Path(temporary) / "malformed.json"
            malformed.write_text("{not-json", encoding="utf-8")
            cases = (
                ("registry", ["--registry", str(malformed)], "registry_json_invalid"),
                ("schema", ["--schema", str(malformed)], "schema_json_invalid"),
            )
            for label, arguments, error in cases:
                with self.subTest(label=label):
                    self.assert_result(self.subprocess_cli.run(arguments), 1, [error])

    def test_non_finite_json_number_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for constant in ("NaN", "Infinity", "-Infinity", "1e400", "-1e400"):
                for kind, option, error in (
                    ("registry", "--registry", "registry_json_invalid"),
                    ("schema", "--schema", "schema_json_invalid"),
                ):
                    with self.subTest(kind=kind, constant=constant):
                        invalid = root / f"{kind}-{constant}.json"
                        invalid.write_text(
                            '{"non_standard_number":' + constant + "}",
                            encoding="utf-8",
                        )
                        self.assert_result(
                            self.subprocess_cli.run([option, str(invalid)]),
                            1,
                            [error],
                        )

    def test_duplicate_json_key_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            duplicate = Path(temporary) / "duplicate.json"
            duplicate.write_text('{"duplicate":1,"duplicate":2}', encoding="utf-8")
            for kind, option, error in (
                ("registry", "--registry", "registry_json_invalid"),
                ("schema", "--schema", "schema_json_invalid"),
            ):
                with self.subTest(kind=kind):
                    self.assert_result(
                        self.subprocess_cli.run([option, str(duplicate)]),
                        1,
                        [error],
                    )

    def test_pythonpath_validator_shadowing_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            attacker_tools = root / "attacker" / "tools"
            attacker_tools.mkdir(parents=True)
            marker = root / "attacker-package-executed"
            (attacker_tools / "__init__.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n",
                encoding="utf-8",
            )
            (attacker_tools / "canonical_repository_registry.py").write_text(
                "def validate_registry(registry, schema):\n    return []\n",
                encoding="utf-8",
            )
            (attacker_tools / "canonical_repository_plan.py").write_text(
                "def validate_execution_plan(plan, registry):\n    return []\n",
                encoding="utf-8",
            )
            invalid_registry = root / "registry.json"
            invalid_plan = root / "plan.md"
            invalid_registry.write_text("{}", encoding="utf-8")
            invalid_plan.write_text("not a canonical plan", encoding="utf-8")

            environment = os.environ.copy()
            environment["PYTHONPATH"] = os.pathsep.join(
                (str(root / "attacker"), str(self.repo_root))
            )
            self.assert_result(
                self.subprocess_cli.run(
                    [
                        "--registry",
                        str(invalid_registry),
                        "--plan",
                        str(invalid_plan),
                    ],
                    environment=environment,
                ),
                1,
                ["schema_validation_failed"],
            )
            self.assertFalse(marker.exists())

    def test_pythonpath_jsonschema_shadowing_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            attacker = root / "attacker"
            fake_jsonschema = attacker / "jsonschema"
            fake_jsonschema.mkdir(parents=True)
            (fake_jsonschema / "__init__.py").write_text(
                "class _Validator:\n"
                "    @staticmethod\n"
                "    def check_schema(schema): pass\n"
                "    def __init__(self, *args, **kwargs): pass\n"
                "    def iter_errors(self, registry): return []\n"
                "Draft202012Validator = _Validator\n"
                "class FormatChecker: pass\n"
                "class SchemaError(Exception): pass\n"
                "class exceptions:\n"
                "    SchemaError = SchemaError\n",
                encoding="utf-8",
            )
            invalid_registry = root / "registry.json"
            invalid_registry.write_text("{}", encoding="utf-8")
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(attacker)
            self.assert_result(
                self.subprocess_cli.run(
                    ["--registry", str(invalid_registry)],
                    environment=environment,
                ),
                1,
                ["schema_validation_failed"],
            )

    def test_pythonpath_stdlib_shadowing_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            attacker = root / "attacker"
            attacker.mkdir()
            marker = root / "stdlib-shadow-executed"
            payload = f"from builtins import open\nopen({str(marker)!r}, 'w').write('x')\n"
            (attacker / "json.py").write_text(payload, encoding="utf-8")
            (attacker / "pathlib.py").write_text(payload, encoding="utf-8")
            invalid_registry = root / "registry.json"
            invalid_registry.write_text("{}", encoding="utf-8")
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(attacker)
            self.assert_result(
                self.subprocess_cli.run(
                    ["--registry", str(invalid_registry)],
                    environment=environment,
                ),
                1,
                ["schema_validation_failed"],
            )
            self.assertFalse(marker.exists())

    def test_invalid_schema_definition_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            invalid = Path(temporary) / "schema.json"
            invalid.write_text('{"type":42}', encoding="utf-8")
            self.assert_result(
                self.subprocess_cli.run(["--schema", str(invalid)]),
                1,
                ["schema_definition_invalid"],
            )

    def test_external_schema_reference_fails_closed_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            schema = Path(temporary) / "external-ref-schema.json"
            schema.write_text(
                json.dumps(
                    {
                        "$schema": "https://json-schema.org/draft/2020-12/schema",
                        "$ref": "http://127.0.0.1:1/remote.json",
                    }
                ),
                encoding="utf-8",
            )
            with patch("socket.create_connection") as network_connection:
                observed = self.in_process_cli.run(["--schema", str(schema)])
            network_connection.assert_not_called()
            self.assert_result(
                observed,
                1,
                ["schema_definition_invalid"],
            )

    def test_all_nonlocal_schema_reference_keywords_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for keyword, reference in (
                ("$ref", "relative-schema.json"),
                ("$dynamicRef", "https://example.invalid/schema"),
                ("$recursiveRef", "file:///tmp/schema.json"),
            ):
                with self.subTest(keyword=keyword):
                    schema = root / f"{keyword[1:]}-schema.json"
                    schema.write_text(
                        json.dumps(
                            {
                                "$schema": (
                                    "https://json-schema.org/draft/2020-12/schema"
                                ),
                                "allOf": [{keyword: reference}],
                            }
                        ),
                        encoding="utf-8",
                    )
                    self.assert_result(
                        self.subprocess_cli.run(["--schema", str(schema)]),
                        1,
                        ["schema_definition_invalid"],
                    )

    def test_local_schema_reference_remains_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            schema = Path(temporary) / "local-ref-schema.json"
            schema.write_text(
                json.dumps(
                    {
                        "$schema": "https://json-schema.org/draft/2020-12/schema",
                        "$defs": {"registry": {"type": "object"}},
                        "$ref": "#/$defs/registry",
                    }
                ),
                encoding="utf-8",
            )
            self.assert_result(
                self.subprocess_cli.run(["--schema", str(schema)]),
                0,
                [],
            )

    def test_schema_validation_failure_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            invalid = Path(temporary) / "registry.json"
            invalid.write_text("{}", encoding="utf-8")
            self.assert_result(
                self.subprocess_cli.run(["--registry", str(invalid)]),
                1,
                ["schema_validation_failed"],
            )

    def test_plan_validation_failure_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            invalid = Path(temporary) / "plan.md"
            invalid.write_text("# no canonical section\n", encoding="utf-8")
            self.assert_result(
                self.subprocess_cli.run(["--plan", str(invalid)]),
                1,
                ["plan_section_missing"],
            )

    def _assert_read_failure(
        self,
        target: Path,
        arguments: list[str],
        exception: OSError,
        expected_error: str,
    ) -> None:
        original_read_bytes = Path.read_bytes

        def controlled_read_bytes(path: Path) -> bytes:
            if path == target:
                raise exception
            return original_read_bytes(path)

        with patch.object(Path, "read_bytes", new=controlled_read_bytes):
            self.assert_result(
                self.in_process_cli.run(arguments),
                1,
                [expected_error],
            )

    def test_registry_permission_error_is_injected_in_process(self) -> None:
        self._assert_read_failure(
            self.registry,
            [],
            PermissionError("denied"),
            "registry_file_unreadable",
        )

    def test_schema_os_error_is_injected_in_process(self) -> None:
        self._assert_read_failure(
            self.schema,
            [],
            OSError("io failure"),
            "schema_file_unreadable",
        )

    def test_plan_permission_error_is_injected_in_process(self) -> None:
        self._assert_read_failure(
            self.plan,
            [],
            PermissionError("denied"),
            "plan_file_unreadable",
        )

    def test_jsonschema_dependency_failure_is_injected_in_process(self) -> None:
        original_import = builtins.__import__

        def controlled_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "jsonschema":
                raise ModuleNotFoundError("jsonschema is unavailable")
            return original_import(name, globals, locals, fromlist, level)

        with patch.object(builtins, "__import__", new=controlled_import):
            self.assert_result(
                self.in_process_cli.run(),
                1,
                ["jsonschema_dependency_missing"],
            )

    def test_registry_validator_exception_fails_closed(self) -> None:
        with self._exact_validator_modules() as (registry_module, _), patch.object(
            registry_module,
            "validate_registry",
            side_effect=RuntimeError("registry validator failed"),
        ):
            self.assert_result(
                self.in_process_cli.run(),
                1,
                ["cli_internal_error"],
            )

    def test_plan_validator_exception_fails_closed(self) -> None:
        with self._exact_validator_modules() as (_, plan_module), patch.object(
            plan_module,
            "validate_execution_plan",
            side_effect=RuntimeError("plan validator failed"),
        ):
            self.assert_result(
                self.in_process_cli.run(),
                1,
                ["cli_internal_error"],
            )

    def test_invalid_validator_result_fails_closed(self) -> None:
        with self._exact_validator_modules() as (registry_module, _):
            for label, invalid_result in (
                ("none", None),
                ("string", "schema_validation_failed"),
                ("mapping", {"error": "schema_validation_failed"}),
                ("empty_code", [""]),
            ):
                with self.subTest(label=label), patch.object(
                    registry_module,
                    "validate_registry",
                    return_value=invalid_result,
                ):
                    self.assert_result(
                        self.in_process_cli.run(),
                        1,
                        ["cli_internal_error"],
                    )

    def test_invalid_plan_validator_result_fails_closed(self) -> None:
        with self._exact_validator_modules() as (_, plan_module):
            for label, invalid_result in (
                ("none", None),
                ("string", "plan_section_missing"),
                ("mapping", {"error": "plan_section_missing"}),
                ("empty_code", [""]),
            ):
                with self.subTest(label=label), patch.object(
                    plan_module,
                    "validate_execution_plan",
                    return_value=invalid_result,
                ):
                    self.assert_result(
                        self.in_process_cli.run(),
                        1,
                        ["cli_internal_error"],
                    )

    def test_cached_registry_module_with_spoofed_origin_is_ignored(self) -> None:
        module_name = "tools.canonical_repository_registry"
        attacker_module = types.ModuleType(module_name)
        attacker_module.__file__ = str(
            self.in_process_cli.module._REGISTRY_VALIDATOR
        )
        attacker_module.validate_registry = lambda registry, schema: []
        with tempfile.TemporaryDirectory() as temporary:
            invalid = Path(temporary) / "registry.json"
            invalid.write_text("{}", encoding="utf-8")
            with patch.dict(sys.modules, {module_name: attacker_module}):
                self.assert_result(
                    self.in_process_cli.run(["--registry", str(invalid)]),
                    1,
                    ["schema_validation_failed"],
                )

    def test_cached_plan_module_with_spoofed_origin_is_ignored(self) -> None:
        module_name = "tools.canonical_repository_plan"
        attacker_module = types.ModuleType(module_name)
        attacker_module.__file__ = str(self.in_process_cli.module._PLAN_VALIDATOR)
        attacker_module.validate_execution_plan = lambda plan, registry: []
        with tempfile.TemporaryDirectory() as temporary:
            invalid = Path(temporary) / "plan.md"
            invalid.write_text("not a canonical plan", encoding="utf-8")
            with patch.dict(sys.modules, {module_name: attacker_module}):
                self.assert_result(
                    self.in_process_cli.run(["--plan", str(invalid)]),
                    1,
                    ["plan_section_missing"],
                )

    def test_private_modules_are_loaded_fresh_from_exact_path(self) -> None:
        cli = self.in_process_cli.module
        registry_module = cli._load_repo_module(cli._REGISTRY_VALIDATOR)
        second_module = cli._load_repo_module(cli._REGISTRY_VALIDATOR)
        self.assertEqual(
            Path(registry_module.__file__).resolve(),
            cli._REGISTRY_VALIDATOR.resolve(),
        )
        self.assertIsNot(registry_module, second_module)

    def test_cached_registry_module_with_wrong_origin_is_irrelevant(self) -> None:
        module_name = "tools.canonical_repository_registry"
        attacker_module = types.ModuleType(module_name)
        attacker_module.__file__ = "/tmp/attacker/canonical_repository_registry.py"
        attacker_module.validate_registry = lambda registry, schema: []
        with patch.dict(sys.modules, {module_name: attacker_module}):
            self.assert_result(
                self.in_process_cli.run(),
                0,
                [],
            )

    def test_validator_errors_are_sorted_and_deduplicated(self) -> None:
        with self._exact_validator_modules() as (registry_module, _), patch.object(
            registry_module,
            "validate_registry",
            return_value=["z_error", "a_error", "z_error"],
        ):
            self.assert_result(
                self.in_process_cli.run(),
                1,
                ["a_error", "z_error"],
            )

    def test_plan_is_not_read_after_registry_validation_failure(self) -> None:
        original_read_bytes = Path.read_bytes

        def forbid_plan_read(path: Path) -> bytes:
            if path == self.plan:
                raise AssertionError("plan must not be read")
            return original_read_bytes(path)

        with self._exact_validator_modules() as (registry_module, _):
            with patch.object(Path, "read_bytes", new=forbid_plan_read), patch.object(
                registry_module,
                "validate_registry",
                return_value=["schema_validation_failed"],
            ):
                self.assert_result(
                    self.in_process_cli.run(),
                    1,
                    ["schema_validation_failed"],
                )


if __name__ == "__main__":
    unittest.main()
