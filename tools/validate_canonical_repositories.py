#!/usr/bin/env python3
"""Validate the canonical repository registry and execution-plan references."""

from __future__ import annotations

import os
import sys


def _strip_pythonpath_entries() -> None:
    """Remove interpreter search paths supplied through ``PYTHONPATH``."""

    configured = os.environ.get("PYTHONPATH")
    if configured is None:
        return
    untrusted = {
        os.path.realpath(entry or os.curdir)
        for entry in configured.split(os.pathsep)
    }
    sys.path[:] = [
        entry
        for entry in sys.path
        if os.path.realpath(entry or os.curdir) not in untrusted
    ]


_strip_pythonpath_entries()

import importlib.util
import json
import math
import stat
from pathlib import Path
from typing import Any, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = REPO_ROOT / "contracts" / "canonical-repositories.v1.json"
DEFAULT_SCHEMA = (
    REPO_ROOT / "contracts" / "schemas" / "canonical-repositories.v1.schema.json"
)
DEFAULT_PLAN = REPO_ROOT / "docs" / "AI_DEVELOPMENT_STUDIO_EXECUTION_PLAN.md"
_REGISTRY_VALIDATOR = REPO_ROOT / "tools" / "canonical_repository_registry.py"
_PLAN_VALIDATOR = REPO_ROOT / "tools" / "canonical_repository_plan.py"
_OPTIONS = {
    "--registry": "registry",
    "--schema": "schema",
    "--plan": "plan",
}


class _ArgumentError(Exception):
    """Raised for every declared command-line argument failure."""


def _bind_repo_root() -> None:
    root = str(REPO_ROOT)
    sys.path[:] = [entry for entry in sys.path if entry != root]
    sys.path.insert(0, root)


def _load_repo_module(expected_path: Path) -> Any:
    resolved = expected_path.resolve(strict=True)
    module_name = f"_ai_os_exact_{resolved.stem}"
    spec = importlib.util.spec_from_file_location(module_name, resolved)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load repository module {resolved}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _purge_dependency_modules(name: str) -> None:
    for module_name in tuple(sys.modules):
        if module_name == name or module_name.startswith(name + "."):
            del sys.modules[module_name]


def _emit(errors: Sequence[str], exit_code: int) -> int:
    normalized = sorted(set(errors))
    result = {"errors": normalized, "valid": not normalized}
    sys.stdout.write(
        json.dumps(
            result,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )
    return exit_code


def _parse_arguments(argv: Sequence[str]) -> dict[str, Path]:
    values: dict[str, Path] = {
        "registry": DEFAULT_REGISTRY,
        "schema": DEFAULT_SCHEMA,
        "plan": DEFAULT_PLAN,
    }
    seen: set[str] = set()
    index = 0

    while index < len(argv):
        token = argv[index]
        if not isinstance(token, str) or not token.startswith("--"):
            raise _ArgumentError

        if "=" in token:
            option, value = token.split("=", 1)
            consumed = 1
        else:
            option = token
            if index + 1 >= len(argv):
                raise _ArgumentError
            value = argv[index + 1]
            if not isinstance(value, str) or value.startswith("-"):
                raise _ArgumentError
            consumed = 2

        destination = _OPTIONS.get(option)
        if (
            destination is None
            or destination in seen
            or not value
            or value.startswith(("-", "="))
        ):
            raise _ArgumentError

        seen.add(destination)
        values[destination] = Path(value)
        index += consumed

    return values


def _read_bytes(path: Path, kind: str) -> tuple[bytes | None, list[str]]:
    try:
        mode = path.stat().st_mode
        if stat.S_ISDIR(mode):
            return None, [f"{kind}_file_is_directory"]
        if not stat.S_ISREG(mode):
            return None, [f"{kind}_file_unreadable"]
        return path.read_bytes(), []
    except FileNotFoundError:
        return None, [f"{kind}_file_missing"]
    except IsADirectoryError:
        return None, [f"{kind}_file_is_directory"]
    except (PermissionError, OSError):
        return None, [f"{kind}_file_unreadable"]


def _decode(content: bytes, kind: str) -> tuple[str | None, list[str]]:
    try:
        return content.decode("utf-8"), []
    except UnicodeDecodeError:
        return None, [f"{kind}_file_unicode_invalid"]


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _parse_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON number: {value}")
    return parsed


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(path: Path, kind: str) -> tuple[Any | None, list[str]]:
    content, errors = _read_bytes(path, kind)
    if errors:
        return None, errors

    text, errors = _decode(content, kind)
    if errors:
        return None, errors

    try:
        return json.loads(
            text,
            parse_constant=_reject_json_constant,
            parse_float=_parse_json_float,
            object_pairs_hook=_reject_duplicate_keys,
        ), []
    except (json.JSONDecodeError, ValueError):
        return None, [f"{kind}_json_invalid"]


def _load_text(path: Path, kind: str) -> tuple[str | None, list[str]]:
    content, errors = _read_bytes(path, kind)
    if errors:
        return None, errors
    return _decode(content, kind)


def _normalized_validator_errors(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise TypeError("validator did not return a list")
    errors = value
    if any(not isinstance(error, str) or not error for error in errors):
        raise TypeError("validator returned an invalid error code")
    return sorted(set(errors))


def main(argv: Sequence[str] | None = None) -> int:
    """Run the fail-closed validator and return its process exit code."""

    try:
        arguments = _parse_arguments(sys.argv[1:] if argv is None else argv)
    except _ArgumentError:
        return _emit(["cli_argument_invalid"], 2)
    except Exception:
        return _emit(["cli_internal_error"], 1)

    try:
        _bind_repo_root()

        registry, errors = _load_json(arguments["registry"], "registry")
        if errors:
            return _emit(errors, 1)

        schema, errors = _load_json(arguments["schema"], "schema")
        if errors:
            return _emit(errors, 1)

        _purge_dependency_modules("jsonschema")
        registry_module = _load_repo_module(_REGISTRY_VALIDATOR)
        errors = _normalized_validator_errors(
            registry_module.validate_registry(registry, schema)
        )
        if errors:
            return _emit(errors, 1)

        plan, errors = _load_text(arguments["plan"], "plan")
        if errors:
            return _emit(errors, 1)

        plan_module = _load_repo_module(_PLAN_VALIDATOR)
        errors = _normalized_validator_errors(
            plan_module.validate_execution_plan(plan, registry)
        )
        if errors:
            return _emit(errors, 1)
    except Exception:
        return _emit(["cli_internal_error"], 1)

    return _emit([], 0)


if __name__ == "__main__":
    raise SystemExit(main())
