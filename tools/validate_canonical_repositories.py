#!/usr/bin/env python3
"""Validate the canonical repository registry and execution-plan references."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = REPO_ROOT / "contracts" / "canonical-repositories.v1.json"
DEFAULT_SCHEMA = (
    REPO_ROOT / "contracts" / "schemas" / "canonical-repositories.v1.schema.json"
)
DEFAULT_PLAN = REPO_ROOT / "docs" / "AI_DEVELOPMENT_STUDIO_EXECUTION_PLAN.md"
_OPTIONS = {
    "--registry": "registry",
    "--schema": "schema",
    "--plan": "plan",
}


class _ArgumentError(Exception):
    """Raised for every declared command-line argument failure."""


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
        if destination is None or destination in seen or not value:
            raise _ArgumentError

        seen.add(destination)
        values[destination] = Path(value)
        index += consumed

    return values


def _read_bytes(path: Path, kind: str) -> tuple[bytes | None, list[str]]:
    try:
        if path.is_dir():
            return None, [f"{kind}_file_is_directory"]
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


def _load_json(path: Path, kind: str) -> tuple[Any | None, list[str]]:
    content, errors = _read_bytes(path, kind)
    if errors:
        return None, errors

    text, errors = _decode(content, kind)
    if errors:
        return None, errors

    try:
        return json.loads(text), []
    except json.JSONDecodeError:
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

    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))

    try:
        from tools.canonical_repository_plan import validate_execution_plan
        from tools.canonical_repository_registry import validate_registry

        registry, errors = _load_json(arguments["registry"], "registry")
        if errors:
            return _emit(errors, 1)

        schema, errors = _load_json(arguments["schema"], "schema")
        if errors:
            return _emit(errors, 1)

        errors = _normalized_validator_errors(validate_registry(registry, schema))
        if errors:
            return _emit(errors, 1)

        plan, errors = _load_text(arguments["plan"], "plan")
        if errors:
            return _emit(errors, 1)

        errors = _normalized_validator_errors(
            validate_execution_plan(plan, registry)
        )
        if errors:
            return _emit(errors, 1)
    except Exception:
        return _emit(["cli_internal_error"], 1)

    return _emit([], 0)


if __name__ == "__main__":
    raise SystemExit(main())
