#!/usr/bin/env python3
"""Trusted B1 always-run result finalizer.

This tool is a deterministic, human-supervised finalizer only. It is not an
Actions adapter, authoritative verifier, Check Run publisher, or automated
delegation component. It emits exactly one schema-valid `result.v1` artifact
per finalization from trusted observation input, and preserves any raw
executor candidate as untrusted, hash-addressed evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ModuleNotFoundError as exc:  # pragma: no cover - exercised by CLI setup
    raise SystemExit(
        "missing dependency: install requirements-b0.txt before running the B1 finalizer"
    ) from exc


REPO_ROOT = Path(__file__).resolve().parents[1]
RESULT_SCHEMA_PATH = REPO_ROOT / "contracts/schemas/result.v1.schema.json"

# Small, explicit bounded-input policy (item 6). These bounds intentionally
# mirror the magnitude of the B0 fixture policy in tools/validate_b0.py
# without importing or mutating that module.
MAX_INPUT_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 16
MAX_LIST_ITEMS = 256

_SHA_PATTERN = r"^[0-9a-f]{40}$"
_PATH_PATTERN = r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$)).+$"
_TASK_ID_PATTERN = r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+#[1-9][0-9]*$"
_LOCAL_ID_PATTERN = r"^[A-Za-z][A-Za-z0-9._-]*$"
_ADAPTER_PATTERN = r"^[a-z][a-z0-9-]*$"
_NO_CHANGE_REASON_PATTERN = r"^[a-z][a-z0-9_]*$"

# Trusted observation input contract. This is a repository-local, bounded
# policy schema for the finalizer's own harness-supplied input; it is not
# part of contracts/schemas/** and carries no authoritative verifier status.
TRUSTED_OBSERVATION_SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version",
        "task_id",
        "execution_id",
        "attempt",
        "executor",
        "started_at",
        "finished_at",
        "git_observation",
        "terminal_status",
        "terminal_reason",
        "finalized_by",
    ],
    "properties": {
        "schema_version": {"const": "1.0.0"},
        "task_id": {"type": "string", "pattern": _TASK_ID_PATTERN},
        "execution_id": {"type": "string", "format": "uuid"},
        "attempt": {"type": "integer", "minimum": 1, "maximum": 3},
        "executor": {
            "type": "object",
            "additionalProperties": False,
            "required": ["adapter", "adapter_version", "identity"],
            "properties": {
                "adapter": {"type": "string", "pattern": _ADAPTER_PATTERN},
                "adapter_version": {"type": "string", "minLength": 1},
                "identity": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "operator_principal",
                        "agent_runtime_id",
                        "credential_principal",
                        "delegation_parent",
                        "role",
                    ],
                    "properties": {
                        "operator_principal": {"type": "string", "minLength": 1},
                        "agent_runtime_id": {"type": "string", "minLength": 1},
                        "credential_principal": {"type": "string", "minLength": 1},
                        "delegation_parent": {"type": "string", "minLength": 1},
                        "role": {
                            "enum": ["author", "verifier", "reviewer", "publisher", "merger"]
                        },
                    },
                },
            },
        },
        "started_at": {"type": "string", "format": "date-time"},
        "finished_at": {"type": "string", "format": "date-time"},
        "git_observation": {
            "type": "object",
            "additionalProperties": False,
            "required": ["base_sha", "head_sha", "authored_commits", "changed_files"],
            "properties": {
                "base_sha": {"type": "string", "pattern": _SHA_PATTERN},
                "head_sha": {"oneOf": [{"type": "string", "pattern": _SHA_PATTERN}, {"type": "null"}]},
                "authored_commits": {
                    "type": "array",
                    "maxItems": MAX_LIST_ITEMS,
                    "items": {"type": "string", "pattern": _SHA_PATTERN},
                },
                "changed_files": {
                    "type": "array",
                    "maxItems": MAX_LIST_ITEMS,
                    "items": {"type": "string", "pattern": _PATH_PATTERN},
                },
            },
        },
        "terminal_status": {
            "enum": ["change_proposed", "no_change_required", "failed", "cancelled", "blocked"]
        },
        "terminal_reason": {"type": "string", "minLength": 1},
        "no_change_reason": {
            "oneOf": [{"type": "string", "pattern": _NO_CHANGE_REASON_PATTERN}, {"type": "null"}]
        },
        "no_change_evidence": {
            "type": "array",
            "maxItems": MAX_LIST_ITEMS,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["type", "artifact_id"],
                "properties": {
                    "type": {"type": "string", "minLength": 1},
                    "artifact_id": {"type": "string", "pattern": _LOCAL_ID_PATTERN},
                },
            },
        },
        "finalized_by": {
            "type": "object",
            "additionalProperties": False,
            "required": ["component_id", "credential_principal"],
            "properties": {
                "component_id": {"type": "string", "minLength": 1},
                "credential_principal": {"type": "string", "minLength": 1},
            },
        },
        "warnings": {"type": "array", "maxItems": MAX_LIST_ITEMS, "items": {"type": "string"}},
        "error": {
            "oneOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["code", "message"],
                    "properties": {
                        "code": {"type": "string", "pattern": r"^[a-z][a-z0-9_]*$"},
                        "message": {"type": "string", "minLength": 1},
                        "diagnostic": {},
                    },
                },
            ]
        },
    },
}

_OBSERVATION_VALIDATOR = Draft202012Validator(
    TRUSTED_OBSERVATION_SCHEMA, format_checker=FormatChecker()
)


class FinalizerPolicyError(ValueError):
    """Raised when trusted observation input violates the finalizer's bounded policy.

    This is fatal and fail-closed: no result artifact is written.
    """


class OverwriteRefused(FileExistsError):
    """Raised when the finalized output already exists (append-only policy)."""


@dataclass(frozen=True)
class CandidateOutcome:
    raw: Optional[bytes]
    parsed: Any
    fault: Optional[str]
    override_attempts: Tuple[str, ...] = field(default_factory=tuple)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_depth(value: Any, current: int = 0) -> int:
    if current > MAX_JSON_DEPTH:
        return current
    if isinstance(value, dict):
        if not value:
            return current
        return max(json_depth(item, current + 1) for item in value.values())
    if isinstance(value, list):
        if not value:
            return current
        return max(json_depth(item, current + 1) for item in value)
    return current


def load_trusted_observation(path: Path) -> Mapping[str, Any]:
    """Load and bound-check the trusted observation input. Fatal on any defect."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise FinalizerPolicyError(
            "trusted observation input is missing: {}".format(path)
        ) from exc
    if len(raw) > MAX_INPUT_BYTES:
        raise FinalizerPolicyError(
            "trusted observation exceeds maximum size of {} bytes".format(MAX_INPUT_BYTES)
        )
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FinalizerPolicyError(
            "trusted observation is not valid JSON: {}".format(exc)
        ) from exc
    if json_depth(document) > MAX_JSON_DEPTH:
        raise FinalizerPolicyError(
            "trusted observation exceeds maximum JSON depth of {}".format(MAX_JSON_DEPTH)
        )
    errors = sorted(
        _OBSERVATION_VALIDATOR.iter_errors(document),
        key=lambda error: (list(error.absolute_path), error.message),
    )
    if errors:
        raise FinalizerPolicyError(
            "trusted observation failed policy schema validation: {}".format(
                "; ".join(error.message for error in errors)
            )
        )
    return document


_OVERRIDE_CANDIDATE_KEYS = (
    "status",
    "terminal_reason",
    "base_sha",
    "head_sha",
    "execution_id",
    "task_id",
    "authored_commits",
    "changed_files",
    "finalized_by",
    "executor",
)


def detect_override_attempts(
    observation: Mapping[str, Any], candidate: Any
) -> Tuple[str, ...]:
    """Flag untrusted candidate fields that disagree with trusted observation data.

    This is transparency only: these candidate values are never used to build
    the finalized result, regardless of whether a conflict is detected.
    """
    if not isinstance(candidate, dict):
        return ()
    git_observation = observation["git_observation"]
    trusted_view = {
        "status": observation["terminal_status"],
        "terminal_reason": observation["terminal_reason"],
        "base_sha": git_observation["base_sha"],
        "head_sha": git_observation["head_sha"],
        "execution_id": observation["execution_id"],
        "task_id": observation["task_id"],
        "authored_commits": git_observation["authored_commits"],
        "changed_files": git_observation["changed_files"],
        "finalized_by": observation["finalized_by"],
        "executor": observation["executor"],
    }
    attempts: List[str] = []
    for key in _OVERRIDE_CANDIDATE_KEYS:
        if key in candidate and candidate[key] != trusted_view[key]:
            attempts.append(key)
    return tuple(attempts)


def load_candidate(path: Optional[Path], observation: Mapping[str, Any]) -> CandidateOutcome:
    """Load the untrusted executor candidate. Never fatal: faults are recorded."""
    if path is None:
        return CandidateOutcome(raw=None, parsed=None, fault="missing")
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return CandidateOutcome(raw=None, parsed=None, fault="missing")
    if len(raw) == 0:
        return CandidateOutcome(raw=raw, parsed=None, fault="empty")
    if len(raw) > MAX_INPUT_BYTES:
        return CandidateOutcome(raw=None, parsed=None, fault="oversized")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return CandidateOutcome(raw=raw, parsed=None, fault="malformed_json")
    if json_depth(parsed) > MAX_JSON_DEPTH:
        return CandidateOutcome(raw=raw, parsed=None, fault="too_deep")
    overrides = detect_override_attempts(observation, parsed)
    return CandidateOutcome(raw=raw, parsed=parsed, fault=None, override_attempts=overrides)


def has_storable_candidate_evidence(candidate: CandidateOutcome) -> bool:
    """True when the candidate has non-empty raw bytes worth preserving as evidence.

    Oversized candidates are rejected before hashing (bounded policy) and an
    empty candidate has no bytes to address, so neither is stored.
    """
    return bool(candidate.raw) and candidate.fault not in ("oversized",)


def build_result(
    observation: Mapping[str, Any], candidate: CandidateOutcome
) -> Dict[str, Any]:
    git_observation = observation["git_observation"]
    warnings: List[str] = list(observation.get("warnings", []))
    artifacts: List[Dict[str, Any]] = []

    if candidate.fault is not None:
        warnings.append("candidate_{}".format(candidate.fault))
    for field_name in candidate.override_attempts:
        warnings.append("candidate_field_override_ignored:{}".format(field_name))
    if has_storable_candidate_evidence(candidate):
        digest = sha256_bytes(candidate.raw)
        artifacts.append(
            {
                "id": "candidate-raw",
                "path": "evidence/{}.raw".format(digest),
                "sha256": digest,
                "media_type": "application/octet-stream",
                "size_bytes": len(candidate.raw),
            }
        )

    result: Dict[str, Any] = {
        "schema_version": "1.0.0",
        "task_id": observation["task_id"],
        "execution_id": observation["execution_id"],
        "attempt": observation["attempt"],
        "executor": observation["executor"],
        "started_at": observation["started_at"],
        "finished_at": observation["finished_at"],
        "base_sha": git_observation["base_sha"],
        "head_sha": git_observation["head_sha"],
        "status": observation["terminal_status"],
        "terminal_reason": observation["terminal_reason"],
        "raw_provider_terminal_reason": None,
        "no_change_reason": observation.get("no_change_reason"),
        "no_change_evidence": observation.get("no_change_evidence", []),
        "authored_commits": git_observation["authored_commits"],
        "changed_files": git_observation["changed_files"],
        "acceptance_results": [],
        "checks": [],
        "artifacts": artifacts,
        "finalized_by": observation["finalized_by"],
        "warnings": warnings,
        "error": observation.get("error"),
    }
    return result


_RESULT_VALIDATOR = Draft202012Validator(
    load_json(RESULT_SCHEMA_PATH), format_checker=FormatChecker()
)


def validate_result_schema(result: Mapping[str, Any]) -> None:
    errors = sorted(
        _RESULT_VALIDATOR.iter_errors(result),
        key=lambda error: (list(error.absolute_path), error.message),
    )
    if errors:
        raise FinalizerPolicyError(
            "finalized result failed result.v1 schema validation: {}".format(
                "; ".join(error.message for error in errors)
            )
        )


def canonical_bytes(document: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _ensure_parent_dir(path: Path, error_context: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise FinalizerPolicyError(
            "failed to prepare directory for {}: {}".format(error_context, exc)
        ) from exc


def _write_staged_file(directory: Path, name_hint: str, data: bytes, mode: int, error_context: str) -> Path:
    """Write `data` to a private staging file in `directory` and durably fsync it.

    The staging file is not visible under its final name and is not
    referenced by anything else. Any failure here (including a write or
    fsync error) is wrapped as FinalizerPolicyError and leaves no trace at
    the eventual final path, since the staging file has never been linked
    there.
    """
    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix=".{}.".format(name_hint), suffix=".tmp", dir=str(directory)
        )
    except OSError as exc:
        raise FinalizerPolicyError(
            "failed to stage {}: {}".format(error_context, exc)
        ) from exc
    tmp_path = Path(tmp_name)
    failure: Optional[OSError] = None
    try:
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise OSError("staging write returned no progress")
            offset += written
        os.fchmod(fd, mode)
        os.fsync(fd)
    except OSError as exc:
        failure = exc
    try:
        os.close(fd)
    except OSError as exc:
        if failure is None:
            failure = exc
    if failure is not None:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise FinalizerPolicyError(
            "failed to stage {}: {}".format(error_context, failure)
        ) from failure
    return tmp_path


def _publish_staged_file(tmp_path: Path, final_path: Path) -> None:
    """Atomically publish a fully written staging file to `final_path`.

    `os.link` either creates `final_path` pointing at the already-durable
    staged bytes, or fails atomically with `FileExistsError` if a file is
    already there; it can never leave `final_path` partially written. The
    staging file (now a redundant second name for the same inode, or an
    orphan if the link failed) is always removed afterwards.
    """
    try:
        os.link(tmp_path, final_path)
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass


def write_exclusive(path: Path, data: bytes) -> None:
    """Publish `data` to `path` exclusively: fail-closed, never overwrite, never partial.

    `path` only becomes visible once its bytes are fully written and
    fsynced to a staging file and that staging file is atomically linked
    into place. No failure before that link (a staging write error, a
    fsync error, a full disk, and so on) can leave `path` behind.
    """
    _ensure_parent_dir(path, "finalized result")
    tmp_path = _write_staged_file(path.parent, path.name, data, 0o444, "finalized result")
    try:
        _publish_staged_file(tmp_path, path)
    except FileExistsError as exc:
        raise OverwriteRefused(
            "finalized output already exists and will not be overwritten: {}".format(path)
        ) from exc
    except OSError as exc:
        raise FinalizerPolicyError(
            "failed to publish finalized result: {}".format(exc)
        ) from exc


def _verify_preexisting_evidence(evidence_path: Path, raw: bytes) -> None:
    """Fail closed unless a pre-existing evidence path is a genuine, matching copy.

    The path is opened once with no-follow semantics, inspected and read only
    through that descriptor, then rebound to the pathname by device/inode.
    Platforms without a real O_NOFOLLOW capability fail closed.
    """
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(no_follow, int) or no_follow == 0:
        raise FinalizerPolicyError(
            "safe pre-existing evidence verification is unavailable: "
            "O_NOFOLLOW is unsupported"
        )
    flags = (
        os.O_RDONLY
        | no_follow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        fd = os.open(str(evidence_path), flags)
    except OSError as exc:
        raise FinalizerPolicyError(
            "pre-existing evidence path cannot be opened safely: {}".format(
                evidence_path
            )
        ) from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise FinalizerPolicyError(
                "pre-existing evidence descriptor is not a regular file: {}".format(
                    evidence_path
                )
            )
        chunks: List[bytes] = []
        remaining = MAX_INPUT_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        existing = b"".join(chunks)
        after = os.fstat(fd)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(before, name) != getattr(after, name) for name in stable_fields):
            raise FinalizerPolicyError(
                "pre-existing evidence changed while it was being read: {}".format(
                    evidence_path
                )
            )
        try:
            bound = os.stat(evidence_path, follow_symlinks=False)
        except (OSError, NotImplementedError) as exc:
            raise FinalizerPolicyError(
                "pre-existing evidence path binding is unverifiable: {}".format(
                    evidence_path
                )
            ) from exc
        if not stat.S_ISREG(bound.st_mode) or (
            bound.st_dev,
            bound.st_ino,
        ) != (
            after.st_dev,
            after.st_ino,
        ):
            raise FinalizerPolicyError(
                "pre-existing evidence path changed during verification: {}".format(
                    evidence_path
                )
            )
        if existing != raw:
            raise FinalizerPolicyError(
                "pre-existing evidence content conflicts with its "
                "hash-addressed path: {}".format(evidence_path)
            )
    except OSError as exc:
        raise FinalizerPolicyError(
            "pre-existing evidence descriptor is unreadable: {}".format(
                evidence_path
            )
        ) from exc
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def store_or_verify_evidence(output_dir: Path, raw: bytes) -> Path:
    """Durably create hash-addressed evidence, or verify an existing copy.

    This must complete successfully before a result referencing it is
    published: a failure here (including a conflicting, unreadable,
    symlinked, non-regular, or unwritable pre-existing path) is fail-closed
    and no result is written. A new evidence path is only created via a
    staged, fsynced, atomically-linked write, so a write or fsync failure
    can never leave a partially written file at the final hash-addressed
    path to poison a later verification.
    """
    digest = sha256_bytes(raw)
    evidence_path = output_dir / "evidence" / "{}.raw".format(digest)
    _ensure_parent_dir(evidence_path, "candidate evidence")
    if evidence_path.exists():
        _verify_preexisting_evidence(evidence_path, raw)
        return evidence_path
    tmp_path = _write_staged_file(
        evidence_path.parent, evidence_path.name, raw, 0o444, "candidate evidence"
    )
    try:
        _publish_staged_file(tmp_path, evidence_path)
    except FileExistsError:
        # Lost a race with a concurrent writer of the same content-addressed
        # evidence bytes; verify rather than treating this as a failure.
        _verify_preexisting_evidence(evidence_path, raw)
    except OSError as exc:
        raise FinalizerPolicyError(
            "failed to publish candidate evidence: {}".format(exc)
        ) from exc
    return evidence_path


def finalize(
    observation_path: Path, candidate_path: Optional[Path], output_dir: Path
) -> Dict[str, Any]:
    observation = load_trusted_observation(observation_path)
    candidate = load_candidate(candidate_path, observation)
    result = build_result(observation, candidate)
    validate_result_schema(result)
    data = canonical_bytes(result)
    result_path = output_dir / "result.json"
    # Append-only: refuse before touching evidence, so a repeat attempt
    # against an existing result never mutates or adds evidence.
    if result_path.exists():
        raise OverwriteRefused(
            "finalized output already exists and will not be overwritten: {}".format(
                result_path
            )
        )
    # Evidence must be durably created (and verified, if already present)
    # before the result that references it is published, so result.json can
    # never point at candidate evidence that was not actually written.
    if has_storable_candidate_evidence(candidate):
        store_or_verify_evidence(output_dir, candidate.raw)
    write_exclusive(result_path, data)
    return {
        "authoritative_verifier": False,
        "bootstrap_scope": "B1",
        "result_path": str(result_path),
        "status": result["status"],
        "terminal_reason": result["terminal_reason"],
        "warnings": result["warnings"],
        "sha256": sha256_bytes(data),
    }


def _fixture_document_path(manifest_dir: Path, relative_path: str) -> Path:
    absolute_path = (manifest_dir / relative_path).resolve()
    if REPO_ROOT not in absolute_path.parents:
        raise FinalizerPolicyError("fixture path escapes repository: {}".format(relative_path))
    return absolute_path


def _check_fixture_hash(manifest_dir: Path, document_spec: Mapping[str, Any]) -> Path:
    absolute_path = _fixture_document_path(manifest_dir, document_spec["path"])
    if not absolute_path.is_file():
        raise FinalizerPolicyError(
            "fixture file does not exist: {}".format(document_spec["path"])
        )
    if absolute_path.stat().st_size > MAX_INPUT_BYTES:
        raise FinalizerPolicyError(
            "fixture file exceeds maximum size of {} bytes: {}".format(
                MAX_INPUT_BYTES, document_spec["path"]
            )
        )
    actual_hash = hashlib.sha256(absolute_path.read_bytes()).hexdigest()
    if actual_hash != document_spec["sha256"]:
        raise FinalizerPolicyError(
            "fixture hash mismatch: {}".format(document_spec["path"])
        )
    return absolute_path


def run_fixture(
    fixture: Mapping[str, Any], manifest_dir: Path, workdir: Path
) -> Dict[str, Any]:
    observation_path = _check_fixture_hash(manifest_dir, fixture["observation"])
    candidate_spec = fixture.get("candidate")
    candidate_path = (
        _check_fixture_hash(manifest_dir, candidate_spec) if candidate_spec else None
    )
    repeat = fixture.get("repeat", 1)
    output_dir = workdir / fixture["id"]
    exit_codes: List[int] = []
    last_report: Optional[Dict[str, Any]] = None
    last_error: Optional[str] = None
    for _ in range(repeat):
        try:
            last_report = finalize(observation_path, candidate_path, output_dir)
            exit_codes.append(0)
            last_error = None
        except OverwriteRefused as exc:
            exit_codes.append(3)
            last_error = "overwrite_refused:{}".format(exc)
        except FinalizerPolicyError as exc:
            exit_codes.append(2)
            last_error = "policy_error:{}".format(exc)

    expected = fixture["expected"]
    expectation_met = exit_codes == expected["exit_codes"]
    if expectation_met and expected.get("schema_valid_result", False):
        result_document = load_json(output_dir / "result.json")
        try:
            validate_result_schema(result_document)
        except FinalizerPolicyError:
            expectation_met = False
    return {
        "id": fixture["id"],
        "actual": {"exit_codes": exit_codes, "last_error": last_error},
        "expected": expected,
        "expectation_met": expectation_met,
        "report": last_report,
    }


def run_suite(manifest_path: Path, workdir: Optional[Path] = None) -> Tuple[int, Dict[str, Any]]:
    manifest = load_json(manifest_path)
    manifest_dir = manifest_path.parent
    if workdir is None:
        import tempfile

        workdir = Path(tempfile.mkdtemp(prefix="b1-finalizer-suite-", dir="/private/tmp"))
    fixture_results = [
        run_fixture(fixture, manifest_dir, workdir) for fixture in manifest["fixtures"]
    ]
    passed = sum(1 for item in fixture_results if item["expectation_met"])
    total = len(fixture_results)
    suite_valid = total > 0 and passed == total
    report = {
        "authoritative_verifier": False,
        "bootstrap_scope": "B1",
        "fixtures": fixture_results,
        "schema_version": "1.0.0",
        "summary": {"failed": total - passed, "passed": passed, "total": total},
        "valid": suite_valid,
    }
    return (0 if suite_valid else 1), report


def write_report(report: Mapping[str, Any]) -> None:
    json.dump(report, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Trusted, always-run B1 result finalizer (non-authoritative bootstrap tool)."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    finalize_parser = subparsers.add_parser(
        "finalize", help="finalize one trusted observation into a result.v1 artifact"
    )
    finalize_parser.add_argument("--observation", type=Path, required=True)
    finalize_parser.add_argument("--candidate", type=Path)
    finalize_parser.add_argument("--output-dir", type=Path, required=True)

    suite_parser = subparsers.add_parser("suite", help="run the immutable B1 fixture manifest")
    suite_parser.add_argument("--manifest", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if args.command == "suite":
        exit_code, report = run_suite(args.manifest.resolve())
        write_report(report)
        return exit_code

    try:
        report = finalize(
            args.observation.resolve(),
            args.candidate.resolve() if args.candidate else None,
            args.output_dir.resolve(),
        )
    except OverwriteRefused as exc:
        write_report(
            {
                "authoritative_verifier": False,
                "bootstrap_scope": "B1",
                "error": "overwrite_refused",
                "message": str(exc),
            }
        )
        return 3
    except FinalizerPolicyError as exc:
        write_report(
            {
                "authoritative_verifier": False,
                "bootstrap_scope": "B1",
                "error": "policy_error",
                "message": str(exc),
            }
        )
        return 2
    write_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
