#!/usr/bin/env python3
"""B3 deterministic terminal-reason propagator and Check Run conclusion source.

This tool is a bounded, deterministic, offline pipeline component only. It is
not itself a GitHub Actions job; it is the trusted logic a real Actions
workflow step invokes (see `.github/workflows/b3-terminal-propagation.yml`)
to turn a trusted provider signal into an authoritative `result.v1`, verify
it with the existing B2 verifier, and compute the one and only value a Check
Run conclusion may be published from.

It composes exactly two existing, unmodified components:

- `tools.finalize_b1.finalize` finalizes a trusted observation (derived here,
  never from adapter self-report or Actions job conclusion) into a
  schema-valid `result.v1` artifact.
- `tools.verify_b2.run_verification` verifies that finalized result against a
  task, a review-attestation, a trusted Git observation, and evidence, and
  emits a schema-valid `verification.v1` report.

The Check Run conclusion this tool derives is `success` iff
`verification.v1.passed` is `true` -- never the adapter's own self-reported
status and never the Actions job's own conclusion. Both of those are only
ever recorded as untrusted, informational fields in the published
`workflow-run-metadata` artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ModuleNotFoundError as exc:  # pragma: no cover - exercised by CLI setup
    raise SystemExit(
        "missing dependency: install requirements-b0.txt before running the B3 propagator"
    ) from exc

REPO_ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__" and str(REPO_ROOT) not in sys.path:
    # `python3 tools/propagate_b3.py ...` (direct script invocation, matching
    # the existing `tools/finalize_b1.py` / `tools/verify_b2.py` usage in
    # contracts/README.md) puts `tools/` itself on sys.path[0], not the repo
    # root, so the `tools.*`-qualified imports below would otherwise fail.
    sys.path.insert(0, str(REPO_ROOT))

from tools.finalize_b1 import FinalizerPolicyError, OverwriteRefused
from tools.finalize_b1 import finalize as b1_finalize
from tools.verify_b2 import Invocation, VerifierInputError
from tools.verify_b2 import canonical_bytes as b2_canonical_bytes
from tools.verify_b2 import load_json, publish_report, run_verification
RESULT_SCHEMA_PATH = REPO_ROOT / "contracts/schemas/result.v1.schema.json"
VERIFICATION_SCHEMA_PATH = REPO_ROOT / "contracts/schemas/verification.v1.schema.json"

MAX_INPUT_BYTES = 1024 * 1024

_SHA_PATTERN = r"^[0-9a-f]{40}$"
_PATH_PATTERN = r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$)).+$"
_TASK_ID_PATTERN = r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+#[1-9][0-9]*$"
_ADAPTER_PATTERN = r"^[a-z][a-z0-9-]*$"

_IDENTITY_SCHEMA: Dict[str, Any] = {
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
        "role": {"enum": ["author", "verifier", "reviewer", "publisher", "merger"]},
    },
}

# Trusted, repository-local provider-signal input contract. This is the
# shape a real Actions always-run finalize job assembles from the executor
# job's own trusted facts (exit codes, wall-clock/job-timeout signals, Git
# state, artifact presence, required-check exit code) before this tool ever
# runs. It is not part of contracts/schemas/** and carries no authoritative
# verifier status beyond this tool's own closed classification.
PROVIDER_SIGNAL_SCHEMA: Dict[str, Any] = {
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
        "workflow_run_id",
        "source_run_id",
        "cancelled_by_owner",
        "adapter_timed_out",
        "job_timed_out",
        "max_turns_exhausted",
        "adapter_error",
        "raw_provider_terminal_reason",
        "adapter_self_report",
        "actions_job_conclusion",
        "untrusted_candidate",
        "git_observation",
        "result_artifact_present",
        "required_evidence_artifact_present",
        "required_check_exit_code",
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
                "identity": _IDENTITY_SCHEMA,
            },
        },
        "started_at": {"type": "string", "format": "date-time"},
        "finished_at": {"type": "string", "format": "date-time"},
        "workflow_run_id": {"type": "string", "minLength": 1},
        "source_run_id": {"oneOf": [{"type": "string", "minLength": 1}, {"type": "null"}]},
        "cancelled_by_owner": {"type": "boolean"},
        "adapter_timed_out": {"type": "boolean"},
        "job_timed_out": {"type": "boolean"},
        "max_turns_exhausted": {"type": "boolean"},
        "adapter_error": {
            "oneOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["code", "message"],
                    "properties": {
                        "code": {"type": "string", "pattern": r"^[a-z][a-z0-9_]*$"},
                        "message": {"type": "string", "minLength": 1},
                    },
                },
            ]
        },
        "raw_provider_terminal_reason": {"oneOf": [{"type": "string", "minLength": 1}, {"type": "null"}]},
        "adapter_self_report": {
            "oneOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["status", "claimed_status", "claimed_terminal_reason"],
                    "properties": {
                        "status": {"enum": ["success", "failed"]},
                        "claimed_status": {
                            "enum": ["change_proposed", "no_change_required", "failed", "cancelled", "blocked"]
                        },
                        "claimed_terminal_reason": {"type": "string", "minLength": 1},
                    },
                },
            ]
        },
        "actions_job_conclusion": {"oneOf": [{"type": "string", "minLength": 1}, {"type": "null"}]},
        "untrusted_candidate": {
            "oneOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["status", "terminal_reason"],
                    "properties": {
                        "status": {
                            "enum": ["change_proposed", "no_change_required", "failed", "cancelled", "blocked"]
                        },
                        "terminal_reason": {"type": "string", "minLength": 1},
                    },
                },
            ]
        },
        "git_observation": {
            "type": "object",
            "additionalProperties": False,
            "required": ["base_sha", "head_sha", "authored_commits", "changed_files"],
            "properties": {
                "base_sha": {"type": "string", "pattern": _SHA_PATTERN},
                "head_sha": {"oneOf": [{"type": "string", "pattern": _SHA_PATTERN}, {"type": "null"}]},
                "authored_commits": {"type": "array", "items": {"type": "string", "pattern": _SHA_PATTERN}},
                "changed_files": {"type": "array", "items": {"type": "string", "pattern": _PATH_PATTERN}},
            },
        },
        "result_artifact_present": {"type": "boolean"},
        "required_evidence_artifact_present": {"type": "boolean"},
        "required_check_exit_code": {"oneOf": [{"type": "integer"}, {"type": "null"}]},
        "finalized_by": {
            "type": "object",
            "additionalProperties": False,
            "required": ["component_id", "credential_principal"],
            "properties": {
                "component_id": {"type": "string", "minLength": 1},
                "credential_principal": {"type": "string", "minLength": 1},
            },
        },
    },
}

_SIGNAL_VALIDATOR = Draft202012Validator(PROVIDER_SIGNAL_SCHEMA, format_checker=FormatChecker())
_RESULT_VALIDATOR = Draft202012Validator(load_json(RESULT_SCHEMA_PATH), format_checker=FormatChecker())
_VERIFICATION_VALIDATOR = Draft202012Validator(
    load_json(VERIFICATION_SCHEMA_PATH), format_checker=FormatChecker()
)

_TERMINAL_REASON_MESSAGES: Dict[str, str] = {
    "max_turns": "adapter exhausted its maximum turn budget before completing",
    "timeout": "execution exceeded its allotted timeout",
    "missing_commit": "no authored commit was observed on the subject ref",
    "missing_artifact": "a required artifact was not produced",
    "empty_diff": "no changed files were observed though a change was required",
    "check_failed": "a required check did not exit zero",
    "cancelled_by_owner": "the run was cancelled by the owner",
}


class B3PropagatorError(ValueError):
    """Raised for any input, policy, or publication failure. Always fail-closed."""


@dataclass(frozen=True)
class Classification:
    status: str
    terminal_reason: str
    error_code: Optional[str]
    error_message: Optional[str]
    timeout_origin: Optional[str]
    missing_artifact_type: Optional[str]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "terminal_reason": self.terminal_reason,
            "timeout_origin": self.timeout_origin,
            "missing_artifact_type": self.missing_artifact_type,
        }


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(document: Mapping[str, Any]) -> bytes:
    return (json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _load_bounded_json(path: Path, label: str) -> Any:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise B3PropagatorError("{} is unreadable: {}".format(label, exc)) from exc
    if len(raw) > MAX_INPUT_BYTES:
        raise B3PropagatorError("{} exceeds maximum size of {} bytes".format(label, MAX_INPUT_BYTES))
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise B3PropagatorError("{} is not valid JSON: {}".format(label, exc)) from exc


def load_provider_signal(path: Path) -> Mapping[str, Any]:
    """Load and validate the trusted provider signal. Fatal on any defect."""
    document = _load_bounded_json(path, "provider signal")
    errors = sorted(_SIGNAL_VALIDATOR.iter_errors(document), key=lambda error: list(error.absolute_path))
    if errors:
        raise B3PropagatorError(
            "provider signal failed policy schema validation: {}".format(
                "; ".join(error.message for error in errors)
            )
        )
    return document


def classify_terminal(signal: Mapping[str, Any]) -> Classification:
    """Deterministically classify the terminal outcome from trusted facts only.

    Adapter self-report (`adapter_self_report`) and the Actions job's own
    conclusion (`actions_job_conclusion`) are never read here: both are
    carried through only as informational, untrusted metadata elsewhere. A
    provider signal claiming green at either layer cannot change the
    classification this function derives from the actually observed
    cancellation, timeout, turn-budget, error, Git, artifact, and check
    facts.
    """
    go = signal["git_observation"]

    if signal["cancelled_by_owner"]:
        return Classification(
            "cancelled", "cancelled_by_owner",
            "cancelled_by_owner", _TERMINAL_REASON_MESSAGES["cancelled_by_owner"],
            None, None,
        )
    if signal["job_timed_out"]:
        return Classification("failed", "timeout", "timeout", _TERMINAL_REASON_MESSAGES["timeout"], "actions_job", None)
    if signal["adapter_timed_out"]:
        return Classification("failed", "timeout", "timeout", _TERMINAL_REASON_MESSAGES["timeout"], "adapter", None)
    if signal["max_turns_exhausted"]:
        return Classification("failed", "max_turns", "max_turns", _TERMINAL_REASON_MESSAGES["max_turns"], None, None)
    if signal["adapter_error"] is not None:
        return Classification(
            "failed", "adapter_error", signal["adapter_error"]["code"], signal["adapter_error"]["message"], None, None
        )
    if not go["authored_commits"]:
        return Classification(
            "failed", "missing_commit", "missing_commit", _TERMINAL_REASON_MESSAGES["missing_commit"], None, None
        )
    if not signal["result_artifact_present"]:
        return Classification(
            "failed", "missing_artifact", "missing_artifact", _TERMINAL_REASON_MESSAGES["missing_artifact"],
            None, "result-artifact",
        )
    if not signal["required_evidence_artifact_present"]:
        return Classification(
            "failed", "missing_artifact", "missing_artifact", _TERMINAL_REASON_MESSAGES["missing_artifact"],
            None, "required-evidence-artifact",
        )
    if not go["changed_files"]:
        return Classification("failed", "empty_diff", "empty_diff", _TERMINAL_REASON_MESSAGES["empty_diff"], None, None)
    if signal["required_check_exit_code"] != 0:
        return Classification("failed", "check_failed", "check_failed", _TERMINAL_REASON_MESSAGES["check_failed"], None, None)
    return Classification("change_proposed", "completed", None, None, None, None)


def build_trusted_observation(signal: Mapping[str, Any], classification: Classification) -> Dict[str, Any]:
    go = signal["git_observation"]
    error = (
        None
        if classification.status == "change_proposed"
        else {"code": classification.error_code, "message": classification.error_message}
    )
    return {
        "schema_version": "1.0.0",
        "task_id": signal["task_id"],
        "execution_id": signal["execution_id"],
        "attempt": signal["attempt"],
        "executor": signal["executor"],
        "started_at": signal["started_at"],
        "finished_at": signal["finished_at"],
        "git_observation": {
            "base_sha": go["base_sha"],
            "head_sha": go["head_sha"],
            "authored_commits": list(go["authored_commits"]),
            "changed_files": list(go["changed_files"]),
        },
        "terminal_status": classification.status,
        "terminal_reason": classification.terminal_reason,
        "no_change_reason": None,
        "no_change_evidence": [],
        "finalized_by": signal["finalized_by"],
        "warnings": [],
        "error": error,
    }


def _write_json(path: Path, document: Mapping[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    return path


def _publish_exclusive(path: Path, data: bytes) -> None:
    """Publish `data` to `path` exclusively: never overwrite, never partial.

    Mirrors the stage-fsync-then-hard-link publication discipline already
    used by the B1 finalizer and B2 verifier for their own authoritative
    artifacts, applied here to the third B3-owned artifact
    (`workflow-run-metadata`).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd, tmp_name = tempfile.mkstemp(prefix=".{}.".format(path.name), suffix=".tmp", dir=str(path.parent))
    except OSError as exc:
        raise B3PropagatorError("failed to stage {}: {}".format(path, exc)) from exc
    tmp_path = Path(tmp_name)
    failure: Optional[OSError] = None
    try:
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise OSError("staging write returned no progress")
            offset += written
        os.fchmod(fd, 0o444)
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
        raise B3PropagatorError("failed to stage {}: {}".format(path, failure)) from failure
    try:
        os.link(tmp_path, path)
    except FileExistsError as exc:
        raise B3PropagatorError("output already exists and will not be overwritten: {}".format(path)) from exc
    except OSError as exc:
        raise B3PropagatorError("failed to publish {}: {}".format(path, exc)) from exc
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass


def build_workflow_run_metadata(
    signal: Mapping[str, Any],
    result: Mapping[str, Any],
    verification: Mapping[str, Any],
    check_run_conclusion: str,
) -> Dict[str, Any]:
    self_report = signal.get("adapter_self_report")
    return {
        "schema_version": "1.0.0",
        "workflow_run_id": signal["workflow_run_id"],
        "source_run_id": signal.get("source_run_id"),
        "execution_id": result["execution_id"],
        "task_id": result["task_id"],
        "check_run_conclusion": check_run_conclusion,
        "verification_id": verification["verification_id"],
        "verification_passed": verification["passed"],
        "raw_provider_terminal_reason": signal.get("raw_provider_terminal_reason"),
        "adapter_self_reported_status": self_report["status"] if self_report else None,
        "actions_job_conclusion": signal.get("actions_job_conclusion"),
        "artifacts_count": len(result["artifacts"]),
        "new_commit": bool(result["authored_commits"]),
    }


@dataclass(frozen=True)
class PipelineOutputs:
    classification: Classification
    result: Dict[str, Any]
    verification: Dict[str, Any]
    check_run_conclusion: str
    workflow_run_metadata: Dict[str, Any]
    result_path: Path
    verification_path: Path
    workflow_run_metadata_path: Path


def run_pipeline(
    signal_path: Path,
    task_path: Path,
    review_path: Path,
    verifier_identity_path: Path,
    verification_id: str,
    evaluated_at: str,
    output_dir: Path,
) -> PipelineOutputs:
    signal = load_provider_signal(signal_path)
    classification = classify_terminal(signal)
    observation = build_trusted_observation(signal, classification)
    observation_path = _write_json(output_dir / "observation.json", observation)

    candidate_spec = signal.get("untrusted_candidate")
    candidate_path: Optional[Path] = None
    if candidate_spec is not None:
        candidate_path = _write_json(output_dir / "candidate.json", candidate_spec)

    finalize_report = b1_finalize(observation_path, candidate_path, output_dir)
    result_path = Path(finalize_report["result_path"])
    result = load_json(result_path)

    go = signal["git_observation"]
    git_observation_doc = {
        "schema_version": "1.0.0",
        "base_sha": go["base_sha"],
        "head_sha": go["head_sha"],
        "authored_commits": list(go["authored_commits"]),
        "changed_files": list(go["changed_files"]),
    }
    git_observation_path = _write_json(output_dir / "git-observation.json", git_observation_doc)

    verifier_identity = load_json(verifier_identity_path)
    expected_subject_sha = go["head_sha"] or ("0" * 40)
    invocation = Invocation(
        verification_id=verification_id,
        evaluated_at=evaluated_at,
        expected_task_id=signal["task_id"],
        expected_execution_id=signal["execution_id"],
        expected_base_sha=go["base_sha"],
        expected_subject_sha=expected_subject_sha,
        verifier_identity=verifier_identity,
    )
    _, verification = run_verification(
        invocation, task_path, result_path, review_path, git_observation_path, output_dir
    )
    verification_path = output_dir / "verification.json"
    publish_report(verification_path, b2_canonical_bytes(verification))

    check_run_conclusion = "success" if verification["passed"] else "failure"
    metadata = build_workflow_run_metadata(signal, result, verification, check_run_conclusion)
    metadata_path = output_dir / "workflow-run-metadata.json"
    _publish_exclusive(metadata_path, canonical_bytes(metadata))

    return PipelineOutputs(
        classification=classification,
        result=result,
        verification=verification,
        check_run_conclusion=check_run_conclusion,
        workflow_run_metadata=metadata,
        result_path=result_path,
        verification_path=verification_path,
        workflow_run_metadata_path=metadata_path,
    )


def _fixture_document_path(manifest_dir: Path, relative_path: str) -> Path:
    absolute_path = (manifest_dir / relative_path).resolve()
    if REPO_ROOT not in absolute_path.parents:
        raise B3PropagatorError("fixture path escapes repository: {}".format(relative_path))
    return absolute_path


def _check_fixture_hash(manifest_dir: Path, document_spec: Mapping[str, Any]) -> Path:
    absolute_path = _fixture_document_path(manifest_dir, document_spec["path"])
    if not absolute_path.is_file():
        raise B3PropagatorError("fixture file does not exist: {}".format(document_spec["path"]))
    if absolute_path.stat().st_size > MAX_INPUT_BYTES:
        raise B3PropagatorError(
            "fixture file exceeds maximum size of {} bytes: {}".format(MAX_INPUT_BYTES, document_spec["path"])
        )
    actual_hash = hashlib.sha256(absolute_path.read_bytes()).hexdigest()
    if actual_hash != document_spec["sha256"]:
        raise B3PropagatorError("fixture hash mismatch: {}".format(document_spec["path"]))
    return absolute_path


def run_fixture(fixture: Mapping[str, Any], manifest_dir: Path, workdir: Path) -> Dict[str, Any]:
    signal_path = _check_fixture_hash(manifest_dir, fixture["signal"])
    task_path = _check_fixture_hash(manifest_dir, fixture["task"])
    review_path = _check_fixture_hash(manifest_dir, fixture["review_attestation"])
    verifier_identity_path = _check_fixture_hash(manifest_dir, fixture["verifier_identity"])
    invocation = fixture["invocation"]

    output_dir = workdir / fixture["id"]
    outputs = run_pipeline(
        signal_path,
        task_path,
        review_path,
        verifier_identity_path,
        invocation["verification_id"],
        invocation["evaluated_at"],
        output_dir,
    )

    actual: Dict[str, Any] = {
        "status": outputs.result["status"],
        "terminal_reason": outputs.result["terminal_reason"],
        "check_run_conclusion": outputs.check_run_conclusion,
        "timeout_origin": outputs.classification.timeout_origin,
        "missing_artifact_type": outputs.classification.missing_artifact_type,
        "source_run_id": outputs.workflow_run_metadata["source_run_id"],
        "raw_provider_terminal_reason": outputs.workflow_run_metadata["raw_provider_terminal_reason"],
        "artifacts_count": outputs.workflow_run_metadata["artifacts_count"],
        "new_commit": outputs.workflow_run_metadata["new_commit"],
        "adapter_self_reported_status": outputs.workflow_run_metadata["adapter_self_reported_status"],
        "actions_job_conclusion": outputs.workflow_run_metadata["actions_job_conclusion"],
    }
    expected = fixture["expected"]
    expectation_met = all(actual[key] == value for key, value in expected.items())

    if expectation_met:
        result_errors = sorted(error.message for error in _RESULT_VALIDATOR.iter_errors(outputs.result))
        verification_errors = sorted(
            error.message for error in _VERIFICATION_VALIDATOR.iter_errors(outputs.verification)
        )
        if result_errors or verification_errors:
            expectation_met = False
        if outputs.workflow_run_metadata["workflow_run_id"] is None or outputs.workflow_run_metadata["execution_id"] is None:
            expectation_met = False

    return {
        "id": fixture["id"],
        "actual": actual,
        "expected": expected,
        "expectation_met": expectation_met,
    }


def run_suite(manifest_path: Path, workdir: Optional[Path] = None) -> Tuple[int, Dict[str, Any]]:
    manifest = load_json(manifest_path)
    manifest_dir = manifest_path.parent
    if workdir is None:
        workdir = Path(tempfile.mkdtemp(prefix="b3-propagator-suite-", dir="/private/tmp"))
    fixture_results = [run_fixture(fixture, manifest_dir, workdir) for fixture in manifest["fixtures"]]
    passed = sum(1 for item in fixture_results if item["expectation_met"])
    total = len(fixture_results)
    suite_valid = total > 0 and passed == total
    report = {
        "authoritative_verifier": False,
        "bootstrap_scope": "B3",
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
        description="Deterministic B3 terminal-reason propagator and Check Run conclusion source "
        "(non-authoritative bootstrap tool composing the existing B1 finalizer and B2 verifier)."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="run one trusted provider signal through the pipeline")
    run_parser.add_argument("--signal", type=Path, required=True)
    run_parser.add_argument("--task", type=Path, required=True)
    run_parser.add_argument("--review-attestation", type=Path, required=True)
    run_parser.add_argument("--verifier-identity", type=Path, required=True)
    run_parser.add_argument("--verification-id", required=True)
    run_parser.add_argument("--evaluated-at", required=True)
    run_parser.add_argument("--output-dir", type=Path, required=True)

    suite_parser = subparsers.add_parser("suite", help="run the immutable B3 fixture manifest")
    suite_parser.add_argument("--manifest", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if args.command == "suite":
        exit_code, report = run_suite(args.manifest.resolve())
        write_report(report)
        return exit_code

    try:
        outputs = run_pipeline(
            args.signal.resolve(),
            args.task.resolve(),
            args.review_attestation.resolve(),
            args.verifier_identity.resolve(),
            args.verification_id,
            args.evaluated_at,
            args.output_dir.resolve(),
        )
    except (B3PropagatorError, FinalizerPolicyError, OverwriteRefused, VerifierInputError) as exc:
        write_report(
            {
                "authoritative_verifier": False,
                "bootstrap_scope": "B3",
                "error": type(exc).__name__,
                "message": str(exc),
            }
        )
        return 2

    write_report(
        {
            "authoritative_verifier": False,
            "bootstrap_scope": "B3",
            "status": outputs.result["status"],
            "terminal_reason": outputs.result["terminal_reason"],
            "check_run_conclusion": outputs.check_run_conclusion,
            "result_path": str(outputs.result_path),
            "verification_path": str(outputs.verification_path),
            "workflow_run_metadata_path": str(outputs.workflow_run_metadata_path),
        }
    )
    return 0 if outputs.check_run_conclusion == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
