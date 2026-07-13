#!/usr/bin/env python3
"""Deterministic offline B2 verifier.

This tool is a bounded, deterministic offline verifier only. It is not a
GitHub Actions adapter, Check Run publisher, or automated merge/delegation
component. It consumes trusted invocation metadata (verification identity,
evaluated-at timestamp, expected task/execution/base/subject SHAs, and
verifier identity) supplied entirely by the caller -- it never generates
time, UUIDs, or identity itself -- together with a task.v1 document, a
finalized result.v1 document, a review-attestation.v1 document, a Git
observation, and evidence bytes rooted under one evidence directory. It
evaluates a fixed set of registered predicate IDs and emits exactly one
schema-valid verification.v1 report.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ModuleNotFoundError as exc:  # pragma: no cover - exercised by CLI setup
    raise SystemExit(
        "missing dependency: install requirements-b0.txt before running the B2 verifier"
    ) from exc


REPO_ROOT = Path(__file__).resolve().parents[1]
TASK_SCHEMA_PATH = REPO_ROOT / "contracts/schemas/task.v1.schema.json"
RESULT_SCHEMA_PATH = REPO_ROOT / "contracts/schemas/result.v1.schema.json"
REVIEW_SCHEMA_PATH = REPO_ROOT / "contracts/schemas/review-attestation.v1.schema.json"
VERIFICATION_SCHEMA_PATH = REPO_ROOT / "contracts/schemas/verification.v1.schema.json"
PREDICATE_REGISTRY_PATH = REPO_ROOT / "contracts/registries/predicates.v1.json"

MAX_INPUT_BYTES = 1024 * 1024

_SHA_PATTERN = r"^[0-9a-f]{40}$"
_PATH_PATTERN = r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$)).+$"

# Trusted, repository-local Git observation input contract. This is not part
# of contracts/schemas/** and carries no authoritative verifier status beyond
# this tool's own closed evaluation.
GIT_OBSERVATION_SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "base_sha", "head_sha", "authored_commits", "changed_files"],
    "properties": {
        "schema_version": {"const": "1.0.0"},
        "base_sha": {"type": "string", "pattern": _SHA_PATTERN},
        "head_sha": {"oneOf": [{"type": "string", "pattern": _SHA_PATTERN}, {"type": "null"}]},
        "authored_commits": {"type": "array", "items": {"type": "string", "pattern": _SHA_PATTERN}},
        "changed_files": {"type": "array", "items": {"type": "string", "pattern": _PATH_PATTERN}},
    },
}

_FORBIDDEN_LINEAGE_FIELDS = ("agent_runtime_id", "credential_principal", "authored_commits")

# The required, closed set of predicate IDs this verifier evaluates, in
# report order (AC-B2-5). Evaluating any predicate outside this set, or
# encountering a task/result reference to a predicate ID outside the
# repository predicate registry, fails closed.
REQUIRED_PREDICATE_IDS = (
    "schema.instance.valid",
    "binding.task_id.equals",
    "binding.execution_id.equals",
    "git.base_sha.equals",
    "git.head_sha.equals",
    "git.changed_paths.allowed",
    "git.diff.non_empty",
    "process.exit_code.equals",
    "acceptance.required.passed",
    "artifact.exists",
    "artifact.sha256.matches",
    "review.subject_sha.equals",
    "review.eligibility.passed",
    "identity.lineage.no_overlap",
)


class VerifierInputError(ValueError):
    """Raised for any input, policy, or publication failure. Always fail-closed."""


@dataclass(frozen=True)
class Invocation:
    verification_id: str
    evaluated_at: str
    expected_task_id: str
    expected_execution_id: str
    expected_base_sha: str
    expected_subject_sha: str
    verifier_identity: Mapping[str, Any]


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_bounded_json(path: Path, label: str) -> Any:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise VerifierInputError("{} is unreadable: {}".format(label, exc)) from exc
    if len(raw) > MAX_INPUT_BYTES:
        raise VerifierInputError(
            "{} exceeds maximum size of {} bytes".format(label, MAX_INPUT_BYTES)
        )
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerifierInputError("{} is not valid JSON: {}".format(label, exc)) from exc


_PREDICATE_REGISTRY = load_json(PREDICATE_REGISTRY_PATH)
_KNOWN_PREDICATE_IDS = {entry["id"] for entry in _PREDICATE_REGISTRY["entries"]}

_TASK_VALIDATOR = Draft202012Validator(load_json(TASK_SCHEMA_PATH), format_checker=FormatChecker())
_RESULT_VALIDATOR = Draft202012Validator(load_json(RESULT_SCHEMA_PATH), format_checker=FormatChecker())
_REVIEW_VALIDATOR = Draft202012Validator(load_json(REVIEW_SCHEMA_PATH), format_checker=FormatChecker())
_GIT_OBSERVATION_VALIDATOR = Draft202012Validator(
    GIT_OBSERVATION_SCHEMA, format_checker=FormatChecker()
)
_VERIFICATION_VALIDATOR = Draft202012Validator(
    load_json(VERIFICATION_SCHEMA_PATH), format_checker=FormatChecker()
)


def _schema_errors(validator: Draft202012Validator, document: Any) -> List[str]:
    return sorted(error.message for error in validator.iter_errors(document))


@dataclass
class PredicateResult:
    predicate_id: str
    passed: bool
    observed: Any
    evidence_artifact_ids: Tuple[str, ...]
    failure_code: Optional[str]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "predicate_id": self.predicate_id,
            "passed": self.passed,
            "observed": self.observed,
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
            "failure_code": self.failure_code,
        }


@dataclass
class EvidenceEntry:
    id: str
    type: str
    uri: str
    sha256: str

    def as_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "type": self.type, "uri": self.uri, "sha256": self.sha256}


def _open_evidence_bytes(evidence_root: Path, relative_path: str) -> bytes:
    """Read evidence bytes safely: relative, contained, regular files only.

    The evidence root directory is opened once as a trusted descriptor. The
    target is opened through that descriptor with O_NOFOLLOW (rejecting a
    symlinked final component), read through that single bounded descriptor,
    and its pathname binding is re-checked by device/inode afterwards to
    detect rebinding/mutation during the read. Any defect fails closed by
    raising; callers translate this into the appropriate failure code.
    """
    import re

    if not re.match(_PATH_PATTERN, relative_path) or relative_path.startswith("/"):
        raise VerifierInputError("evidence path is not a safe relative path: {}".format(relative_path))

    resolved_root = evidence_root.resolve()
    candidate = (resolved_root / relative_path).resolve()
    try:
        candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise VerifierInputError("evidence path escapes evidence root: {}".format(relative_path)) from exc

    no_follow = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(no_follow, int) or no_follow == 0:
        raise VerifierInputError("safe evidence reads are unavailable: O_NOFOLLOW is unsupported")

    try:
        root_fd = os.open(str(resolved_root), os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise VerifierInputError("evidence root cannot be opened: {}".format(exc)) from exc
    try:
        flags = os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            fd = os.open(relative_path, flags, dir_fd=root_fd)
        except FileNotFoundError as exc:
            raise FileNotFoundError(relative_path) from exc
        except OSError as exc:
            raise VerifierInputError("evidence path cannot be opened safely: {}".format(exc)) from exc
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise VerifierInputError(
                    "evidence descriptor is not a regular file: {}".format(relative_path)
                )
            chunks: List[bytes] = []
            remaining = MAX_INPUT_BYTES + 1
            while remaining > 0:
                chunk = os.read(fd, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > MAX_INPUT_BYTES:
                raise VerifierInputError(
                    "evidence exceeds maximum size of {} bytes: {}".format(
                        MAX_INPUT_BYTES, relative_path
                    )
                )
            after = os.fstat(fd)
            stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if any(getattr(before, name) != getattr(after, name) for name in stable):
                raise VerifierInputError(
                    "evidence mutated while being read: {}".format(relative_path)
                )
            try:
                bound = os.stat(relative_path, dir_fd=root_fd, follow_symlinks=False)
            except OSError as exc:
                raise VerifierInputError(
                    "evidence path binding is unverifiable: {}".format(relative_path)
                ) from exc
            if not stat.S_ISREG(bound.st_mode) or (bound.st_dev, bound.st_ino) != (
                after.st_dev,
                after.st_ino,
            ):
                raise VerifierInputError(
                    "evidence path was rebound during verification: {}".format(relative_path)
                )
            return data
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)


class B2Verifier:
    def __init__(
        self,
        invocation: Invocation,
        task: Mapping[str, Any],
        result: Mapping[str, Any],
        review: Mapping[str, Any],
        git_observation: Mapping[str, Any],
        evidence_root: Path,
    ) -> None:
        self.invocation = invocation
        self.task = task
        self.result = result
        self.review = review
        self.git_observation = git_observation
        self.evidence_root = evidence_root
        self._evidence: Dict[str, EvidenceEntry] = {}

    def _register_evidence(self, entry_id: str, entry_type: str, uri: str, data: bytes) -> str:
        self._evidence[entry_id] = EvidenceEntry(entry_id, entry_type, uri, sha256_bytes(data))
        return entry_id

    def evaluate(self) -> Tuple[bool, List[PredicateResult], List[EvidenceEntry]]:
        task_bytes = json.dumps(self.task, sort_keys=True).encode("utf-8")
        result_bytes = json.dumps(self.result, sort_keys=True).encode("utf-8")
        review_bytes = json.dumps(self.review, sort_keys=True).encode("utf-8")
        git_bytes = json.dumps(self.git_observation, sort_keys=True).encode("utf-8")
        self._register_evidence("task-input", "task-artifact", "input:task", task_bytes)
        self._register_evidence("result-input", "result-artifact", "input:result", result_bytes)
        self._register_evidence(
            "review-attestation-input", "review-attestation", "input:review-attestation", review_bytes
        )
        self._register_evidence(
            "git-observation-input", "git-observation", "input:git-observation", git_bytes
        )

        schema_errors: List[str] = []
        schema_errors.extend(
            "task:{}".format(message) for message in _schema_errors(_TASK_VALIDATOR, self.task)
        )
        schema_errors.extend(
            "result:{}".format(message) for message in _schema_errors(_RESULT_VALIDATOR, self.result)
        )
        schema_errors.extend(
            "review_attestation:{}".format(message)
            for message in _schema_errors(_REVIEW_VALIDATOR, self.review)
        )
        schema_errors.extend(
            "git_observation:{}".format(message)
            for message in _schema_errors(_GIT_OBSERVATION_VALIDATOR, self.git_observation)
        )

        if schema_errors:
            row = PredicateResult(
                predicate_id="schema.instance.valid",
                passed=False,
                observed={"errors": sorted(schema_errors)},
                evidence_artifact_ids=(
                    "task-input",
                    "result-input",
                    "review-attestation-input",
                    "git-observation-input",
                ),
                failure_code="schema_validation_failed",
            )
            return False, [row], sorted(self._evidence.values(), key=lambda item: item.id)

        rows: List[PredicateResult] = [
            PredicateResult(
                predicate_id="schema.instance.valid",
                passed=True,
                observed={"errors": []},
                evidence_artifact_ids=(
                    "task-input",
                    "result-input",
                    "review-attestation-input",
                    "git-observation-input",
                ),
                failure_code=None,
            )
        ]
        rows.append(self._binding_task_id())
        rows.append(self._binding_execution_id())
        rows.append(self._git_base_sha())
        rows.append(self._git_head_sha())
        rows.append(self._git_changed_paths_allowed())
        rows.append(self._git_diff_non_empty())
        rows.append(self._process_exit_code())
        rows.append(self._acceptance_required_passed())
        artifact_exists_row, artifact_bytes_by_id = self._artifact_exists()
        rows.append(artifact_exists_row)
        rows.append(self._artifact_sha256_matches(artifact_bytes_by_id))
        rows.append(self._review_subject_sha())
        rows.append(self._review_eligibility_passed())
        rows.append(self._identity_lineage_no_overlap())

        passed = all(row.passed for row in rows)
        return passed, rows, sorted(self._evidence.values(), key=lambda item: item.id)

    def _binding_task_id(self) -> PredicateResult:
        expected = self.invocation.expected_task_id
        observed = {
            "expected_task_id": expected,
            "task_task_id": self.task["task_id"],
            "result_task_id": self.result["task_id"],
        }
        ok = expected == self.task["task_id"] == self.result["task_id"]
        return PredicateResult(
            "binding.task_id.equals",
            ok,
            observed,
            ("task-input", "result-input"),
            None if ok else "task_id_mismatch",
        )

    def _binding_execution_id(self) -> PredicateResult:
        expected = self.invocation.expected_execution_id
        observed = {"expected_execution_id": expected, "result_execution_id": self.result["execution_id"]}
        ok = expected == self.result["execution_id"]
        return PredicateResult(
            "binding.execution_id.equals",
            ok,
            observed,
            ("result-input",),
            None if ok else "execution_id_mismatch",
        )

    def _git_base_sha(self) -> PredicateResult:
        expected = self.invocation.expected_base_sha
        observed = {
            "expected_base_sha": expected,
            "task_base_sha": self.task["base_sha"],
            "git_observation_base_sha": self.git_observation["base_sha"],
        }
        ok = expected == self.task["base_sha"] == self.git_observation["base_sha"]
        return PredicateResult(
            "git.base_sha.equals",
            ok,
            observed,
            ("task-input", "git-observation-input"),
            None if ok else "base_sha_mismatch",
        )

    def _git_head_sha(self) -> PredicateResult:
        expected = self.invocation.expected_subject_sha
        observed = {
            "expected_subject_sha": expected,
            "result_head_sha": self.result["head_sha"],
            "git_observation_head_sha": self.git_observation["head_sha"],
        }
        ok = expected == self.result["head_sha"] == self.git_observation["head_sha"]
        return PredicateResult(
            "git.head_sha.equals",
            ok,
            observed,
            ("result-input", "git-observation-input"),
            None if ok else "head_sha_mismatch",
        )

    def _git_changed_paths_allowed(self) -> PredicateResult:
        allowed_paths = self.task["allowed_paths"]
        denied_paths = self.task["denied_paths"]
        violations = []
        for changed_path in self.result["changed_files"]:
            allowed = any(fnmatch.fnmatchcase(changed_path, pattern) for pattern in allowed_paths)
            denied = any(fnmatch.fnmatchcase(changed_path, pattern) for pattern in denied_paths)
            if not allowed or denied:
                violations.append(changed_path)
        ok = not violations
        return PredicateResult(
            "git.changed_paths.allowed",
            ok,
            {"violations": violations},
            ("task-input", "result-input"),
            None if ok else "scope_violation",
        )

    def _git_diff_non_empty(self) -> PredicateResult:
        change_required = self.task["change_policy"]["change_required"]
        changed_files = self.git_observation["changed_files"]
        ok = (not change_required) or bool(changed_files)
        return PredicateResult(
            "git.diff.non_empty",
            ok,
            {"change_required": change_required, "changed_file_count": len(changed_files)},
            ("task-input", "git-observation-input"),
            None if ok else "empty_diff",
        )

    def _process_exit_code(self) -> PredicateResult:
        checks_by_id = {check["id"]: check for check in self.result["checks"]}
        failures = []
        for required_check in self.task["required_checks"]:
            if not required_check["required"]:
                continue
            actual = checks_by_id.get(required_check["id"])
            if actual is None or actual["command_id"] != required_check["command_id"] or actual["exit_code"] != 0:
                failures.append(required_check["id"])
        ok = not failures
        return PredicateResult(
            "process.exit_code.equals",
            ok,
            {"failed_checks": failures},
            ("task-input", "result-input"),
            None if ok else "check_failed",
        )

    def _acceptance_required_passed(self) -> PredicateResult:
        results_by_id = {item["id"]: item for item in self.result["acceptance_results"]}
        unknown_predicates: List[str] = []
        failed_criteria: List[str] = []
        missing_criteria: List[str] = []

        all_predicate_ids = {criterion["predicate_id"] for criterion in self.task["acceptance_criteria"]}
        for check in self.task["required_checks"]:
            for postcondition in check["expected_postconditions"]:
                all_predicate_ids.add(postcondition["predicate_id"])
        for predicate_id in sorted(all_predicate_ids):
            if predicate_id not in _KNOWN_PREDICATE_IDS:
                unknown_predicates.append(predicate_id)

        if unknown_predicates:
            return PredicateResult(
                "acceptance.required.passed",
                False,
                {"unknown_predicates": unknown_predicates},
                ("task-input",),
                "unknown_predicate",
            )

        for criterion in self.task["acceptance_criteria"]:
            if not criterion["required"]:
                continue
            actual = results_by_id.get(criterion["id"])
            if actual is None:
                missing_criteria.append(criterion["id"])
                continue
            if actual["predicate_id"] != criterion["predicate_id"] or not actual["passed"]:
                failed_criteria.append(criterion["id"])

        if missing_criteria:
            return PredicateResult(
                "acceptance.required.passed",
                False,
                {"missing_criteria": missing_criteria},
                ("task-input", "result-input"),
                "acceptance_failed",
            )
        ok = not failed_criteria
        return PredicateResult(
            "acceptance.required.passed",
            ok,
            {"failed_criteria": failed_criteria},
            ("task-input", "result-input"),
            None if ok else "acceptance_failed",
        )

    def _referenced_artifact_ids(self) -> List[str]:
        referenced: List[str] = []
        for item in self.result["acceptance_results"]:
            referenced.extend(item["evidence_artifact_ids"])
        for item in self.result["checks"]:
            referenced.extend(item["evidence_artifact_ids"])
        for item in self.result["no_change_evidence"]:
            referenced.append(item["artifact_id"])
        return referenced

    def _artifact_exists(self) -> Tuple[PredicateResult, Dict[str, bytes]]:
        declared = {item["id"]: item for item in self.result["artifacts"]}
        unresolved = sorted({rid for rid in self._referenced_artifact_ids() if rid not in declared})
        if unresolved:
            row = PredicateResult(
                "artifact.exists",
                False,
                {"unresolved_artifact_ids": unresolved},
                ("result-input",),
                "unresolved_artifact_reference",
            )
            return row, {}

        missing: List[str] = []
        artifact_bytes: Dict[str, bytes] = {}
        for artifact_id, artifact in declared.items():
            try:
                data = _open_evidence_bytes(self.evidence_root, artifact["path"])
            except FileNotFoundError:
                missing.append(artifact_id)
                continue
            except VerifierInputError:
                missing.append(artifact_id)
                continue
            artifact_bytes[artifact_id] = data
            self._register_evidence(
                "artifact-{}".format(artifact_id), "artifact-metadata", artifact["path"], data
            )
        ok = not missing
        row = PredicateResult(
            "artifact.exists",
            ok,
            {"missing_artifacts": sorted(missing)},
            ("result-input",),
            None if ok else "missing_artifact",
        )
        return row, artifact_bytes

    def _artifact_sha256_matches(self, artifact_bytes: Mapping[str, bytes]) -> PredicateResult:
        declared = {item["id"]: item for item in self.result["artifacts"]}
        mismatched: List[str] = []
        for artifact_id, data in artifact_bytes.items():
            expected_hash = declared[artifact_id]["sha256"]
            if sha256_bytes(data) != expected_hash:
                mismatched.append(artifact_id)
        ok = not mismatched
        evidence_ids = tuple("artifact-{}".format(aid) for aid in sorted(artifact_bytes))
        return PredicateResult(
            "artifact.sha256.matches",
            ok,
            {"mismatched_artifacts": sorted(mismatched)},
            evidence_ids,
            None if ok else "artifact_hash_mismatch",
        )

    def _review_subject_sha(self) -> PredicateResult:
        expected = self.result["head_sha"]
        observed = {"result_head_sha": expected, "reviewed_sha": self.review["reviewed_sha"]}
        ok = expected == self.review["reviewed_sha"]
        return PredicateResult(
            "review.subject_sha.equals",
            ok,
            observed,
            ("result-input", "review-attestation-input"),
            None if ok else "review_subject_mismatch",
        )

    def _review_eligibility_passed(self) -> PredicateResult:
        eligible = self.review["eligibility"]["eligible"]
        return PredicateResult(
            "review.eligibility.passed",
            eligible,
            {"eligible": eligible, "reason_codes": self.review["eligibility"]["reason_codes"]},
            ("review-attestation-input",),
            None if eligible else "review_ineligible",
        )

    def _identity_lineage_no_overlap(self) -> PredicateResult:
        overlaps = [
            item["field"]
            for item in self.review["eligibility"]["overlap_results"]
            if item["field"] in _FORBIDDEN_LINEAGE_FIELDS and item["overlap"]
        ]
        ok = not overlaps
        return PredicateResult(
            "identity.lineage.no_overlap",
            ok,
            {"overlapping_fields": sorted(overlaps)},
            ("review-attestation-input",),
            None if ok else "identity_conflict",
        )


def build_report(
    invocation: Invocation,
    passed: bool,
    predicate_results: Sequence[PredicateResult],
    evidence: Sequence[EvidenceEntry],
) -> Dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "verification_id": invocation.verification_id,
        "task_id": invocation.expected_task_id,
        "execution_id": invocation.expected_execution_id,
        "subject_sha": invocation.expected_subject_sha,
        "verifier_identity": dict(invocation.verifier_identity),
        "passed": passed,
        "predicate_results": [row.as_dict() for row in predicate_results],
        "evidence": [entry.as_dict() for entry in evidence],
        "evaluated_at": invocation.evaluated_at,
    }


def validate_report_schema(report: Mapping[str, Any]) -> None:
    errors = _schema_errors(_VERIFICATION_VALIDATOR, report)
    if errors:
        raise VerifierInputError(
            "verification report failed verification.v1 schema validation: {}".format("; ".join(errors))
        )


def canonical_bytes(document: Mapping[str, Any]) -> bytes:
    return (json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _write_staged_file(directory: Path, name_hint: str, data: bytes) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    try:
        fd, tmp_name = tempfile.mkstemp(prefix=".{}.".format(name_hint), suffix=".tmp", dir=str(directory))
    except OSError as exc:
        raise VerifierInputError("failed to stage verification report: {}".format(exc)) from exc
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
        raise VerifierInputError("failed to stage verification report: {}".format(failure)) from failure
    return tmp_path


def publish_report(output_path: Path, data: bytes) -> None:
    """Publish `data` to `output_path` exclusively: never overwrite, never partial.

    The report only becomes visible once fully written and fsynced to a
    staging file and that staging file is atomically hard-linked into place.
    No failure before that link step can leave a visible final path.
    """
    tmp_path = _write_staged_file(output_path.parent, output_path.name, data)
    try:
        os.link(tmp_path, output_path)
    except FileExistsError as exc:
        raise VerifierInputError(
            "verification output already exists and will not be overwritten: {}".format(output_path)
        ) from exc
    except OSError as exc:
        raise VerifierInputError("failed to publish verification report: {}".format(exc)) from exc
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass


def run_verification(
    invocation: Invocation,
    task_path: Path,
    result_path: Path,
    review_path: Path,
    git_observation_path: Path,
    evidence_root: Path,
) -> Tuple[int, Dict[str, Any]]:
    try:
        task = _load_bounded_json(task_path, "task document")
        result = _load_bounded_json(result_path, "result document")
        review = _load_bounded_json(review_path, "review-attestation document")
        git_observation = _load_bounded_json(git_observation_path, "git observation document")
    except VerifierInputError:
        row = PredicateResult(
            "schema.instance.valid",
            False,
            {"errors": ["input document could not be loaded"]},
            (),
            "schema_validation_failed",
        )
        report = build_report(invocation, False, [row], [])
        validate_report_schema(report)
        return 1, report

    verifier = B2Verifier(invocation, task, result, review, git_observation, evidence_root)
    passed, predicate_results, evidence = verifier.evaluate()
    report = build_report(invocation, passed, predicate_results, evidence)
    validate_report_schema(report)
    return (0 if passed else 1), report


def _fixture_document_path(manifest_dir: Path, relative_path: str) -> Path:
    absolute_path = (manifest_dir / relative_path).resolve()
    if REPO_ROOT not in absolute_path.parents:
        raise VerifierInputError("fixture path escapes repository: {}".format(relative_path))
    return absolute_path


def _check_fixture_hash(manifest_dir: Path, document_spec: Mapping[str, Any]) -> Path:
    absolute_path = _fixture_document_path(manifest_dir, document_spec["path"])
    if not absolute_path.is_file():
        raise VerifierInputError("fixture file does not exist: {}".format(document_spec["path"]))
    if absolute_path.stat().st_size > MAX_INPUT_BYTES:
        raise VerifierInputError(
            "fixture file exceeds maximum size of {} bytes: {}".format(MAX_INPUT_BYTES, document_spec["path"])
        )
    actual_hash = hashlib.sha256(absolute_path.read_bytes()).hexdigest()
    if actual_hash != document_spec["sha256"]:
        raise VerifierInputError("fixture hash mismatch: {}".format(document_spec["path"]))
    return absolute_path


def _invocation_from_spec(manifest_dir: Path, spec: Mapping[str, Any]) -> Invocation:
    identity_path = _check_fixture_hash(manifest_dir, spec["verifier_identity"])
    return Invocation(
        verification_id=spec["verification_id"],
        evaluated_at=spec["evaluated_at"],
        expected_task_id=spec["expected_task_id"],
        expected_execution_id=spec["expected_execution_id"],
        expected_base_sha=spec["expected_base_sha"],
        expected_subject_sha=spec["expected_subject_sha"],
        verifier_identity=load_json(identity_path),
    )


def run_fixture(fixture: Mapping[str, Any], manifest_dir: Path, workdir: Path) -> Dict[str, Any]:
    task_path = _check_fixture_hash(manifest_dir, fixture["task"])
    result_path = _check_fixture_hash(manifest_dir, fixture["result"])
    review_path = _check_fixture_hash(manifest_dir, fixture["review_attestation"])
    git_observation_path = _check_fixture_hash(manifest_dir, fixture["git_observation"])
    evidence_root = _fixture_document_path(manifest_dir, fixture["evidence_root"])
    invocation = _invocation_from_spec(manifest_dir, fixture["invocation"])

    repeat = fixture.get("repeat", 1)
    output_dir = workdir / fixture["id"]
    exit_codes: List[int] = []
    passed_values: List[bool] = []
    failure_code_sets: List[List[str]] = []
    reports: List[Dict[str, Any]] = []
    for attempt in range(repeat):
        exit_code, report = run_verification(
            invocation, task_path, result_path, review_path, git_observation_path, evidence_root
        )
        exit_codes.append(exit_code)
        passed_values.append(report["passed"])
        failure_code_sets.append(
            sorted(
                {
                    row["failure_code"]
                    for row in report["predicate_results"]
                    if row["failure_code"] is not None
                }
            )
        )
        reports.append(report)
        output_path = output_dir / "verification-{}.json".format(attempt)
        publish_report(output_path, canonical_bytes(report))

    expected = fixture["expected"]
    expectation_met = (
        all(code == expected["exit_code"] for code in exit_codes)
        and all(value == expected["passed"] for value in passed_values)
        and all(codes == sorted(expected["failure_codes"]) for codes in failure_code_sets)
    )
    if expectation_met and expected.get("byte_identical"):
        canonical = [canonical_bytes(report) for report in reports]
        expectation_met = len(set(canonical)) == 1

    return {
        "id": fixture["id"],
        "actual": {
            "exit_codes": exit_codes,
            "passed_values": passed_values,
            "failure_code_sets": failure_code_sets,
        },
        "expected": expected,
        "expectation_met": expectation_met,
    }


def run_suite(manifest_path: Path, workdir: Optional[Path] = None) -> Tuple[int, Dict[str, Any]]:
    manifest = load_json(manifest_path)
    manifest_dir = manifest_path.parent
    if workdir is None:
        workdir = Path(tempfile.mkdtemp(prefix="b2-verifier-suite-", dir="/private/tmp"))
    fixture_results = [run_fixture(fixture, manifest_dir, workdir) for fixture in manifest["fixtures"]]
    passed = sum(1 for item in fixture_results if item["expectation_met"])
    total = len(fixture_results)
    suite_valid = total > 0 and passed == total
    report = {
        "authoritative_verifier": False,
        "bootstrap_scope": "B2",
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
        description="Deterministic offline B2 verifier (non-authoritative bootstrap tool)."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify_parser = subparsers.add_parser("verify", help="verify one trusted invocation")
    verify_parser.add_argument("--verification-id", required=True)
    verify_parser.add_argument("--evaluated-at", required=True)
    verify_parser.add_argument("--expected-task-id", required=True)
    verify_parser.add_argument("--expected-execution-id", required=True)
    verify_parser.add_argument("--expected-base-sha", required=True)
    verify_parser.add_argument("--expected-subject-sha", required=True)
    verify_parser.add_argument("--verifier-identity", type=Path, required=True)
    verify_parser.add_argument("--task", type=Path, required=True)
    verify_parser.add_argument("--result", type=Path, required=True)
    verify_parser.add_argument("--review-attestation", type=Path, required=True)
    verify_parser.add_argument("--git-observation", type=Path, required=True)
    verify_parser.add_argument("--evidence-root", type=Path, required=True)
    verify_parser.add_argument("--output", type=Path, required=True)

    suite_parser = subparsers.add_parser("suite", help="run the immutable B2 fixture manifest")
    suite_parser.add_argument("--manifest", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if args.command == "suite":
        exit_code, report = run_suite(args.manifest.resolve())
        write_report(report)
        return exit_code

    invocation = Invocation(
        verification_id=args.verification_id,
        evaluated_at=args.evaluated_at,
        expected_task_id=args.expected_task_id,
        expected_execution_id=args.expected_execution_id,
        expected_base_sha=args.expected_base_sha,
        expected_subject_sha=args.expected_subject_sha,
        verifier_identity=load_json(args.verifier_identity.resolve()),
    )
    exit_code, report = run_verification(
        invocation,
        args.task.resolve(),
        args.result.resolve(),
        args.review_attestation.resolve(),
        args.git_observation.resolve(),
        args.evidence_root.resolve(),
    )
    try:
        publish_report(args.output.resolve(), canonical_bytes(report))
    except VerifierInputError as exc:
        write_report({"authoritative_verifier": False, "bootstrap_scope": "B2", "error": "publish_failed", "message": str(exc)})
        return 1
    write_report(report)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
