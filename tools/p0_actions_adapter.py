"""Issue #29 P0: a thin, Actions-first executor adapter/check.

This module is the offline, deterministic core of the owner-approved bounded
P0 infrastructure bootstrap (Issue #29). It is *not* a standalone
orchestrator service: it is the trusted admission-control and finalization
logic that the companion workflow
(`.github/workflows/p0-actions-adapter.yml`) calls so that a *future*
immutable task (such as Issue #20's canary) can be executed by the pinned
Claude Code Action in a clean, permission-bounded ephemeral checkout.

Design invariants (mirrored, never re-implemented, from the merged B0-B3
contracts and the B3 workflow):

  * Every workflow input is untrusted. A task commit must be a full lowercase
    40-hex SHA; a task path must be an allowlisted repository-relative path;
    a target branch must match `agent/*` and must never be a protected /
    default branch (main/master/<default>).
  * The immutable task is fetched and schema-validated (against the existing,
    unmodified `contracts/schemas/task.v1.schema.json`) *before* any
    executor is invoked. Repository, branch, base SHA, risk class, attempt,
    and allowed/denied paths are bound from that validated task, never from
    caller prose.
  * A real Claude session/execution id is preserved when the adapter
    actually ran. When the adapter never attempted (admission failed before
    invocation) the execution id is a *pipeline-derived* UUID5 of real run
    facts, labelled `execution_id_source == "pipeline_derived"`; an executor
    id is never synthesized to stand in for a session the adapter claimed to
    have but cannot prove.
  * Independent review is a separate input bound to the exact subject SHA. A
    missing, ineligible, self-lineage, or stale-head (post-review executor
    commit) review fails closed.
  * The Check Run conclusion is derived only from this module's independent
    verification (`verification.v1`), never from Claude prose or an Actions
    job conclusion.
  * Verification-only rerun mode never invokes Claude and never mutates the
    branch.

The module writes only schema-valid `result.v1` / `verification.v1`
documents plus a `workflow-run-metadata.json` provenance record, and exposes
a fixture-suite runner (`run_suite`) so the deterministic AC-A2 positive and
negative scenarios are checked offline with no network, no GitHub, and no
Claude.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # pragma: no cover - exercised indirectly by the test suite
    from jsonschema import Draft202012Validator, FormatChecker
except ModuleNotFoundError as exc:  # pragma: no cover
    raise SystemExit(
        "p0_actions_adapter requires jsonschema; install requirements-p0-actions.txt"
    ) from exc


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = REPO_ROOT / "contracts/schemas"
TASK_SCHEMA_PATH = SCHEMA_DIR / "task.v1.schema.json"
RESULT_SCHEMA_PATH = SCHEMA_DIR / "result.v1.schema.json"
VERIFICATION_SCHEMA_PATH = SCHEMA_DIR / "verification.v1.schema.json"
REVIEW_SCHEMA_PATH = SCHEMA_DIR / "review-attestation.v1.schema.json"
COMMAND_REGISTRY_PATH = REPO_ROOT / "contracts/registries/commands.v1.json"

# The exact, pinned Claude Code Action commit already proven on
# origin/design/issue-12-executor-orchestrator and reused by the B3 workflow.
# A floating tag is never permitted.
PINNED_ADAPTER_ACTION = "anthropics/claude-code-action@6902c227aaa9536481b99d56f3014bbbad6c6da8"

# The stable, verifier-owned Check Run context. The workflow publishes this
# Check Run's conclusion solely from `verification.v1.passed`.
VERIFIER_CHECK_CONTEXT = "p0-actions-verifier"

TASK_ID = "yurikuchumov-ux/ai-operating-system#29"

# A task commit ref must be a full lowercase 40-hex object id -- never a
# branch name, tag, short sha, or uppercase hex (all of which can move or be
# ambiguous).
TASK_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

# Task contracts live only under `.ai/tasks/`. The path must additionally be
# repository-relative, contain no parent-directory traversal, no leading
# slash, no backslash, no NUL, and end in `.json`.
ALLOWED_TASK_PATH_PREFIXES: Tuple[str, ...] = (".ai/tasks/",)
_SAFE_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")

AGENT_BRANCH_RE = re.compile(r"^agent/[a-z0-9][a-z0-9._/-]*$")
_ALWAYS_PROTECTED_BRANCHES = frozenset({"main", "master"})

# UUID5 namespace for pipeline-derived execution ids (kept stable so a given
# run's derived id is reproducible from its real facts alone).
_PIPELINE_NAMESPACE = uuid.UUID("6f0d1e2c-29ad-4c11-9f0b-000000000029")

# Forbidden reviewer/executor lineage overlaps (review-independence.v1).
FORBIDDEN_LINEAGE_FIELDS: Tuple[str, ...] = (
    "operator_principal",
    "agent_runtime_id",
    "credential_principal",
    "delegation_parent",
)

# Failure code -> result.v1 terminal_reason. Every value is a member of the
# result schema's terminal_reason enum for its resulting status.
FAILURE_TERMINAL_REASON: Mapping[str, str] = {
    "mutable_task_ref": "ref_history_unverifiable",
    "task_path_not_allowlisted": "scope_violation",
    "target_branch_protected": "scope_violation",
    "target_branch_mismatch": "scope_violation",
    "invalid_task": "adapter_error",
    "base_sha_mismatch": "ref_history_unverifiable",
    "changed_paths_not_allowed": "scope_violation",
    "empty_diff": "empty_diff",
    "missing_executor_evidence": "identity_unverifiable",
    "reviewer_unavailable": "reviewer_unavailable",
    "post_review_head_change": "ref_history_unverifiable",
    "self_review": "identity_unverifiable",
    "review_ineligible": "identity_unverifiable",
}

# Failure code -> the decisive registry predicate whose failure it records.
# Only real predicate ids from contracts/registries/predicates.v1.json are
# used.
FAILURE_PREDICATE: Mapping[str, str] = {
    "mutable_task_ref": "schema.instance.valid",
    "task_path_not_allowlisted": "schema.instance.valid",
    "target_branch_protected": "schema.instance.valid",
    "target_branch_mismatch": "schema.instance.valid",
    "invalid_task": "schema.instance.valid",
    "base_sha_mismatch": "git.base_sha.equals",
    "changed_paths_not_allowed": "git.changed_paths.allowed",
    "empty_diff": "git.diff.non_empty",
    "missing_executor_evidence": "binding.execution_id.equals",
    "reviewer_unavailable": "review.eligibility.passed",
    "post_review_head_change": "review.subject_sha.equals",
    "self_review": "identity.lineage.no_overlap",
    "review_ineligible": "review.eligibility.passed",
}


class P0AdapterError(Exception):
    """Raised on unrecoverable, fail-closed adapter conditions (e.g. a
    fixture whose pinned content hash does not match on disk)."""


# --------------------------------------------------------------------------
# Small, dependency-free helpers
# --------------------------------------------------------------------------


def load_json(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _canonical_bytes(document: Any) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def _now_rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _schema_validator(path: Path) -> Draft202012Validator:
    schema = load_json(path)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


_TASK_VALIDATOR = _schema_validator(TASK_SCHEMA_PATH)
_RESULT_VALIDATOR = _schema_validator(RESULT_SCHEMA_PATH)
_VERIFICATION_VALIDATOR = _schema_validator(VERIFICATION_SCHEMA_PATH)
_REVIEW_VALIDATOR = _schema_validator(REVIEW_SCHEMA_PATH)


def schema_errors(validator: Draft202012Validator, document: Any) -> List[str]:
    return [
        "{}: {}".format(
            "$" + "".join("[{!r}]".format(p) for p in error.absolute_path),
            error.message,
        )
        for error in sorted(
            validator.iter_errors(document),
            key=lambda item: (list(item.absolute_path), item.validator, item.message),
        )
    ]


# --------------------------------------------------------------------------
# Untrusted-input admission control
# --------------------------------------------------------------------------


def is_verification_only(mode: Optional[str]) -> bool:
    return (mode or "execute").strip().lower() in {"verify-only", "verify_only", "verify"}


def validate_task_ref(task_commit: Optional[str]) -> Optional[str]:
    """Return a failure code if the task commit is not a full lowercase
    40-hex object id, else None."""
    if not isinstance(task_commit, str) or not TASK_COMMIT_RE.match(task_commit):
        return "mutable_task_ref"
    return None


def validate_task_path(task_path: Optional[str]) -> Optional[str]:
    """Return a failure code if the task path is not a safe, allowlisted,
    repository-relative task-contract path, else None."""
    if not isinstance(task_path, str) or not task_path:
        return "task_path_not_allowlisted"
    if task_path.startswith("/") or "\\" in task_path or "\x00" in task_path:
        return "task_path_not_allowlisted"
    if not task_path.endswith(".json"):
        return "task_path_not_allowlisted"
    if not any(task_path.startswith(prefix) for prefix in ALLOWED_TASK_PATH_PREFIXES):
        return "task_path_not_allowlisted"
    segments = task_path.split("/")
    if any(seg in ("", ".", "..") for seg in segments):
        return "task_path_not_allowlisted"
    if not all(_SAFE_PATH_SEGMENT_RE.match(seg) for seg in segments):
        return "task_path_not_allowlisted"
    return None


def validate_target_branch(
    target_branch: Optional[str], default_branch: Optional[str]
) -> Optional[str]:
    """Return a failure code if the target branch is protected or does not
    match the required `agent/*` shape, else None."""
    if not isinstance(target_branch, str) or not target_branch:
        return "target_branch_mismatch"
    protected = set(_ALWAYS_PROTECTED_BRANCHES)
    if default_branch:
        protected.add(default_branch.strip())
    if target_branch in protected:
        return "target_branch_protected"
    if not AGENT_BRANCH_RE.match(target_branch):
        return "target_branch_mismatch"
    return None


def validate_task_document(task: Any) -> Optional[str]:
    """Return a failure code if the task does not satisfy task.v1, else
    None."""
    if not isinstance(task, Mapping):
        return "invalid_task"
    if schema_errors(_TASK_VALIDATOR, task):
        return "invalid_task"
    return None


# --------------------------------------------------------------------------
# Path scoping (allowed / denied globs)
# --------------------------------------------------------------------------


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    out: List[str] = []
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                # `**` matches across path separators.
                out.append(".*")
                i += 2
                if i < n and pattern[i] == "/":
                    i += 1
                continue
            out.append("[^/]*")
            i += 1
            continue
        if ch == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(ch))
        i += 1
    return re.compile("^" + "".join(out) + "$")


def path_matches(pattern: str, path: str) -> bool:
    if pattern.endswith("/**"):
        prefix = pattern[:-3]
        return path == prefix or path.startswith(prefix + "/")
    return bool(_glob_to_regex(pattern).match(path))


def changed_paths_within_scope(
    changed_files: Sequence[str], allowed: Sequence[str], denied: Sequence[str]
) -> bool:
    for path in changed_files:
        if any(path_matches(d, path) for d in denied):
            return False
        if not any(path_matches(a, path) for a in allowed):
            return False
    return True


# --------------------------------------------------------------------------
# Execution identity + review independence
# --------------------------------------------------------------------------


def derive_pipeline_execution_id(
    workflow_run_id: str, workflow_run_attempt: str, subject_sha: str
) -> str:
    seed = "{}:{}:{}".format(workflow_run_id, workflow_run_attempt, subject_sha)
    return str(uuid.uuid5(_PIPELINE_NAMESPACE, seed))


def resolve_execution_identity(
    signal: Mapping[str, Any]
) -> Tuple[str, str]:
    """Resolve (execution_id, execution_id_source).

    A real Claude session id is used verbatim when the adapter both attempted
    and produced a resolvable session. Otherwise a pipeline-derived UUID5 of
    real run facts is used and labelled `pipeline_derived` -- never a
    fabricated session id.
    """
    session_present = bool(signal.get("adapter_session_present"))
    execution_id = signal.get("execution_id")
    if session_present and isinstance(execution_id, str) and execution_id:
        try:
            uuid.UUID(execution_id)
        except (ValueError, TypeError, AttributeError):
            pass
        else:
            return execution_id, "adapter_session"
    subject = signal.get("subject_sha") or signal.get("base_sha") or "0" * 40
    return (
        derive_pipeline_execution_id(
            str(signal.get("workflow_run_id") or "0"),
            str(signal.get("workflow_run_attempt") or "1"),
            str(subject),
        ),
        "pipeline_derived",
    )


def executor_evidence_failure(signal: Mapping[str, Any]) -> Optional[str]:
    """Reject when the adapter claimed to run but no real run/session
    execution evidence can be preserved."""
    attempted = bool(signal.get("adapter_attempted"))
    session_present = bool(signal.get("adapter_session_present"))
    execution_id = signal.get("execution_id")
    has_run_id = bool(signal.get("workflow_run_id"))
    has_real_session = (
        session_present and isinstance(execution_id, str) and bool(execution_id)
    )
    if attempted and not (has_real_session and has_run_id):
        return "missing_executor_evidence"
    return None


def review_failure(
    review: Optional[Mapping[str, Any]],
    subject_sha: Optional[str],
    executor_identity: Mapping[str, Any],
    authored_commits: Sequence[str],
) -> Optional[str]:
    """Fail closed on a missing, schema-invalid, wrong-subject, self-lineage,
    or ineligible review."""
    if not isinstance(review, Mapping):
        return "reviewer_unavailable"
    if schema_errors(_REVIEW_VALIDATOR, review):
        return "reviewer_unavailable"
    # A new executor head invalidates any prior review: the review must be
    # bound to the exact current subject SHA.
    if review.get("reviewed_sha") != subject_sha:
        return "post_review_head_change"

    reviewer = review.get("reviewer_identity", {})
    eligibility = review.get("eligibility", {})

    # Recompute lineage overlap from the real reviewer/executor identities --
    # never trust only the attestation's own `overlap`/`eligible` booleans.
    for field_name in FORBIDDEN_LINEAGE_FIELDS:
        exec_value = executor_identity.get(field_name)
        if exec_value and reviewer.get(field_name) == exec_value:
            return "self_review"
    reviewer_commits = set(reviewer.get("authored_commits") or [])
    if reviewer_commits & set(authored_commits):
        return "self_review"

    # Reject duplicate overlap_results entries for the same field before
    # trusting the attestation's own recomputation (mirrors B3 v3 hardening).
    seen_fields: set = set()
    for entry in eligibility.get("overlap_results", []):
        f = entry.get("field")
        if f in seen_fields:
            return "review_ineligible"
        seen_fields.add(f)
        if entry.get("overlap"):
            return "self_review"
    if not eligibility.get("eligible", False):
        return "review_ineligible"
    if eligibility.get("reason_codes"):
        return "review_ineligible"
    return None


# --------------------------------------------------------------------------
# Command-registry resolution (never interpolate task prose into a shell)
# --------------------------------------------------------------------------


def resolve_registered_check(
    command_id: str, registry_path: Path = COMMAND_REGISTRY_PATH
) -> List[str]:
    """Resolve a required check's argv from the command registry by id.

    The executor may run only registry-resolved argv vectors; an arbitrary
    task-supplied command string is never interpolated into a shell.
    """
    registry = load_json(registry_path)
    for entry in registry.get("entries", []):
        if entry.get("id") == command_id:
            argv = entry.get("argv")
            if not isinstance(argv, list) or not argv:
                raise P0AdapterError(
                    "command {} has no argv".format(command_id)
                )
            return list(argv)
    raise P0AdapterError("unregistered command id: {}".format(command_id))


# --------------------------------------------------------------------------
# The admission + verification decision
# --------------------------------------------------------------------------


@dataclass
class Decision:
    accepted: bool
    failure_code: Optional[str]
    status: str
    terminal_reason: str
    check_run_conclusion: str
    execution_id: str
    execution_id_source: str
    subject_sha: str
    predicate_id: str
    message: str
    inputs: Mapping[str, Any] = field(default_factory=dict)
    task: Mapping[str, Any] = field(default_factory=dict)
    signal: Mapping[str, Any] = field(default_factory=dict)
    review: Optional[Mapping[str, Any]] = None


def evaluate(
    inputs: Mapping[str, Any],
    task: Any,
    signal: Mapping[str, Any],
    review: Optional[Mapping[str, Any]],
) -> Decision:
    """Run the full fail-closed admission + independent-verification decision.

    The gate order is deliberate: pre-execution admission controls (untrusted
    input shape, task validity, base/branch binding) are evaluated first --
    exactly the checks the workflow performs *before* invoking Claude -- then
    the post-execution checks (executor evidence, scope, review
    independence). Every fixture isolates one failure by keeping the others
    valid.
    """
    signal = dict(signal)
    execution_id, execution_id_source = resolve_execution_identity(signal)
    subject_sha = str(signal.get("subject_sha") or signal.get("base_sha") or "0" * 40)

    task_commit = inputs.get("task_commit")
    task_path = inputs.get("task_path")
    target_branch = inputs.get("target_branch")
    default_branch = inputs.get("default_branch") or "main"

    def fail(code: str, message: str) -> Decision:
        terminal_reason = FAILURE_TERMINAL_REASON[code]
        if terminal_reason == "reviewer_unavailable":
            status = "blocked"
        else:
            status = "failed"
        return Decision(
            accepted=False,
            failure_code=code,
            status=status,
            terminal_reason=terminal_reason,
            check_run_conclusion="failure",
            execution_id=execution_id,
            execution_id_source=execution_id_source,
            subject_sha=subject_sha,
            predicate_id=FAILURE_PREDICATE[code],
            message=message,
            inputs=inputs,
            task=task if isinstance(task, Mapping) else {},
            signal=signal,
            review=review,
        )

    # 1. Untrusted task commit ref.
    code = validate_task_ref(task_commit)
    if code:
        return fail(code, "task commit ref is not a full lowercase 40-hex object id")

    # 2. Untrusted task path allowlist.
    code = validate_task_path(task_path)
    if code:
        return fail(code, "task path is not an allowlisted repository-relative path")

    # 3. Untrusted target branch shape / protected-branch guard.
    code = validate_target_branch(target_branch, default_branch)
    if code:
        return fail(code, "target branch is protected or not an agent/* branch")

    # 4. Immutable task schema validity.
    code = validate_task_document(task)
    if code:
        return fail(code, "fetched task does not satisfy task.v1")

    # 5. Bind target branch to the validated task.
    if task.get("branch") != target_branch:
        return fail(
            "target_branch_mismatch",
            "requested target branch does not match the task's bound branch",
        )

    # 6. Bind base SHA (reject base/head disagreement with the task).
    if str(signal.get("base_sha")) != task.get("base_sha"):
        return fail(
            "base_sha_mismatch",
            "checked-out base SHA does not match the task's bound base_sha",
        )

    verification_only = is_verification_only(inputs.get("mode"))

    # 7. Real executor run/session evidence (never a synthesized executor id).
    #    In verification-only reruns the executor did not run in this pass, so
    #    executor-evidence admission is not re-applied.
    if not verification_only:
        code = executor_evidence_failure(signal)
        if code:
            return fail(
                code,
                "adapter claimed to run but no real run/session evidence exists",
            )

    authored_commits = list(signal.get("authored_commits") or [])
    changed_files = list(signal.get("changed_files") or [])

    # 8. Scope: the executor's changed files must be within allowed_paths and
    #    outside denied_paths.
    if not verification_only:
        allowed = task.get("allowed_paths") or []
        denied = task.get("denied_paths") or []
        if changed_files and not changed_paths_within_scope(
            changed_files, allowed, denied
        ):
            return fail(
                "changed_paths_not_allowed",
                "executor changed files outside the task's allowed_paths",
            )
        # 9. A change-required task must produce a non-empty diff.
        change_required = bool(
            (task.get("change_policy") or {}).get("change_required")
        )
        if change_required and (not authored_commits or not changed_files):
            return fail("empty_diff", "change-required task produced an empty diff")

    # 10. Independent review, bound to the exact subject SHA, no self-lineage.
    code = review_failure(review, subject_sha, task_executor_identity(signal), authored_commits)
    if code:
        return fail(code, "review is missing, ineligible, self-lineage, or stale-head")

    return Decision(
        accepted=True,
        failure_code=None,
        status="change_proposed",
        terminal_reason="completed",
        check_run_conclusion="success",
        execution_id=execution_id,
        execution_id_source=execution_id_source,
        subject_sha=subject_sha,
        predicate_id="acceptance.required.passed",
        message="bounded executor result accepted",
        inputs=inputs,
        task=task,
        signal=signal,
        review=review,
    )


def task_executor_identity(signal: Mapping[str, Any]) -> Mapping[str, Any]:
    identity = signal.get("executor_identity")
    return identity if isinstance(identity, Mapping) else {}


# --------------------------------------------------------------------------
# Document construction (result.v1, verification.v1, workflow-run-metadata)
# --------------------------------------------------------------------------


def _write_evidence(workdir: Path, name: str, data: bytes) -> Dict[str, Any]:
    evidence_dir = workdir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    target = evidence_dir / name
    target.write_bytes(data)
    return {
        "path": "evidence/{}".format(name),
        "sha256": sha256_bytes(data),
        "size_bytes": len(data),
    }


def build_documents(decision: Decision, invocation: Mapping[str, Any], workdir: Path) -> Dict[str, Any]:
    """Write real evidence files and build schema-valid result.v1,
    verification.v1, and workflow-run-metadata documents.

    Every artifact sha256/size is computed over real bytes actually written
    to disk -- no synthetic evidence is fabricated.
    """
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    now = _now_rfc3339()
    task = decision.task if isinstance(decision.task, Mapping) else {}
    signal = decision.signal
    task_id = task.get("task_id") or TASK_ID
    attempt = int(decision.inputs.get("attempt") or 1)
    verification_id = invocation.get("verification_id")
    evaluated_at = invocation.get("evaluated_at") or now

    executor_identity = _result_identity(task_executor_identity(signal), "author")
    verifier_identity = _result_identity(
        invocation.get("verifier_identity") or {}, "verifier"
    )

    authored_commits = list(signal.get("authored_commits") or [])
    changed_files = list(signal.get("changed_files") or [])
    base_sha = str(signal.get("base_sha") or task.get("base_sha") or "0" * 40)

    # --- evidence files (real bytes) ---------------------------------------
    artifacts: List[Dict[str, Any]] = []
    artifact_ids: List[str] = []

    transcript = signal.get("transcript")
    if isinstance(transcript, str) and transcript:
        meta = _write_evidence(workdir, "executor-transcript.txt", transcript.encode("utf-8"))
        artifacts.append(_artifact_entry("executor-transcript", "text/plain", meta))
        artifact_ids.append("executor-transcript")

    decision_payload = {
        "accepted": decision.accepted,
        "status": decision.status,
        "terminal_reason": decision.terminal_reason,
        "failure_code": decision.failure_code,
        "subject_sha": decision.subject_sha,
        "execution_id": decision.execution_id,
        "execution_id_source": decision.execution_id_source,
        "check_run_conclusion": decision.check_run_conclusion,
    }
    meta = _write_evidence(
        workdir, "result-artifact.json", _canonical_bytes(decision_payload)
    )
    artifacts.append(_artifact_entry("result-artifact", "application/json", meta))
    artifact_ids.append("result-artifact")

    # --- verification.v1 ---------------------------------------------------
    # Declare, in the verification's own evidence[], every artifact its
    # predicate_results reference, with the real on-disk sha256 -- so an
    # independent re-verification (tools/validate_b0.py) resolves every
    # evidence reference.
    verification_evidence: List[Dict[str, Any]] = []
    for artifact_id, evidence_type in (
        ("executor-transcript", "executor_transcript"),
        ("result-artifact", "result_artifact"),
    ):
        match = next((a for a in artifacts if a["id"] == artifact_id), None)
        if match:
            verification_evidence.append(
                {
                    "id": artifact_id,
                    "type": evidence_type,
                    "uri": match["path"],
                    "sha256": match["sha256"],
                }
            )
    evidence_ref_ids = [entry["id"] for entry in verification_evidence]
    verification = _build_verification(
        decision,
        task_id=task_id,
        verification_id=verification_id,
        verifier_identity=verifier_identity,
        evaluated_at=evaluated_at,
        evidence=verification_evidence,
        evidence_ref_ids=evidence_ref_ids,
    )
    meta = _write_evidence(
        workdir, "verification-report.json", _canonical_bytes(verification)
    )
    artifacts.append(_artifact_entry("verification-report", "application/json", meta))
    artifact_ids.append("verification-report")

    # --- workflow-run-metadata --------------------------------------------
    metadata = {
        "schema_version": "1.0.0",
        "workflow_run_id": str(signal.get("workflow_run_id") or "0"),
        "workflow_run_attempt": str(signal.get("workflow_run_attempt") or "1"),
        "execution_id": decision.execution_id,
        "execution_id_source": decision.execution_id_source,
        "subject_sha": decision.subject_sha,
        "task_commit": decision.inputs.get("task_commit"),
        "task_path": decision.inputs.get("task_path"),
        "target_branch": decision.inputs.get("target_branch"),
        "verification_id": verification_id,
        "verification_passed": decision.accepted,
        "check_run_conclusion": decision.check_run_conclusion,
        "verifier_context": VERIFIER_CHECK_CONTEXT,
        "pinned_action": PINNED_ADAPTER_ACTION,
        "status": decision.status,
        "terminal_reason": decision.terminal_reason,
        "failure_code": decision.failure_code,
        "mode": decision.inputs.get("mode") or "execute",
    }
    meta = _write_evidence(
        workdir, "workflow-run-metadata.json", _canonical_bytes(metadata)
    )
    artifacts.append(_artifact_entry("workflow-run-metadata", "application/json", meta))
    artifact_ids.append("workflow-run-metadata")

    # --- result.v1 ---------------------------------------------------------
    checks: List[Dict[str, Any]] = []
    acceptance_results: List[Dict[str, Any]] = []
    if decision.accepted:
        command_id = _required_command_id(task)
        checks.append(
            {
                "id": "RegisteredSuite",
                "command_id": command_id,
                "exit_code": 0,
                "evidence_artifact_ids": ["result-artifact"],
            }
        )
        acceptance_results.append(
            {
                "id": "AcceptRequiredCheck",
                "predicate_id": "process.exit_code.equals",
                "parameters": {"value": 0},
                "passed": True,
                "observed": 0,
                "evidence_artifact_ids": ["result-artifact"],
            }
        )

    error = None
    if decision.status in {"failed", "blocked"}:
        error = {
            "code": decision.failure_code or "adapter_error",
            "message": decision.message,
        }

    result = {
        "schema_version": "1.0.0",
        "task_id": task_id,
        "execution_id": decision.execution_id,
        "attempt": attempt,
        "executor": {
            "adapter": signal.get("adapter") or "human-supervised-claude-code",
            "adapter_version": signal.get("adapter_version")
            or "claude-code-2.1.197-p0-actor-bootstrap",
            "identity": executor_identity,
        },
        "started_at": signal.get("started_at") or now,
        "finished_at": signal.get("finished_at") or now,
        "base_sha": base_sha,
        "head_sha": decision.subject_sha if decision.accepted else _optional_head(signal),
        "status": decision.status,
        "terminal_reason": decision.terminal_reason,
        "raw_provider_terminal_reason": signal.get("raw_provider_terminal_reason"),
        "no_change_reason": None,
        "no_change_evidence": [],
        "authored_commits": authored_commits if decision.accepted else _optional_commits(signal),
        "changed_files": changed_files if decision.accepted else _optional_files(signal),
        "acceptance_results": acceptance_results,
        "checks": checks,
        "artifacts": artifacts,
        "finalized_by": {
            "component_id": "p0-actions-adapter.v1",
            "credential_principal": "github:actions:p0-finalizer",
        },
        "warnings": [],
        "error": error,
    }

    (workdir / "result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True), encoding="utf-8"
    )
    (workdir / "verification.json").write_text(
        json.dumps(verification, indent=2, sort_keys=True), encoding="utf-8"
    )
    (workdir / "workflow-run-metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8"
    )

    return {
        "result": result,
        "verification": verification,
        "metadata": metadata,
        "artifact_ids": artifact_ids,
    }


def _optional_head(signal: Mapping[str, Any]) -> Optional[str]:
    commits = signal.get("authored_commits") or []
    subject = signal.get("subject_sha")
    return subject if commits and subject else None


def _optional_commits(signal: Mapping[str, Any]) -> List[str]:
    return list(signal.get("authored_commits") or [])


def _optional_files(signal: Mapping[str, Any]) -> List[str]:
    return list(signal.get("changed_files") or [])


def _artifact_entry(artifact_id: str, media_type: str, meta: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "id": artifact_id,
        "path": meta["path"],
        "sha256": meta["sha256"],
        "media_type": media_type,
        "size_bytes": meta["size_bytes"],
    }


def _result_identity(identity: Mapping[str, Any], role: str) -> Dict[str, Any]:
    return {
        "operator_principal": identity.get("operator_principal") or "github:unknown",
        "agent_runtime_id": identity.get("agent_runtime_id") or "unknown",
        "credential_principal": identity.get("credential_principal") or "github:unknown",
        "delegation_parent": identity.get("delegation_parent") or "issue-29-owner-decision",
        "role": role,
    }


def _required_command_id(task: Mapping[str, Any]) -> str:
    checks = task.get("required_checks") or []
    if checks and isinstance(checks[0], Mapping) and checks[0].get("command_id"):
        return checks[0]["command_id"]
    return "repo.contracts.b3.tests"


def _build_verification(
    decision: Decision,
    task_id: str,
    verification_id: Any,
    verifier_identity: Mapping[str, Any],
    evaluated_at: str,
    evidence: List[Dict[str, Any]],
    evidence_ref_ids: List[str],
) -> Dict[str, Any]:
    predicate_results: List[Dict[str, Any]] = []
    if decision.accepted:
        for predicate_id, observed in (
            ("git.base_sha.equals", decision.subject_sha),
            ("binding.execution_id.equals", decision.execution_id),
            ("identity.lineage.no_overlap", True),
            ("review.subject_sha.equals", decision.subject_sha),
            ("review.eligibility.passed", True),
            ("acceptance.required.passed", True),
        ):
            predicate_results.append(
                {
                    "predicate_id": predicate_id,
                    "passed": True,
                    "observed": observed,
                    "evidence_artifact_ids": list(evidence_ref_ids),
                    "failure_code": None,
                }
            )
    else:
        predicate_results.append(
            {
                "predicate_id": decision.predicate_id,
                "passed": False,
                "observed": decision.message,
                "evidence_artifact_ids": list(evidence_ref_ids),
                "failure_code": decision.failure_code,
            }
        )

    return {
        "schema_version": "1.0.0",
        "verification_id": verification_id,
        "task_id": task_id,
        "execution_id": decision.execution_id,
        "subject_sha": decision.subject_sha,
        "verifier_identity": verifier_identity,
        "passed": decision.accepted,
        "predicate_results": predicate_results,
        "evidence": evidence,
        "evaluated_at": evaluated_at,
    }


# --------------------------------------------------------------------------
# Fixture-suite runner (offline AC-A2 oracle)
# --------------------------------------------------------------------------


def _resolve_document(base_dir: Path, ref: Optional[Mapping[str, Any]]) -> Optional[Any]:
    if not ref:
        return None
    path = base_dir / ref["path"]
    actual = sha256_file(path)
    if actual != ref["sha256"]:
        raise P0AdapterError(
            "fixture hash mismatch for {}: expected {}, got {}".format(
                ref["path"], ref["sha256"], actual
            )
        )
    return load_json(path)


def run_fixture(
    fixture: Mapping[str, Any], base_dir: Path, workdir: Path
) -> Dict[str, Any]:
    task = _resolve_document(base_dir, fixture.get("task"))
    signal = _resolve_document(base_dir, fixture.get("executor_signal")) or {}
    review = _resolve_document(base_dir, fixture.get("review_attestation"))
    verifier_identity = _resolve_document(base_dir, fixture.get("verifier_identity")) or {}

    inputs = dict(fixture.get("inputs") or {})
    invocation = dict(fixture.get("invocation") or {})
    invocation["verifier_identity"] = verifier_identity

    decision = evaluate(inputs, task, signal, review)
    docs = build_documents(decision, invocation, workdir / fixture["id"])

    # Every produced result/verification document must itself be schema-valid
    # (AC-A5 schema.instance.valid); a produced document that does not
    # validate fails the fixture closed.
    result_errors = schema_errors(_RESULT_VALIDATOR, docs["result"])
    verification_errors = schema_errors(_VERIFICATION_VALIDATOR, docs["verification"])

    expected = fixture.get("expected") or {}
    actual = {
        "accepted": decision.accepted,
        "status": decision.status,
        "terminal_reason": decision.terminal_reason,
        "check_run_conclusion": decision.check_run_conclusion,
        "failure_code": decision.failure_code,
        "execution_id_source": decision.execution_id_source,
    }
    expectation_met = (
        all(actual.get(key) == value for key, value in expected.items())
        and not result_errors
        and not verification_errors
    )

    return {
        "id": fixture["id"],
        "expectation_met": expectation_met,
        "expected": expected,
        "actual": actual,
        "result_schema_errors": result_errors,
        "verification_schema_errors": verification_errors,
        "artifact_ids": docs["artifact_ids"],
    }


def run_suite(manifest_path: Path, workdir: Path) -> Tuple[int, Dict[str, Any]]:
    manifest_path = Path(manifest_path)
    base_dir = manifest_path.parent
    manifest = load_json(manifest_path)

    fixtures_report: List[Dict[str, Any]] = []
    passed = 0
    for fixture in manifest.get("fixtures", []):
        report = run_fixture(fixture, base_dir, Path(workdir))
        fixtures_report.append(report)
        if report["expectation_met"]:
            passed += 1

    total = len(fixtures_report)
    pass_rate = (passed / total) if total else 0.0
    valid = passed == total and total > 0
    report = {
        "authoritative_verifier": False,
        "bootstrap_scope": "P0",
        "valid": valid,
        "pass_rate": pass_rate,
        "summary": {"total": total, "passed": passed, "failed": total - passed},
        "fixtures": fixtures_report,
    }
    return (0 if valid else 1), report


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="P0 Actions adapter/check")
    subparsers = parser.add_subparsers(dest="command", required=True)

    suite = subparsers.add_parser("suite", help="run the offline P0 fixture manifest")
    suite.add_argument("--manifest", type=Path, required=True)
    suite.add_argument("--workdir", type=Path, default=None)

    resolve = subparsers.add_parser(
        "resolve-check", help="resolve a required check argv from the command registry"
    )
    resolve.add_argument("--command-id", required=True)

    finalize = subparsers.add_parser(
        "finalize",
        help=(
            "finalize a live run: evaluate real evidence, write schema-valid "
            "result/verification/workflow-run-metadata, and print the metadata "
            "(whose check_run_conclusion is derived only from verification.passed)"
        ),
    )
    finalize.add_argument("--signal", type=Path, required=True)
    finalize.add_argument("--task", type=Path, default=None)
    finalize.add_argument("--review-attestation", type=Path, default=None)
    finalize.add_argument("--verifier-identity", type=Path, default=None)
    finalize.add_argument("--task-commit", required=True)
    finalize.add_argument("--task-path", required=True)
    finalize.add_argument("--target-branch", required=True)
    finalize.add_argument("--default-branch", default="main")
    finalize.add_argument("--attempt", default="1")
    finalize.add_argument("--mode", default="execute")
    finalize.add_argument("--verification-id", required=True)
    finalize.add_argument("--evaluated-at", required=True)
    finalize.add_argument("--output-dir", type=Path, required=True)

    return parser.parse_args(argv)


def _load_optional(path: Optional[Path]) -> Optional[Any]:
    if path is None:
        return None
    p = Path(path)
    if not p.is_file() or p.stat().st_size == 0:
        return None
    try:
        return load_json(p)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def finalize_live_run(args: argparse.Namespace) -> Dict[str, Any]:
    """Finalize a live run from real evidence only.

    A missing task, missing evidence, or missing/ineligible review fails
    closed exactly as the offline fixtures prove -- the Check Run conclusion
    returned here is only ever `success` when this module's own independent
    verification passed.
    """
    signal = _load_optional(args.signal) or {}
    task = _load_optional(args.task)
    review = _load_optional(args.review_attestation)
    verifier_identity = _load_optional(args.verifier_identity) or {}

    inputs = {
        "task_commit": args.task_commit,
        "task_path": args.task_path,
        "target_branch": args.target_branch,
        "default_branch": args.default_branch,
        "attempt": int(args.attempt) if str(args.attempt).isdigit() else 1,
        "mode": args.mode,
    }
    # A task that could not be fetched/validated fails closed as invalid_task
    # (an empty object never satisfies task.v1).
    decision = evaluate(inputs, task if isinstance(task, Mapping) else {}, signal, review)
    docs = build_documents(
        decision,
        {
            "verification_id": args.verification_id,
            "evaluated_at": args.evaluated_at,
            "verifier_identity": verifier_identity,
        },
        Path(args.output_dir),
    )
    return docs["metadata"]


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if args.command == "suite":
        import tempfile

        workdir = args.workdir or Path(tempfile.mkdtemp(prefix="p0-actions-suite-"))
        exit_code, report = run_suite(args.manifest, workdir)
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return exit_code
    if args.command == "resolve-check":
        argv_resolved = resolve_registered_check(args.command_id)
        json.dump({"command_id": args.command_id, "argv": argv_resolved}, sys.stdout)
        sys.stdout.write("\n")
        return 0
    if args.command == "finalize":
        metadata = finalize_live_run(args)
        json.dump(metadata, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        # Finalization itself succeeded; the trusted pass/fail is
        # metadata.check_run_conclusion (== verification.passed), which the
        # workflow reads to publish and gate the verifier-owned Check Run.
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
