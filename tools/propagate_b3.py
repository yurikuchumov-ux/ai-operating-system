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

Two further trust boundaries are enforced structurally, not by convention:

- `execution_id` is never caller-supplied and never `uuid.uuid4()`
  randomness. It is either the adapter's own real `session_id` -- parsed by
  a bounded, fail-closed parser from the pinned Claude Code Action's actual
  `execution_file`/`structured_output` text -- or, when the adapter never
  attempted to run, a UUID5 deterministically derived from real,
  platform-verifiable Actions run facts (`workflow_run_id`,
  `workflow_run_attempt`, `attempt`). See `resolve_execution_identity`.
- `timeout` is only ever classified from explicit elapsed-time-versus-budget
  evidence (`job_elapsed_seconds` >= `job_timeout_budget_seconds`, or the
  adapter equivalent). An Actions job that failed or was cancelled without
  that evidence is classified `runner_lost` (the adapter never attempted) or
  `adapter_error` (it attempted but its session is unresolvable, or it
  reported a real error) -- never blanket-mapped to `timeout`.

`trusted_subject_sha` is a required, non-nullable signal field: the one
explicit subject SHA the calling workflow resolved (`github.event.
pull_request.head.sha` on `pull_request`, never the synthetic merge ref/
commit `actions/checkout` and `context.sha` default to on that event; `github.
sha` only on `workflow_dispatch`). It is used, unchanged, for the B2
verifier's `expected_subject_sha` binding and republished on
`workflow-run-metadata` as `subject_sha` for the workflow's Check Run
`head_sha` -- so every trust-bearing use of "the commit under test" in this
pipeline traces back to that one caller-resolved value, never `context.sha`
read again independently downstream.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ModuleNotFoundError as exc:  # pragma: no cover - exercised by CLI setup
    raise SystemExit(
        "missing dependency: install requirements-b0.txt before running the B3 propagator"
    ) from exc

# Issue #27 v3 correction: jsonschema's `date-time` format assertion is only
# ever enforced when a real RFC 3339 checker implementation is importable
# (`rfc3339_validator` or `strict_rfc3339`) -- if neither is installed, the
# `format: date-time` keyword is silently never checked at all, and a bare
# digit string such as an unconverted `date -u +%s` epoch value passes
# schema validation cleanly. `requirements-b0.txt` pins `rfc3339-validator`
# so that `FormatChecker()` above validates it, but this import and the
# explicit `_require_rfc3339_utc` check below are the second, load-bearing
# enforcement: correctness must not depend solely on that optional
# jsonschema format-checker registration succeeding.
try:
    from rfc3339_validator import validate_rfc3339 as _validate_rfc3339
except ModuleNotFoundError as exc:  # pragma: no cover - exercised by CLI setup
    raise SystemExit(
        "missing dependency: install requirements-b0.txt (rfc3339-validator) before running the B3 propagator"
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
        "attempt",
        "executor",
        "started_at",
        "finished_at",
        "workflow_run_id",
        "workflow_run_attempt",
        "source_run_id",
        "trusted_subject_sha",
        "cancelled_by_owner",
        "adapter_attempted",
        "adapter_step_outcome",
        "job_elapsed_seconds",
        "job_timeout_budget_seconds",
        "adapter_elapsed_seconds",
        "adapter_timeout_budget_seconds",
        "max_turns_exhausted",
        "adapter_error",
        "raw_provider_terminal_reason",
        "adapter_self_report",
        "actions_job_conclusion",
        "untrusted_candidate",
        "execution_file_content",
        "structured_output_raw",
        "git_observation",
        "result_artifact_present",
        "required_evidence_artifact_present",
        "required_check_exit_code",
        "finalized_by",
    ],
    "properties": {
        "schema_version": {"const": "1.0.0"},
        "task_id": {"type": "string", "pattern": _TASK_ID_PATTERN},
        # `execution_id` is intentionally NOT a field of this schema: it is
        # never caller-supplied. See `resolve_execution_identity` -- it is
        # derived only from the adapter's real session_id or, failing that,
        # deterministically from real Actions run facts, never accepted as
        # raw input (which would reopen the door to a fabricated/random
        # value masquerading as trusted).
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
        "workflow_run_attempt": {"type": "string", "minLength": 1},
        "source_run_id": {"oneOf": [{"type": "string", "minLength": 1}, {"type": "null"}]},
        # The one, explicit, trusted subject SHA for this run -- resolved by
        # the workflow from `github.event.pull_request.head.sha` on
        # `pull_request` events (never the synthetic merge ref/commit
        # `actions/checkout` defaults to) or `github.sha` on
        # `workflow_dispatch`, and used consistently for the checkout `ref`,
        # the Git observation, the B2 verifier's `expected_subject_sha`
        # binding, and the published Check Run's `head_sha`. Never null:
        # this is always the exact commit actually under test, independent
        # of whether any commits are observed ahead of `base_sha` (that
        # distinction is `git_observation.head_sha`, which -- unlike this
        # field -- is nulled to drive `missing_commit` classification).
        "trusted_subject_sha": {"type": "string", "pattern": _SHA_PATTERN},
        "cancelled_by_owner": {"type": "boolean"},
        # Whether the adapter action step actually started executing (e.g.
        # observed via the execute job's own `steps.adapter.outcome` being
        # non-null). This is a directly observable platform fact, not the
        # adapter's own self-report of success/failure.
        "adapter_attempted": {"type": "boolean"},
        "adapter_step_outcome": {
            "oneOf": [{"enum": ["success", "failure", "cancelled", "skipped"]}, {"type": "null"}]
        },
        # Explicit elapsed-time-versus-budget evidence. `timeout` is only
        # ever classified when elapsed >= budget for one of these pairs --
        # never from a blanket "the job failed" inference.
        "job_elapsed_seconds": {"oneOf": [{"type": "integer", "minimum": 0}, {"type": "null"}]},
        "job_timeout_budget_seconds": {"oneOf": [{"type": "integer", "minimum": 1}, {"type": "null"}]},
        "adapter_elapsed_seconds": {"oneOf": [{"type": "integer", "minimum": 0}, {"type": "null"}]},
        "adapter_timeout_budget_seconds": {"oneOf": [{"type": "integer", "minimum": 1}, {"type": "null"}]},
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
        # Bounded, real text captured from the pinned Claude Code Action's
        # own outputs at that exact pin (`execution_file`, read from disk,
        # and `structured_output`, taken verbatim). `resolve_execution_identity`
        # is the only place these are read, and only to extract a real
        # `session_id` -- never to determine success/failure.
        "execution_file_content": {"oneOf": [{"type": "string", "maxLength": 1000000}, {"type": "null"}]},
        "structured_output_raw": {"oneOf": [{"type": "string", "maxLength": 1000000}, {"type": "null"}]},
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
        # Issue #27 correction: real, directly observed facts needed to
        # populate `result.checks` / `result.acceptance_results` truthfully.
        # All five are optional (not in `required`) so every pre-existing
        # signal fixture remains schema-valid unchanged; a signal that omits
        # them simply yields no per-criterion evidence, never a fabricated
        # one (see `build_checks_and_acceptance`).
        "dependencies_installed_before_adapter": {"type": "boolean"},
        # The exact registered-check command string this signal expects to
        # find inside the adapter's own transcript
        # (`execution_file_content`). Matched verbatim by
        # `resolve_adapter_registered_command_result`; never used to alter
        # what command is actually run.
        "adapter_registered_command": {"oneOf": [{"type": "string", "minLength": 1}, {"type": "null"}]},
        # The real, bounded stdout/stderr this job's own directly executed
        # required check produced -- never the adapter's transcript, never a
        # summary of it.
        "required_check_log": {"oneOf": [{"type": "string", "maxLength": 1000000}, {"type": "null"}]},
        "task_commit": {"oneOf": [{"type": "string", "pattern": _SHA_PATTERN}, {"type": "null"}]},
        "review_attestation_commit": {"oneOf": [{"type": "string", "pattern": _SHA_PATTERN}, {"type": "null"}]},
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
    "runner_lost": "the runner was lost before the adapter action could start",
}

# UUID pattern for the pinned Claude Code Action's own `session_id`. Claude
# Code session identifiers are themselves UUID-formatted; a present but
# non-UUID-shaped value is treated as malformed (session unresolvable), not
# coerced or trusted.
_SESSION_ID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_MAX_SESSION_SEARCH_DEPTH = 8
_MAX_SESSION_SEARCH_NODES = 2000

# Fixed, non-secret namespace for UUID5 derivation. Any valid UUID works
# here; it is not itself sensitive, it only seeds a deterministic hash of
# real Actions run facts so that fallback `execution_id` values are
# reproducible and traceable rather than `uuid.uuid4()` randomness.
_EXECUTION_ID_NAMESPACE = uuid.UUID("5b3b3b3b-b3b3-4b3b-8b3b-b3b3b3b3b3b3")


def _find_session_id(node: Any, depth: int, budget: List[int]) -> Optional[str]:
    """Bounded depth-first search for a `session_id`/`sessionId` string.

    `budget` is a mutable one-element visit counter so a deeply-nested but
    under-size-limit document cannot cause unbounded search work; both the
    depth limit and the node-visit budget fail closed to "not found" (never
    raise), leaving the caller to treat that as an unresolvable session.
    """
    if depth > _MAX_SESSION_SEARCH_DEPTH or budget[0] <= 0:
        return None
    budget[0] -= 1
    if isinstance(node, dict):
        for key in ("session_id", "sessionId"):
            value = node.get(key)
            if isinstance(value, str) and value:
                return value
        for value in node.values():
            found = _find_session_id(value, depth + 1, budget)
            if found is not None:
                return found
    elif isinstance(node, list):
        for item in node:
            found = _find_session_id(item, depth + 1, budget)
            if found is not None:
                return found
    return None


def _extract_session_id_from_text(text: Optional[str]) -> Optional[str]:
    """Bounded, best-effort extraction of a `session_id` field from JSON or
    JSON-Lines text. Returns the raw string value if found, else `None` --
    every failure mode here (unreadable, oversized, not JSON, no matching
    field) is "not found", never an exception; the caller is responsible for
    fail-closed treatment of `None`.
    """
    if not text:
        return None
    if len(text.encode("utf-8")) > MAX_INPUT_BYTES:
        return None
    stripped = text.strip()
    if not stripped:
        return None
    candidates: List[Any] = []
    try:
        candidates.append(json.loads(stripped))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        pass
    # The action's `execution_file` is commonly a transcript of
    # newline-delimited JSON events; the most recent well-formed line is
    # the most likely place to find the session identifier.
    for line in reversed(stripped.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            candidates.append(json.loads(line))
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            continue
        break
    for candidate in candidates:
        found = _find_session_id(candidate, 0, [_MAX_SESSION_SEARCH_NODES])
        if found is not None:
            return found
    return None


def resolve_adapter_session_id(
    execution_file_content: Optional[str], structured_output_raw: Optional[str]
) -> Optional[str]:
    """Bounded, fail-closed extraction of the pinned Claude Code Action's own
    session identifier from its real `execution_file`/`structured_output`
    text. Returns a normalized, UUID-validated session id string, or `None`
    if neither source yields one -- callers must treat `None` as
    unresolvable (`adapter_error`), never fabricate a substitute.
    """
    for text in (execution_file_content, structured_output_raw):
        raw = _extract_session_id_from_text(text)
        if raw is not None and _SESSION_ID_PATTERN.match(raw.strip()):
            return raw.strip().lower()
    return None


_MAX_TRANSCRIPT_EVENTS_SCANNED = 2000


def resolve_adapter_registered_command_result(
    execution_file_content: Optional[str], registered_command: Optional[str]
) -> Optional[bool]:
    """Bounded, fail-closed determination of whether the adapter's own
    transcript shows it actually ran `registered_command` via a `Bash` tool
    call, and whether that call's own `tool_result` carries no error.

    This reads only structural transcript fields the harness itself sets
    (`tool_use.input.command`, `tool_result.tool_use_id`,
    `tool_result.is_error`) -- never the adapter's own natural-language
    summary/self-report of the outcome. Returns `True` (the exact command
    ran and did not error), `False` (it ran and did error), or `None` (the
    command was never found in the transcript, or the transcript could not
    be parsed) -- callers must treat `None` as "not confirmed", never
    coerce it to `True`.
    """
    if not execution_file_content or not registered_command:
        return None
    if len(execution_file_content.encode("utf-8")) > MAX_INPUT_BYTES:
        return None
    try:
        events = json.loads(execution_file_content)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return None
    if not isinstance(events, list):
        return None
    events = events[:_MAX_TRANSCRIPT_EVENTS_SCANNED]
    expected = registered_command.strip()

    target_tool_use_ids: set = set()
    for event in events:
        if not isinstance(event, dict):
            continue
        content = (event.get("message") or {}).get("content") if isinstance(event.get("message"), dict) else None
        if not isinstance(content, list):
            continue
        for item in content:
            if not isinstance(item, dict) or item.get("type") != "tool_use" or item.get("name") != "Bash":
                continue
            tool_input = item.get("input")
            command = tool_input.get("command") if isinstance(tool_input, dict) else None
            tool_use_id = item.get("id")
            if isinstance(command, str) and command.strip() == expected and isinstance(tool_use_id, str):
                target_tool_use_ids.add(tool_use_id)

    if not target_tool_use_ids:
        return None

    result_ok: Optional[bool] = None
    for event in events:
        if not isinstance(event, dict):
            continue
        content = (event.get("message") or {}).get("content") if isinstance(event.get("message"), dict) else None
        if not isinstance(content, list):
            continue
        for item in content:
            if (
                isinstance(item, dict)
                and item.get("type") == "tool_result"
                and item.get("tool_use_id") in target_tool_use_ids
            ):
                result_ok = not bool(item.get("is_error"))
    return result_ok


def derive_pipeline_execution_id(workflow_run_id: str, workflow_run_attempt: str, attempt: int) -> str:
    """Deterministic UUID5 fallback execution id, derived from real,
    platform-verifiable Actions run facts. Reproducible and traceable to the
    exact run/attempt -- never `uuid.uuid4()` randomness."""
    name = "b3-terminal-propagation:{}:{}:{}".format(workflow_run_id, workflow_run_attempt, attempt)
    return str(uuid.uuid5(_EXECUTION_ID_NAMESPACE, name))


def resolve_execution_identity(signal: Mapping[str, Any]) -> Tuple[str, Optional[str], Optional[str]]:
    """Resolve the trusted `execution_id` for this run.

    When the adapter action attempted to run, its own real `session_id` --
    parsed by `resolve_adapter_session_id`, never fabricated -- is used
    directly as `execution_id`. When the adapter never attempted, or its
    session id cannot be resolved from its real output, `execution_id`
    instead falls back to `derive_pipeline_execution_id`. Returns
    `(execution_id, resolved_session_id_or_None, session_error_or_None)`;
    `session_error` is set, and must be classified `adapter_error`, exactly
    when the adapter attempted to run but no session id could be resolved.
    """
    session_id: Optional[str] = None
    session_error: Optional[str] = None
    if signal["adapter_attempted"]:
        session_id = resolve_adapter_session_id(
            signal.get("execution_file_content"), signal.get("structured_output_raw")
        )
        if session_id is None:
            session_error = (
                "adapter action ran but no valid session_id could be extracted "
                "from its execution_file or structured_output"
            )
    execution_id = session_id or derive_pipeline_execution_id(
        signal["workflow_run_id"], signal["workflow_run_attempt"], signal["attempt"]
    )
    return execution_id, session_id, session_error


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


_RFC3339_TIMESTAMP_FIELDS = ("started_at", "finished_at")


def _require_rfc3339_utc(value: Any, field: str) -> None:
    """Mandatory, explicit RFC 3339 parse/check -- fails closed on anything
    that is not a genuine RFC 3339 timestamp string, independent of whether
    jsonschema's own `format: date-time` FormatChecker happened to enforce
    it. This is the fix for the live defect where an unconverted Unix epoch
    string (e.g. `"1784120958"`, from an un-converted `date -u +%s` value)
    was published as `started_at`: that value is not RFC 3339 and must be
    rejected here even if the optional format-checker registration were
    ever silently absent or bypassed."""
    if not isinstance(value, str) or not _validate_rfc3339(value):
        raise B3PropagatorError(
            "provider signal field {} is not a valid RFC 3339 UTC timestamp: {!r}".format(field, value)
        )


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
    for field in _RFC3339_TIMESTAMP_FIELDS:
        _require_rfc3339_utc(document.get(field), field)
    return document


def classify_terminal(
    signal: Mapping[str, Any],
    session_error: Optional[str],
    adapter_check_result: Optional[bool] = None,
) -> Classification:
    """Deterministically classify the terminal outcome from trusted facts only.

    Adapter self-report (`adapter_self_report`) and the Actions job's own
    conclusion (`actions_job_conclusion`) are never read here: both are
    carried through only as informational, untrusted metadata elsewhere. A
    provider signal claiming green at either layer cannot change the
    classification this function derives from the actually observed
    cancellation, timeout, turn-budget, session-resolution, error, Git,
    artifact, and check facts.

    `timeout` is classified only from explicit elapsed-time-versus-budget
    evidence, computed here rather than trusted as a pre-set boolean: a
    provider signal cannot claim `timeout` without also supplying the
    elapsed/budget numbers that actually demonstrate it. An Actions job that
    ended abnormally without that evidence is `runner_lost` (the adapter
    never attempted) or `adapter_error` (it attempted but failed or its
    session is unresolvable) -- never blanket-mapped to `timeout`.

    `session_error` (from `resolve_execution_identity`) is non-`None` only
    when the adapter attempted to run but its real session id could not be
    resolved from its own execution_file/structured_output; that is itself
    classified `adapter_error`, never silently ignored.

    `adapter_check_result` (from `resolve_adapter_registered_command_result`)
    is `True`/`False` only when the adapter's own transcript shows it
    actually ran the exact registered command; `False` -- a real, directly
    observed failure of that command, never the adapter's self-report -- is
    classified `check_failed` here, independently of whether this job's own
    separately executed copy of the same check passed. `None` (the command
    was never found in the transcript, e.g. because the signal predates
    this field, or a task does not require this evidence) is never treated
    as a failure at this classification layer; a task that requires it does
    so instead through its own `acceptance_criteria` on the resulting
    `result.acceptance_results` entry (see `build_checks_and_acceptance`).
    """
    go = signal["git_observation"]

    if signal["cancelled_by_owner"]:
        return Classification(
            "cancelled", "cancelled_by_owner",
            "cancelled_by_owner", _TERMINAL_REASON_MESSAGES["cancelled_by_owner"],
            None, None,
        )

    job_timed_out = (
        signal["job_elapsed_seconds"] is not None
        and signal["job_timeout_budget_seconds"] is not None
        and signal["job_elapsed_seconds"] >= signal["job_timeout_budget_seconds"]
    )
    if job_timed_out:
        return Classification("failed", "timeout", "timeout", _TERMINAL_REASON_MESSAGES["timeout"], "actions_job", None)

    adapter_timed_out = (
        signal["adapter_elapsed_seconds"] is not None
        and signal["adapter_timeout_budget_seconds"] is not None
        and signal["adapter_elapsed_seconds"] >= signal["adapter_timeout_budget_seconds"]
    )
    if adapter_timed_out:
        return Classification("failed", "timeout", "timeout", _TERMINAL_REASON_MESSAGES["timeout"], "adapter", None)

    if signal["max_turns_exhausted"]:
        return Classification("failed", "max_turns", "max_turns", _TERMINAL_REASON_MESSAGES["max_turns"], None, None)

    if not signal["adapter_attempted"]:
        return Classification(
            "failed", "runner_lost", "runner_lost", _TERMINAL_REASON_MESSAGES["runner_lost"], None, None
        )

    if session_error is not None:
        return Classification("failed", "adapter_error", "adapter_session_unresolvable", session_error, None, None)

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
    if adapter_check_result is False:
        return Classification(
            "failed", "check_failed", "check_failed",
            "the adapter's own real transcript shows the registered command did not exit zero",
            None, None,
        )
    return Classification("change_proposed", "completed", None, None, None, None)


def build_trusted_observation(
    signal: Mapping[str, Any], classification: Classification, execution_id: str
) -> Dict[str, Any]:
    go = signal["git_observation"]
    error = (
        None
        if classification.status == "change_proposed"
        else {"code": classification.error_code, "message": classification.error_message}
    )
    return {
        "schema_version": "1.0.0",
        "task_id": signal["task_id"],
        "execution_id": execution_id,
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


_KNOWN_CHECK_COMMAND_ID = "repo.contracts.b3.tests"


def _write_evidence_file(output_dir: Path, name: str, data: bytes) -> None:
    evidence_dir = output_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    path = evidence_dir / name
    if not path.exists():
        path.write_bytes(data)


def _fixture_manifest_matches_required_scenarios(
    manifest_relative_path: str, required_scenarios: Sequence[Mapping[str, Any]]
) -> bool:
    """Real, direct check of the checked-out `fixtures/b3/manifest.v1.json`
    (never a self-report): every declared `required_scenarios` entry must
    exist in the actual manifest with its `expected` fields matching."""
    try:
        manifest_path = (REPO_ROOT / manifest_relative_path).resolve()
        manifest_path.relative_to(REPO_ROOT)
        manifest = _load_bounded_json(manifest_path, "fixture manifest")
    except (B3PropagatorError, ValueError, OSError):
        return False
    if not isinstance(manifest, dict):
        return False
    by_id = {
        fixture.get("id"): fixture.get("expected", {})
        for fixture in manifest.get("fixtures", [])
        if isinstance(fixture, dict)
    }
    for spec in required_scenarios:
        expected = by_id.get(spec.get("id"))
        if expected is None:
            return False
        for key, value in spec.items():
            if key == "id":
                continue
            if expected.get(key) != value:
                return False
    return True


def _recompute_field_overlap(
    field: str, signal: Mapping[str, Any], review: Mapping[str, Any]
) -> bool:
    """Real, per-field recomputation of one lineage-overlap fact from the
    executor identity/authored commits actually observed and the reviewer
    identity actually loaded from the fetched review-attestation document.
    Shared by `_identity_lineage_passes` (the aggregate AC-C6 gate) and
    `_self_reported_overlap_results_consistent` (the self-report
    cross-check) so both read the exact same recomputation."""
    executor_identity = signal.get("executor", {}).get("identity", {})
    reviewer_identity = review.get("reviewer_identity", {})
    if field == "authored_commits":
        result_commits = set(signal.get("git_observation", {}).get("authored_commits", []))
        reviewer_commits = set(reviewer_identity.get("authored_commits", []))
        return bool(result_commits & reviewer_commits)
    return executor_identity.get(field) == reviewer_identity.get(field)


def _identity_lineage_passes(
    task: Mapping[str, Any], signal: Mapping[str, Any], review: Optional[Mapping[str, Any]]
) -> bool:
    """Real recomputation of lineage-overlap freedom -- mirrors (without
    importing or modifying) `verify_b2.B2Verifier._actual_lineage_overlaps`."""
    if review is None:
        return False
    reviewer_identity = review.get("reviewer_identity")
    if not isinstance(reviewer_identity, dict):
        return False
    forbidden = task.get("review_policy", {}).get("forbidden_lineage_overlaps", [])
    return not any(_recompute_field_overlap(field, signal, review) for field in forbidden)


def _expected_author_values(field: str, signal: Mapping[str, Any]) -> Optional[List[str]]:
    """The exact `author_values` a genuine `overlap_results` entry for
    `field` must carry, bound to real, directly observed executor data --
    never trusted from the entry's own self-assertion. A scalar identity
    field's expected value is the single-element list of the executor's own
    real identity field value; `authored_commits`' expected value is the
    exact, sorted set of commits this run's own Git observation actually
    recorded. Returns `None` (never matches) when the underlying real value
    is itself missing or malformed."""
    if field == "authored_commits":
        commits = signal.get("git_observation", {}).get("authored_commits")
        if not isinstance(commits, list) or not all(isinstance(c, str) for c in commits):
            return None
        return sorted(set(commits))
    value = signal.get("executor", {}).get("identity", {}).get(field)
    if not isinstance(value, str) or not value:
        return None
    return [value]


def _expected_reviewer_value(field: str, review: Mapping[str, Any]) -> Optional[str]:
    """The exact `reviewer_value` a genuine `overlap_results` entry for
    `field` must carry, bound to the reviewer's own real identity -- never
    trusted from the entry's own self-assertion. `authored_commits` uses the
    canonical string `"none"` for an empty reviewer authored-commit set, or
    else a deterministic comma-joined, sorted SHA list."""
    reviewer_identity = review.get("reviewer_identity", {})
    if field == "authored_commits":
        commits = reviewer_identity.get("authored_commits")
        if not isinstance(commits, list) or not all(isinstance(c, str) for c in commits):
            return None
        sorted_commits = sorted(set(commits))
        return ",".join(sorted_commits) if sorted_commits else "none"
    value = reviewer_identity.get(field)
    if not isinstance(value, str) or not value:
        return None
    return value


def _self_reported_overlap_results_consistent(
    review: Mapping[str, Any], signal: Mapping[str, Any], forbidden: Sequence[str]
) -> bool:
    """The review-attestation's own self-asserted `eligibility.overlap_results`
    must not disagree with what is independently recomputed here for every
    forbidden lineage field -- a reviewer document claiming `overlap: false`
    for a field this tool recomputes as actually overlapping (or vice
    versa) fails closed rather than being trusted at face value. A missing,
    malformed, or incomplete `overlap_results` array also fails closed.

    Issue #27 v3 correction: a schema-valid `overlap_results` array may
    still carry more than one entry for the same `field` (the schema does
    not forbid it); a naive `{item["field"]: item["overlap"] for item in
    ...}` dict comprehension then lets whichever entry appears last silently
    win, so a contradicting first entry is discarded unseen. Every `field`
    value across the whole array -- not only the ones this task forbids --
    is therefore checked for duplication *before* any dict is built from it;
    any duplicate fails the whole criterion closed instead of picking a
    winner. Each forbidden field's entry must also carry `author_values`
    exactly equal to `_expected_author_values` and `reviewer_value` exactly
    equal to `_expected_reviewer_value` -- not just an `overlap` boolean
    that happens to agree with the recomputation -- so a self-report cannot
    assert a correct boolean while attaching fabricated identity values."""
    entries = review.get("eligibility", {}).get("overlap_results")
    if not isinstance(entries, list):
        return False
    fields: List[Any] = []
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or "field" not in entry
            or "overlap" not in entry
            or "author_values" not in entry
            or "reviewer_value" not in entry
        ):
            return False
        fields.append(entry["field"])
    if len(fields) != len(set(fields)):
        return False
    self_reported: Dict[str, Mapping[str, Any]] = {entry["field"]: entry for entry in entries}
    for field in forbidden:
        entry = self_reported.get(field)
        if entry is None:
            return False
        if bool(entry["overlap"]) != _recompute_field_overlap(field, signal, review):
            return False
        if entry.get("author_values") != _expected_author_values(field, signal):
            return False
        if entry.get("reviewer_value") != _expected_reviewer_value(field, review):
            return False
    return True


_AC_C5_RECOGNIZED_CONTROL_INPUTS = {"task-artifact", "review-attestation"}

# Issue #27 v3 correction: the exact, pinned immutable v3 task control
# commit AC-C5 independently checks `signal["task_commit"]` against --
# never merely "is task_commit present" (the reviewed false-positive), but
# "is it the one specific commit the workflow's fetch step is pinned to".
# A compromised or buggy signal claiming any other commit value is
# rejected here, independent of the workflow's own fetch-step self-report.
_EXPECTED_V3_TASK_COMMIT = "15bb125fa77c432084791aa5615515e136b7c9af"

# Issue #27 v3 correction: independent review of commit 06ac835 reproduced a
# real false-positive class in AC-C5 -- deleting `review_attestation_commit`
# from `required_provenance`, deleting `adapter-transcript` from
# `required_result_artifact_ids`, replacing/deleting `post_publication_gate`,
# or shrinking `not_asserted_until_post_publication` all still let the
# criterion pass, because only "the supplied lists are non-empty" was ever
# checked, never that the supplied `parameters` object is the *exact*
# immutable object the v3 task contract declares. This constant is that
# exact object (`parameter_shape_policy: "exact"`); `_evaluate_ac_c5` now
# requires byte-for-byte structural equality against it -- every key, every
# list's exact membership and order -- before any evidence is evaluated at
# all. A parameters object that differs in any way (missing, added,
# duplicated, reordered, wrong-type, or wrong-value field) fails closed here,
# never partially credited.
_EXPECTED_AC_C5_PARAMETERS_V3: Dict[str, Any] = {
    "parameter_shape_policy": "exact",
    "evaluation_phase": "result_finalization",
    "required_result_artifact_ids": ["adapter-transcript", "required-check-log"],
    "required_control_inputs": ["task-artifact", "review-attestation"],
    "required_provenance": [
        "workflow_run_id",
        "workflow_run_attempt",
        "execution_id",
        "subject_sha",
        "task_commit",
        "review_attestation_commit",
    ],
    "not_asserted_until_post_publication": ["verification-report", "workflow-run-metadata"],
    "post_publication_gate": "verification.passed_and_check_run_conclusion",
}


def _artifact_matches_declared(artifact: Mapping[str, Any], output_dir: Path) -> bool:
    """Independently re-read one already-built result-artifact entry's own
    bytes from disk under the evidence root and recompute size/sha256 --
    never trust the entry dict's own claims about itself. Fails closed
    (`False`) on any missing file, path escaping the evidence root,
    oversized content, or size/hash mismatch; never raises."""
    path_value = artifact.get("path")
    if not isinstance(path_value, str) or not path_value:
        return False
    try:
        output_root = output_dir.resolve()
        absolute = (output_dir / path_value).resolve()
        absolute.relative_to(output_root)
    except (OSError, ValueError):
        return False
    if not absolute.is_file():
        return False
    try:
        raw = absolute.read_bytes()
    except OSError:
        return False
    if len(raw) > MAX_INPUT_BYTES:
        return False
    return len(raw) == artifact.get("size_bytes") and sha256_bytes(raw) == artifact.get("sha256")


def _evaluate_ac_c5(
    params: Mapping[str, Any],
    task: Mapping[str, Any],
    signal: Mapping[str, Any],
    review: Optional[Mapping[str, Any]],
    execution_id: str,
    artifacts: Sequence[Mapping[str, Any]],
    output_dir: Path,
) -> Tuple[bool, Dict[str, Any]]:
    """Independently verify, at result-finalization time only, exactly the
    facts the v2 task contract narrows AC-C5 to: real result evidence
    artifacts (bytes re-read and re-hashed from disk via
    `_artifact_matches_declared`, never trusted from the already-built
    artifact dict alone), real task/review control inputs actually loaded
    and bound to this run's own task ID / base SHA / subject SHA, and every
    required provenance field genuinely non-null -- including that
    `task_commit` is exactly the one pinned v2 control commit
    (`_EXPECTED_V3_TASK_COMMIT`). Never asserts `verification-report` or
    `workflow-run-metadata` existence: both are post-publication outputs
    that do not exist yet at this point in the pipeline (they are gated
    later by `verification.passed` and the Check Run conclusion), and any
    parameter shape that tries to claim one of those as already-required
    here is rejected outright, not silently ignored. Any other
    missing/malformed/unrecognized parameter shape also fails closed.

    Issue #27 v3 correction: before any of the above, `params` must equal
    `_EXPECTED_AC_C5_PARAMETERS_V3` exactly -- not merely "have the right
    keys with non-empty lists" (the reviewed false-positive class: deleting
    `review_attestation_commit` from `required_provenance`, deleting
    `adapter-transcript` from `required_result_artifact_ids`, or
    replacing/deleting `post_publication_gate` all previously still passed).
    Any deviation -- missing, added, duplicated, reordered, wrong-type, or
    wrong-value field, anywhere in the object -- fails closed here, before
    any artifact/provenance/binding evidence is examined at all."""
    if params != _EXPECTED_AC_C5_PARAMETERS_V3:
        return False, {"error": "ac_c5_parameter_shape_mismatch"}

    observed: Dict[str, Any] = {}

    if params.get("evaluation_phase") != "result_finalization":
        return False, {"error": "unsupported_evaluation_phase"}

    required_artifact_ids = params.get("required_result_artifact_ids")
    required_control_inputs = params.get("required_control_inputs")
    required_provenance = params.get("required_provenance")
    post_publication_only = params.get("not_asserted_until_post_publication")
    if (
        not isinstance(required_artifact_ids, list)
        or not required_artifact_ids
        or not isinstance(required_control_inputs, list)
        or not required_control_inputs
        or not isinstance(required_provenance, list)
        or not required_provenance
        or not isinstance(post_publication_only, list)
    ):
        return False, {"error": "malformed_ac_c5_parameters"}

    # Structural guard against the exact false-positive class this
    # correction closes: a parameter shape that lists a post-publication
    # artifact/control-input type (`verification-report`,
    # `workflow-run-metadata`) among what must already be present at
    # result-finalization time. Never silently ignored -- fails the whole
    # criterion closed instead of pretending not-yet-existing evidence is
    # already there.
    claimed_early = (set(required_artifact_ids) | set(required_control_inputs)) & set(
        post_publication_only
    )
    if claimed_early:
        observed["post_publication_outputs_wrongly_claimed"] = sorted(claimed_early)
        return False, observed

    by_id = {a.get("id"): a for a in artifacts if isinstance(a, Mapping)}
    artifacts_ok = True
    for artifact_id in required_artifact_ids:
        entry = by_id.get(artifact_id)
        entry_ok = entry is not None and _artifact_matches_declared(entry, output_dir)
        observed["artifact_verified:{}".format(artifact_id)] = entry_ok
        artifacts_ok = artifacts_ok and entry_ok

    provenance_values: Dict[str, Any] = {
        "workflow_run_id": signal.get("workflow_run_id"),
        "workflow_run_attempt": signal.get("workflow_run_attempt"),
        "execution_id": execution_id,
        "subject_sha": signal.get("trusted_subject_sha"),
        "task_commit": signal.get("task_commit"),
        "review_attestation_commit": signal.get("review_attestation_commit"),
    }
    provenance_ok = True
    for field in required_provenance:
        value = provenance_values.get(field)
        present = value is not None and value != ""
        observed["provenance_present:{}".format(field)] = present
        provenance_ok = provenance_ok and present

    task_commit_ok = signal.get("task_commit") == _EXPECTED_V3_TASK_COMMIT
    observed["task_commit_matches_pinned_v2_commit"] = task_commit_ok

    go = signal.get("git_observation", {})
    task_bound = (
        task is not None
        and task.get("task_id") == signal.get("task_id")
        and task.get("base_sha") == go.get("base_sha")
    )
    review_bound = (
        review is not None
        and review.get("task_id") == signal.get("task_id")
        and review.get("reviewed_sha") == signal.get("trusted_subject_sha")
    )
    control_inputs_ok = True
    for control_input in required_control_inputs:
        if control_input not in _AC_C5_RECOGNIZED_CONTROL_INPUTS:
            observed["unsupported_control_input:{}".format(control_input)] = True
            control_inputs_ok = False
            continue
        bound = task_bound if control_input == "task-artifact" else review_bound
        observed["control_input_loaded_and_bound:{}".format(control_input)] = bound
        control_inputs_ok = control_inputs_ok and bound

    passed = artifacts_ok and provenance_ok and task_commit_ok and control_inputs_ok
    return passed, observed


def _evaluate_ac_c6(
    params: Mapping[str, Any],
    task: Mapping[str, Any],
    signal: Mapping[str, Any],
    review: Optional[Mapping[str, Any]],
) -> Tuple[bool, Dict[str, Any]]:
    """Independently verify every fact the v2 task contract narrows AC-C6
    to, never trusting the review-attestation's own self-assertions alone:
    the configured review policy and risk class actually match both this
    criterion's own parameters and the task's own declared policy/risk
    class, eligibility is genuinely `true` with empty `reason_codes`,
    forbidden lineage overlaps are independently recomputed as absent, and
    the review document's own self-reported `overlap_results` cannot
    disagree with that recomputation. Any missing/malformed parameter
    shape, an unloaded review, or a missing `eligibility` object fails
    closed."""
    if (
        not isinstance(params.get("required_policy_id"), str)
        or not params.get("required_policy_id")
        or not isinstance(params.get("required_risk_class"), str)
        or not params.get("required_risk_class")
        or not isinstance(params.get("forbidden_lineage_overlaps"), list)
        or not params.get("forbidden_lineage_overlaps")
        or params.get("require_eligible") is not True
        or params.get("require_reason_codes_empty") is not True
        or params.get("required_distinct_from_executor") is not True
        # Issue #27 v3 correction: the task contract now declares these
        # three booleans explicitly; a parameter shape that omits or
        # disables any of them must not silently fall back to the v2
        # behavior -- it fails closed exactly like any other malformed
        # parameter shape.
        or params.get("reject_duplicate_overlap_fields") is not True
        or params.get("require_author_values_match_observed") is not True
        or params.get("require_reviewer_value_match_identity") is not True
    ):
        return False, {"error": "malformed_ac_c6_parameters"}

    if review is None:
        return False, {"error": "review_attestation_not_loaded"}
    eligibility = review.get("eligibility")
    if not isinstance(eligibility, dict):
        return False, {"error": "review_eligibility_missing"}

    required_policy_id = params["required_policy_id"]
    required_risk_class = params["required_risk_class"]
    forbidden = params["forbidden_lineage_overlaps"]
    observed: Dict[str, Any] = {}

    policy_ok = (
        eligibility.get("policy_id") == required_policy_id
        and task.get("review_policy", {}).get("policy_id") == required_policy_id
    )
    observed["policy_id_matches"] = policy_ok

    risk_class_ok = (
        eligibility.get("risk_class") == required_risk_class
        and task.get("risk_class") == required_risk_class
    )
    observed["risk_class_matches"] = risk_class_ok

    eligible_ok = eligibility.get("eligible") is True
    observed["eligible"] = eligible_ok

    reason_codes_ok = eligibility.get("reason_codes") == []
    observed["reason_codes_empty"] = reason_codes_ok

    recomputed_overlap_free = _identity_lineage_passes(task, signal, review)
    observed["recomputed_lineage_overlap_free"] = recomputed_overlap_free

    self_report_consistent = _self_reported_overlap_results_consistent(review, signal, forbidden)
    observed["self_reported_overlap_results_consistent"] = self_report_consistent

    passed = (
        policy_ok
        and risk_class_ok
        and eligible_ok
        and reason_codes_ok
        and recomputed_overlap_free
        and self_report_consistent
    )
    return passed, observed


def _evaluate_criterion(
    criterion: Mapping[str, Any],
    task: Mapping[str, Any],
    checks: Sequence[Mapping[str, Any]],
    signal: Mapping[str, Any],
    review: Optional[Mapping[str, Any]],
    adapter_check_result: Optional[bool],
    direct_exit: Optional[int],
    deps_installed: bool,
    execution_id: str,
    artifacts: Sequence[Mapping[str, Any]],
    output_dir: Path,
) -> Tuple[bool, Dict[str, Any]]:
    """Truthfully evaluate one task-declared acceptance criterion from real,
    directly observed evidence only. Never reads `adapter_self_report`,
    `actions_job_conclusion`, or `raw_provider_terminal_reason`. Returns
    `(passed, observed)`; an unrecognized predicate/parameter shape fails
    closed (`passed=False`) rather than guessing."""
    predicate_id = criterion["predicate_id"]
    params = criterion["parameters"]
    checks_by_id = {check["id"]: check for check in checks}

    if predicate_id == "process.exit_code.equals":
        component = params.get("component")
        if component == "claude-adapter-registered-command":
            passed = adapter_check_result is True and deps_installed and params.get("value", 0) == 0
            return passed, {
                "adapter_check_result": adapter_check_result,
                "dependencies_installed_before_adapter": deps_installed,
            }
        if component == "finalize-direct-required-check":
            passed = direct_exit is not None and direct_exit == params.get("value", 0)
            return passed, {"required_check_exit_code": direct_exit}
        return False, {"error": "unsupported_component"}

    if predicate_id == "schema.instance.valid":
        linked_check = checks_by_id.get(params.get("required_check_id"))
        check_ok = linked_check is not None and linked_check["exit_code"] == 0
        declared_ids = {c["id"] for c in task.get("acceptance_criteria", [])}
        ids_ok = set(params.get("required_acceptance_ids", [])) <= declared_ids
        passed = check_ok and ids_ok and bool(checks)
        return passed, {"required_check_ok": check_ok, "required_acceptance_ids_declared": ids_ok}

    if predicate_id == "fixture.pass_rate.equals":
        manifest_rel = params.get("manifest")
        manifest_ok = bool(manifest_rel) and _fixture_manifest_matches_required_scenarios(
            manifest_rel, params.get("required_scenarios", [])
        )
        linked_ok = bool(criterion.get("linked_checks")) and all(
            checks_by_id.get(cid, {}).get("exit_code") == 0 for cid in criterion["linked_checks"]
        )
        return manifest_ok and linked_ok, {"manifest_matches_required_scenarios": manifest_ok}

    if predicate_id == "artifact.exists":
        return _evaluate_ac_c5(params, task, signal, review, execution_id, artifacts, output_dir)

    if predicate_id == "identity.lineage.no_overlap":
        return _evaluate_ac_c6(params, task, signal, review)

    return False, {"error": "unsupported_predicate"}


def build_checks_and_acceptance(
    task: Optional[Mapping[str, Any]],
    review: Optional[Mapping[str, Any]],
    signal: Mapping[str, Any],
    adapter_check_result: Optional[bool],
    execution_id: str,
    output_dir: Path,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Build `result.checks` / `result.acceptance_results` / additional
    `result.artifacts` entries from trusted, directly observed evidence only.

    Never derives a passing entry from `adapter_self_report`,
    `actions_job_conclusion`, or `raw_provider_terminal_reason`: only the
    adapter's own transcript (`adapter_check_result`, from
    `resolve_adapter_registered_command_result`), this job's own directly
    executed check exit code (`required_check_exit_code`), and other
    directly-observed signal/task/review facts are read. When there is no
    real evidence to attach (no adapter transcript and no direct check log
    captured), returns empty lists -- the same behavior as before this
    correction -- rather than fabricate anything.
    """
    if task is None:
        return [], [], []

    artifacts: List[Dict[str, Any]] = []
    evidence_ids: List[str] = []

    execution_file_content = signal.get("execution_file_content")
    if execution_file_content:
        raw = execution_file_content.encode("utf-8")
        digest = sha256_bytes(raw)
        _write_evidence_file(output_dir, "adapter-transcript.txt", raw)
        artifacts.append(
            {
                "id": "adapter-transcript",
                "path": "evidence/adapter-transcript.txt",
                "sha256": digest,
                "media_type": "text/plain",
                "size_bytes": len(raw),
            }
        )
        evidence_ids.append("adapter-transcript")

    required_check_log = signal.get("required_check_log")
    if required_check_log:
        raw = required_check_log.encode("utf-8")
        digest = sha256_bytes(raw)
        _write_evidence_file(output_dir, "required-check-log.txt", raw)
        artifacts.append(
            {
                "id": "required-check-log",
                "path": "evidence/required-check-log.txt",
                "sha256": digest,
                "media_type": "text/plain",
                "size_bytes": len(raw),
            }
        )
        evidence_ids.append("required-check-log")

    if not evidence_ids:
        return [], [], []

    direct_exit = signal.get("required_check_exit_code")
    deps_installed = bool(signal.get("dependencies_installed_before_adapter"))
    combined_ok = adapter_check_result is True and direct_exit == 0 and deps_installed
    check_exit_code = 0 if combined_ok else 1
    evidence_ids = sorted(evidence_ids)

    checks: List[Dict[str, Any]] = []
    for required_check in task.get("required_checks", []):
        if required_check.get("command_id") != _KNOWN_CHECK_COMMAND_ID:
            continue
        checks.append(
            {
                "id": required_check["id"],
                "command_id": required_check["command_id"],
                "exit_code": check_exit_code,
                "evidence_artifact_ids": list(evidence_ids),
            }
        )
    checks_ids = {check["id"] for check in checks}

    acceptance_results: List[Dict[str, Any]] = []
    for criterion in task.get("acceptance_criteria", []):
        if not any(cid in checks_ids for cid in criterion.get("linked_checks", [])):
            continue
        passed, observed = _evaluate_criterion(
            criterion, task, checks, signal, review, adapter_check_result, direct_exit, deps_installed,
            execution_id, artifacts, output_dir,
        )
        acceptance_results.append(
            {
                "id": criterion["id"],
                "predicate_id": criterion["predicate_id"],
                "parameters": criterion["parameters"],
                "passed": passed,
                "observed": observed,
                "evidence_artifact_ids": list(evidence_ids),
            }
        )

    return checks, acceptance_results, artifacts


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
    session_id: Optional[str],
    session_error: Optional[str],
) -> Dict[str, Any]:
    self_report = signal.get("adapter_self_report")
    return {
        "schema_version": "1.0.0",
        "workflow_run_id": signal["workflow_run_id"],
        "workflow_run_attempt": signal["workflow_run_attempt"],
        "source_run_id": signal.get("source_run_id"),
        # The one explicit trusted subject SHA, threaded through unchanged
        # from the signal -- this is what the workflow's Check Run
        # publication step must use for `head_sha`, never `context.sha`
        # (which is the synthetic merge commit on `pull_request` events).
        "subject_sha": signal["trusted_subject_sha"],
        "execution_id": result["execution_id"],
        # Whether `execution_id` above is the adapter's own real session_id
        # or the deterministic Actions-run-derived fallback (never random).
        "execution_id_source": "adapter_session" if session_id is not None else "pipeline_derived",
        "adapter_session_id": session_id,
        "session_resolution_error": session_error,
        "task_id": result["task_id"],
        "check_run_conclusion": check_run_conclusion,
        "verification_id": verification["verification_id"],
        "verification_passed": verification["passed"],
        "raw_provider_terminal_reason": signal.get("raw_provider_terminal_reason"),
        "adapter_self_reported_status": self_report["status"] if self_report else None,
        "actions_job_conclusion": signal.get("actions_job_conclusion"),
        "adapter_attempted": signal["adapter_attempted"],
        "artifacts_count": len(result["artifacts"]),
        "new_commit": bool(result["authored_commits"]),
        "result_artifact_present": signal["result_artifact_present"],
        "required_evidence_artifact_present": signal["required_evidence_artifact_present"],
        # Exact task control commit and exact fetched review-attestation
        # commit, threaded through unchanged from the signal when available
        # (AC-C5). Never fabricated: absent when the corresponding fetch
        # step did not resolve one.
        "task_commit": signal.get("task_commit"),
        "review_attestation_commit": signal.get("review_attestation_commit"),
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
    execution_id, session_id, session_error = resolve_execution_identity(signal)
    adapter_check_result = resolve_adapter_registered_command_result(
        signal.get("execution_file_content"), signal.get("adapter_registered_command")
    )
    classification = classify_terminal(signal, session_error, adapter_check_result)
    observation = build_trusted_observation(signal, classification, execution_id)
    observation_path = _write_json(output_dir / "observation.json", observation)

    candidate_spec = signal.get("untrusted_candidate")
    candidate_path: Optional[Path] = None
    if candidate_spec is not None:
        candidate_path = _write_json(output_dir / "candidate.json", candidate_spec)

    # The existing, unmodified B1 finalizer still runs exactly as before,
    # writing its own raw result under a nested `b1-raw/` subdirectory of
    # this same evidence root so its candidate-evidence path convention
    # (`evidence/<sha>.raw`, relative to *its own* output dir) never
    # collides with the additional evidence this correction writes directly
    # under `output_dir/evidence/`. Its `checks`/`acceptance_results` are
    # always empty (a known B1 bootstrap limitation this correction cannot
    # fix by editing the denied `tools/finalize_b1.py`); the authoritative,
    # enriched `result.json` this pipeline actually publishes and verifies
    # is built immediately below from that same raw result plus real,
    # directly observed check/acceptance evidence -- never by modifying B1.
    b1_output_dir = output_dir / "b1-raw"
    finalize_report = b1_finalize(observation_path, candidate_path, b1_output_dir)
    b1_result_path = Path(finalize_report["result_path"])
    b1_result = load_json(b1_result_path)

    task_doc: Optional[Mapping[str, Any]] = None
    try:
        task_doc = _load_bounded_json(task_path, "task document")
    except B3PropagatorError:
        task_doc = None
    review_doc: Optional[Mapping[str, Any]] = None
    try:
        review_doc = _load_bounded_json(review_path, "review-attestation document")
    except B3PropagatorError:
        review_doc = None

    checks, acceptance_results, extra_artifacts = build_checks_and_acceptance(
        task_doc, review_doc, signal, adapter_check_result, execution_id, output_dir
    )
    # B1 candidate-evidence artifact paths are relative to its own nested
    # `b1-raw/` output dir; rewritten here so they still resolve correctly
    # against the one shared evidence root (`output_dir`) this pipeline's
    # verification step actually reads from.
    rebased_b1_artifacts = [
        {**artifact, "path": "b1-raw/{}".format(artifact["path"])} for artifact in b1_result["artifacts"]
    ]
    result = dict(b1_result)
    result["artifacts"] = rebased_b1_artifacts + extra_artifacts
    result["checks"] = checks
    result["acceptance_results"] = acceptance_results
    result_errors = sorted(error.message for error in _RESULT_VALIDATOR.iter_errors(result))
    if result_errors:
        raise B3PropagatorError(
            "enriched result failed result.v1 schema validation: {}".format("; ".join(result_errors))
        )
    result_path = output_dir / "result.json"
    _publish_exclusive(result_path, canonical_bytes(result))

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
    # Bound to the one explicit trusted subject SHA the signal carries --
    # never derived from the (possibly nulled, for missing_commit
    # classification) `git_observation.head_sha`, and never `context.sha`
    # or any other value a caller could substitute.
    expected_subject_sha = signal["trusted_subject_sha"]
    invocation = Invocation(
        verification_id=verification_id,
        evaluated_at=evaluated_at,
        expected_task_id=signal["task_id"],
        expected_execution_id=execution_id,
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
    metadata = build_workflow_run_metadata(
        signal, result, verification, check_run_conclusion, session_id, session_error
    )
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
    try:
        outputs = run_pipeline(
            signal_path,
            task_path,
            review_path,
            verifier_identity_path,
            invocation["verification_id"],
            invocation["evaluated_at"],
            output_dir,
        )
    except B3PropagatorError as exc:
        # Issue #27 v3 correction: a trusted input that fails closed before
        # a result can even be finalized -- e.g. a provider signal whose
        # `started_at` is not RFC 3339 (`load_provider_signal`'s own
        # mandatory `_require_rfc3339_utc` check) -- must still surface as
        # one failed fixture-oracle scenario with `check_run_conclusion:
        # "failure"`, not an uncaught exception that aborts the entire
        # suite. This is deliberately narrow: only `B3PropagatorError`
        # (this tool's own fail-closed input/policy exception) is caught
        # here; a real programming defect still raises and fails loudly.
        actual = {
            "status": "failed",
            "terminal_reason": None,
            "check_run_conclusion": "failure",
            "timeout_origin": None,
            "missing_artifact_type": None,
            "source_run_id": None,
            "raw_provider_terminal_reason": None,
            "artifacts_count": None,
            "new_commit": None,
            "adapter_self_reported_status": None,
            "actions_job_conclusion": None,
            "execution_id_source": None,
            "adapter_session_id": None,
            "pipeline_error": str(exc),
        }
        expected = fixture["expected"]
        expectation_met = all(actual.get(key) == value for key, value in expected.items())
        return {"id": fixture["id"], "actual": actual, "expected": expected, "expectation_met": expectation_met}

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
        "execution_id_source": outputs.workflow_run_metadata["execution_id_source"],
        "adapter_session_id": outputs.workflow_run_metadata["adapter_session_id"],
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
        # AC-B3-3 corrective invariant: `execution_id` is never a random,
        # unaccountable value. It must equal either the resolved adapter
        # session id or the deterministic pipeline-derived fallback -- both
        # tracked on the published metadata -- never anything else.
        raw_signal = _load_bounded_json(signal_path, "provider signal")
        expected_fallback = derive_pipeline_execution_id(
            raw_signal["workflow_run_id"], raw_signal["workflow_run_attempt"], raw_signal["attempt"]
        )
        if outputs.result["execution_id"] not in (
            outputs.workflow_run_metadata["adapter_session_id"],
            expected_fallback,
        ):
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
