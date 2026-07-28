#!/usr/bin/env python3
"""Unprivileged, fail-closed Gate 1 candidate client.

This module is candidate-controlled.  It never performs privileged operations,
selects an authorization, opens a repository path, or executes another program.
The trusted default-branch controller supplies a canonical sealed context on
file descriptor 3 and a single finite broker channel on file descriptor 4.
The client can only request the manifest-bound operation sequence below.

Nothing emitted by this process is authorization or a final Gate 1 verdict.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import sys
from typing import Any, BinaryIO, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


CONTEXT_FD = 3
PROTOCOL_FD = 4
MAX_CONTEXT_BYTES = 512 * 1024
MAX_FRAME_BYTES = 64 * 1024
MAX_TRANSCRIPT_FRAMES = 24
PROTOCOL_VERSION = "g1-broker-v1"
CONTEXT_VERSION = "g1v1"
EVIDENCE_SCHEMA_VERSION = "2.0.0"
CANDIDATE_NOTICE = (
    "candidate report only; trusted control-plane evidence owns Gate 1 disposition"
)

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
LABEL_RE = re.compile(r"^g1v1-([0-9a-f]{40})-([123c])$")
TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$"
)
LABEL_COLOR_RE = re.compile(r"^[0-9a-f]{6}$")

PHASES = ("1", "2", "3", "c")
NORMAL_CASES = (
    "success",
    "nonzero",
    "signal",
    "timeout",
    "background-child",
    "setsid-child",
    "double-fork-setsid",
    "retained-writer",
    "fd-tamper",
    "writer-handoff",
    "invalid-output",
    "output-flood",
    "fork-limit",
    "memory-limit",
    "nofile-limit",
    "fsize-limit",
    "tmpfs-limit",
    "sandbox-probe",
    "crash-storm",
)
CANCELLATION_CASE = "operator-cancel"
APPROVED_CANDIDATE_PATHS = (
    ".github/workflows/p0-v2-runner-feasibility.yml",
    "contracts/schemas/p0-v2-runner-feasibility-evidence.v1.schema.json",
    "tests/test_b3_p0_v2_runner_feasibility.py",
    "tools/p0_v2_runner_probe.py",
)
OBSOLETE_SCHEMA_PATH = "contracts/p0-v2-runner-evidence.schema.json"
EXPECTED_REPOSITORY = "yurikuchumov-ux/ai-operating-system"
EXPECTED_REPOSITORY_ID = 1296950956
EXPECTED_OWNER_LOGIN = "yurikuchumov-ux"
EXPECTED_OWNER_ID = 299144523
EXPECTED_ISSUE_NUMBER = 70
EXPECTED_PR_NUMBER = 71
EXPECTED_CANDIDATE_BRANCH = "agent/issue-70-p0-v2-feasibility-gate1"

ALLOWED_ENVIRONMENT = {
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
    "P0V2_CANDIDATE": "1",
    "PYTHONHASHSEED": "0",
}
FORBIDDEN_ENVIRONMENT_NAMES = {
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_RESULTS_URL",
    "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_RUNTIME_URL",
    "BASH_ENV",
    "DOCKER_HOST",
    "GITHUB_ENV",
    "GITHUB_OUTPUT",
    "GITHUB_PATH",
    "GITHUB_STATE",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "SSH_AUTH_SOCK",
}
FORBIDDEN_SOCKET_PATHS = (
    "/run/dbus/system_bus_socket",
    "/run/docker.sock",
    "/run/systemd/private",
    "/var/run/dbus/system_bus_socket",
    "/var/run/docker.sock",
)


class CandidateError(RuntimeError):
    """A deterministic, non-authoritative candidate failure."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _reject_duplicate_pairs(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CandidateError("JSON_DUPLICATE_KEY", key)
        result[key] = value
    return result


def _reject_float(value: str) -> None:
    raise CandidateError("JSON_NUMBER_REJECTED", value)


def strict_json_loads(payload: bytes, *, limit: int) -> Any:
    if not payload or len(payload) > limit:
        raise CandidateError("JSON_SIZE_INVALID", str(len(payload)))
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CandidateError("JSON_NOT_UTF8", str(exc.start)) from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
    except CandidateError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise CandidateError("JSON_INVALID", str(exc)) from exc
    _validate_json_tree(value, depth=0)
    return value


def _validate_json_tree(value: Any, *, depth: int) -> None:
    if depth > 32:
        raise CandidateError("JSON_DEPTH_EXCEEDED", str(depth))
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if not -(2**53 - 1) <= value <= 2**53 - 1:
            raise CandidateError("JSON_INTEGER_RANGE", str(value))
        return
    if isinstance(value, list):
        if len(value) > 4096:
            raise CandidateError("JSON_ARRAY_TOO_LARGE", str(len(value)))
        for item in value:
            _validate_json_tree(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 4096:
            raise CandidateError("JSON_OBJECT_TOO_LARGE", str(len(value)))
        for key, item in value.items():
            if not isinstance(key, str):
                raise CandidateError("JSON_KEY_NOT_STRING", repr(key))
            _validate_json_tree(item, depth=depth + 1)
        return
    raise CandidateError("JSON_TYPE_REJECTED", type(value).__name__)


def canonical_json_bytes(value: Any) -> bytes:
    _validate_json_tree(value, depth=0)
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise CandidateError("CONTEXT_TYPE", label)
    return value


def _exact_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    expected_set = set(expected)
    actual = set(value)
    if actual != expected_set:
        missing = sorted(expected_set - actual)
        extra = sorted(actual - expected_set)
        raise CandidateError(
            "CONTEXT_KEYS", f"{label}:missing={missing!r}:extra={extra!r}"
        )


def _string(value: Any, label: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise CandidateError("CONTEXT_STRING", label)
    if any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
        raise CandidateError("CONTEXT_STRING_ASCII", label)
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise CandidateError("CONTEXT_INTEGER", label)
    return value


def _sha1(value: Any, label: str) -> str:
    text = _string(value, label, maximum=40)
    if SHA1_RE.fullmatch(text) is None:
        raise CandidateError("CONTEXT_SHA1", label)
    return text


def _sha256(value: Any, label: str) -> str:
    text = _string(value, label, maximum=64)
    if SHA256_RE.fullmatch(text) is None:
        raise CandidateError("CONTEXT_SHA256", label)
    return text


def parse_label(value: Any) -> Tuple[str, str]:
    label = _string(value, "authorization.label", maximum=47)
    match = LABEL_RE.fullmatch(label)
    if match is None or len(label.encode("ascii")) != 47:
        raise CandidateError("LABEL_INVALID", label)
    return match.group(1), match.group(2)


def validate_sealed_context(value: Any) -> Mapping[str, Any]:
    context = _mapping(value, "context")
    _exact_keys(
        context,
        (
            "context_version",
            "authorization",
            "candidate",
            "control",
            "event",
            "workflow",
            "digests",
            "snapshots",
            "synthetic_merge",
            "staging",
            "replay",
        ),
        "context",
    )
    if context["context_version"] != CONTEXT_VERSION:
        raise CandidateError("CONTEXT_VERSION", repr(context["context_version"]))

    authorization = _mapping(context["authorization"], "authorization")
    _exact_keys(
        authorization,
        ("version", "phase", "label", "trusted_main_sha"),
        "authorization",
    )
    if authorization["version"] != CONTEXT_VERSION:
        raise CandidateError("AUTHORIZATION_VERSION", repr(authorization["version"]))
    if authorization["phase"] not in PHASES:
        raise CandidateError("AUTHORIZATION_PHASE", repr(authorization["phase"]))
    label_sha, label_phase = parse_label(authorization["label"])
    trusted_main_sha = _sha1(
        authorization["trusted_main_sha"], "authorization.trusted_main_sha"
    )
    if (label_sha, label_phase) != (trusted_main_sha, authorization["phase"]):
        raise CandidateError("AUTHORIZATION_LABEL_MISMATCH", authorization["label"])

    candidate = _mapping(context["candidate"], "candidate")
    _exact_keys(
        candidate,
        (
            "origin_base_sha",
            "head_sha",
            "parent_sha",
            "tree_sha",
            "repository",
            "repository_id",
            "head_repository",
            "head_repository_id",
            "owner_login",
            "owner_id",
            "same_repository",
            "no_fork",
            "branch",
            "pr_number",
            "paths",
        ),
        "candidate",
    )
    for name in ("origin_base_sha", "head_sha", "parent_sha", "tree_sha"):
        _sha1(candidate[name], f"candidate.{name}")
    for name in ("repository", "head_repository", "owner_login", "branch"):
        _string(candidate[name], f"candidate.{name}", maximum=255)
    for name in ("repository_id", "head_repository_id", "owner_id", "pr_number"):
        _positive_int(candidate[name], f"candidate.{name}")
    if candidate["same_repository"] is not True or candidate["no_fork"] is not True:
        raise CandidateError("CANDIDATE_FORK_REJECTED", "same_repository/no_fork")
    if candidate["repository"] != candidate["head_repository"]:
        raise CandidateError("CANDIDATE_REPOSITORY_MISMATCH", "repository")
    if candidate["repository_id"] != candidate["head_repository_id"]:
        raise CandidateError("CANDIDATE_REPOSITORY_MISMATCH", "repository_id")
    if (
        candidate["repository"] != EXPECTED_REPOSITORY
        or candidate["repository_id"] != EXPECTED_REPOSITORY_ID
        or candidate["owner_login"] != EXPECTED_OWNER_LOGIN
        or candidate["owner_id"] != EXPECTED_OWNER_ID
        or candidate["branch"] != EXPECTED_CANDIDATE_BRANCH
        or candidate["pr_number"] != EXPECTED_PR_NUMBER
    ):
        raise CandidateError("CANDIDATE_IDENTITY", "repository/owner/branch/pr")
    if candidate["head_sha"] == candidate["parent_sha"]:
        raise CandidateError("CANDIDATE_HISTORY", "head equals parent")
    paths = candidate["paths"]
    if not isinstance(paths, list) or len(paths) != len(APPROVED_CANDIDATE_PATHS):
        raise CandidateError("CANDIDATE_PATHS", "cardinality")
    path_names: List[str] = []
    for index, item_value in enumerate(paths):
        item = _mapping(item_value, f"candidate.paths[{index}]")
        _exact_keys(item, ("path", "mode", "git_blob_sha", "sha256"), "candidate.path")
        path_names.append(_string(item["path"], "candidate.path", maximum=255))
        if item["mode"] != "100644":
            raise CandidateError("CANDIDATE_MODE", path_names[-1])
        _sha1(item["git_blob_sha"], "candidate.git_blob_sha")
        _sha256(item["sha256"], "candidate.sha256")
    if tuple(path_names) != APPROVED_CANDIDATE_PATHS:
        raise CandidateError("CANDIDATE_PATHS", repr(path_names))
    if OBSOLETE_SCHEMA_PATH in path_names:
        raise CandidateError("OBSOLETE_SCHEMA_PATH", OBSOLETE_SCHEMA_PATH)

    control = _mapping(context["control"], "control")
    _exact_keys(
        control,
        (
            "repository",
            "repository_id",
            "owner_login",
            "owner_id",
            "issue_number",
            "issue_id",
            "issue_node_id",
            "issue_state",
            "issue_is_pull_request",
            "live_pr_base_sha",
        ),
        "control",
    )
    for name in ("repository", "owner_login", "issue_node_id"):
        _string(control[name], f"control.{name}", maximum=255)
    for name in ("repository_id", "owner_id", "issue_number", "issue_id"):
        _positive_int(control[name], f"control.{name}")
    if control["issue_state"] != "open" or control["issue_is_pull_request"] is not False:
        raise CandidateError("ISSUE_STATE", "expected open non-PR issue")
    if control["issue_number"] != EXPECTED_ISSUE_NUMBER:
        raise CandidateError("ISSUE_IDENTITY", repr(control["issue_number"]))
    _sha1(control["live_pr_base_sha"], "control.live_pr_base_sha")
    if control["repository"] != candidate["repository"]:
        raise CandidateError("CONTROL_REPOSITORY_MISMATCH", "repository")
    if control["repository_id"] != candidate["repository_id"]:
        raise CandidateError("CONTROL_REPOSITORY_MISMATCH", "repository_id")
    if control["owner_login"] != candidate["owner_login"]:
        raise CandidateError("CONTROL_OWNER_MISMATCH", "owner_login")
    if control["owner_id"] != candidate["owner_id"]:
        raise CandidateError("CONTROL_OWNER_MISMATCH", "owner_id")

    event = _mapping(context["event"], "event")
    _exact_keys(
        event,
        (
            "name",
            "action",
            "event_path_sha256",
            "issue_event_id",
            "issue_event_node_id",
            "label_id",
            "label_node_id",
            "label_name",
            "label_color",
            "label_description",
            "label_default",
            "created_at",
            "actor_login",
            "actor_id",
            "triggering_actor_login",
            "triggering_actor_id",
            "sender_login",
            "sender_id",
            "run_id",
            "run_attempt",
            "run_created_at",
            "boot_id",
        ),
        "event",
    )
    if event["name"] != "issues" or event["action"] != "labeled":
        raise CandidateError("EVENT_KIND", f"{event['name']}/{event['action']}")
    _sha256(event["event_path_sha256"], "event.event_path_sha256")
    for name in (
        "issue_event_id",
        "label_id",
        "actor_id",
        "triggering_actor_id",
        "sender_id",
        "run_id",
    ):
        _positive_int(event[name], f"event.{name}")
    _positive_int(event["run_attempt"], "event.run_attempt")
    if event["run_attempt"] != 1:
        raise CandidateError("RUN_ATTEMPT", repr(event["run_attempt"]))
    for name in (
        "issue_event_node_id",
        "label_node_id",
        "label_color",
        "actor_login",
        "triggering_actor_login",
        "sender_login",
        "boot_id",
    ):
        _string(event[name], f"event.{name}", maximum=255)
    if event["label_description"] is not None:
        _string(event["label_description"], "event.label_description", maximum=1024)
    if not isinstance(event["label_default"], bool):
        raise CandidateError("LABEL_DEFAULT", repr(event["label_default"]))
    if LABEL_COLOR_RE.fullmatch(event["label_color"]) is None:
        raise CandidateError("LABEL_COLOR", repr(event["label_color"]))
    if event["label_name"] != authorization["label"]:
        raise CandidateError("EVENT_LABEL_MISMATCH", repr(event["label_name"]))
    for login_field, id_field in (
        ("actor_login", "actor_id"),
        ("triggering_actor_login", "triggering_actor_id"),
        ("sender_login", "sender_id"),
    ):
        if (
            event[login_field] != EXPECTED_OWNER_LOGIN
            or event[id_field] != EXPECTED_OWNER_ID
        ):
            raise CandidateError(
                "EVENT_OWNER_MISMATCH", f"{login_field}/{id_field}"
            )
    for name in ("created_at", "run_created_at"):
        timestamp = _string(event[name], f"event.{name}", maximum=40)
        if TIMESTAMP_RE.fullmatch(timestamp) is None:
            raise CandidateError("TIMESTAMP_INVALID", f"event.{name}")

    workflow = _mapping(context["workflow"], "workflow")
    _exact_keys(
        workflow,
        ("path", "ref", "sha", "blob_sha", "github_ref", "github_workflow_sha"),
        "workflow",
    )
    if workflow["path"] != ".github/workflows/p0-v2-gate1-trusted-canary.yml":
        raise CandidateError("WORKFLOW_PATH", repr(workflow["path"]))
    expected_ref = (
        f"{candidate['repository']}/{workflow['path']}@refs/heads/main"
    )
    if workflow["ref"] != expected_ref:
        raise CandidateError("WORKFLOW_REF", repr(workflow["ref"]))
    for name in ("sha", "blob_sha", "github_workflow_sha"):
        _sha1(workflow[name], f"workflow.{name}")
    if workflow["sha"] != trusted_main_sha or workflow["github_workflow_sha"] != trusted_main_sha:
        raise CandidateError("WORKFLOW_SHA_MISMATCH", "trusted main")
    if workflow["github_ref"] != "refs/heads/main":
        raise CandidateError("WORKFLOW_GITHUB_REF", repr(workflow["github_ref"]))

    digests = _mapping(context["digests"], "digests")
    _exact_keys(
        digests,
        (
            "authorization_manifest",
            "controller",
            "broker_protocol",
            "candidate_probe",
            "evidence_schema",
            "synthetic_merge_tool",
            "synthetic_merge_normalization",
        ),
        "digests",
    )
    for name, digest in digests.items():
        _sha256(digest, f"digests.{name}")

    snapshots = _mapping(context["snapshots"], "snapshots")
    _exact_keys(
        snapshots,
        ("pre_acquisition_sha256", "pre_broker_sha256", "post_cleanup_sha256"),
        "snapshots",
    )
    _sha256(snapshots["pre_acquisition_sha256"], "snapshots.pre_acquisition")
    _sha256(snapshots["pre_broker_sha256"], "snapshots.pre_broker")
    if snapshots["post_cleanup_sha256"] is not None:
        raise CandidateError("POST_CLEANUP_PREMATURE", "must be null before candidate")

    synthetic = _mapping(context["synthetic_merge"], "synthetic_merge")
    _exact_keys(
        synthetic,
        (
            "sha",
            "ordered_parents",
            "tree_sha",
            "algorithm",
            "tool_version_sha256",
            "normalization_sha256",
            "construction_manifest_sha256",
            "conflict",
            "exact_tree_proof_sha256",
        ),
        "synthetic_merge",
    )
    values = list(synthetic.values())
    if any(value is not None for value in values):
        if any(value is None for value in values):
            raise CandidateError("SYNTHETIC_MERGE_PARTIAL", "mixed null/non-null")
        _sha1(synthetic["sha"], "synthetic_merge.sha")
        _sha1(synthetic["tree_sha"], "synthetic_merge.tree_sha")
        parents = synthetic["ordered_parents"]
        if not isinstance(parents, list) or len(parents) != 2:
            raise CandidateError("SYNTHETIC_MERGE_PARENTS", repr(parents))
        for index, parent in enumerate(parents):
            _sha1(parent, f"synthetic_merge.ordered_parents[{index}]")
        if parents != [trusted_main_sha, candidate["head_sha"]]:
            raise CandidateError(
                "SYNTHETIC_MERGE_PARENTS",
                "expected trusted main then candidate head",
            )
        if synthetic["algorithm"] != "git-merge-tree-write-tree-v1":
            raise CandidateError(
                "SYNTHETIC_MERGE_ALGORITHM", repr(synthetic["algorithm"])
            )
        for name in (
            "tool_version_sha256",
            "normalization_sha256",
            "construction_manifest_sha256",
        ):
            _sha256(synthetic[name], f"synthetic_merge.{name}")
        if (
            synthetic["construction_manifest_sha256"]
            != digests["authorization_manifest"]
        ):
            raise CandidateError(
                "SYNTHETIC_MERGE_MANIFEST", "authorization manifest mismatch"
            )
        if synthetic["tool_version_sha256"] != digests["synthetic_merge_tool"]:
            raise CandidateError(
                "SYNTHETIC_MERGE_TOOL", "manifest-bound tool digest mismatch"
            )
        if (
            synthetic["normalization_sha256"]
            != digests["synthetic_merge_normalization"]
        ):
            raise CandidateError(
                "SYNTHETIC_MERGE_NORMALIZATION",
                "manifest-bound normalization digest mismatch",
            )
        if synthetic["conflict"] is not False:
            raise CandidateError("SYNTHETIC_MERGE_CONFLICT", repr(synthetic["conflict"]))
        _sha256(
            synthetic["exact_tree_proof_sha256"],
            "synthetic_merge.exact_tree_proof_sha256",
        )

    staging = context["staging"]
    if not isinstance(staging, list) or not staging:
        raise CandidateError("STAGING_INVALID", "empty")
    staged_names: Set[str] = set()
    for index, item_value in enumerate(staging):
        item = _mapping(item_value, f"staging[{index}]")
        _exact_keys(
            item,
            ("name", "device", "inode", "size", "mode", "link_count", "sha256"),
            "staging.item",
        )
        name = _string(item["name"], "staging.name", maximum=128)
        if name in staged_names:
            raise CandidateError("STAGING_DUPLICATE", name)
        staged_names.add(name)
        for field in ("device", "inode", "size"):
            _positive_int(item[field], f"staging.{name}.{field}")
        if isinstance(item["link_count"], bool) or item["link_count"] != 1:
            raise CandidateError("STAGING_LINK_COUNT", name)
        if item["mode"] not in ("0400", "0444", "0500", "0555"):
            raise CandidateError("STAGING_MODE", name)
        _sha256(item["sha256"], f"staging.{name}.sha256")

    replay = _mapping(context["replay"], "replay")
    _exact_keys(
        replay,
        (
            "phase_consumed",
            "prior_phase_labels",
            "prior_run_ids",
            "overlapping_run",
            "sequence_sha256",
        ),
        "replay",
    )
    if replay["phase_consumed"] is not False or replay["overlapping_run"] is not False:
        raise CandidateError("REPLAY_STATE", "consumed/overlapping")
    prior_labels = replay["prior_phase_labels"]
    prior_runs = replay["prior_run_ids"]
    if not isinstance(prior_labels, list) or not isinstance(prior_runs, list):
        raise CandidateError("REPLAY_LIST", "prior values")
    if len(prior_labels) != len(set(prior_labels)):
        raise CandidateError("REPLAY_DUPLICATE", "labels")
    if len(prior_runs) != len(set(prior_runs)):
        raise CandidateError("REPLAY_DUPLICATE", "runs")
    for label in prior_labels:
        prior_sha, prior_phase = parse_label(label)
        if prior_sha != trusted_main_sha or prior_phase == authorization["phase"]:
            raise CandidateError("REPLAY_LABEL", label)
    for run_id in prior_runs:
        _positive_int(run_id, "replay.prior_run_id")
        if run_id == event["run_id"]:
            raise CandidateError("REPLAY_RUN_ID", str(run_id))
    expected_prior_phases = {
        "1": [],
        "2": ["1"],
        "3": ["1", "2"],
        "c": ["1", "2", "3"],
    }[authorization["phase"]]
    actual_prior_phases = [parse_label(label)[1] for label in prior_labels]
    if actual_prior_phases != expected_prior_phases:
        raise CandidateError(
            "REPLAY_PHASE_SEQUENCE",
            f"expected={expected_prior_phases!r}:actual={actual_prior_phases!r}",
        )
    if len(prior_runs) != len(expected_prior_phases):
        raise CandidateError("REPLAY_RUN_SEQUENCE", repr(prior_runs))
    _sha256(replay["sequence_sha256"], "replay.sequence_sha256")

    return context


def validate_environment(environment: Mapping[str, str]) -> None:
    actual = dict(environment)
    forbidden = sorted(name for name in actual if name in FORBIDDEN_ENVIRONMENT_NAMES)
    if forbidden:
        raise CandidateError("FORBIDDEN_ENVIRONMENT", ",".join(forbidden))
    if actual != ALLOWED_ENVIRONMENT:
        missing = sorted(set(ALLOWED_ENVIRONMENT) - set(actual))
        extra = sorted(set(actual) - set(ALLOWED_ENVIRONMENT))
        wrong = sorted(
            name
            for name in set(actual) & set(ALLOWED_ENVIRONMENT)
            if actual[name] != ALLOWED_ENVIRONMENT[name]
        )
        raise CandidateError(
            "ENVIRONMENT_NOT_MINIMAL",
            f"missing={missing!r}:extra={extra!r}:wrong={wrong!r}",
        )


def validate_proc_status(status_text: str) -> None:
    fields: Dict[str, str] = {}
    for line in status_text.splitlines():
        if ":" in line:
            name, value = line.split(":", 1)
            if name in fields:
                raise CandidateError("PROC_STATUS_DUPLICATE", name)
            fields[name] = value.strip()
    for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        if fields.get(name) != "0000000000000000":
            raise CandidateError("CAPABILITY_NOT_EMPTY", f"{name}={fields.get(name)!r}")
    if fields.get("NoNewPrivs") != "1":
        raise CandidateError("NO_NEW_PRIVS_MISSING", repr(fields.get("NoNewPrivs")))
    if fields.get("Seccomp") != "2":
        raise CandidateError("SECCOMP_FILTER_MISSING", repr(fields.get("Seccomp")))
    groups = fields.get("Groups", "").split()
    if groups:
        raise CandidateError("SUPPLEMENTARY_GROUPS", repr(groups))
    nspid = fields.get("NSpid", "").split()
    if len(nspid) < 2:
        raise CandidateError("PID_NAMESPACE_MISSING", repr(nspid))


def validate_open_fds(fd_links: Mapping[int, str]) -> None:
    if set(fd_links) != {0, 1, 2, CONTEXT_FD, PROTOCOL_FD}:
        raise CandidateError("FD_SET_INVALID", repr(sorted(fd_links)))
    if not (
        fd_links[0] == "/dev/null" or fd_links[0].startswith("pipe:[")
    ):
        raise CandidateError("STDIN_FD_TYPE", fd_links[0])
    for fd in (1, 2):
        if not fd_links[fd].startswith("pipe:["):
            raise CandidateError("CAPTURE_FD_TYPE", f"{fd}:{fd_links[fd]}")
    if not fd_links[CONTEXT_FD].startswith(("pipe:[", "/memfd:", "memfd:")):
        raise CandidateError("CONTEXT_FD_TYPE", fd_links[CONTEXT_FD])
    if not fd_links[PROTOCOL_FD].startswith("socket:["):
        raise CandidateError("PROTOCOL_FD_TYPE", fd_links[PROTOCOL_FD])
    for fd, target in fd_links.items():
        if fd >= CONTEXT_FD and target.startswith("/"):
            raise CandidateError("WRITABLE_PATH_FD", f"{fd}:{target}")


def collect_fd_links(proc_fd_path: str = "/proc/self/fd") -> Dict[int, str]:
    result: Dict[int, str] = {}
    try:
        entries = os.listdir(proc_fd_path)
    except OSError as exc:
        raise CandidateError("FD_ENUMERATION_FAILED", str(exc)) from exc
    for entry in entries:
        if not entry.isdecimal():
            raise CandidateError("FD_NAME_INVALID", entry)
        fd = int(entry)
        try:
            result[fd] = os.readlink(f"{proc_fd_path}/{entry}")
        except FileNotFoundError:
            # The directory iterator itself may transiently occupy an fd.
            continue
        except OSError as exc:
            raise CandidateError("FD_READLINK_FAILED", entry) from exc
    return result


def validate_runtime() -> Dict[str, Any]:
    if os.geteuid() == 0 or os.getuid() == 0:
        raise CandidateError("ROOT_EXECUTION_FORBIDDEN", "candidate uid/euid is zero")
    if os.getegid() == 0 or os.getgid() == 0:
        raise CandidateError("ROOT_GROUP_FORBIDDEN", "candidate gid/egid is zero")
    validate_environment(os.environ)
    try:
        with open("/proc/self/status", "r", encoding="ascii", errors="strict") as handle:
            validate_proc_status(handle.read())
    except OSError as exc:
        raise CandidateError("PROC_STATUS_UNAVAILABLE", str(exc)) from exc
    fd_links = collect_fd_links()
    validate_open_fds(fd_links)
    exposed = [path for path in FORBIDDEN_SOCKET_PATHS if os.path.exists(path)]
    if exposed:
        raise CandidateError("HOST_SOCKET_VISIBLE", ",".join(exposed))
    return {
        "uid": os.getuid(),
        "gid": os.getgid(),
        "fd_targets_sha256": sha256_bytes(
            canonical_json_bytes({str(key): value for key, value in fd_links.items()})
        ),
        "environment_sha256": sha256_bytes(canonical_json_bytes(dict(os.environ))),
    }


def _read_exact(fd: int, count: int) -> bytes:
    chunks: List[bytes] = []
    remaining = count
    while remaining:
        chunk = os.read(fd, remaining)
        if not chunk:
            raise CandidateError("UNEXPECTED_EOF", str(remaining))
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_length_prefixed(fd: int, *, maximum: int) -> bytes:
    header = _read_exact(fd, 4)
    length = struct.unpack(">I", header)[0]
    if length <= 0 or length > maximum:
        raise CandidateError("FRAME_LENGTH_INVALID", str(length))
    return _read_exact(fd, length)


def write_length_prefixed(fd: int, payload: bytes, *, maximum: int) -> None:
    if not payload or len(payload) > maximum:
        raise CandidateError("FRAME_LENGTH_INVALID", str(len(payload)))
    message = struct.pack(">I", len(payload)) + payload
    view = memoryview(message)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise CandidateError("FRAME_WRITE_FAILED", str(len(view)))
        view = view[written:]


def _request(
    seq: int, op: str, context_sha256: str, case: Optional[str] = None
) -> Dict[str, Any]:
    request: Dict[str, Any] = {
        "v": PROTOCOL_VERSION,
        "seq": seq,
        "op": op,
        "context_sha256": context_sha256,
    }
    if case is not None:
        request["case"] = case
    return request


def operation_sequence(phase: str, context_sha256: str) -> List[Dict[str, Any]]:
    if phase not in PHASES:
        raise CandidateError("AUTHORIZATION_PHASE", repr(phase))
    _sha256(context_sha256, "protocol.context_sha256")
    operations: List[Tuple[str, Optional[str]]] = [
        ("HELLO", None),
        ("PREFLIGHT", None),
    ]
    if phase == "c":
        operations.extend(
            (("RUN_CASE", CANCELLATION_CASE), ("WAIT_CANCELLATION", None))
        )
    else:
        operations.extend(("RUN_CASE", case) for case in NORMAL_CASES)
        operations.append(("FINISH", None))
    if len(operations) > MAX_TRANSCRIPT_FRAMES:
        raise CandidateError("PROTOCOL_OPERATION_COUNT", str(len(operations)))
    return [
        _request(index + 1, op, context_sha256, case)
        for index, (op, case) in enumerate(operations)
    ]


def validate_response(response: Any, request: Mapping[str, Any]) -> Mapping[str, Any]:
    item = _mapping(response, "broker.response")
    _exact_keys(
        item,
        ("v", "seq", "op", "ok", "record_sha256"),
        "broker.response",
    )
    if item["v"] != PROTOCOL_VERSION:
        raise CandidateError("PROTOCOL_VERSION", repr(item["v"]))
    if (
        isinstance(item["seq"], bool)
        or not isinstance(item["seq"], int)
        or not isinstance(item["op"], str)
    ):
        raise CandidateError("PROTOCOL_TYPE", repr(item))
    if item["seq"] != request["seq"] or item["op"] != request["op"]:
        raise CandidateError("PROTOCOL_ORDER", repr(item))
    if item["ok"] is not True:
        raise CandidateError("BROKER_REJECTED", str(request["op"]))
    _sha256(item["record_sha256"], "broker.record_sha256")
    return item


def exchange_protocol(
    protocol_fd: int, context: Mapping[str, Any], context_payload: bytes
) -> List[Dict[str, Any]]:
    context_sha256 = sha256_bytes(context_payload)
    transcript: List[Dict[str, Any]] = []
    for request in operation_sequence(context["authorization"]["phase"], context_sha256):
        request_payload = canonical_json_bytes(request)
        write_length_prefixed(protocol_fd, request_payload, maximum=MAX_FRAME_BYTES)
        response_payload = read_length_prefixed(protocol_fd, maximum=MAX_FRAME_BYTES)
        response = strict_json_loads(response_payload, limit=MAX_FRAME_BYTES)
        if canonical_json_bytes(response) != response_payload:
            raise CandidateError("PROTOCOL_RESPONSE_NOT_CANONICAL", str(request["seq"]))
        validated = dict(validate_response(response, request))
        transcript.append(
            {
                "request_sha256": sha256_bytes(request_payload),
                "response_sha256": sha256_bytes(response_payload),
                "record_sha256": validated["record_sha256"],
                "seq": request["seq"],
                "op": request["op"],
            }
        )
        if request["op"] == "WAIT_CANCELLATION":
            raise CandidateError(
                "CANCELLATION_WAIT_RETURNED",
                "trusted controller must terminate the waiting candidate",
            )
    return transcript


def build_candidate_report(
    context: Mapping[str, Any],
    context_payload: bytes,
    transcript: Sequence[Mapping[str, Any]],
    runtime: Mapping[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "evidence_kind": "p0-v2-gate1-unprivileged-candidate-report",
        "candidate_notice": CANDIDATE_NOTICE,
        "authorization_version": context["authorization"]["version"],
        "phase": context["authorization"]["phase"],
        "label": context["authorization"]["label"],
        "sealed_context_sha256": sha256_bytes(context_payload),
        "candidate_head_sha": context["candidate"]["head_sha"],
        "trusted_control_main_sha": context["authorization"]["trusted_main_sha"],
        "live_pr_base_sha": context["control"]["live_pr_base_sha"],
        "run_id": context["event"]["run_id"],
        "run_attempt": context["event"]["run_attempt"],
        "runtime": dict(runtime),
        "transcript": [dict(item) for item in transcript],
        "transcript_sha256": sha256_bytes(canonical_json_bytes(list(transcript))),
        "outcome": "CANDIDATE_REPORT_COMPLETE",
    }


def run_client(
    *,
    context_fd: int = CONTEXT_FD,
    protocol_fd: int = PROTOCOL_FD,
    output: Optional[BinaryIO] = None,
    runtime: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    if output is None:
        output = sys.stdout.buffer
    runtime_evidence = dict(runtime) if runtime is not None else validate_runtime()
    context_payload = read_length_prefixed(context_fd, maximum=MAX_CONTEXT_BYTES)
    context_value = strict_json_loads(context_payload, limit=MAX_CONTEXT_BYTES)
    context = validate_sealed_context(context_value)
    canonical_context = canonical_json_bytes(context)
    if canonical_context != context_payload:
        raise CandidateError("SEALED_CONTEXT_NOT_CANONICAL", "byte mismatch")
    transcript = exchange_protocol(protocol_fd, context, context_payload)
    report = build_candidate_report(
        context, context_payload, transcript, runtime_evidence
    )
    output.write(canonical_json_bytes(report) + b"\n")
    output.flush()
    return report


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments:
        raise CandidateError("ARGUMENTS_FORBIDDEN", repr(arguments))
    run_client()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CandidateError as exc:
        sys.stderr.write(
            canonical_json_bytes(
                {
                    "candidate_error": exc.code,
                    "detail_sha256": sha256_bytes(exc.detail.encode("utf-8")),
                }
            ).decode("ascii")
            + "\n"
        )
        raise SystemExit(2)
