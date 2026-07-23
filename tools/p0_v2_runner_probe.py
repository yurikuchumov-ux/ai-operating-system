#!/usr/bin/env python3
"""P0 v2 Gate 1: fail-closed GitHub-hosted runner substrate probe.

This is candidate feasibility code, not a production sandbox and not an
authoritative GATE1_* decision maker.  It deliberately uses only the Python
standard library.  The trusted supervisor runs as root, while every hostile
fixture runs in a systemd-created DynamicUser service and one cgroup-v2
subtree.  Child output is captured through protected non-seekable FIFOs and
is never copied to the Actions command parser.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import errno
import hashlib
import json
import mmap
import os
import re
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple


SCHEMA_VERSION = "1.0.0"
EVIDENCE_KIND = "p0-v2-runner-feasibility-candidate"
CANDIDATE_NOTICE = (
    "candidate evidence only; an independent reviewer owns the GATE1_* decision"
)
REQUIRED_IDENTITY_NAMES = {
    "github.repository",
    "github.pr_number",
    "github.event_action",
    "github.workflow",
    "github.workflow_ref",
    "github.workflow_sha",
    "github.event_name",
    "github.run_id",
    "github.run_attempt",
    "github.pr_head_sha",
    "github.pr_head_repository",
    "github.pr_head_ref",
    "github.pr_base_sha",
    "github.pr_base_repository",
    "github.pr_base_ref",
    "github.pr_merge_sha",
    "runner.image",
    "runner.arch",
    "runner.boot_id",
}
REQUIRED_SOURCE_NAMES = {
    "source.probe_sha256",
    "source.schema_sha256",
    "source.workflow_sha256",
    "source.test_sha256",
    "source.task_commit",
    "source.task_sha256",
}
JOURNAL_PHASES = {
    "initialized",
    "core_pattern_original_recorded",
    "core_pattern_suppressed",
    "case_bound",
    "fixture_released",
    "finalizer_bound",
    "cgroup_kill_written",
    "cgroup_empty_observed",
    "stream_eof_observed",
    "unit_unloaded",
    "core_pattern_restored",
    "evidence_sealed",
}
CONTROL_TASK_COMMIT = "e0587c2e3134c30f761206689191f6de822c491a"
CONTROL_TASK_SHA256 = "0886b8125c66d3ad9fa22f271978ebc3e8cab726cacbaff0cab65caf0e604934"
ROOT_RUNTIME = Path("/run/p0-v2-gate1")
CGROUP_ROOT = Path("/sys/fs/cgroup")
CORE_PATTERN_PATH = Path("/proc/sys/kernel/core_pattern")
MAX_RETAINED_COMBINED = 1024 * 1024
MAX_TOTAL_COMBINED = 8 * 1024 * 1024
CASE_TIMEOUT_SECONDS = 20.0
CLEANUP_TIMEOUT_SECONDS = 10.0

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA64_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
SAFE_UNIT_RE = re.compile(r"^p0-v2-g1-[a-z0-9-]{1,96}\.service$")
SAFE_CGROUP_RE = re.compile(r"^/system\.slice/p0-v2-g1-[a-z0-9-]{1,96}\.service$")

OUTCOMES = {
    "SETUP_ERROR",
    "SUCCESS",
    "NONZERO_EXIT",
    "SIGNAL",
    "TIMEOUT",
    "ACTIONS_CANCELLED",
    "OUTPUT_LIMIT",
    "RESOURCE_OOM",
    "CLEANUP_FAILURE",
    "EMPTY_PROOF_FAILURE",
    "CAPTURE_FAILURE",
    "EVIDENCE_SEAL_FAILURE",
    "INCONCLUSIVE",
}

CASES = (
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

EXPECTED_CASE_OUTCOMES = {
    "success": "SUCCESS",
    "nonzero": "NONZERO_EXIT",
    "signal": "SIGNAL",
    "timeout": "TIMEOUT",
    "background-child": "SUCCESS",
    "setsid-child": "SUCCESS",
    "double-fork-setsid": "SUCCESS",
    "retained-writer": "SUCCESS",
    "fd-tamper": "SUCCESS",
    "writer-handoff": "SUCCESS",
    "invalid-output": "SUCCESS",
    "output-flood": "OUTPUT_LIMIT",
    "fork-limit": "SUCCESS",
    "memory-limit": "RESOURCE_OOM",
    "nofile-limit": "SUCCESS",
    "fsize-limit": "SIGNAL",
    "tmpfs-limit": "SUCCESS",
    "sandbox-probe": "SUCCESS",
    "crash-storm": "SUCCESS",
    "operator-cancel": "ACTIONS_CANCELLED",
}

REQUESTED_ENVIRONMENT = {
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
}

SYSTEMD_OPTIONAL_ENVIRONMENT = {
    "INVOCATION_ID": re.compile(r"^[0-9a-f]{32}$"),
    "SYSTEMD_EXEC_PID": re.compile(r"^[1-9][0-9]*$"),
    "MEMORY_PRESSURE_WATCH": re.compile(r"^/.+$"),
    "MEMORY_PRESSURE_WRITE": re.compile(r"^.+$"),
}

FORBIDDEN_ENV_PREFIXES = (
    "ACTIONS_",
    "CI",
    "GITHUB_",
    "INPUT_",
    "RUNNER_",
    "ACTIONS_ID_TOKEN_",
)

SYSTEMD_PROPERTIES_BASE = (
    "RemainAfterExit=yes",
    "DynamicUser=yes",
    "SetLoginEnvironment=no",
    "SupplementaryGroups=",
    "NoNewPrivileges=yes",
    "CapabilityBoundingSet=",
    "AmbientCapabilities=",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "PrivateMounts=yes",
    "PrivateDevices=yes",
    "DevicePolicy=closed",
    "PrivateNetwork=yes",
    "PrivateIPC=yes",
    "ProtectProc=invisible",
    "ProcSubset=pid",
    "ProtectControlGroups=yes",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectKernelLogs=yes",
    "ProtectClock=yes",
    "ProtectHostname=yes",
    "RestrictAddressFamilies=none",
    "RestrictNamespaces=yes",
    "RestrictSUIDSGID=yes",
    "LockPersonality=yes",
    "RestrictRealtime=yes",
    "MemoryDenyWriteExecute=yes",
    "SystemCallArchitectures=native",
    "SystemCallFilter=~@mount @privileged @raw-io @reboot @swap bpf perf_event_open io_uring_setup io_uring_enter io_uring_register keyctl add_key request_key",
    "KeyringMode=private",
    "RemoveIPC=yes",
    "UMask=0077",
    "KillMode=control-group",
    "SendSIGKILL=yes",
    "TimeoutStopSec=3s",
    "RuntimeMaxSec=120s",
    "TasksMax=64",
    "MemoryMax=256M",
    "MemorySwapMax=0",
    "MemoryOOMGroup=yes",
    "OOMPolicy=kill",
    "CPUQuota=100%",
    "LimitNOFILE=128",
    "LimitFSIZE=8M",
    "LimitCORE=0",
    "TemporaryFileSystem=/tmp:rw,nodev,nosuid,noexec,size=8M",
    "TemporaryFileSystem=/var/tmp:rw,nodev,nosuid,noexec,size=8M",
)

SYSTEMD_SHOW_PROPERTIES = (
    "Type",
    "DynamicUser",
    "User",
    "Group",
    "SetLoginEnvironment",
    "SupplementaryGroups",
    "NoNewPrivileges",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "ProtectSystem",
    "ProtectHome",
    "PrivateMounts",
    "PrivateDevices",
    "DevicePolicy",
    "PrivateNetwork",
    "PrivateIPC",
    "ProtectProc",
    "ProcSubset",
    "ProtectControlGroups",
    "ProtectKernelTunables",
    "ProtectKernelModules",
    "ProtectKernelLogs",
    "ProtectClock",
    "ProtectHostname",
    "RestrictAddressFamilies",
    "RestrictNamespaces",
    "RestrictSUIDSGID",
    "LockPersonality",
    "RestrictRealtime",
    "MemoryDenyWriteExecute",
    "SystemCallArchitectures",
    "SystemCallFilter",
    "KeyringMode",
    "RemoveIPC",
    "UMask",
    "KillMode",
    "SendSIGKILL",
    "TimeoutStopUSec",
    "RuntimeMaxUSec",
    "TasksMax",
    "MemoryMax",
    "MemorySwapMax",
    "MemoryOOMGroup",
    "OOMPolicy",
    "CPUQuotaPerSecUSec",
    "TemporaryFileSystem",
    "LimitNOFILE",
    "LimitFSIZE",
    "LimitCORE",
    "InvocationID",
    "ControlGroup",
    "MainPID",
    "WorkingDirectory",
)

REQUIRED_SYSTEMD_VALUES = {
    "DynamicUser": "yes",
    "SetLoginEnvironment": "no",
    "SupplementaryGroups": "",
    "NoNewPrivileges": "yes",
    "CapabilityBoundingSet": "",
    "AmbientCapabilities": "",
    "ProtectSystem": "strict",
    "ProtectHome": "yes",
    "PrivateMounts": "yes",
    "PrivateDevices": "yes",
    "DevicePolicy": "closed",
    "PrivateNetwork": "yes",
    "PrivateIPC": "yes",
    "ProtectProc": "invisible",
    "ProcSubset": "pid",
    "ProtectControlGroups": "yes",
    "ProtectKernelTunables": "yes",
    "ProtectKernelModules": "yes",
    "ProtectKernelLogs": "yes",
    "ProtectClock": "yes",
    "ProtectHostname": "yes",
    "RestrictAddressFamilies": "",
    "RestrictNamespaces": "yes",
    "RestrictSUIDSGID": "yes",
    "LockPersonality": "yes",
    "RestrictRealtime": "yes",
    "MemoryDenyWriteExecute": "yes",
    "SystemCallArchitectures": "native",
    "KeyringMode": "private",
    "RemoveIPC": "yes",
    "UMask": "0077",
    "KillMode": "control-group",
    "SendSIGKILL": "yes",
    "TimeoutStopUSec": "3s",
    "RuntimeMaxUSec": "2min",
    "TasksMax": "64",
    "MemoryMax": "268435456",
    "MemorySwapMax": "0",
    "MemoryOOMGroup": "yes",
    "OOMPolicy": "kill",
    "CPUQuotaPerSecUSec": "1s",
    "LimitNOFILE": "128",
    "LimitFSIZE": "8388608",
    "LimitCORE": "0",
}


class ProbeError(RuntimeError):
    """A fail-closed candidate-probe failure with a stable code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail[:1000]


def observation(name: str, authority: str, value: Any) -> Dict[str, Any]:
    return {"name": name, "authority": authority, "value": value}


def error_record(code: str, detail: str, authority: str = "supervisor_observed") -> Dict[str, str]:
    return {"code": code, "authority": authority, "detail": detail[:1000]}


def lifecycle_event(name: str) -> Dict[str, Any]:
    return {
        "name": name,
        "monotonic_ns": time.monotonic_ns(),
        "authority": "supervisor_observed",
    }


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_safe_token(name: str, value: str) -> str:
    if not SAFE_TOKEN_RE.fullmatch(value):
        raise ProbeError("INVALID_INPUT", f"{name} is not a safe fixed token")
    return value


def validate_sha40(name: str, value: str) -> str:
    if not SHA40_RE.fullmatch(value):
        raise ProbeError("INVALID_INPUT", f"{name} is not a canonical 40-hex SHA")
    return value


def _json_type_matches(instance: Any, expected: str) -> bool:
    mapping = {
        "null": type(None),
        "boolean": bool,
        "number": (int, float),
        "integer": int,
        "string": str,
        "array": list,
        "object": dict,
    }
    if expected in {"integer", "number"} and isinstance(instance, bool):
        return False
    return isinstance(instance, mapping[expected])


def validate_schema_instance(instance: Any, schema: Mapping[str, Any], root: Mapping[str, Any], path: str = "$") -> None:
    """Validate the deliberately small JSON-Schema subset used by Gate 1."""

    if "$ref" in schema:
        ref = schema["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            raise ProbeError("SCHEMA_UNSUPPORTED", f"{path}: unsupported ref")
        target: Any = root
        for part in ref[2:].split("/"):
            target = target[part.replace("~1", "/").replace("~0", "~")]
        validate_schema_instance(instance, target, root, path)
        return
    for sub in schema.get("allOf", []):
        validate_schema_instance(instance, sub, root, path)
    if "const" in schema and instance != schema["const"]:
        raise ProbeError("SCHEMA_INVALID", f"{path}: const mismatch")
    if "enum" in schema and instance not in schema["enum"]:
        raise ProbeError("SCHEMA_INVALID", f"{path}: enum mismatch")
    expected = schema.get("type")
    if expected is not None:
        expected_types = [expected] if isinstance(expected, str) else expected
        if not any(_json_type_matches(instance, item) for item in expected_types):
            raise ProbeError("SCHEMA_INVALID", f"{path}: type mismatch")
    if isinstance(instance, str):
        if "pattern" in schema and re.fullmatch(schema["pattern"], instance) is None:
            raise ProbeError("SCHEMA_INVALID", f"{path}: pattern mismatch")
        if len(instance) < schema.get("minLength", 0):
            raise ProbeError("SCHEMA_INVALID", f"{path}: shorter than minLength")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            raise ProbeError("SCHEMA_INVALID", f"{path}: longer than maxLength")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            raise ProbeError("SCHEMA_INVALID", f"{path}: below minimum")
        if "maximum" in schema and instance > schema["maximum"]:
            raise ProbeError("SCHEMA_INVALID", f"{path}: above maximum")
    if isinstance(instance, list):
        if len(instance) < schema.get("minItems", 0):
            raise ProbeError("SCHEMA_INVALID", f"{path}: too few items")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            raise ProbeError("SCHEMA_INVALID", f"{path}: too many items")
        if schema.get("uniqueItems"):
            encoded_items = [canonical_json_bytes(item) for item in instance]
            if len(encoded_items) != len(set(encoded_items)):
                raise ProbeError("SCHEMA_INVALID", f"{path}: duplicate items")
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(instance):
                validate_schema_instance(item, item_schema, root, f"{path}[{index}]")
    if isinstance(instance, dict):
        required = schema.get("required", [])
        missing = [key for key in required if key not in instance]
        if missing:
            raise ProbeError("SCHEMA_INVALID", f"{path}: missing {','.join(missing)}")
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        if additional is False:
            unknown = sorted(set(instance) - set(properties))
            if unknown:
                raise ProbeError("SCHEMA_INVALID", f"{path}: unknown {','.join(unknown)}")
        for key, value in instance.items():
            if key in properties:
                validate_schema_instance(value, properties[key], root, f"{path}.{key}")
            elif isinstance(additional, Mapping):
                validate_schema_instance(value, additional, root, f"{path}.{key}")


def validate_evidence(evidence: Mapping[str, Any], schema_path: Path) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validate_schema_instance(evidence, schema, schema)
    events = [item["monotonic_ns"] for item in evidence["lifecycle"]]
    if events != sorted(events):
        raise ProbeError("SCHEMA_INVALID", "lifecycle is not monotonic")
    for collection_name in ("identity", "source", "host"):
        names = [item["name"] for item in evidence[collection_name]]
        if len(names) != len(set(names)):
            raise ProbeError("SCHEMA_INVALID", f"{collection_name}: duplicate observation")
    if {item["name"] for item in evidence["identity"]} != REQUIRED_IDENTITY_NAMES:
        raise ProbeError("SCHEMA_INVALID", "identity: wrong observation set")
    if {item["name"] for item in evidence["source"]} != REQUIRED_SOURCE_NAMES:
        raise ProbeError("SCHEMA_INVALID", "source: wrong observation set")
    controls = evidence["controls"]
    for collection_name in ("requested", "systemd_reported", "effective_observed"):
        values = controls[collection_name]
        if not values:
            raise ProbeError("SCHEMA_INVALID", f"controls.{collection_name}: empty")
        names = [item["name"] for item in values]
        if len(names) != len(set(names)):
            raise ProbeError(
                "SCHEMA_INVALID",
                f"controls.{collection_name}: duplicate observation",
            )
    serialized = canonical_json_bytes(evidence)
    if b"reviewer_api_observed" in serialized:
        raise ProbeError(
            "SCHEMA_INVALID",
            "candidate evidence cannot claim reviewer authority",
        )
    case_ids = [case["id"] for case in evidence["cases"]]
    if len(case_ids) != len(set(case_ids)):
        raise ProbeError("SCHEMA_INVALID", "duplicate case id")
    for case in evidence["cases"]:
        if case["finished_monotonic_ns"] < case["started_monotonic_ns"]:
            raise ProbeError("SCHEMA_INVALID", f"{case['id']}: time reversed")
        cleanup = case["cleanup"]
        if cleanup["unit_unloaded_after_empty"] and not cleanup["recursive_populated_zero_observed"]:
            raise ProbeError("SCHEMA_INVALID", f"{case['id']}: unload before empty proof")
        if cleanup["streams_eof_after_empty"] and not cleanup["recursive_populated_zero_observed"]:
            raise ProbeError("SCHEMA_INVALID", f"{case['id']}: EOF before empty proof")
    if evidence["outcome"] == "SUCCESS":
        if case_ids != list(CASES):
            raise ProbeError("SCHEMA_INVALID", "SUCCESS requires exact normal case set")
        if evidence["errors"] or any(case["errors"] for case in evidence["cases"]):
            raise ProbeError("SCHEMA_INVALID", "SUCCESS cannot contain errors")
        for case in evidence["cases"]:
            cleanup = case["cleanup"]
            if case["outcome"] != EXPECTED_CASE_OUTCOMES[case["id"]]:
                raise ProbeError("SCHEMA_INVALID", f"{case['id']}: outcome mismatch")
            if case["requested_argv"] != case["kernel_observed_argv"]:
                raise ProbeError("SCHEMA_INVALID", f"{case['id']}: argv mismatch")
            if not environment_contract_satisfied(
                case["requested_environment"],
                case["kernel_observed_environment"],
            ):
                raise ProbeError("SCHEMA_INVALID", f"{case['id']}: environment mismatch")
            if not all(
                (
                    cleanup["direct_cgroup_kill_written"],
                    cleanup["recursive_populated_zero_observed"],
                    cleanup["streams_eof_after_empty"],
                    cleanup["unit_unloaded_after_empty"],
                )
            ):
                raise ProbeError("SCHEMA_INVALID", f"{case['id']}: cleanup incomplete")
        if not all(
            item["value"] is True
            for item in controls["effective_observed"]
            if isinstance(item["value"], bool)
        ):
            raise ProbeError("SCHEMA_INVALID", "SUCCESS has false effective control")
        expected_lifecycle = [
            "supervisor_started",
            "host_preflight_complete",
            "core_pattern_suppressed",
        ]
        per_case_lifecycle = [
            "unit_created",
            "bootstrap_observed",
            "hostile_released",
            "outcome_observed",
            "cgroup_kill_written",
            "cgroup_empty_observed",
            "streams_eof_observed",
            "unit_unloaded",
        ]
        for _ in CASES:
            expected_lifecycle.extend(per_case_lifecycle)
        expected_lifecycle.append("core_pattern_restored")
        if [item["name"] for item in evidence["lifecycle"]] != expected_lifecycle:
            raise ProbeError("SCHEMA_INVALID", "SUCCESS lifecycle mismatch")
    if evidence["outcome"] == "ACTIONS_CANCELLED":
        cancellation = evidence["cancellation"]
        if case_ids != ["operator-cancel"]:
            raise ProbeError("SCHEMA_INVALID", "cancellation requires exact case")
        if evidence["errors"] or evidence["cases"][0]["errors"]:
            raise ProbeError("SCHEMA_INVALID", "cancellation cannot contain errors")
        if (
            not cancellation["finalizer_ran"]
            or not cancellation["same_vm_cleanup_observed"]
            or cancellation["claim_type"] != "ordinary_github_cancellation"
        ):
            raise ProbeError("SCHEMA_INVALID", "cancellation proof incomplete")
        cancelled_case = evidence["cases"][0]
        cancelled_cleanup = cancelled_case["cleanup"]
        if (
            cancelled_case["outcome"] != "ACTIONS_CANCELLED"
            or cancelled_case["requested_argv"]
            != cancelled_case["kernel_observed_argv"]
            or not environment_contract_satisfied(
                cancelled_case["requested_environment"],
                cancelled_case["kernel_observed_environment"],
            )
            or not all(
                (
                    cancelled_cleanup["direct_cgroup_kill_written"],
                    cancelled_cleanup["recursive_populated_zero_observed"],
                    cancelled_cleanup["streams_eof_after_empty"],
                    cancelled_cleanup["unit_unloaded_after_empty"],
                )
            )
            or not all(
                item["value"] is True
                for item in controls["effective_observed"]
                if isinstance(item["value"], bool)
            )
        ):
            raise ProbeError("SCHEMA_INVALID", "cancellation witness incomplete")
        expected_lifecycle = [
            "finalizer_started",
            "cgroup_kill_written",
            "cgroup_empty_observed",
            "streams_eof_observed",
            "unit_unloaded",
            "core_pattern_restored",
            "finalizer_complete",
        ]
        if [item["name"] for item in evidence["lifecycle"]] != expected_lifecycle:
            raise ProbeError("SCHEMA_INVALID", "cancellation lifecycle mismatch")


def write_atomic_owned(path: Path, payload: bytes, uid: int, gid: int) -> None:
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise ProbeError("EVIDENCE_WRITE_FAILED", path.name)
            view = view[written:]
        os.fchown(fd, uid, gid)
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)


def atomic_seal(path: Path, evidence: Mapping[str, Any], schema_path: Path, uid: int, gid: int) -> str:
    validate_evidence(evidence, schema_path)
    payload = canonical_json_bytes(evidence)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    digest = sha256_bytes(payload)
    manifest_path = path.with_suffix(path.suffix + ".manifest.json")
    manifest = {
        "manifest_version": "1.0.0",
        "evidence_file": path.name,
        "evidence_sha256": digest,
        "identity": evidence["identity"],
        "source": evidence["source"],
    }
    write_atomic_owned(path, payload, uid, gid)
    write_atomic_owned(
        manifest_path,
        canonical_json_bytes(manifest),
        uid,
        gid,
    )
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return digest


def run_command(argv: Sequence[str], *, timeout: float = 20.0, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        list(argv),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if check and completed.returncode != 0:
        raise ProbeError(
            "HOST_COMMAND_FAILED",
            f"{argv[0]} exited {completed.returncode}: {completed.stderr[:400]!r}",
        )
    return completed


def read_text(path: Path, limit: int = 1024 * 1024) -> str:
    data = path.read_bytes()
    if len(data) > limit:
        raise ProbeError("HOST_OBSERVATION_TOO_LARGE", str(path))
    return data.decode("utf-8", "replace")


def systemctl_value(unit: str, property_name: str) -> str:
    return run_command(
        ["/usr/bin/systemctl", "show", unit, f"--property={property_name}", "--value"]
    ).stdout.decode("utf-8", "replace").strip()


def parse_systemd_int(property_name: str, raw: str) -> int:
    try:
        return int(raw, 10)
    except ValueError as exc:
        raise ProbeError(
            "SYSTEMD_PROPERTY_INVALID",
            f"{property_name} expected integer, observed {raw!r}",
        ) from exc


def classify_systemd_outcome(result: str, code: int, status_value: int) -> str:
    if result == "oom-kill":
        return "RESOURCE_OOM"
    if code == os.CLD_EXITED and status_value == 0:
        return "SUCCESS"
    if code == os.CLD_EXITED:
        return "NONZERO_EXIT"
    if code in {os.CLD_KILLED, os.CLD_DUMPED}:
        return "SIGNAL"
    raise ProbeError(
        "SYSTEMD_EXIT_CODE_UNSUPPORTED",
        f"ExecMainCode={code} ExecMainStatus={status_value}",
    )


def systemctl_properties(unit: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for name in SYSTEMD_SHOW_PROPERTIES:
        result[name] = systemctl_value(unit, name)
    return result


def validate_systemd_properties(
    properties: Mapping[str, str],
    expected_working_directory: Path,
) -> None:
    for name, expected in REQUIRED_SYSTEMD_VALUES.items():
        observed = properties.get(name)
        if observed != expected:
            raise ProbeError(
                "SYSTEMD_PROPERTY_INEFFECTIVE",
                f"{name}: expected {expected!r}, observed {observed!r}",
            )
    if not properties.get("SystemCallFilter"):
        raise ProbeError("SYSTEMD_PROPERTY_INEFFECTIVE", "SystemCallFilter empty")
    temporary_filesystems = properties.get("TemporaryFileSystem", "")
    for required_mount in ("/tmp:", "/var/tmp:", "size=8M", "noexec"):
        if required_mount not in temporary_filesystems:
            raise ProbeError(
                "SYSTEMD_PROPERTY_INEFFECTIVE",
                f"TemporaryFileSystem missing {required_mount}",
            )
    if properties.get("WorkingDirectory") != str(expected_working_directory):
        raise ProbeError(
            "SYSTEMD_PROPERTY_INEFFECTIVE",
            f"WorkingDirectory={properties.get('WorkingDirectory')!r}",
        )


def unload_unit(unit: str, timeout: float = CLEANUP_TIMEOUT_SECONDS) -> None:
    stop_result = run_command(
        ["/usr/bin/systemctl", "stop", unit],
        check=False,
    )
    reset_result = run_command(
        ["/usr/bin/systemctl", "reset-failed", unit],
        check=False,
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        completed = run_command(
            ["/usr/bin/systemctl", "show", unit, "--property=LoadState", "--value"],
            check=False,
        )
        load_state = completed.stdout.decode("utf-8", "replace").strip()
        if completed.returncode != 0 or load_state == "not-found":
            return
        time.sleep(0.05)
    if stop_result.returncode != 0 or reset_result.returncode != 0:
        raise ProbeError(
            "UNIT_UNLOAD_COMMAND_FAILED",
            (
                f"stop={stop_result.returncode} "
                f"reset={reset_result.returncode}"
            ),
        )
    raise ProbeError("UNIT_UNLOAD_NOT_OBSERVED", unit)


def state_path_for(run_id: str, run_attempt: str) -> Path:
    validate_safe_token("run_id", run_id)
    validate_safe_token("run_attempt", run_attempt)
    return ROOT_RUNTIME / f"state-{run_id}-{run_attempt}.json"


def write_root_state(path: Path, state: Mapping[str, Any]) -> None:
    payload = canonical_json_bytes(state)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def load_root_state(path: Path) -> Dict[str, Any]:
    st = path.stat()
    if st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600:
        raise ProbeError("STATE_UNTRUSTED", "state record is not root-owned mode 0600")
    value = json.loads(path.read_text(encoding="utf-8"))
    required = {
        "journal_version",
        "phase",
        "run_id",
        "run_attempt",
        "head_sha",
        "source_sha256",
        "schema_sha256",
        "workflow_file_sha256",
        "test_file_sha256",
        "evidence_dir",
        "schema_path",
        "core_pattern_original_base64",
        "core_pattern_original_recorded",
        "core_pattern_active_base64",
        "coredump_before",
        "active_case",
        "terminal_evidence_sha256",
    }
    if set(value) != required:
        raise ProbeError("STATE_UNTRUSTED", "state record fields mismatch")
    if value["journal_version"] != 1:
        raise ProbeError("STATE_UNTRUSTED", "unsupported journal version")
    if value["phase"] not in JOURNAL_PHASES:
        raise ProbeError("STATE_UNTRUSTED", "unsupported journal phase")
    if not isinstance(value["core_pattern_original_recorded"], bool):
        raise ProbeError("STATE_UNTRUSTED", "invalid core record state")
    for digest_name in (
        "source_sha256",
        "schema_sha256",
        "workflow_file_sha256",
        "test_file_sha256",
    ):
        if not SHA64_RE.fullmatch(value[digest_name]):
            raise ProbeError("STATE_UNTRUSTED", f"unsafe {digest_name}")
    validate_sha40("head_sha", value["head_sha"])
    for key in ("core_pattern_original_base64", "core_pattern_active_base64"):
        try:
            base64.b64decode(value[key], validate=True)
        except (ValueError, TypeError) as exc:
            raise ProbeError("STATE_UNTRUSTED", f"invalid {key}") from exc
    active_case = value["active_case"]
    if active_case is not None:
        required_case = {
            "unit",
            "invocation_id",
            "cgroup_path",
            "cgroup_device",
            "cgroup_inode",
            "dynamic_uid",
            "dynamic_gid",
            "main_pid",
            "nonce",
            "stdout_fifo",
            "stdout_fifo_device",
            "stdout_fifo_inode",
            "stderr_fifo",
            "stderr_fifo_device",
            "stderr_fifo_inode",
            "state_dir",
            "exec_dir",
            "staged_probe",
            "staged_probe_device",
            "staged_probe_inode",
            "staged_probe_mode",
            "staged_probe_uid",
            "staged_probe_gid",
            "host_tmp_sentinel",
            "host_tmp_sentinel_sha256",
            "requested_argv",
            "kernel_observed_argv",
            "kernel_observed_argv_raw_base64",
            "requested_environment",
            "kernel_observed_environment",
            "kernel_observed_environment_raw_base64",
            "capture_fd_identity",
        }
        if set(active_case) != required_case:
            raise ProbeError("STATE_UNTRUSTED", "active case fields mismatch")
        if not SAFE_UNIT_RE.fullmatch(active_case["unit"]):
            raise ProbeError("STATE_UNTRUSTED", "unsafe unit name")
        if not SAFE_CGROUP_RE.fullmatch(active_case["cgroup_path"]):
            raise ProbeError("STATE_UNTRUSTED", "unsafe cgroup path")
        nonce = active_case["nonce"]
        if not re.fullmatch(r"[0-9a-f]{16}", nonce):
            raise ProbeError("STATE_UNTRUSTED", "unsafe nonce")
        expected_state_dir = ROOT_RUNTIME / f"case-{nonce}"
        expected_exec_dir = ROOT_RUNTIME / f"exec-{nonce}"
        if Path(active_case["state_dir"]) != expected_state_dir:
            raise ProbeError("STATE_UNTRUSTED", "unsafe state directory")
        if Path(active_case["exec_dir"]) != expected_exec_dir:
            raise ProbeError("STATE_UNTRUSTED", "unsafe executable directory")
        if Path(active_case["staged_probe"]) != expected_exec_dir / "probe.py":
            raise ProbeError("STATE_UNTRUSTED", "unsafe staged probe")
        for stream in ("stdout", "stderr"):
            if Path(active_case[f"{stream}_fifo"]) != expected_state_dir / f"{stream}.fifo":
                raise ProbeError("STATE_UNTRUSTED", f"unsafe {stream} fifo")
        if Path(active_case["host_tmp_sentinel"]) != Path("/tmp") / f"p0-v2-host-{nonce}":
            raise ProbeError("STATE_UNTRUSTED", "unsafe host sentinel")
        if not SHA64_RE.fullmatch(active_case["host_tmp_sentinel_sha256"]):
            raise ProbeError("STATE_UNTRUSTED", "unsafe sentinel digest")
        if not re.fullmatch(r"[0-9a-f]{32}", active_case["invocation_id"]):
            raise ProbeError("STATE_UNTRUSTED", "unsafe invocation id")
        if not isinstance(active_case["main_pid"], int) or active_case["main_pid"] <= 1:
            raise ProbeError("STATE_UNTRUSTED", "unsafe main pid")
        if not isinstance(active_case["capture_fd_identity"], dict):
            raise ProbeError("STATE_UNTRUSTED", "invalid capture fd identity")
        for raw_field in (
            "kernel_observed_argv_raw_base64",
            "kernel_observed_environment_raw_base64",
        ):
            if not isinstance(active_case[raw_field], list):
                raise ProbeError("STATE_UNTRUSTED", f"invalid {raw_field}")
            for item in active_case[raw_field]:
                try:
                    base64.b64decode(item, validate=True)
                except (ValueError, TypeError) as exc:
                    raise ProbeError(
                        "STATE_UNTRUSTED",
                        f"invalid {raw_field} item",
                    ) from exc
    return value


@dataclass
class StreamCapture:
    retained_limit: int
    digest: Any = field(default_factory=hashlib.sha256)
    byte_count: int = 0
    retained: bytearray = field(default_factory=bytearray)
    eof_observed: bool = False

    def feed(self, data: bytes) -> None:
        self.digest.update(data)
        self.byte_count += len(data)
        available = max(0, self.retained_limit - len(self.retained))
        if available:
            self.retained.extend(data[:available])

    def document(self) -> Dict[str, Any]:
        return {
            "authority": "supervisor_observed",
            "payload_authority": "child_untrusted",
            "byte_count": self.byte_count,
            "sha256": self.digest.hexdigest(),
            "retained_base64": base64.b64encode(bytes(self.retained)).decode("ascii"),
            "retained_byte_count": len(self.retained),
            "truncated": self.byte_count > len(self.retained),
            "eof_observed": self.eof_observed,
        }


def drain_streams(
    selector: selectors.BaseSelector,
    captures: MutableMapping[str, StreamCapture],
    *,
    wait: float,
) -> int:
    received = 0
    for key, _ in selector.select(wait):
        name = str(key.data)
        try:
            data = os.read(key.fd, 65536)
        except BlockingIOError:
            continue
        if data:
            captures[name].feed(data)
            received += len(data)
        else:
            captures[name].eof_observed = True
            selector.unregister(key.fd)
            os.close(key.fd)
    return received


def parse_proc_nul(path: Path) -> List[str]:
    raw = path.read_bytes()
    return [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]


def parse_proc_nul_raw(path: Path) -> List[bytes]:
    raw = path.read_bytes()
    if raw and not raw.endswith(b"\0"):
        raise ProbeError("PROC_NUL_RECORD_TRUNCATED", str(path))
    return [part for part in raw.split(b"\0") if part]


def parse_proc_environment(path: Path) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for item in parse_proc_nul(path):
        key, separator, value = item.partition("=")
        if separator:
            result[key] = value
    return result


def validate_observed_environment(
    raw_items: Sequence[bytes],
    requested: Mapping[str, str],
) -> Dict[str, str]:
    observed: Dict[str, str] = {}
    for raw_item in raw_items:
        key_bytes, separator, value_bytes = raw_item.partition(b"=")
        if not separator:
            raise ProbeError("ENVIRONMENT_ENTRY_MALFORMED", repr(raw_item[:200]))
        try:
            key = key_bytes.decode("ascii", "strict")
            value = value_bytes.decode("utf-8", "strict")
        except UnicodeError as exc:
            raise ProbeError("ENVIRONMENT_ENTRY_ENCODING_INVALID", repr(raw_item[:200])) from exc
        if key in observed:
            raise ProbeError("ENVIRONMENT_DUPLICATE_KEY", key)
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", key):
            raise ProbeError("ENVIRONMENT_KEY_INVALID", key)
        observed[key] = value
    for key, value in requested.items():
        if observed.get(key) != value:
            raise ProbeError(
                "ENVIRONMENT_REQUEST_MISMATCH",
                f"{key}: {observed.get(key)!r}",
            )
    extras = set(observed) - set(requested)
    if extras != set(SYSTEMD_OPTIONAL_ENVIRONMENT).intersection(observed):
        raise ProbeError("ENVIRONMENT_EXTRA_KEY", ",".join(sorted(extras)))
    for key in extras:
        if not SYSTEMD_OPTIONAL_ENVIRONMENT[key].fullmatch(observed[key]):
            raise ProbeError("ENVIRONMENT_OPTIONAL_VALUE_INVALID", key)
    for key in observed:
        if key.startswith(FORBIDDEN_ENV_PREFIXES):
            raise ProbeError("FORBIDDEN_ENVIRONMENT_VISIBLE", key)
    return observed


def environment_contract_satisfied(
    requested: Mapping[str, str],
    observed: Mapping[str, str],
) -> bool:
    try:
        raw_items = [
            f"{key}={value}".encode("utf-8")
            for key, value in observed.items()
        ]
        validate_observed_environment(raw_items, requested)
    except ProbeError:
        return False
    return True


def parse_status(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            result[key] = value.strip()
    return result


def read_cgroup_events(fd: int) -> Dict[str, int]:
    os.lseek(fd, 0, os.SEEK_SET)
    raw = os.read(fd, 4096).decode("ascii", "strict")
    result: Dict[str, int] = {}
    for line in raw.splitlines():
        key, value = line.split()
        result[key] = int(value)
    return result


def wait_cgroup_empty(events_fd: int, timeout: float = CLEANUP_TIMEOUT_SECONDS) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if read_cgroup_events(events_fd).get("populated") == 0:
            return True
        time.sleep(0.05)
    return False


def cgroup_resource_snapshot(cgroup_dir: Path) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for name in (
        "memory.current",
        "memory.peak",
        "memory.swap.current",
        "memory.events",
        "pids.current",
        "pids.peak",
        "pids.events",
        "cpu.stat",
    ):
        path = cgroup_dir / name
        if path.exists():
            result[name] = read_text(path, 65536).strip()
    return result


def parse_counter_file(raw: str) -> Dict[str, int]:
    result: Dict[str, int] = {}
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) == 2:
            result[fields[0]] = int(fields[1])
    return result


def safe_unit_name(run_id: str, case_id: str, nonce: str) -> str:
    validate_safe_token("run_id", run_id)
    if case_id not in CASES and case_id != "operator-cancel":
        raise ProbeError("INVALID_CASE", case_id)
    if not re.fullmatch(r"[0-9a-f]{16}", nonce):
        raise ProbeError("INVALID_NONCE", nonce)
    raw = f"p0-v2-g1-{run_id[-12:].lower()}-{case_id[:20]}-{nonce}.service"
    if not SAFE_UNIT_RE.fullmatch(raw):
        raise ProbeError("INVALID_UNIT", raw)
    return raw


def systemd_properties(
    state_dir: Path,
    staged_probe: Path,
    barrier: Path,
    stdout_fifo: Path,
    stderr_fifo: Path,
) -> List[str]:
    forbidden = (
        "CI GITHUB_ACTION GITHUB_ACTIONS GITHUB_ACTION_PATH GITHUB_ACTION_REPOSITORY "
        "GITHUB_ACTOR GITHUB_API_URL GITHUB_ENV GITHUB_EVENT_NAME GITHUB_EVENT_PATH "
        "GITHUB_GRAPHQL_URL GITHUB_HEAD_REF GITHUB_JOB GITHUB_OUTPUT GITHUB_PATH "
        "GITHUB_REF GITHUB_REPOSITORY GITHUB_RUN_ATTEMPT GITHUB_RUN_ID GITHUB_SHA "
        "GITHUB_STEP_SUMMARY GITHUB_TOKEN GITHUB_WORKFLOW GITHUB_WORKSPACE "
        "ACTIONS_CACHE_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL "
        "ACTIONS_RESULTS_URL RUNNER_ARCH RUNNER_DEBUG RUNNER_ENVIRONMENT RUNNER_NAME "
        "RUNNER_OS RUNNER_TEMP RUNNER_TOOL_CACHE"
    )
    return [
        *SYSTEMD_PROPERTIES_BASE,
        f"StandardInput=file:{barrier}",
        f"StandardOutput=file:{stdout_fifo}",
        f"StandardError=file:{stderr_fifo}",
        (
            f"InaccessiblePaths={state_dir} /run/systemd/private "
            "/run/docker.sock /var/run/docker.sock "
            "/run/containerd/containerd.sock"
        ),
        f"BindReadOnlyPaths={staged_probe}",
        f"WorkingDirectory={staged_probe.parent}",
        *(f"Environment={key}={value}" for key, value in REQUESTED_ENVIRONMENT.items()),
        f"UnsetEnvironment={forbidden}",
    ]


def render_systemd_run_argv(
    unit: str,
    interpreter: Path,
    staged_probe: Path,
    case_id: str,
    nonce: str,
    state_dir: Path,
    barrier: Path,
    stdout_fifo: Path,
    stderr_fifo: Path,
) -> List[str]:
    if not SAFE_UNIT_RE.fullmatch(unit):
        raise ProbeError("INVALID_UNIT", unit)
    if not interpreter.is_absolute() or not staged_probe.is_absolute():
        raise ProbeError("INVALID_EXECUTABLE", "absolute executable paths required")
    argv = [
        "/usr/bin/systemd-run",
        "--unit",
        unit.removesuffix(".service"),
        "--service-type=exec",
        "--no-block",
        "--quiet",
        "--expand-environment=no",
    ]
    for prop in systemd_properties(
        state_dir,
        staged_probe,
        barrier,
        stdout_fifo,
        stderr_fifo,
    ):
        argv.append(f"--property={prop}")
    argv.extend(
        [
            str(interpreter),
            "-I",
            str(staged_probe),
            "fixture",
            "--case",
            case_id,
            "--nonce",
            nonce,
        ]
    )
    return argv


def read_limited_bytes(path: Path, limit: int = 4096) -> bytes:
    value = path.read_bytes()
    if len(value) > limit:
        raise ProbeError("HOST_OBSERVATION_TOO_LARGE", str(path))
    return value


def write_kernel_setting(path: Path, value: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_TRUNC)
    try:
        offset = 0
        while offset < len(value):
            written = os.write(fd, value[offset:])
            if written <= 0:
                raise ProbeError("KERNEL_SETTING_WRITE_FAILED", str(path))
            offset += written
    finally:
        os.close(fd)


def suppress_core_pattern(state_path: Path, journal: MutableMapping[str, Any]) -> bytes:
    original = read_limited_bytes(CORE_PATTERN_PATH)
    journal["core_pattern_original_base64"] = base64.b64encode(original).decode("ascii")
    journal["core_pattern_original_recorded"] = True
    journal["core_pattern_active_base64"] = ""
    journal["phase"] = "core_pattern_original_recorded"
    write_root_state(state_path, journal)
    active = original
    if original.lstrip().startswith(b"|"):
        active = b"core\n"
        write_kernel_setting(CORE_PATTERN_PATH, active)
        observed = read_limited_bytes(CORE_PATTERN_PATH)
        if observed != active:
            raise ProbeError(
                "COREDUMP_SUPPRESSION_FAILED",
                "core_pattern write did not stick byte-for-byte",
            )
    journal["core_pattern_active_base64"] = base64.b64encode(active).decode("ascii")
    journal["phase"] = "core_pattern_suppressed"
    write_root_state(state_path, journal)
    return active


def restore_core_pattern(journal: MutableMapping[str, Any]) -> bytes:
    try:
        original = base64.b64decode(
            journal["core_pattern_original_base64"],
            validate=True,
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise ProbeError("COREDUMP_RESTORE_FAILED", "missing trusted original bytes") from exc
    observed = read_limited_bytes(CORE_PATTERN_PATH)
    if observed != original:
        write_kernel_setting(CORE_PATTERN_PATH, original)
        observed = read_limited_bytes(CORE_PATTERN_PATH)
    if observed != original:
        raise ProbeError(
            "COREDUMP_RESTORE_FAILED",
            "core_pattern restoration mismatch",
        )
    return observed


def filesystem_snapshot(paths: Sequence[Path]) -> List[Dict[str, Any]]:
    snapshot: List[Dict[str, Any]] = []
    for root in paths:
        candidates = [root]
        if root.is_dir():
            candidates.extend(sorted(root.iterdir(), key=lambda item: item.name))
        for candidate in candidates:
            try:
                observed = candidate.lstat()
            except OSError as exc:
                snapshot.append(
                    {
                        "path": str(candidate),
                        "error": f"{exc.errno}:{exc.strerror}",
                    }
                )
                continue
            item: Dict[str, Any] = {
                "path": str(candidate),
                "device": observed.st_dev,
                "inode": observed.st_ino,
                "mode": stat.S_IMODE(observed.st_mode),
                "uid": observed.st_uid,
                "gid": observed.st_gid,
                "size": observed.st_size,
                "mtime_ns": observed.st_mtime_ns,
                "type": stat.S_IFMT(observed.st_mode),
            }
            if stat.S_ISREG(observed.st_mode) and observed.st_size <= 1024 * 1024:
                item["sha256"] = sha256_path(candidate)
            snapshot.append(item)
    return snapshot


def coredump_effect_snapshot() -> Dict[str, Any]:
    config_paths = [Path("/etc/systemd/coredump.conf")]
    config_dir = Path("/etc/systemd/coredump.conf.d")
    if config_dir.is_dir():
        config_paths.extend(
            sorted(
                (
                    item
                    for item in config_dir.iterdir()
                    if item.is_file() or item.is_symlink()
                ),
                key=lambda item: item.name,
            )
        )
    package = run_command(
        ["/usr/bin/dpkg-query", "-W", "-f=${Status}\\t${Version}\\n", "systemd-coredump"],
        check=False,
    )
    units: Dict[str, Dict[str, Any]] = {}
    for unit in ("systemd-coredump.socket", "systemd-coredump.service"):
        completed = run_command(
            [
                "/usr/bin/systemctl",
                "show",
                unit,
                "--property=LoadState,ActiveState,SubState,InvocationID,NRestarts",
            ],
            check=False,
        )
        units[unit] = {
            "returncode": completed.returncode,
            "stdout": completed.stdout.decode("utf-8", "replace"),
            "stderr": completed.stderr.decode("utf-8", "replace"),
        }
    journal = run_command(
        ["/usr/bin/journalctl", "--show-cursor", "-n", "0", "--no-pager"],
        check=False,
    )
    return {
        "package": {
            "returncode": package.returncode,
            "stdout": package.stdout.decode("utf-8", "replace"),
            "stderr": package.stderr.decode("utf-8", "replace"),
        },
        "configuration": filesystem_snapshot(config_paths),
        "helper_units": units,
        "storage": filesystem_snapshot([Path("/var/lib/systemd/coredump")]),
        "journal_cursor": {
            "returncode": journal.returncode,
            "stdout": journal.stdout.decode("utf-8", "replace"),
            "stderr": journal.stderr.decode("utf-8", "replace"),
        },
    }


def journal_delta_since(snapshot: Mapping[str, Any]) -> Dict[str, Any]:
    cursor_text = str(snapshot.get("journal_cursor", {}).get("stdout", ""))
    match = re.search(r"-- cursor: (\S+)", cursor_text)
    if match is None:
        raise ProbeError("JOURNAL_CURSOR_MISSING", cursor_text[:200])
    completed = run_command(
        [
            "/usr/bin/journalctl",
            "--after-cursor",
            match.group(1),
            "--lines",
            "500",
            "--output",
            "json",
            "--no-pager",
        ],
        check=False,
    )
    if completed.returncode != 0:
        raise ProbeError(
            "JOURNAL_DELTA_FAILED",
            completed.stderr.decode("utf-8", "replace")[:400],
        )
    payload = completed.stdout
    if len(payload) > 4 * 1024 * 1024:
        raise ProbeError("JOURNAL_DELTA_TOO_LARGE", str(len(payload)))
    text = payload.decode("utf-8", "replace")
    return {
        "returncode": completed.returncode,
        "sha256": sha256_bytes(payload),
        "line_count": len(text.splitlines()),
        "coredump_related_lines": [
            line[:4000]
            for line in text.splitlines()
            if "systemd-coredump" in line or "COREDUMP" in line
        ],
    }


def host_preflight() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    observations: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    checks = (
        (Path("/usr/bin/systemd-run"), "systemd_run"),
        (Path("/usr/bin/systemctl"), "systemctl"),
        (CGROUP_ROOT / "cgroup.controllers", "unified_cgroup_v2"),
        (CORE_PATTERN_PATH, "core_pattern"),
    )
    for path, name in checks:
        observations.append(observation(f"host.path.{name}", "kernel_observed", str(path)))
        if not path.exists():
            errors.append(error_record("REQUIRED_HOST_PATH_MISSING", str(path), "kernel_observed"))
    comm = read_text(Path("/proc/1/comm"), 128).strip() if Path("/proc/1/comm").exists() else ""
    observations.append(observation("host.pid1_comm", "kernel_observed", comm))
    if comm != "systemd":
        errors.append(error_record("PID1_NOT_SYSTEMD", comm, "kernel_observed"))
    observations.append(
        observation(
            "host.kernel_release",
            "kernel_observed",
            os.uname().release,
        )
    )
    observations.append(
        observation(
            "host.boot_id",
            "kernel_observed",
            read_text(Path("/proc/sys/kernel/random/boot_id"), 128).strip(),
        )
    )
    os_release = read_text(Path("/etc/os-release"), 65536) if Path("/etc/os-release").exists() else ""
    observations.append(observation("host.os_release", "platform_file_observed", os_release))
    image_version = ""
    image_path = Path("/etc/runner-images-generation")
    if image_path.exists():
        image_version = read_text(image_path, 65536)
    observations.append(observation("host.runner_image_manifest", "platform_file_observed", image_version))
    systemd_version = run_command(["/usr/bin/systemd", "--version"], check=False).stdout.decode(
        "utf-8", "replace"
    )
    observations.append(observation("host.systemd_version", "platform_file_observed", systemd_version))
    observations.append(
        observation(
            "host.cgroup_controllers",
            "kernel_observed",
            read_text(CGROUP_ROOT / "cgroup.controllers", 4096)
            if (CGROUP_ROOT / "cgroup.controllers").exists()
            else "",
        )
    )
    observations.append(
        observation(
            "host.core_pattern_before",
            "kernel_observed",
            read_text(CORE_PATTERN_PATH, 4096).strip() if CORE_PATTERN_PATH.exists() else "",
        )
    )
    return observations, errors


def wait_main_pid(unit: str, timeout: float = 15.0) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        raw = systemctl_value(unit, "MainPID")
        try:
            pid = int(raw)
        except ValueError:
            pid = 0
        if pid > 1 and Path(f"/proc/{pid}").exists():
            return pid
        time.sleep(0.05)
    raise ProbeError("MAIN_PID_UNAVAILABLE", unit)


def observe_bootstrap(
    pid: int,
    cgroup_path: str,
    requested_argv: Sequence[str],
    requested_environment: Mapping[str, str],
    stdout_identity: Tuple[int, int],
    stderr_identity: Tuple[int, int],
) -> Tuple[List[str], Dict[str, str], List[Dict[str, Any]]]:
    proc = Path("/proc") / str(pid)
    raw_argv = parse_proc_nul_raw(proc / "cmdline")
    expected_raw_argv = [value.encode("utf-8") for value in requested_argv]
    if raw_argv != expected_raw_argv:
        raise ProbeError("ARGV_EXACT_MISMATCH", repr(raw_argv))
    try:
        argv = [value.decode("utf-8", "strict") for value in raw_argv]
    except UnicodeError as exc:
        raise ProbeError("ARGV_ENCODING_INVALID", repr(raw_argv)) from exc
    raw_environment = parse_proc_nul_raw(proc / "environ")
    environment = validate_observed_environment(
        raw_environment,
        requested_environment,
    )
    status = parse_status(read_text(proc / "status"))
    limits_text = read_text(proc / "limits")
    proc_cgroup = read_text(proc / "cgroup", 65536)
    if f"0::{cgroup_path}" not in proc_cgroup:
        raise ProbeError("CGROUP_BINDING_MISMATCH", proc_cgroup)
    if status.get("NoNewPrivs") != "1":
        raise ProbeError("NO_NEW_PRIVILEGES_INEFFECTIVE", status.get("NoNewPrivs", "missing"))
    for capability_field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        if int(status.get(capability_field, "1"), 16) != 0:
            raise ProbeError(
                "CAPABILITY_BOUNDARY_INEFFECTIVE",
                f"{capability_field}={status.get(capability_field, 'missing')}",
            )
    uid_values = status.get("Uid", "").split()
    gid_values = status.get("Gid", "").split()
    if (
        len(uid_values) != 4
        or len(set(uid_values)) != 1
        or uid_values[0] == "0"
        or len(gid_values) != 4
        or len(set(gid_values)) != 1
        or gid_values[0] == "0"
    ):
        raise ProbeError("DEDICATED_UID_INEFFECTIVE", status.get("Uid", "missing"))
    supplementary = status.get("Groups", "").split()
    if any(value != gid_values[0] for value in supplementary):
        raise ProbeError("SUPPLEMENTARY_GROUP_INEFFECTIVE", status.get("Groups", ""))
    required_limits = {
        "Max open files": "128",
        "Max file size": "8388608",
        "Max core file size": "0",
    }
    for limit_name, expected_soft in required_limits.items():
        matching = [
            line for line in limits_text.splitlines() if line.startswith(limit_name)
        ]
        if len(matching) != 1:
            raise ProbeError("LIMIT_OBSERVATION_MISSING", limit_name)
        fields = matching[0][len(limit_name):].split()
        if not fields or fields[0] != expected_soft:
            raise ProbeError(
                "LIMIT_INEFFECTIVE",
                f"{limit_name}: {matching[0]}",
            )
    fd_entries = sorted(item.name for item in (proc / "fd").iterdir())
    fd_identity: Dict[str, Dict[str, Any]] = {}
    for fd_name, expected in (("1", stdout_identity), ("2", stderr_identity)):
        fd_path = proc / "fd" / fd_name
        fd_stat = fd_path.stat()
        if (
            not stat.S_ISFIFO(fd_stat.st_mode)
            or (fd_stat.st_dev, fd_stat.st_ino) != expected
        ):
            raise ProbeError("CHILD_CAPTURE_FD_MISMATCH", fd_name)
        fd_identity[fd_name] = {
            "target": os.readlink(fd_path),
            "device": fd_stat.st_dev,
            "inode": fd_stat.st_ino,
            "mode": stat.S_IMODE(fd_stat.st_mode),
            "fdinfo": read_text(proc / "fdinfo" / fd_name, 4096),
        }
    namespace_ids = {
        item.name: os.readlink(item)
        for item in (proc / "ns").iterdir()
        if item.name in {"mnt", "net", "ipc", "pid", "user", "uts", "cgroup"}
    }
    supervisor_namespace_ids = {
        name: os.readlink(Path("/proc/self/ns") / name)
        for name in namespace_ids
    }
    for required_private_namespace in ("mnt", "net", "ipc", "uts"):
        if (
            namespace_ids.get(required_private_namespace)
            == supervisor_namespace_ids.get(required_private_namespace)
        ):
            raise ProbeError(
                "NAMESPACE_BOUNDARY_INEFFECTIVE",
                required_private_namespace,
            )
    observations = [
        observation("bootstrap.status", "kernel_observed", status),
        observation("bootstrap.limits", "kernel_observed", limits_text),
        observation("bootstrap.mountinfo", "kernel_observed", read_text(proc / "mountinfo")),
        observation("bootstrap.cgroup", "kernel_observed", proc_cgroup),
        observation("bootstrap.file_descriptors", "kernel_observed", fd_entries),
        observation("bootstrap.capture_fd_identity", "kernel_observed", fd_identity),
        observation(
            "bootstrap.argv_raw_base64",
            "kernel_observed",
            [base64.b64encode(item).decode("ascii") for item in raw_argv],
        ),
        observation(
            "bootstrap.environment_raw_base64",
            "kernel_observed",
            [base64.b64encode(item).decode("ascii") for item in raw_environment],
        ),
        observation("bootstrap.namespaces", "kernel_observed", namespace_ids),
        observation(
            "bootstrap.supervisor_namespaces",
            "kernel_observed",
            supervisor_namespace_ids,
        ),
    ]
    return argv, environment, observations


def _empty_stream_document() -> Dict[str, Any]:
    return StreamCapture(MAX_RETAINED_COMBINED // 2).document()


def verify_dynamic_user_source_access(
    path: Path,
    expected_sha256: str,
    uid: int,
    gid: int,
) -> None:
    pid = os.fork()
    if pid == 0:
        try:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            if sha256_path(path) != expected_sha256:
                os._exit(71)
            try:
                writable = os.open(path, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
            except OSError:
                writable = -1
            if writable >= 0:
                os.close(writable)
                os._exit(72)
            try:
                sibling = os.open(
                    path.with_name("replacement.py"),
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except OSError:
                sibling = -1
            if sibling >= 0:
                os.close(sibling)
                os._exit(73)
            os._exit(0)
        except BaseException:
            os._exit(74)
    waited, status_value = os.waitpid(pid, 0)
    if waited != pid or not os.WIFEXITED(status_value) or os.WEXITSTATUS(status_value) != 0:
        raise ProbeError(
            "DYNAMIC_USER_SOURCE_ACCESS_INVALID",
            f"wait_status={status_value}",
        )


def run_case(
    *,
    case_id: str,
    run_id: str,
    run_attempt: str,
    head_sha: str,
    source_path: Path,
    source_sha256: str,
    schema_path: Path,
    evidence_dir: Path,
    evidence_uid: int,
    evidence_gid: int,
    state_path: Path,
    journal: MutableMapping[str, Any],
    lifecycle: List[Dict[str, Any]],
) -> Dict[str, Any]:
    started = time.monotonic_ns()
    nonce = uuid.uuid4().hex[:16]
    unit = safe_unit_name(run_id, case_id, nonce)
    state_dir = ROOT_RUNTIME / f"case-{nonce}"
    state_dir.mkdir(mode=0o700)
    exec_dir = ROOT_RUNTIME / f"exec-{nonce}"
    exec_dir.mkdir(mode=0o700)
    staged_probe = exec_dir / "probe.py"
    shutil.copyfile(source_path, staged_probe)
    os.chown(staged_probe, 0, 0)
    os.chmod(staged_probe, 0o555)
    os.chown(exec_dir, 0, 0)
    os.chmod(exec_dir, 0o555)
    if sha256_path(staged_probe) != source_sha256:
        raise ProbeError("STAGED_SOURCE_DIGEST_MISMATCH", case_id)
    staged_stat = staged_probe.stat()
    if (
        staged_stat.st_uid != 0
        or staged_stat.st_gid != 0
        or stat.S_IMODE(staged_stat.st_mode) != 0o555
        or not stat.S_ISREG(staged_stat.st_mode)
    ):
        raise ProbeError("STAGED_SOURCE_METADATA_MISMATCH", case_id)
    barrier = state_dir / "barrier.fifo"
    stdout_fifo = state_dir / "stdout.fifo"
    stderr_fifo = state_dir / "stderr.fifo"
    for fifo in (barrier, stdout_fifo, stderr_fifo):
        os.mkfifo(fifo, 0o600)
        os.chown(fifo, 0, 0)
    stdout_stat = os.stat(stdout_fifo, follow_symlinks=False)
    stderr_stat = os.stat(stderr_fifo, follow_symlinks=False)
    if not stat.S_ISFIFO(stdout_stat.st_mode) or not stat.S_ISFIFO(stderr_stat.st_mode):
        raise ProbeError("CAPTURE_NOT_FIFO", case_id)
    host_tmp_sentinel = Path("/tmp") / f"p0-v2-host-{nonce}"
    sentinel_payload = os.urandom(32)
    sentinel_fd = os.open(
        host_tmp_sentinel,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.write(sentinel_fd, sentinel_payload)
        os.fsync(sentinel_fd)
    finally:
        os.close(sentinel_fd)
    sentinel_sha256 = sha256_bytes(sentinel_payload)
    state_dir_fd = os.open(
        state_dir,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
    )
    stdout_fd = os.open(
        stdout_fifo.name,
        os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=state_dir_fd,
    )
    stderr_fd = os.open(
        stderr_fifo.name,
        os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=state_dir_fd,
    )
    barrier_fd = os.open(
        barrier.name,
        os.O_RDWR | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=state_dir_fd,
    )
    selector = selectors.DefaultSelector()
    selector.register(stdout_fd, selectors.EVENT_READ, "stdout")
    selector.register(stderr_fd, selectors.EVENT_READ, "stderr")
    captures = {
        "stdout": StreamCapture(MAX_RETAINED_COMBINED // 2),
        "stderr": StreamCapture(MAX_RETAINED_COMBINED // 2),
    }
    interpreter = Path("/usr/bin/python3").resolve()
    requested_argv = [
        str(interpreter),
        "-I",
        str(staged_probe),
        "fixture",
        "--case",
        case_id,
        "--nonce",
        nonce,
    ]
    launch_argv = render_systemd_run_argv(
        unit,
        interpreter,
        staged_probe,
        case_id,
        nonce,
        state_dir,
        barrier,
        stdout_fifo,
        stderr_fifo,
    )
    observations: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    outcome = "INCONCLUSIVE"
    kill_written = False
    empty_observed = False
    eof_after_empty = False
    unloaded_after_empty = False
    events_fd: Optional[int] = None
    kill_fd: Optional[int] = None
    cgroup_path = ""
    resource_before: Dict[str, Any] = {}
    kernel_argv: List[str] = []
    kernel_environment: Dict[str, str] = {}
    try:
        run_command(launch_argv)
        lifecycle.append(lifecycle_event("unit_created"))
        pid = wait_main_pid(unit)
        cgroup_path = systemctl_value(unit, "ControlGroup")
        if not SAFE_CGROUP_RE.fullmatch(cgroup_path):
            raise ProbeError("INVALID_CGROUP_PATH", cgroup_path)
        proc_cgroup = read_text(Path(f"/proc/{pid}/cgroup"), 65536)
        if f"0::{cgroup_path}" not in proc_cgroup:
            raise ProbeError("CGROUP_BINDING_MISMATCH", proc_cgroup)
        cgroup_dir = CGROUP_ROOT / cgroup_path.lstrip("/")
        if not cgroup_dir.is_dir():
            raise ProbeError("CGROUP_PATH_MISSING", str(cgroup_dir))
        cgroup_type = read_text(cgroup_dir / "cgroup.type", 128).strip()
        if cgroup_type != "domain":
            raise ProbeError("CGROUP_NOT_DOMAIN", cgroup_type)
        events_fd = os.open(
            cgroup_dir / "cgroup.events",
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        kill_fd = os.open(
            cgroup_dir / "cgroup.kill",
            os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        resource_before = cgroup_resource_snapshot(cgroup_dir)
        kernel_argv, kernel_environment, bootstrap_observations = observe_bootstrap(
            pid,
            cgroup_path,
            requested_argv,
            REQUESTED_ENVIRONMENT,
            (stdout_stat.st_dev, stdout_stat.st_ino),
            (stderr_stat.st_dev, stderr_stat.st_ino),
        )
        observations.extend(bootstrap_observations)
        properties = systemctl_properties(unit)
        validate_systemd_properties(properties, exec_dir)
        cgroup_stat = cgroup_dir.stat()
        bootstrap_status = next(
            item["value"]
            for item in bootstrap_observations
            if item["name"] == "bootstrap.status"
        )
        dynamic_uid = int(bootstrap_status["Uid"].split()[0])
        dynamic_gid = int(bootstrap_status["Gid"].split()[0])
        argv_raw_base64 = next(
            item["value"]
            for item in bootstrap_observations
            if item["name"] == "bootstrap.argv_raw_base64"
        )
        environment_raw_base64 = next(
            item["value"]
            for item in bootstrap_observations
            if item["name"] == "bootstrap.environment_raw_base64"
        )
        capture_fd_identity = next(
            item["value"]
            for item in bootstrap_observations
            if item["name"] == "bootstrap.capture_fd_identity"
        )
        verify_dynamic_user_source_access(
            staged_probe,
            source_sha256,
            dynamic_uid,
            dynamic_gid,
        )
        invocation_id = properties.get("InvocationID", "")
        if not re.fullmatch(r"[0-9a-f]{32}", invocation_id):
            raise ProbeError("INVOCATION_ID_INVALID", invocation_id)
        observations.append(observation("unit.properties", "systemd_observed", properties))
        observations.append(observation("cgroup.type", "kernel_observed", cgroup_type))
        observations.append(
            observation(
                "cgroup.resources.before",
                "kernel_observed",
                resource_before,
            )
        )
        active_case = {
            "unit": unit,
            "invocation_id": invocation_id,
            "cgroup_path": cgroup_path,
            "cgroup_device": cgroup_stat.st_dev,
            "cgroup_inode": cgroup_stat.st_ino,
            "dynamic_uid": dynamic_uid,
            "dynamic_gid": dynamic_gid,
            "main_pid": pid,
            "nonce": nonce,
            "staged_probe": str(staged_probe),
            "staged_probe_device": staged_stat.st_dev,
            "staged_probe_inode": staged_stat.st_ino,
            "staged_probe_mode": stat.S_IMODE(staged_stat.st_mode),
            "staged_probe_uid": staged_stat.st_uid,
            "staged_probe_gid": staged_stat.st_gid,
            "host_tmp_sentinel": str(host_tmp_sentinel),
            "host_tmp_sentinel_sha256": sentinel_sha256,
            "stdout_fifo": str(stdout_fifo),
            "stdout_fifo_device": stdout_stat.st_dev,
            "stdout_fifo_inode": stdout_stat.st_ino,
            "stderr_fifo": str(stderr_fifo),
            "stderr_fifo_device": stderr_stat.st_dev,
            "stderr_fifo_inode": stderr_stat.st_ino,
            "state_dir": str(state_dir),
            "exec_dir": str(exec_dir),
            "requested_argv": requested_argv,
            "kernel_observed_argv": kernel_argv,
            "kernel_observed_argv_raw_base64": argv_raw_base64,
            "requested_environment": REQUESTED_ENVIRONMENT,
            "kernel_observed_environment": kernel_environment,
            "kernel_observed_environment_raw_base64": environment_raw_base64,
            "capture_fd_identity": capture_fd_identity,
        }
        journal["active_case"] = active_case
        journal["phase"] = "case_bound"
        write_root_state(state_path, journal)
        lifecycle.append(lifecycle_event("bootstrap_observed"))
        os.write(barrier_fd, b"R")
        journal["phase"] = "fixture_released"
        write_root_state(state_path, journal)
        lifecycle.append(lifecycle_event("hostile_released"))
        if case_id == "operator-cancel":
            print("P0_V2_CANCEL_CANARY_ACTIVE=1", flush=True)
        deadline = time.monotonic() + CASE_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            drain_streams(selector, captures, wait=0.05)
            total = captures["stdout"].byte_count + captures["stderr"].byte_count
            if total > MAX_TOTAL_COMBINED:
                outcome = "OUTPUT_LIMIT"
                break
            substate = systemctl_value(unit, "SubState")
            if substate in {"exited", "failed", "dead"}:
                result = systemctl_value(unit, "Result")
                code = parse_systemd_int(
                    "ExecMainCode",
                    systemctl_value(unit, "ExecMainCode"),
                )
                status_value = parse_systemd_int(
                    "ExecMainStatus",
                    systemctl_value(unit, "ExecMainStatus"),
                )
                observations.extend(
                    [
                        observation("unit.result", "systemd_observed", result),
                        observation("unit.exec_main_code", "systemd_observed", code),
                        observation("unit.exec_main_status", "systemd_observed", status_value),
                    ]
                )
                outcome = classify_systemd_outcome(result, code, status_value)
                break
        else:
            outcome = "TIMEOUT"
        lifecycle.append(lifecycle_event("outcome_observed"))
        os.write(kill_fd, b"1")
        kill_written = True
        lifecycle.append(lifecycle_event("cgroup_kill_written"))
        if not wait_cgroup_empty(events_fd):
            outcome = "EMPTY_PROOF_FAILURE"
            raise ProbeError("CGROUP_NOT_EMPTY", case_id)
        empty_observed = True
        lifecycle.append(lifecycle_event("cgroup_empty_observed"))
        resource_after = cgroup_resource_snapshot(cgroup_dir)
        observations.append(
            observation(
                "cgroup.resources.after",
                "kernel_observed",
                resource_after,
            )
        )
        if case_id == "memory-limit":
            before_oom = parse_counter_file(
                str(resource_before.get("memory.events", ""))
            ).get("oom_kill", 0)
            after_oom = parse_counter_file(
                str(resource_after.get("memory.events", ""))
            ).get("oom_kill", 0)
            if after_oom <= before_oom:
                raise ProbeError("MEMORY_OOM_NOT_OBSERVED", case_id)
        if case_id == "fork-limit":
            before_max = parse_counter_file(
                str(resource_before.get("pids.events", ""))
            ).get("max", 0)
            after_max = parse_counter_file(
                str(resource_after.get("pids.events", ""))
            ).get("max", 0)
            if after_max <= before_max:
                raise ProbeError("TASKS_MAX_NOT_OBSERVED", case_id)
        if int(str(resource_after.get("memory.swap.current", "0") or "0")) != 0:
            raise ProbeError("MEMORY_SWAP_OBSERVED", case_id)
        eof_deadline = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
        while selector.get_map() and time.monotonic() < eof_deadline:
            drain_streams(selector, captures, wait=0.05)
        eof_after_empty = not selector.get_map()
        if not eof_after_empty:
            outcome = "CAPTURE_FAILURE"
            raise ProbeError("STREAM_EOF_NOT_OBSERVED", case_id)
        lifecycle.append(lifecycle_event("streams_eof_observed"))
        unload_unit(unit)
        unloaded_after_empty = True
        lifecycle.append(lifecycle_event("unit_unloaded"))
    except ProbeError as exc:
        errors.append(error_record(exc.code, exc.detail))
        if outcome == "INCONCLUSIVE":
            outcome = "SETUP_ERROR"
    except BaseException as exc:
        errors.append(error_record("UNEXPECTED_SUPERVISOR_ERROR", repr(exc)))
        if outcome == "INCONCLUSIVE":
            outcome = "SETUP_ERROR"
    finally:
        if kill_fd is not None and not kill_written:
            try:
                os.write(kill_fd, b"1")
                kill_written = True
            except OSError as exc:
                errors.append(error_record("CGROUP_KILL_FAILED", repr(exc), "kernel_observed"))
        if events_fd is not None and not empty_observed:
            try:
                empty_observed = wait_cgroup_empty(events_fd)
            except OSError as exc:
                errors.append(error_record("CGROUP_EMPTY_OBSERVE_FAILED", repr(exc), "kernel_observed"))
        if empty_observed and not eof_after_empty:
            try:
                eof_deadline = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
                while selector.get_map() and time.monotonic() < eof_deadline:
                    drain_streams(selector, captures, wait=0.05)
                eof_after_empty = not selector.get_map()
                if not eof_after_empty:
                    errors.append(
                        error_record(
                            "STREAM_EOF_NOT_OBSERVED",
                            case_id,
                            "supervisor_observed",
                        )
                    )
            except OSError as exc:
                errors.append(
                    error_record(
                        "STREAM_DRAIN_FAILED",
                        repr(exc),
                        "supervisor_observed",
                    )
                )
        if (
            SAFE_UNIT_RE.fullmatch(unit)
            and empty_observed
            and eof_after_empty
            and not unloaded_after_empty
        ):
            try:
                unload_unit(unit)
                unloaded_after_empty = True
            except ProbeError as exc:
                errors.append(error_record(exc.code, exc.detail, "systemd_observed"))
        for fd in (kill_fd, events_fd, barrier_fd, state_dir_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        for key in list(selector.get_map().values()):
            try:
                selector.unregister(key.fd)
                os.close(key.fd)
            except OSError:
                pass
        selector.close()
        if kill_written and empty_observed and eof_after_empty and unloaded_after_empty:
            sentinel_ok = True
            try:
                final_staged_stat = staged_probe.stat()
                if (
                    [item.name for item in exec_dir.iterdir()] != ["probe.py"]
                    or final_staged_stat.st_dev != staged_stat.st_dev
                    or final_staged_stat.st_ino != staged_stat.st_ino
                    or stat.S_IMODE(final_staged_stat.st_mode) != 0o555
                    or sha256_path(staged_probe) != source_sha256
                ):
                    raise ProbeError(
                        "STAGED_SOURCE_MUTATED",
                        case_id,
                    )
            except BaseException as exc:
                sentinel_ok = False
                errors.append(
                    error_record(
                        "STAGED_SOURCE_MUTATED",
                        repr(exc),
                        "kernel_observed",
                    )
                )
            if (
                not host_tmp_sentinel.is_file()
                or sha256_path(host_tmp_sentinel) != sentinel_sha256
            ):
                sentinel_ok = False
                errors.append(
                    error_record(
                        "HOST_TMP_ISOLATION_FAILED",
                        str(host_tmp_sentinel),
                        "kernel_observed",
                    )
                )
            else:
                host_tmp_sentinel.unlink()
            if sentinel_ok:
                journal["active_case"] = None
                journal["phase"] = "core_pattern_suppressed"
                write_root_state(state_path, journal)
                shutil.rmtree(state_dir, ignore_errors=True)
                shutil.rmtree(exec_dir, ignore_errors=True)
    if outcome not in OUTCOMES:
        outcome = "INCONCLUSIVE"
    return {
        "id": case_id,
        "outcome": outcome,
        "outcome_authority": "supervisor_observed",
        "started_monotonic_ns": started,
        "finished_monotonic_ns": time.monotonic_ns(),
        "requested_argv": requested_argv,
        "requested_argv_authority": "supervisor_observed",
        "kernel_observed_argv": kernel_argv,
        "kernel_observed_argv_authority": "kernel_observed",
        "requested_environment": REQUESTED_ENVIRONMENT,
        "requested_environment_authority": "supervisor_observed",
        "kernel_observed_environment": kernel_environment,
        "kernel_observed_environment_authority": "kernel_observed",
        "stdout": captures["stdout"].document(),
        "stderr": captures["stderr"].document(),
        "cleanup": {
            "direct_cgroup_kill_written": kill_written,
            "direct_cgroup_kill_authority": "kernel_observed",
            "recursive_populated_zero_observed": empty_observed,
            "recursive_populated_zero_authority": "kernel_observed",
            "path_absence_used_as_proof": False,
            "streams_eof_after_empty": eof_after_empty,
            "streams_eof_authority": "supervisor_observed",
            "unit_unloaded_after_empty": unloaded_after_empty,
            "unit_unloaded_authority": "systemd_observed",
        },
        "observations": observations,
        "errors": errors,
    }


def make_evidence(
    args: argparse.Namespace,
    *,
    outcome: str,
    identity: List[Dict[str, Any]],
    source: List[Dict[str, Any]],
    host: List[Dict[str, Any]],
    requested_controls: List[Dict[str, Any]],
    reported_controls: List[Dict[str, Any]],
    effective_controls: List[Dict[str, Any]],
    lifecycle: List[Dict[str, Any]],
    cases: List[Dict[str, Any]],
    cancellation: Mapping[str, Any],
    errors: List[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "evidence_kind": EVIDENCE_KIND,
        "candidate_notice": CANDIDATE_NOTICE,
        "outcome": outcome,
        "outcome_authority": "supervisor_observed",
        "identity": identity,
        "source": source,
        "host": host,
        "controls": {
            "requested": requested_controls,
            "systemd_reported": reported_controls,
            "effective_observed": effective_controls,
        },
        "lifecycle": lifecycle,
        "cases": cases,
        "cancellation": dict(cancellation),
        "errors": errors,
    }


def supervisor(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        print("P0_V2_STATUS=SETUP_ERROR")
        return 2
    ROOT_RUNTIME.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chown(ROOT_RUNTIME, 0, 0)
    os.chmod(ROOT_RUNTIME, 0o700)
    source_path = Path(args.source_path).resolve()
    schema_path = Path(args.schema_path).resolve()
    workflow_file = Path(args.workflow_file).resolve()
    test_file = Path(args.test_file).resolve()
    evidence_dir = Path(args.evidence_dir).resolve()
    validate_sha40("head_sha", args.head_sha)
    validate_sha40("base_sha", args.base_sha)
    validate_sha40("merge_sha", args.merge_sha)
    validate_sha40("workflow_sha", args.workflow_sha)
    if (
        args.repository != "yurikuchumov-ux/ai-operating-system"
        or args.pr_number != "71"
        or args.head_repository != args.repository
        or args.head_ref != "agent/issue-70-p0-v2-feasibility-gate1"
        or args.base_repository != args.repository
        or args.base_ref != "main"
        or args.base_sha != "d4f10b714de3afae84d48dfcd3daa6405092a973"
        or args.event_name != "pull_request"
        or args.event_action not in {"ready_for_review", "reopened", "labeled"}
        or args.cancel_canary != (args.event_action == "labeled")
        or not args.workflow_ref.startswith(
            f"{args.repository}/.github/workflows/p0-v2-runner-feasibility.yml@"
        )
    ):
        raise ProbeError("GITHUB_CONTEXT_MISMATCH", "authorized event binding failed")
    source_sha = sha256_path(source_path)
    schema_sha = sha256_path(schema_path)
    workflow_file_sha = sha256_path(workflow_file)
    test_file_sha = sha256_path(test_file)
    state_path = state_path_for(args.run_id, args.run_attempt)
    journal: Dict[str, Any] = {
        "journal_version": 1,
        "phase": "initialized",
        "run_id": args.run_id,
        "run_attempt": args.run_attempt,
        "head_sha": args.head_sha,
        "source_sha256": source_sha,
        "schema_sha256": schema_sha,
        "workflow_file_sha256": workflow_file_sha,
        "test_file_sha256": test_file_sha,
        "evidence_dir": str(evidence_dir),
        "schema_path": str(schema_path),
        "core_pattern_original_base64": "",
        "core_pattern_original_recorded": False,
        "core_pattern_active_base64": "",
        "coredump_before": {},
        "active_case": None,
        "terminal_evidence_sha256": "",
    }
    lifecycle = [lifecycle_event("supervisor_started")]
    host, errors = host_preflight()
    coredump_before: Dict[str, Any] = {}
    try:
        coredump_before = coredump_effect_snapshot()
        journal["coredump_before"] = coredump_before
        host.append(
            observation(
                "host.coredump_effects_before",
                "platform_file_observed",
                coredump_before,
            )
        )
    except BaseException as exc:
        errors.append(
            error_record(
                "COREDUMP_SNAPSHOT_FAILED",
                repr(exc),
                "platform_file_observed",
            )
        )
    lifecycle.append(lifecycle_event("host_preflight_complete"))
    identity = [
        observation("github.repository", "github_context_claim", args.repository),
        observation("github.pr_number", "github_context_claim", args.pr_number),
        observation("github.event_action", "github_context_claim", args.event_action),
        observation("github.workflow", "github_context_claim", args.workflow),
        observation("github.workflow_ref", "github_context_claim", args.workflow_ref),
        observation("github.workflow_sha", "github_context_claim", args.workflow_sha),
        observation("github.event_name", "github_context_claim", args.event_name),
        observation("github.run_id", "github_context_claim", args.run_id),
        observation("github.run_attempt", "github_context_claim", args.run_attempt),
        observation("github.pr_head_sha", "github_context_claim", args.head_sha),
        observation(
            "github.pr_head_repository",
            "github_context_claim",
            args.head_repository,
        ),
        observation("github.pr_head_ref", "github_context_claim", args.head_ref),
        observation("github.pr_base_sha", "github_context_claim", args.base_sha),
        observation(
            "github.pr_base_repository",
            "github_context_claim",
            args.base_repository,
        ),
        observation("github.pr_base_ref", "github_context_claim", args.base_ref),
        observation("github.pr_merge_sha", "github_context_claim", args.merge_sha),
        observation("runner.image", "github_context_claim", args.runner_image),
        observation("runner.arch", "github_context_claim", args.runner_arch),
        observation(
            "runner.boot_id",
            "kernel_observed",
            read_text(Path("/proc/sys/kernel/random/boot_id"), 128).strip(),
        ),
    ]
    source = [
        observation("source.probe_sha256", "supervisor_observed", source_sha),
        observation("source.schema_sha256", "supervisor_observed", schema_sha),
        observation(
            "source.workflow_sha256",
            "supervisor_observed",
            workflow_file_sha,
        ),
        observation("source.test_sha256", "supervisor_observed", test_file_sha),
        observation("source.task_commit", "github_context_claim", CONTROL_TASK_COMMIT),
        observation("source.task_sha256", "github_context_claim", CONTROL_TASK_SHA256),
    ]
    requested_controls = [
        observation(
            f"requested.{index:03d}",
            "supervisor_observed",
            value,
        )
        for index, value in enumerate(SYSTEMD_PROPERTIES_BASE)
    ]
    cases: List[Dict[str, Any]] = []
    reported_controls: List[Dict[str, Any]] = []
    effective_controls: List[Dict[str, Any]] = []
    active_core_pattern = b""
    overall = "INCONCLUSIVE"
    try:
        if errors:
            raise ProbeError("HOST_PREFLIGHT_FAILED", "required host capability missing")
        active_core_pattern = suppress_core_pattern(state_path, journal)
        lifecycle.append(lifecycle_event("core_pattern_suppressed"))
        host.extend(
            [
                observation(
                    "host.core_pattern_original_base64",
                    "kernel_observed",
                    journal["core_pattern_original_base64"],
                ),
                observation(
                    "host.core_pattern_active_base64",
                    "kernel_observed",
                    base64.b64encode(active_core_pattern).decode("ascii"),
                ),
            ]
        )
        chosen_case_ids = ("operator-cancel",) if args.cancel_canary else tuple(CASES)
        for case_id in chosen_case_ids:
            case = run_case(
                case_id=case_id,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                head_sha=args.head_sha,
                source_path=source_path,
                source_sha256=source_sha,
                schema_path=schema_path,
                evidence_dir=evidence_dir,
                evidence_uid=args.evidence_uid,
                evidence_gid=args.evidence_gid,
                state_path=state_path,
                journal=journal,
                lifecycle=lifecycle,
            )
            cases.append(case)
            expected_outcome = EXPECTED_CASE_OUTCOMES[case_id]
            if case["outcome"] != expected_outcome:
                mismatch = error_record(
                    "CASE_OUTCOME_MISMATCH",
                    f"{case_id}: expected {expected_outcome}, observed {case['outcome']}",
                )
                case["errors"].append(mismatch)
                errors.append(mismatch)
            for item in case["observations"]:
                if item["name"] == "unit.properties" and isinstance(item["value"], dict):
                    reported_controls.extend(
                        observation(
                            f"{case_id}.{key.lower()}",
                            "systemd_observed",
                            value,
                        )
                        for key, value in sorted(item["value"].items())
                    )
            effective_controls.extend(
                [
                    observation(
                        f"{case_id}.argv_matches",
                        "kernel_observed",
                        case["requested_argv"] == case["kernel_observed_argv"],
                    ),
                    observation(
                        f"{case_id}.environment_contains_no_forbidden_family",
                        "kernel_observed",
                        environment_contract_satisfied(
                            case["requested_environment"],
                            case["kernel_observed_environment"],
                        ),
                    ),
                    observation(
                        f"{case_id}.systemd_properties_match",
                        "systemd_observed",
                        True,
                    ),
                    observation(
                        f"{case_id}.capture_fd_identity",
                        "kernel_observed",
                        True,
                    ),
                    observation(
                        f"{case_id}.direct_cgroup_kill",
                        "kernel_observed",
                        case["cleanup"]["direct_cgroup_kill_written"],
                    ),
                    observation(
                        f"{case_id}.recursive_populated_zero",
                        "kernel_observed",
                        case["cleanup"]["recursive_populated_zero_observed"],
                    ),
                    observation(
                        f"{case_id}.streams_eof_after_empty",
                        "supervisor_observed",
                        case["cleanup"]["streams_eof_after_empty"],
                    ),
                    observation(
                        f"{case_id}.unit_unloaded_after_empty",
                        "systemd_observed",
                        case["cleanup"]["unit_unloaded_after_empty"],
                    ),
                ]
            )
            if case["errors"]:
                break
        if (
            not errors
            and [case["id"] for case in cases] == list(chosen_case_ids)
            and len({case["id"] for case in cases}) == len(chosen_case_ids)
            and all(
                not case["errors"]
                and case["outcome"] == EXPECTED_CASE_OUTCOMES[case["id"]]
                and case["requested_argv"] == case["kernel_observed_argv"]
                and environment_contract_satisfied(
                    case["requested_environment"],
                    case["kernel_observed_environment"],
                )
                and case["cleanup"]["direct_cgroup_kill_written"]
                and case["cleanup"]["recursive_populated_zero_observed"]
                and case["cleanup"]["streams_eof_after_empty"]
                and case["cleanup"]["unit_unloaded_after_empty"]
                for case in cases
            )
        ):
            overall = "SUCCESS"
        else:
            overall = "INCONCLUSIVE"
    except ProbeError as exc:
        errors.append(error_record(exc.code, exc.detail))
        overall = "SETUP_ERROR"
    except BaseException as exc:
        errors.append(error_record("UNEXPECTED_SUPERVISOR_ERROR", repr(exc)))
        overall = "SETUP_ERROR"
    finally:
        if journal["core_pattern_original_recorded"]:
            try:
                restored = restore_core_pattern(journal)
                journal["phase"] = "core_pattern_restored"
                write_root_state(state_path, journal)
                lifecycle.append(lifecycle_event("core_pattern_restored"))
                host.append(
                    observation(
                        "host.core_pattern_after_base64",
                        "kernel_observed",
                        base64.b64encode(restored).decode("ascii"),
                    )
                )
            except BaseException as exc:
                errors.append(error_record("COREDUMP_RESTORE_FAILED", repr(exc), "kernel_observed"))
                overall = "CLEANUP_FAILURE"
    coredump_unchanged = True
    try:
        coredump_after = coredump_effect_snapshot()
        host.append(
            observation(
                "host.coredump_effects_after",
                "platform_file_observed",
                coredump_after,
            )
        )
        for invariant in ("package", "configuration", "helper_units", "storage"):
            if coredump_before.get(invariant) != coredump_after.get(invariant):
                coredump_unchanged = False
                errors.append(
                    error_record(
                        "COREDUMP_SIDE_EFFECT_OBSERVED",
                        invariant,
                        "platform_file_observed",
                    )
                )
                overall = "CLEANUP_FAILURE"
        journal_delta = journal_delta_since(coredump_before)
        host.append(
            observation(
                "host.journal_delta",
                "platform_file_observed",
                journal_delta,
            )
        )
        if journal_delta["coredump_related_lines"]:
            coredump_unchanged = False
            errors.append(
                error_record(
                    "COREDUMP_JOURNAL_SIDE_EFFECT_OBSERVED",
                    str(len(journal_delta["coredump_related_lines"])),
                    "platform_file_observed",
                )
            )
            overall = "CLEANUP_FAILURE"
    except BaseException as exc:
        coredump_unchanged = False
        errors.append(
            error_record(
                "COREDUMP_SNAPSHOT_FAILED",
                repr(exc),
                "platform_file_observed",
            )
        )
        overall = "CLEANUP_FAILURE"
    effective_controls.extend(
        [
            observation(
                "host.core_pattern_restored",
                "kernel_observed",
                journal.get("phase") == "core_pattern_restored",
            ),
            observation(
                "host.coredump_no_unauthorized_side_effect",
                "platform_file_observed",
                coredump_unchanged,
            ),
        ]
    )
    cancellation = {
        "claim_type": "unobserved" if args.cancel_canary else "not_requested",
        "authority": "github_context_claim",
        "finalizer_ran": False,
        "same_vm_cleanup_observed": False,
        "force_cancellation_proven": False,
    }
    evidence = make_evidence(
        args,
        outcome=overall,
        identity=identity,
        source=source,
        host=host,
        requested_controls=requested_controls,
        reported_controls=reported_controls,
        effective_controls=effective_controls,
        lifecycle=lifecycle,
        cases=cases,
        cancellation=cancellation,
        errors=errors,
    )
    try:
        digest = atomic_seal(
            evidence_dir / "candidate-evidence.json",
            evidence,
            schema_path,
            args.evidence_uid,
            args.evidence_gid,
        )
        journal["terminal_evidence_sha256"] = digest
        journal["phase"] = "evidence_sealed"
        write_root_state(state_path, journal)
    except BaseException:
        print("P0_V2_STATUS=EVIDENCE_SEAL_FAILURE")
        return 3
    print(f"P0_V2_STATUS={overall}")
    print(f"P0_V2_EVIDENCE_SHA256={digest}")
    return 0 if overall == "SUCCESS" else 1


def finalize_cancelled(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        print("P0_V2_FINALIZER_STATUS=SETUP_ERROR")
        return 2
    lifecycle = [lifecycle_event("finalizer_started")]
    errors: List[Dict[str, Any]] = []
    state_path = state_path_for(args.run_id, args.run_attempt)
    evidence_path = Path(args.evidence_dir).resolve() / "candidate-evidence.json"
    captures = {
        "stdout": StreamCapture(MAX_RETAINED_COMBINED // 2),
        "stderr": StreamCapture(MAX_RETAINED_COMBINED // 2),
    }
    kill_written = False
    empty = False
    eof = False
    unloaded = False
    restored = False
    properties: Dict[str, str] = {}
    outcome = "CLEANUP_FAILURE"
    selector: Optional[selectors.BaseSelector] = None
    events_fd: Optional[int] = None
    kill_fd: Optional[int] = None
    directory_fd: Optional[int] = None
    state: Dict[str, Any] = {}
    active_case: Dict[str, Any] = {}

    def persist_phase(phase: str) -> None:
        state["phase"] = phase
        write_root_state(state_path, state)

    def open_bound_fifo(field: str) -> int:
        nonlocal directory_fd
        state_dir = Path(active_case["state_dir"])
        fifo_path = Path(active_case[f"{field}_fifo"])
        if fifo_path.parent != state_dir or fifo_path.name != f"{field}.fifo":
            raise ProbeError("FIFO_PATH_MISMATCH", str(fifo_path))
        if directory_fd is None:
            directory_fd = os.open(
                state_dir,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            )
        fd = os.open(
            fifo_path.name,
            os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        observed = os.fstat(fd)
        if (
            not stat.S_ISFIFO(observed.st_mode)
            or observed.st_dev != active_case[f"{field}_fifo_device"]
            or observed.st_ino != active_case[f"{field}_fifo_inode"]
        ):
            os.close(fd)
            raise ProbeError("FIFO_IDENTITY_MISMATCH", field)
        return fd

    try:
        state = load_root_state(state_path)
        if state["head_sha"] != args.head_sha:
            raise ProbeError("STATE_HEAD_MISMATCH", state["head_sha"])
        source_path = Path(args.source_path).resolve()
        schema_path = Path(args.schema_path).resolve()
        workflow_file = Path(args.workflow_file).resolve()
        test_file = Path(args.test_file).resolve()
        if sha256_path(source_path) != state["source_sha256"]:
            raise ProbeError("STATE_SOURCE_MISMATCH", "finalizer source digest mismatch")
        if sha256_path(schema_path) != state["schema_sha256"]:
            raise ProbeError("STATE_SCHEMA_MISMATCH", "finalizer schema digest mismatch")
        if sha256_path(workflow_file) != state["workflow_file_sha256"]:
            raise ProbeError(
                "STATE_WORKFLOW_MISMATCH",
                "finalizer workflow digest mismatch",
            )
        if sha256_path(test_file) != state["test_file_sha256"]:
            raise ProbeError("STATE_TEST_MISMATCH", "finalizer test digest mismatch")
        validate_sha40("base_sha", args.base_sha)
        validate_sha40("merge_sha", args.merge_sha)
        validate_sha40("workflow_sha", args.workflow_sha)
        if (
            args.repository != "yurikuchumov-ux/ai-operating-system"
            or args.pr_number != "71"
            or args.head_repository != args.repository
            or args.head_ref != "agent/issue-70-p0-v2-feasibility-gate1"
            or args.base_repository != args.repository
            or args.base_ref != "main"
            or args.base_sha != "d4f10b714de3afae84d48dfcd3daa6405092a973"
            or args.event_name != "pull_request"
            or args.event_action != "labeled"
            or not args.workflow_ref.startswith(
                f"{args.repository}/.github/workflows/p0-v2-runner-feasibility.yml@"
            )
        ):
            raise ProbeError(
                "GITHUB_CONTEXT_MISMATCH",
                "finalizer event binding failed",
            )
        if Path(state["evidence_dir"]).resolve() != Path(args.evidence_dir).resolve():
            raise ProbeError("STATE_EVIDENCE_DIR_MISMATCH", state["evidence_dir"])
        if Path(state["schema_path"]).resolve() != schema_path:
            raise ProbeError("STATE_SCHEMA_PATH_MISMATCH", state["schema_path"])

        if state["phase"] == "evidence_sealed":
            terminal_digest = state["terminal_evidence_sha256"]
            if not SHA64_RE.fullmatch(terminal_digest):
                raise ProbeError("STATE_TERMINAL_DIGEST_INVALID", terminal_digest)
            if not evidence_path.is_file() or sha256_path(evidence_path) != terminal_digest:
                raise ProbeError("STATE_TERMINAL_EVIDENCE_MISMATCH", str(evidence_path))
            manifest_path = evidence_path.with_suffix(
                evidence_path.suffix + ".manifest.json"
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if (
                manifest.get("manifest_version") != "1.0.0"
                or manifest.get("evidence_file") != evidence_path.name
                or manifest.get("evidence_sha256") != terminal_digest
            ):
                raise ProbeError(
                    "STATE_TERMINAL_MANIFEST_MISMATCH",
                    str(manifest_path),
                )
            prior = json.loads(evidence_path.read_text(encoding="utf-8"))
            if prior.get("outcome") != "ACTIONS_CANCELLED":
                raise ProbeError("STATE_TERMINAL_OUTCOME_MISMATCH", str(prior.get("outcome")))
            print("P0_V2_FINALIZER_STATUS=ACTIONS_CANCELLED")
            print(f"P0_V2_EVIDENCE_SHA256={terminal_digest}")
            return 0

        raw_active_case = state.get("active_case")
        if not isinstance(raw_active_case, dict):
            raise ProbeError("STATE_ACTIVE_CASE_MISSING", state["phase"])
        active_case = raw_active_case
        stdout_fd = open_bound_fifo("stdout")
        stderr_fd = open_bound_fifo("stderr")
        selector = selectors.DefaultSelector()
        selector.register(stdout_fd, selectors.EVENT_READ, "stdout")
        selector.register(stderr_fd, selectors.EVENT_READ, "stderr")

        properties = systemctl_properties(active_case["unit"])
        if properties.get("InvocationID") != active_case["invocation_id"]:
            raise ProbeError("INVOCATION_ID_MISMATCH", properties.get("InvocationID", ""))
        if properties.get("ControlGroup") != active_case["cgroup_path"]:
            raise ProbeError("CONTROL_GROUP_MISMATCH", properties.get("ControlGroup", ""))
        if parse_systemd_int("MainPID", properties.get("MainPID", "0")) != active_case[
            "main_pid"
        ]:
            raise ProbeError("MAIN_PID_MISMATCH", properties.get("MainPID", ""))
        for fd_name, stream in (("1", "stdout"), ("2", "stderr")):
            fd_path = Path("/proc") / str(active_case["main_pid"]) / "fd" / fd_name
            fd_stat = fd_path.stat()
            if (
                not stat.S_ISFIFO(fd_stat.st_mode)
                or fd_stat.st_dev != active_case[f"{stream}_fifo_device"]
                or fd_stat.st_ino != active_case[f"{stream}_fifo_inode"]
                or os.readlink(fd_path)
                != active_case["capture_fd_identity"][fd_name]["target"]
            ):
                raise ProbeError("CHILD_CAPTURE_FD_MISMATCH", fd_name)
        cgroup_dir = CGROUP_ROOT / active_case["cgroup_path"].lstrip("/")
        cgroup_stat = cgroup_dir.stat()
        if (
            cgroup_stat.st_dev != active_case["cgroup_device"]
            or cgroup_stat.st_ino != active_case["cgroup_inode"]
        ):
            raise ProbeError("CGROUP_IDENTITY_MISMATCH", str(cgroup_dir))
        events_fd = os.open(
            cgroup_dir / "cgroup.events",
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        kill_fd = os.open(
            cgroup_dir / "cgroup.kill",
            os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        persist_phase("finalizer_bound")

        os.write(kill_fd, b"1")
        kill_written = True
        persist_phase("cgroup_kill_written")
        lifecycle.append(lifecycle_event("cgroup_kill_written"))
        empty = wait_cgroup_empty(events_fd)
        if not empty:
            raise ProbeError("CGROUP_NOT_EMPTY", active_case["unit"])
        persist_phase("cgroup_empty_observed")
        lifecycle.append(lifecycle_event("cgroup_empty_observed"))

        eof_deadline = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
        while selector.get_map() and time.monotonic() < eof_deadline:
            drain_streams(selector, captures, wait=0.05)
        eof = not selector.get_map()
        if not eof:
            raise ProbeError("STREAM_EOF_NOT_OBSERVED", active_case["unit"])
        persist_phase("stream_eof_observed")
        lifecycle.append(lifecycle_event("streams_eof_observed"))

        for fd_name in ("kill_fd", "events_fd"):
            fd_value = kill_fd if fd_name == "kill_fd" else events_fd
            if fd_value is not None:
                os.close(fd_value)
                if fd_name == "kill_fd":
                    kill_fd = None
                else:
                    events_fd = None
        unload_unit(active_case["unit"])
        unloaded = True
        lifecycle.append(lifecycle_event("unit_unloaded"))
        host_tmp_sentinel = Path(active_case["host_tmp_sentinel"])
        expected_sentinel = Path("/tmp") / f"p0-v2-host-{active_case['nonce']}"
        if (
            host_tmp_sentinel != expected_sentinel
            or not host_tmp_sentinel.is_file()
            or sha256_path(host_tmp_sentinel)
            != active_case["host_tmp_sentinel_sha256"]
        ):
            raise ProbeError(
                "HOST_TMP_ISOLATION_FAILED",
                str(host_tmp_sentinel),
            )
        staged_probe = Path(active_case["staged_probe"])
        staged_stat = staged_probe.stat()
        if (
            staged_stat.st_dev != active_case["staged_probe_device"]
            or staged_stat.st_ino != active_case["staged_probe_inode"]
            or stat.S_IMODE(staged_stat.st_mode)
            != active_case["staged_probe_mode"]
            or staged_stat.st_uid != active_case["staged_probe_uid"]
            or staged_stat.st_gid != active_case["staged_probe_gid"]
            or sha256_path(staged_probe) != state["source_sha256"]
        ):
            raise ProbeError("STAGED_SOURCE_MUTATED", str(staged_probe))
        host_tmp_sentinel.unlink()
        persist_phase("unit_unloaded")
    except ProbeError as exc:
        errors.append(error_record(exc.code, exc.detail))
    except BaseException as exc:
        errors.append(error_record("FINALIZER_FAILED", repr(exc)))
    finally:
        for fd in (kill_fd, events_fd, directory_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if selector is not None:
            for key in list(selector.get_map().values()):
                try:
                    selector.unregister(key.fd)
                    os.close(key.fd)
                except OSError:
                    pass
            selector.close()
        if state and state.get("core_pattern_original_recorded"):
            try:
                restored_bytes = restore_core_pattern(state)
                restored = True
                state["phase"] = "core_pattern_restored"
                write_root_state(state_path, state)
                lifecycle.append(lifecycle_event("core_pattern_restored"))
            except BaseException as exc:
                errors.append(
                    error_record(
                        "COREDUMP_RESTORE_FAILED",
                        repr(exc),
                        "kernel_observed",
                    )
                )

    if kill_written and empty and eof and unloaded and restored and not errors:
        outcome = "ACTIONS_CANCELLED"
        lifecycle.append(lifecycle_event("finalizer_complete"))

    host, host_errors = host_preflight()
    errors.extend(host_errors)
    host.append(
        observation(
            "host.core_pattern_after_finalizer_base64",
            "kernel_observed",
            base64.b64encode(read_limited_bytes(CORE_PATTERN_PATH)).decode("ascii")
            if CORE_PATTERN_PATH.exists()
            else "",
        )
    )
    coredump_unchanged = True
    try:
        coredump_after = coredump_effect_snapshot()
        host.append(
            observation(
                "host.coredump_effects_after",
                "platform_file_observed",
                coredump_after,
            )
        )
        for invariant in ("package", "configuration", "helper_units", "storage"):
            if state.get("coredump_before", {}).get(invariant) != coredump_after.get(
                invariant
            ):
                coredump_unchanged = False
                errors.append(
                    error_record(
                        "COREDUMP_SIDE_EFFECT_OBSERVED",
                        invariant,
                        "platform_file_observed",
                    )
                )
        journal_delta = journal_delta_since(state.get("coredump_before", {}))
        host.append(
            observation(
                "host.journal_delta",
                "platform_file_observed",
                journal_delta,
            )
        )
        if journal_delta["coredump_related_lines"]:
            coredump_unchanged = False
            errors.append(
                error_record(
                    "COREDUMP_JOURNAL_SIDE_EFFECT_OBSERVED",
                    str(len(journal_delta["coredump_related_lines"])),
                    "platform_file_observed",
                )
            )
    except BaseException as exc:
        coredump_unchanged = False
        errors.append(
            error_record(
                "COREDUMP_SNAPSHOT_FAILED",
                repr(exc),
                "platform_file_observed",
            )
        )
    if errors:
        outcome = "CLEANUP_FAILURE"

    identity = [
        observation("github.repository", "github_context_claim", args.repository),
        observation("github.pr_number", "github_context_claim", args.pr_number),
        observation("github.event_action", "github_context_claim", args.event_action),
        observation("github.workflow", "github_context_claim", args.workflow),
        observation("github.workflow_ref", "github_context_claim", args.workflow_ref),
        observation("github.workflow_sha", "github_context_claim", args.workflow_sha),
        observation("github.event_name", "github_context_claim", args.event_name),
        observation("github.run_id", "github_context_claim", args.run_id),
        observation("github.run_attempt", "github_context_claim", args.run_attempt),
        observation("github.pr_head_sha", "github_context_claim", args.head_sha),
        observation(
            "github.pr_head_repository",
            "github_context_claim",
            args.head_repository,
        ),
        observation("github.pr_head_ref", "github_context_claim", args.head_ref),
        observation("github.pr_base_sha", "github_context_claim", args.base_sha),
        observation(
            "github.pr_base_repository",
            "github_context_claim",
            args.base_repository,
        ),
        observation("github.pr_base_ref", "github_context_claim", args.base_ref),
        observation("github.pr_merge_sha", "github_context_claim", args.merge_sha),
        observation("runner.image", "github_context_claim", args.runner_image),
        observation("runner.arch", "github_context_claim", args.runner_arch),
        observation(
            "runner.boot_id",
            "kernel_observed",
            read_text(Path("/proc/sys/kernel/random/boot_id"), 128).strip(),
        ),
    ]
    source_path = Path(args.source_path).resolve()
    schema_path = Path(args.schema_path).resolve()
    source = [
        observation("source.probe_sha256", "supervisor_observed", sha256_path(source_path)),
        observation("source.schema_sha256", "supervisor_observed", sha256_path(schema_path)),
        observation(
            "source.workflow_sha256",
            "supervisor_observed",
            sha256_path(Path(args.workflow_file).resolve()),
        ),
        observation(
            "source.test_sha256",
            "supervisor_observed",
            sha256_path(Path(args.test_file).resolve()),
        ),
        observation("source.task_commit", "github_context_claim", CONTROL_TASK_COMMIT),
        observation("source.task_sha256", "github_context_claim", CONTROL_TASK_SHA256),
    ]
    requested_argv = active_case.get("requested_argv", [])
    observed_argv = active_case.get("kernel_observed_argv", [])
    requested_environment = active_case.get("requested_environment", {})
    observed_environment = active_case.get("kernel_observed_environment", {})
    case = {
        "id": "operator-cancel",
        "outcome": outcome,
        "outcome_authority": "supervisor_observed",
        "started_monotonic_ns": lifecycle[0]["monotonic_ns"],
        "finished_monotonic_ns": time.monotonic_ns(),
        "requested_argv": requested_argv,
        "requested_argv_authority": "supervisor_observed",
        "kernel_observed_argv": observed_argv,
        "kernel_observed_argv_authority": "kernel_observed",
        "requested_environment": requested_environment,
        "requested_environment_authority": "supervisor_observed",
        "kernel_observed_environment": observed_environment,
        "kernel_observed_environment_authority": "kernel_observed",
        "stdout": captures["stdout"].document(),
        "stderr": captures["stderr"].document(),
        "cleanup": {
            "direct_cgroup_kill_written": kill_written,
            "direct_cgroup_kill_authority": "kernel_observed",
            "recursive_populated_zero_observed": empty,
            "recursive_populated_zero_authority": "kernel_observed",
            "path_absence_used_as_proof": False,
            "streams_eof_after_empty": eof,
            "streams_eof_authority": "supervisor_observed",
            "unit_unloaded_after_empty": unloaded,
            "unit_unloaded_authority": "systemd_observed",
        },
        "observations": [
            observation("unit.properties", "systemd_observed", properties),
            observation(
                "cancellation.workflow_state",
                "github_context_claim",
                "cancelled",
            ),
            observation(
                "cancellation.core_pattern_restored",
                "kernel_observed",
                restored,
            ),
            observation(
                "bootstrap.argv_raw_base64",
                "kernel_observed",
                active_case.get("kernel_observed_argv_raw_base64", []),
            ),
            observation(
                "bootstrap.environment_raw_base64",
                "kernel_observed",
                active_case.get("kernel_observed_environment_raw_base64", []),
            ),
        ],
        "errors": errors.copy(),
    }
    evidence = make_evidence(
        args,
        outcome=outcome,
        identity=identity,
        source=source,
        host=host,
        requested_controls=[
            observation(f"requested.{index:03d}", "supervisor_observed", value)
            for index, value in enumerate(SYSTEMD_PROPERTIES_BASE)
        ],
        reported_controls=[
            observation(f"unit.{key.lower()}", "systemd_observed", value)
            for key, value in sorted(properties.items())
        ],
        effective_controls=[
            observation(
                "bootstrap.argv_matches",
                "kernel_observed",
                requested_argv == observed_argv,
            ),
            observation(
                "bootstrap.environment_matches",
                "kernel_observed",
                environment_contract_satisfied(
                    requested_environment,
                    observed_environment,
                ),
            ),
            observation(
                "bootstrap.capture_fd_identity",
                "kernel_observed",
                bool(active_case.get("capture_fd_identity")),
            ),
            observation("cleanup.cgroup_kill", "kernel_observed", kill_written),
            observation("cleanup.populated_zero", "kernel_observed", empty),
            observation("cleanup.streams_eof", "supervisor_observed", eof),
            observation("cleanup.unit_unloaded", "systemd_observed", unloaded),
            observation("cleanup.core_pattern_restored", "kernel_observed", restored),
            observation(
                "cleanup.coredump_no_unauthorized_side_effect",
                "platform_file_observed",
                coredump_unchanged,
            ),
        ],
        lifecycle=lifecycle,
        cases=[case],
        cancellation={
            "claim_type": "ordinary_github_cancellation",
            "authority": "github_context_claim",
            "finalizer_ran": True,
            "same_vm_cleanup_observed": outcome == "ACTIONS_CANCELLED",
            "force_cancellation_proven": False,
        },
        errors=errors,
    )
    try:
        digest = atomic_seal(
            evidence_path,
            evidence,
            schema_path,
            args.evidence_uid,
            args.evidence_gid,
        )
        state["terminal_evidence_sha256"] = digest
        state["phase"] = "evidence_sealed"
        write_root_state(state_path, state)
    except BaseException:
        print("P0_V2_FINALIZER_STATUS=EVIDENCE_SEAL_FAILURE")
        return 3
    print(f"P0_V2_FINALIZER_STATUS={outcome}")
    print(f"P0_V2_EVIDENCE_SHA256={digest}")
    return 0 if outcome == "ACTIONS_CANCELLED" else 1


def fixture_case(case_id: str, nonce: str) -> int:
    if not re.fullmatch(r"[0-9a-f]{16}", nonce):
        return 89
    release = os.read(0, 1)
    if release != b"R":
        return 91
    if case_id == "success":
        os.write(1, b"success\n")
        return 0
    if case_id == "nonzero":
        os.write(2, b"nonzero\n")
        return 17
    if case_id == "signal":
        os.kill(os.getpid(), signal.SIGTERM)
        return 92
    if case_id == "timeout" or case_id == "operator-cancel":
        time.sleep(300)
        return 0
    if case_id in {"background-child", "retained-writer"}:
        if os.fork() == 0:
            time.sleep(300)
            os._exit(0)
        return 0
    if case_id == "setsid-child":
        if os.fork() == 0:
            os.setsid()
            time.sleep(300)
            os._exit(0)
        return 0
    if case_id == "double-fork-setsid":
        if os.fork() == 0:
            os.setsid()
            if os.fork() == 0:
                time.sleep(300)
                os._exit(0)
            os._exit(0)
        return 0
    if case_id == "fd-tamper":
        results = []
        for operation in ("ftruncate", "lseek"):
            try:
                if operation == "ftruncate":
                    os.ftruncate(1, 0)
                else:
                    os.lseek(1, 0, os.SEEK_SET)
                results.append(f"{operation}:unexpected-success")
            except OSError as exc:
                results.append(f"{operation}:{exc.errno}")
        duplicate = os.dup(1)
        os.write(duplicate, (";".join(results) + "\n").encode("ascii"))
        os.close(duplicate)
        return 24 if any(item.endswith("unexpected-success") for item in results) else 0
    if case_id == "writer-handoff":
        if os.fork() == 0:
            inherited = os.dup(1)
            os.close(1)
            os.write(inherited, b"writer-handoff\n")
            time.sleep(300)
            os._exit(0)
        return 0
    if case_id == "invalid-output":
        os.write(1, b"\xff\xfe::warning::untrusted\n")
        os.write(2, b"::set-output name=x::untrusted\nGITHUB_ENV=untrusted\n")
        return 0
    if case_id == "output-flood":
        block = b"x" * 65536
        while True:
            os.write(1, block)
            os.write(2, block)
    if case_id == "fork-limit":
        children = []
        while True:
            try:
                pid = os.fork()
            except OSError as exc:
                if exc.errno in {errno.EAGAIN, errno.ENOMEM}:
                    return 0
                return 31
            if pid == 0:
                time.sleep(300)
                os._exit(0)
            children.append(pid)
    if case_id == "memory-limit":
        allocations = []
        while True:
            block = bytearray(16 * 1024 * 1024)
            for offset in range(0, len(block), mmap.PAGESIZE):
                block[offset] = 1
            allocations.append(block)
    if case_id == "nofile-limit":
        descriptors = []
        while True:
            try:
                descriptors.append(os.open("/dev/null", os.O_RDONLY))
            except OSError as exc:
                if exc.errno == errno.EMFILE:
                    return 0
                return 32
    if case_id == "fsize-limit":
        destination = os.open(
            "/tmp/fsize-limit",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        block = b"f" * (1024 * 1024)
        while True:
            os.write(destination, block)
    if case_id == "tmpfs-limit":
        block = b"t" * (1024 * 1024)
        try:
            for index in range(16):
                with open(f"/tmp/tmpfs-{index}", "wb", buffering=0) as stream:
                    stream.write(block)
        except OSError as exc:
            if exc.errno in {errno.ENOSPC, errno.EDQUOT}:
                return 0
            return 33
        return 34
    if case_id == "sandbox-probe":
        failures: List[str] = []

        def require_oserror(label: str, operation) -> None:
            try:
                operation()
                failures.append(label)
            except OSError:
                pass

        host_sentinel = Path("/tmp") / f"p0-v2-host-{nonce}"
        if host_sentinel.exists():
            failures.append("host-tmp-visible")
        host_sentinel.write_bytes(b"child-private-tmp")
        require_oserror(
            "root-readable",
            lambda: os.open("/root", os.O_RDONLY | os.O_DIRECTORY),
        )
        require_oserror(
            "cgroup-writable",
            lambda: os.open("/sys/fs/cgroup/cgroup.procs", os.O_WRONLY),
        )
        require_oserror(
            "sysctl-writable",
            lambda: os.open("/proc/sys/kernel/core_pattern", os.O_WRONLY),
        )
        require_oserror(
            "host-process-visible",
            lambda: os.open("/proc/1/status", os.O_RDONLY),
        )
        require_oserror(
            "actions-command-writable",
            lambda: os.open(
                "/home/runner/work/_temp/_runner_file_commands/p0-v2",
                os.O_WRONLY | os.O_CREAT,
                0o600,
            ),
        )
        for family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX):
            try:
                candidate = socket.socket(family, socket.SOCK_STREAM)
                candidate.close()
                failures.append(f"socket:{family}")
            except OSError:
                pass
        for socket_path in (
            "/run/systemd/private",
            "/run/docker.sock",
            "/var/run/docker.sock",
            "/run/containerd/containerd.sock",
        ):
            try:
                mode = os.stat(socket_path, follow_symlinks=False).st_mode
            except OSError:
                continue
            if stat.S_ISSOCK(mode):
                try:
                    candidate = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    candidate.settimeout(0.5)
                    candidate.connect(socket_path)
                    failures.append(f"host-socket:{socket_path}")
                except OSError:
                    pass
                finally:
                    try:
                        candidate.close()
                    except UnboundLocalError:
                        pass
        for label, operation in (
            ("setuid-root", lambda: os.setuid(0)),
            ("setgid-root", lambda: os.setgid(0)),
            (
                "realtime",
                lambda: os.sched_setscheduler(
                    0,
                    os.SCHED_FIFO,
                    os.sched_param(1),
                ),
            ),
        ):
            require_oserror(label, operation)
        try:
            executable = mmap.mmap(
                -1,
                mmap.PAGESIZE,
                prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
            )
            executable.close()
            failures.append("writable-executable-memory")
        except OSError:
            pass
        if os.uname().machine != "x86_64":
            failures.append(f"unexpected-architecture:{os.uname().machine}")
        else:
            libc = ctypes.CDLL(None, use_errno=True)
            libc.syscall.restype = ctypes.c_long

            def require_syscall_denial(
                label: str,
                number: int,
                *arguments: int,
            ) -> None:
                ctypes.set_errno(0)
                result = libc.syscall(number, *arguments)
                observed_errno = ctypes.get_errno()
                if result != -1 or observed_errno not in {
                    errno.EPERM,
                    errno.EACCES,
                    errno.ENOSYS,
                }:
                    failures.append(
                        f"syscall:{label}:{result}:{observed_errno}"
                    )

            for syscall_probe in (
                ("mount", 165, 0, 0, 0, 0, 0),
                ("swapon", 167, 0, 0),
                ("reboot", 169, 0, 0, 0, 0),
                ("iopl", 172, 3),
                ("init_module", 175, 0, 0, 0),
                ("add_key", 248, 0, 0, 0, 0, 0),
                ("request_key", 249, 0, 0, 0, 0),
                ("keyctl", 250, 0, 0, 0, 0, 0),
                ("unshare", 272, 0x00020000),
                ("perf_event_open", 298, 0, 0, -1, -1, 0),
                ("finit_module", 313, -1, 0, 0),
                ("bpf", 321, 0, 0, 0),
                ("io_uring_setup", 425, 1, 0),
            ):
                require_syscall_denial(
                    syscall_probe[0],
                    syscall_probe[1],
                    *syscall_probe[2:],
                )
            ctypes.set_errno(0)
            personality_result = libc.syscall(135, 0x0008)
            personality_errno = ctypes.get_errno()
            if personality_result != -1 or personality_errno not in {
                errno.EPERM,
                errno.EACCES,
                errno.ENOSYS,
            }:
                failures.append(
                    f"syscall:personality:{personality_result}:{personality_errno}"
                )
        for argv, label in (
            (["/usr/bin/sudo", "-n", "/usr/bin/true"], "sudo"),
            (["/usr/bin/unshare", "--mount", "/usr/bin/true"], "unshare"),
        ):
            try:
                completed = subprocess.run(
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2,
                    check=False,
                )
                if completed.returncode == 0:
                    failures.append(label)
            except (OSError, subprocess.TimeoutExpired):
                pass
        unknown = Path("/tmp/p0-v2-unknown")
        unknown.write_bytes(b"not-an-executable\n")
        unknown.chmod(0o700)
        try:
            completed = subprocess.run(
                [str(unknown)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
                check=False,
            )
            if completed.returncode == 0:
                failures.append("unknown-executable")
        except (OSError, subprocess.TimeoutExpired):
            pass
        if failures:
            os.write(2, canonical_json_bytes(failures))
            return 23
        return 0
    if case_id == "crash-storm":
        signals = (signal.SIGSEGV, signal.SIGABRT, signal.SIGBUS, signal.SIGILL)
        children = []
        for sig in signals:
            pid = os.fork()
            if pid == 0:
                os.kill(os.getpid(), sig)
                os._exit(99)
            children.append(pid)
        for pid in children:
            os.waitpid(pid, 0)
        return 0
    return 90


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    fixture = subparsers.add_parser("fixture")
    fixture.add_argument("--case", required=True)
    fixture.add_argument("--nonce", required=True)
    for command in ("supervisor", "finalize"):
        child = subparsers.add_parser(command)
        child.add_argument("--run-id", required=True)
        child.add_argument("--run-attempt", required=True)
        child.add_argument("--pr-number", required=True)
        child.add_argument("--event-action", required=True)
        child.add_argument("--head-sha", required=True)
        child.add_argument("--head-repository", required=True)
        child.add_argument("--head-ref", required=True)
        child.add_argument("--base-sha", required=True)
        child.add_argument("--base-repository", required=True)
        child.add_argument("--base-ref", required=True)
        child.add_argument("--merge-sha", required=True)
        child.add_argument("--repository", required=True)
        child.add_argument("--workflow", required=True)
        child.add_argument("--workflow-ref", required=True)
        child.add_argument("--workflow-sha", required=True)
        child.add_argument("--workflow-file", required=True)
        child.add_argument("--test-file", required=True)
        child.add_argument("--event-name", required=True)
        child.add_argument("--runner-image", required=True)
        child.add_argument("--runner-arch", required=True)
        child.add_argument("--source-path", required=True)
        child.add_argument("--schema-path", required=True)
        child.add_argument("--evidence-dir", required=True)
        child.add_argument("--evidence-uid", type=int, required=True)
        child.add_argument("--evidence-gid", type=int, required=True)
        if command == "supervisor":
            child.add_argument("--cancel-canary", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if args.command == "fixture":
        return fixture_case(args.case, args.nonce)
    if args.command == "supervisor":
        return supervisor(args)
    if args.command == "finalize":
        return finalize_cancelled(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
