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
import errno
import hashlib
import json
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
    "output-flood",
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
    "output-flood": "OUTPUT_LIMIT",
    "sandbox-probe": "SUCCESS",
    "crash-storm": "SUCCESS",
    "operator-cancel": "ACTIONS_CANCELLED",
}

REQUESTED_ENVIRONMENT = {
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
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
    "LimitNOFILE",
    "LimitFSIZE",
    "LimitCORE",
    "ControlGroup",
    "MainPID",
)


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
    for case in evidence["cases"]:
        if case["finished_monotonic_ns"] < case["started_monotonic_ns"]:
            raise ProbeError("SCHEMA_INVALID", f"{case['id']}: time reversed")
        cleanup = case["cleanup"]
        if cleanup["unit_unloaded_after_empty"] and not cleanup["recursive_populated_zero_observed"]:
            raise ProbeError("SCHEMA_INVALID", f"{case['id']}: unload before empty proof")
        if cleanup["streams_eof_after_empty"] and not cleanup["recursive_populated_zero_observed"]:
            raise ProbeError("SCHEMA_INVALID", f"{case['id']}: EOF before empty proof")


def atomic_seal(path: Path, evidence: Mapping[str, Any], schema_path: Path, uid: int, gid: int) -> str:
    validate_evidence(evidence, schema_path)
    payload = canonical_json_bytes(evidence)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
        os.fchown(fd, uid, gid)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    digest = sha256_bytes(payload)
    digest_path = path.with_suffix(path.suffix + ".sha256")
    digest_payload = f"{digest}  {path.name}\n".encode("ascii")
    digest_fd = os.open(digest_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(digest_fd, digest_payload)
        os.fsync(digest_fd)
        os.fchown(digest_fd, uid, gid)
    finally:
        os.close(digest_fd)
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


def systemctl_properties(unit: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for name in SYSTEMD_SHOW_PROPERTIES:
        result[name] = systemctl_value(unit, name)
    return result


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
        "unit",
        "cgroup_path",
        "run_id",
        "run_attempt",
        "nonce",
        "uid",
        "gid",
        "source_sha256",
        "stdout_fifo",
        "stderr_fifo",
        "core_pattern_original",
        "evidence_dir",
        "schema_path",
        "head_sha",
        "requested_argv",
        "requested_environment",
    }
    if set(value) != required:
        raise ProbeError("STATE_UNTRUSTED", "state record fields mismatch")
    if not SAFE_UNIT_RE.fullmatch(value["unit"]):
        raise ProbeError("STATE_UNTRUSTED", "unsafe unit name")
    if not SAFE_CGROUP_RE.fullmatch(value["cgroup_path"]):
        raise ProbeError("STATE_UNTRUSTED", "unsafe cgroup path")
    if not SHA64_RE.fullmatch(value["source_sha256"]):
        raise ProbeError("STATE_UNTRUSTED", "unsafe source digest")
    validate_sha40("head_sha", value["head_sha"])
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


def parse_proc_environment(path: Path) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for item in parse_proc_nul(path):
        key, separator, value = item.partition("=")
        if separator:
            result[key] = value
    return result


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


def systemd_properties(state_dir: Path, barrier: Path, stdout_fifo: Path, stderr_fifo: Path) -> List[str]:
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
        f"InaccessiblePaths={state_dir}",
        *(f"Environment={key}={value}" for key, value in REQUESTED_ENVIRONMENT.items()),
        f"UnsetEnvironment={forbidden}",
    ]


def render_systemd_run_argv(
    unit: str,
    interpreter: Path,
    staged_probe: Path,
    case_id: str,
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
    for prop in systemd_properties(state_dir, barrier, stdout_fifo, stderr_fifo):
        argv.append(f"--property={prop}")
    argv.extend(
        [
            str(interpreter),
            "-I",
            str(staged_probe),
            "fixture",
            "--case",
            case_id,
        ]
    )
    return argv


def suppress_core_pattern() -> Tuple[str, str]:
    original = read_text(CORE_PATTERN_PATH, 4096).strip()
    active = original
    if original.startswith("|"):
        CORE_PATTERN_PATH.write_text("core\n", encoding="ascii")
        active = read_text(CORE_PATTERN_PATH, 4096).strip()
        if active != "core":
            raise ProbeError("COREDUMP_SUPPRESSION_FAILED", "core_pattern write did not stick")
    return original, active


def restore_core_pattern(original: str) -> None:
    CORE_PATTERN_PATH.write_text(original + "\n", encoding="utf-8")
    observed = read_text(CORE_PATTERN_PATH, 4096).strip()
    if observed != original:
        raise ProbeError("COREDUMP_RESTORE_FAILED", "core_pattern restoration mismatch")


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


def observe_bootstrap(pid: int, cgroup_path: str) -> Tuple[List[str], Dict[str, str], List[Dict[str, Any]]]:
    proc = Path("/proc") / str(pid)
    argv = parse_proc_nul(proc / "cmdline")
    environment = parse_proc_environment(proc / "environ")
    status = parse_status(read_text(proc / "status"))
    proc_cgroup = read_text(proc / "cgroup", 65536)
    if f"0::{cgroup_path}" not in proc_cgroup:
        raise ProbeError("CGROUP_BINDING_MISMATCH", proc_cgroup)
    if status.get("NoNewPrivs") != "1":
        raise ProbeError("NO_NEW_PRIVILEGES_INEFFECTIVE", status.get("NoNewPrivs", "missing"))
    if int(status.get("CapEff", "1"), 16) != 0:
        raise ProbeError("CAPABILITY_BOUNDARY_INEFFECTIVE", status.get("CapEff", "missing"))
    uid_values = status.get("Uid", "").split()
    if not uid_values or uid_values[0] == "0":
        raise ProbeError("DEDICATED_UID_INEFFECTIVE", status.get("Uid", "missing"))
    for key in environment:
        if key.startswith(FORBIDDEN_ENV_PREFIXES):
            raise ProbeError("FORBIDDEN_ENVIRONMENT_VISIBLE", key)
    fd_entries = sorted(item.name for item in (proc / "fd").iterdir())
    namespace_ids = {
        item.name: os.readlink(item)
        for item in (proc / "ns").iterdir()
        if item.name in {"mnt", "net", "ipc", "pid", "user", "uts", "cgroup"}
    }
    observations = [
        observation("bootstrap.status", "kernel_observed", status),
        observation("bootstrap.limits", "kernel_observed", read_text(proc / "limits")),
        observation("bootstrap.mountinfo", "kernel_observed", read_text(proc / "mountinfo")),
        observation("bootstrap.cgroup", "kernel_observed", proc_cgroup),
        observation("bootstrap.file_descriptors", "kernel_observed", fd_entries),
        observation("bootstrap.namespaces", "kernel_observed", namespace_ids),
    ]
    return argv, environment, observations


def _empty_stream_document() -> Dict[str, Any]:
    return StreamCapture(MAX_RETAINED_COMBINED // 2).document()


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
    core_pattern_original: str,
) -> Dict[str, Any]:
    started = time.monotonic_ns()
    nonce = uuid.uuid4().hex[:16]
    unit = safe_unit_name(run_id, case_id, nonce)
    state_dir = ROOT_RUNTIME / f"case-{nonce}"
    state_dir.mkdir(mode=0o700)
    staged_probe = state_dir / "probe.py"
    shutil.copyfile(source_path, staged_probe)
    os.chown(staged_probe, 0, 0)
    os.chmod(staged_probe, 0o555)
    if sha256_path(staged_probe) != source_sha256:
        raise ProbeError("STAGED_SOURCE_DIGEST_MISMATCH", case_id)
    barrier = state_dir / "barrier.fifo"
    stdout_fifo = state_dir / "stdout.fifo"
    stderr_fifo = state_dir / "stderr.fifo"
    for fifo in (barrier, stdout_fifo, stderr_fifo):
        os.mkfifo(fifo, 0o600)
        os.chown(fifo, 0, 0)
    stdout_fd = os.open(stdout_fifo, os.O_RDONLY | os.O_NONBLOCK)
    stderr_fd = os.open(stderr_fifo, os.O_RDONLY | os.O_NONBLOCK)
    barrier_fd = os.open(barrier, os.O_RDWR | os.O_NONBLOCK)
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
    ]
    launch_argv = render_systemd_run_argv(
        unit,
        interpreter,
        staged_probe,
        case_id,
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
    kernel_argv: List[str] = []
    kernel_environment: Dict[str, str] = {}
    state_path = state_path_for(run_id, run_attempt)
    try:
        run_command(launch_argv)
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
        events_fd = os.open(cgroup_dir / "cgroup.events", os.O_RDONLY)
        kill_fd = os.open(cgroup_dir / "cgroup.kill", os.O_WRONLY)
        kernel_argv, kernel_environment, bootstrap_observations = observe_bootstrap(pid, cgroup_path)
        observations.extend(bootstrap_observations)
        properties = systemctl_properties(unit)
        observations.append(observation("unit.properties", "systemd_observed", properties))
        observations.append(observation("cgroup.type", "kernel_observed", cgroup_type))
        state = {
            "unit": unit,
            "cgroup_path": cgroup_path,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "nonce": nonce,
            "uid": evidence_uid,
            "gid": evidence_gid,
            "source_sha256": source_sha256,
            "stdout_fifo": str(stdout_fifo),
            "stderr_fifo": str(stderr_fifo),
            "core_pattern_original": core_pattern_original,
            "evidence_dir": str(evidence_dir),
            "schema_path": str(schema_path),
            "head_sha": head_sha,
            "requested_argv": requested_argv,
            "requested_environment": REQUESTED_ENVIRONMENT,
        }
        write_root_state(state_path, state)
        os.write(barrier_fd, b"R")
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
                code = systemctl_value(unit, "ExecMainCode")
                status_value = systemctl_value(unit, "ExecMainStatus")
                observations.extend(
                    [
                        observation("unit.result", "systemd_observed", result),
                        observation("unit.exec_main_code", "systemd_observed", code),
                        observation("unit.exec_main_status", "systemd_observed", status_value),
                    ]
                )
                if result == "oom-kill":
                    outcome = "RESOURCE_OOM"
                elif code == "exited" and status_value == "0":
                    outcome = "SUCCESS"
                elif code == "exited":
                    outcome = "NONZERO_EXIT"
                else:
                    outcome = "SIGNAL"
                break
        else:
            outcome = "TIMEOUT"
        os.write(kill_fd, b"1")
        kill_written = True
        if not wait_cgroup_empty(events_fd):
            outcome = "EMPTY_PROOF_FAILURE"
            raise ProbeError("CGROUP_NOT_EMPTY", case_id)
        empty_observed = True
        eof_deadline = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
        while selector.get_map() and time.monotonic() < eof_deadline:
            drain_streams(selector, captures, wait=0.05)
        eof_after_empty = not selector.get_map()
        if not eof_after_empty:
            outcome = "CAPTURE_FAILURE"
            raise ProbeError("STREAM_EOF_NOT_OBSERVED", case_id)
        run_command(["/usr/bin/systemctl", "stop", unit], check=False)
        run_command(["/usr/bin/systemctl", "reset-failed", unit], check=False)
        unloaded_after_empty = True
        state_path.unlink(missing_ok=True)
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
        if SAFE_UNIT_RE.fullmatch(unit):
            run_command(["/usr/bin/systemctl", "stop", unit], check=False)
            run_command(["/usr/bin/systemctl", "reset-failed", unit], check=False)
        for fd in (kill_fd, events_fd, barrier_fd):
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
        shutil.rmtree(state_dir, ignore_errors=True)
    if outcome not in OUTCOMES:
        outcome = "INCONCLUSIVE"
    return {
        "id": case_id,
        "outcome": outcome,
        "outcome_authority": "supervisor_observed",
        "started_monotonic_ns": started,
        "finished_monotonic_ns": time.monotonic_ns(),
        "requested_argv": requested_argv,
        "kernel_observed_argv": kernel_argv,
        "requested_environment": REQUESTED_ENVIRONMENT,
        "kernel_observed_environment": kernel_environment,
        "stdout": captures["stdout"].document(),
        "stderr": captures["stderr"].document(),
        "cleanup": {
            "authority": "kernel_observed",
            "direct_cgroup_kill_written": kill_written,
            "recursive_populated_zero_observed": empty_observed,
            "path_absence_used_as_proof": False,
            "streams_eof_after_empty": eof_after_empty,
            "unit_unloaded_after_empty": unloaded_after_empty,
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
    evidence_dir = Path(args.evidence_dir).resolve()
    validate_sha40("head_sha", args.head_sha)
    validate_sha40("merge_sha", args.merge_sha)
    source_sha = sha256_path(source_path)
    schema_sha = sha256_path(schema_path)
    lifecycle = [lifecycle_event("supervisor_started")]
    host, errors = host_preflight()
    lifecycle.append(lifecycle_event("host_preflight_complete"))
    identity = [
        observation("github.repository", "github_context_claim", args.repository),
        observation("github.workflow", "github_context_claim", args.workflow),
        observation("github.event_name", "github_context_claim", args.event_name),
        observation("github.run_id", "github_context_claim", args.run_id),
        observation("github.run_attempt", "github_context_claim", args.run_attempt),
        observation("github.pr_head_sha", "github_context_claim", args.head_sha),
        observation("github.pr_merge_sha", "github_context_claim", args.merge_sha),
        observation("runner.image", "github_context_claim", args.runner_image),
        observation("runner.arch", "github_context_claim", args.runner_arch),
    ]
    source = [
        observation("source.probe_sha256", "supervisor_observed", source_sha),
        observation("source.schema_sha256", "supervisor_observed", schema_sha),
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
    original_core_pattern = ""
    active_core_pattern = ""
    overall = "INCONCLUSIVE"
    try:
        if errors:
            raise ProbeError("HOST_PREFLIGHT_FAILED", "required host capability missing")
        original_core_pattern, active_core_pattern = suppress_core_pattern()
        lifecycle.append(lifecycle_event("core_pattern_suppressed"))
        host.extend(
            [
                observation("host.core_pattern_original", "kernel_observed", original_core_pattern),
                observation("host.core_pattern_active", "kernel_observed", active_core_pattern),
            ]
        )
        chosen_cases: Iterable[str] = ("operator-cancel",) if args.cancel_canary else CASES
        for case_id in chosen_cases:
            if case_id == "operator-cancel":
                print("P0_V2_CANCEL_CANARY_ACTIVE=1", flush=True)
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
                core_pattern_original=original_core_pattern,
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
                        not any(
                            key.startswith(FORBIDDEN_ENV_PREFIXES)
                            for key in case["kernel_observed_environment"]
                        ),
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
                ]
            )
            if case["errors"]:
                break
        if all(
            case["cleanup"]["direct_cgroup_kill_written"]
            and case["cleanup"]["recursive_populated_zero_observed"]
            and case["cleanup"]["streams_eof_after_empty"]
            for case in cases
        ) and len(cases) == len(tuple(chosen_cases)):
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
        if original_core_pattern:
            try:
                restore_core_pattern(original_core_pattern)
                lifecycle.append(lifecycle_event("core_pattern_restored"))
                host.append(
                    observation(
                        "host.core_pattern_after",
                        "kernel_observed",
                        read_text(CORE_PATTERN_PATH, 4096).strip(),
                    )
                )
            except BaseException as exc:
                errors.append(error_record("COREDUMP_RESTORE_FAILED", repr(exc), "kernel_observed"))
                overall = "CLEANUP_FAILURE"
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
    state: Dict[str, Any] = {}
    captures = {
        "stdout": StreamCapture(MAX_RETAINED_COMBINED // 2),
        "stderr": StreamCapture(MAX_RETAINED_COMBINED // 2),
    }
    kill_written = False
    empty = False
    eof = False
    unloaded = False
    properties: Dict[str, str] = {}
    outcome = "CLEANUP_FAILURE"
    try:
        state = load_root_state(state_path)
        if state["head_sha"] != args.head_sha:
            raise ProbeError("STATE_HEAD_MISMATCH", state["head_sha"])
        if sha256_path(Path(args.source_path).resolve()) != state["source_sha256"]:
            raise ProbeError("STATE_SOURCE_MISMATCH", "finalizer source digest mismatch")
        stdout_fd = os.open(state["stdout_fifo"], os.O_RDONLY | os.O_NONBLOCK)
        stderr_fd = os.open(state["stderr_fifo"], os.O_RDONLY | os.O_NONBLOCK)
        selector = selectors.DefaultSelector()
        selector.register(stdout_fd, selectors.EVENT_READ, "stdout")
        selector.register(stderr_fd, selectors.EVENT_READ, "stderr")
        properties = systemctl_properties(state["unit"])
        cgroup_dir = CGROUP_ROOT / state["cgroup_path"].lstrip("/")
        if not cgroup_dir.is_dir():
            raise ProbeError("CGROUP_PATH_MISSING", str(cgroup_dir))
        events_fd = os.open(cgroup_dir / "cgroup.events", os.O_RDONLY)
        kill_fd = os.open(cgroup_dir / "cgroup.kill", os.O_WRONLY)
        try:
            os.write(kill_fd, b"1")
            kill_written = True
            empty = wait_cgroup_empty(events_fd)
        finally:
            os.close(kill_fd)
            os.close(events_fd)
        if not empty:
            raise ProbeError("CGROUP_NOT_EMPTY", state["unit"])
        eof_deadline = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
        while selector.get_map() and time.monotonic() < eof_deadline:
            drain_streams(selector, captures, wait=0.05)
        eof = not selector.get_map()
        for key in list(selector.get_map().values()):
            selector.unregister(key.fd)
            os.close(key.fd)
        selector.close()
        if not eof:
            raise ProbeError("STREAM_EOF_NOT_OBSERVED", state["unit"])
        run_command(["/usr/bin/systemctl", "stop", state["unit"]], check=False)
        run_command(["/usr/bin/systemctl", "reset-failed", state["unit"]], check=False)
        unloaded = True
        restore_core_pattern(state["core_pattern_original"])
        lifecycle.extend(
            [
                lifecycle_event("core_pattern_restored"),
                lifecycle_event("finalizer_complete"),
            ]
        )
        state_path.unlink(missing_ok=True)
        outcome = "ACTIONS_CANCELLED"
    except BaseException as exc:
        errors.append(error_record("FINALIZER_FAILED", repr(exc)))
    host, host_errors = host_preflight()
    errors.extend(host_errors)
    host.append(
        observation(
            "host.core_pattern_after_finalizer",
            "kernel_observed",
            read_text(CORE_PATTERN_PATH, 4096).strip() if CORE_PATTERN_PATH.exists() else "",
        )
    )
    identity = [
        observation("github.repository", "github_context_claim", args.repository),
        observation("github.workflow", "github_context_claim", args.workflow),
        observation("github.event_name", "github_context_claim", args.event_name),
        observation("github.run_id", "github_context_claim", args.run_id),
        observation("github.run_attempt", "github_context_claim", args.run_attempt),
        observation("github.pr_head_sha", "github_context_claim", args.head_sha),
        observation("github.pr_merge_sha", "github_context_claim", args.merge_sha),
        observation("runner.image", "github_context_claim", args.runner_image),
        observation("runner.arch", "github_context_claim", args.runner_arch),
    ]
    source_path = Path(args.source_path).resolve()
    schema_path = Path(args.schema_path).resolve()
    source = [
        observation("source.probe_sha256", "supervisor_observed", sha256_path(source_path)),
        observation("source.schema_sha256", "supervisor_observed", sha256_path(schema_path)),
        observation("source.task_commit", "github_context_claim", CONTROL_TASK_COMMIT),
        observation("source.task_sha256", "github_context_claim", CONTROL_TASK_SHA256),
    ]
    requested_argv = state.get("requested_argv", [])
    requested_environment = state.get("requested_environment", {})
    case = {
        "id": "operator-cancel",
        "outcome": outcome,
        "outcome_authority": "supervisor_observed",
        "started_monotonic_ns": lifecycle[0]["monotonic_ns"],
        "finished_monotonic_ns": time.monotonic_ns(),
        "requested_argv": requested_argv,
        "kernel_observed_argv": [],
        "requested_environment": requested_environment,
        "kernel_observed_environment": {},
        "stdout": captures["stdout"].document(),
        "stderr": captures["stderr"].document(),
        "cleanup": {
            "authority": "kernel_observed",
            "direct_cgroup_kill_written": kill_written,
            "recursive_populated_zero_observed": empty,
            "path_absence_used_as_proof": False,
            "streams_eof_after_empty": eof,
            "unit_unloaded_after_empty": unloaded,
        },
        "observations": [
            observation("unit.properties", "systemd_observed", properties),
            observation(
                "cancellation.workflow_state",
                "github_context_claim",
                "cancelled",
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
            observation("cleanup.cgroup_kill", "kernel_observed", kill_written),
            observation("cleanup.populated_zero", "kernel_observed", empty),
            observation("cleanup.streams_eof", "supervisor_observed", eof),
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
            Path(args.evidence_dir).resolve() / "candidate-evidence.json",
            evidence,
            schema_path,
            args.evidence_uid,
            args.evidence_gid,
        )
    except BaseException as exc:
        print("P0_V2_FINALIZER_STATUS=EVIDENCE_SEAL_FAILURE")
        return 3
    print(f"P0_V2_FINALIZER_STATUS={outcome}")
    print(f"P0_V2_EVIDENCE_SHA256={digest}")
    return 0 if outcome == "ACTIONS_CANCELLED" else 1


def fixture_case(case_id: str) -> int:
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
        return 0
    if case_id == "output-flood":
        block = b"x" * 65536
        while True:
            os.write(1, block)
            os.write(2, block)
    if case_id == "sandbox-probe":
        failures: List[str] = []
        for path in (
            "/home/runner",
            "/root",
            "/sys/fs/cgroup",
            "/run/systemd/private",
            "/var/run/docker.sock",
        ):
            try:
                os.listdir(path)
                failures.append(f"visible:{path}")
            except OSError:
                pass
        for family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX):
            try:
                candidate = socket.socket(family, socket.SOCK_STREAM)
                candidate.close()
                failures.append(f"socket:{family}")
            except OSError:
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
    for command in ("supervisor", "finalize"):
        child = subparsers.add_parser(command)
        child.add_argument("--run-id", required=True)
        child.add_argument("--run-attempt", required=True)
        child.add_argument("--head-sha", required=True)
        child.add_argument("--schema-path", required=True)
        child.add_argument("--evidence-dir", required=True)
        child.add_argument("--evidence-uid", type=int, required=True)
        child.add_argument("--evidence-gid", type=int, required=True)
        if command == "supervisor":
            child.add_argument("--source-path", required=True)
            child.add_argument("--repository", required=True)
            child.add_argument("--workflow", required=True)
            child.add_argument("--event-name", required=True)
            child.add_argument("--merge-sha", required=True)
            child.add_argument("--runner-image", required=True)
            child.add_argument("--runner-arch", required=True)
            child.add_argument("--cancel-canary", action="store_true")
        else:
            child.add_argument("--source-path", required=True)
            child.add_argument("--repository", required=True)
            child.add_argument("--workflow", required=True)
            child.add_argument("--event-name", required=True)
            child.add_argument("--merge-sha", required=True)
            child.add_argument("--runner-image", required=True)
            child.add_argument("--runner-arch", required=True)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if args.command == "fixture":
        return fixture_case(args.case)
    if args.command == "supervisor":
        return supervisor(args)
    if args.command == "finalize":
        return finalize_cancelled(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
