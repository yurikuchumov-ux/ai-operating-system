#!/usr/bin/env python3
"""P0 v2 Gate 1: fail-closed GitHub-hosted runner substrate probe.

This contains candidate feasibility code plus a structurally separate,
proof-ineligible discovery mode.  It is not a production sandbox and not an
authoritative GATE1_* decision maker.  It deliberately uses only the Python
standard library.  The trusted candidate supervisor runs as root, while every
hostile fixture runs in a systemd-created DynamicUser service and one cgroup-v2
subtree.  Discovery never releases a hostile fixture.  Child output is captured
through protected non-seekable FIFOs and is never copied to the Actions command
parser.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import datetime
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
# Reviewer-owned decision namespace. Only the one fixed candidate notice above may
# name it; every other candidate-controlled string, mapping key, or decoded child
# byte that carries this token is rejected as a forged authority claim.
GATE1_NAMESPACE_TOKEN = "GATE1_"

# F7-B0 is a separate, discovery-only evidence domain.  It may describe the
# hosted Linux representation needed to design later differential witnesses,
# but can never satisfy a mandatory effect or enter the candidate outcome gate.
DISCOVERY_EVIDENCE_KIND = "p0-v2-runner-feasibility-discovery"
DISCOVERY_NOTICE = (
    "discovery-only host representation; proof-ineligible by construction; "
    "not candidate evidence and not a decision"
)
DISCOVERY_PROOF_INELIGIBLE_REASON = (
    "discovery mode proves no mandatory effect, moves no property out of "
    "effect_unproven, cannot reach candidate SUCCESS, and has no reviewer authority"
)
TRUSTED_BOOTSTRAP_OBSERVED = "trusted_bootstrap_observed"
DISCOVERY_SURFACES = (
    "runner_image",
    "kernel",
    "systemd",
    "cgroup_topology",
    "mountinfo_topology",
    "bpf_prog_query",
    "device_nodes",
    "executable_abis",
    "field_availability",
)
DISCOVERY_SURFACE_AUTHORITIES = {
    "runner_image": "github_context_claim",
    "kernel": "kernel_observed",
    "systemd": "systemd_observed",
    "cgroup_topology": "platform_file_observed",
    "mountinfo_topology": "platform_file_observed",
    "bpf_prog_query": TRUSTED_BOOTSTRAP_OBSERVED,
    "device_nodes": "platform_file_observed",
    "executable_abis": "supervisor_observed",
    "field_availability": "platform_file_observed",
}
DISCOVERY_MAX_RECORDS = len(DISCOVERY_SURFACES)
DISCOVERY_MAX_RECORD_BYTES = 256 * 1024
DISCOVERY_MAX_TOTAL_BYTES = 1024 * 1024
DISCOVERY_MAX_MOUNTS = 4096
DISCOVERY_MAX_DEVICE_NODES = 512
DISCOVERY_MAX_ABIS = 16
DISCOVERY_MAX_FIELDS = 512
DISCOVERY_SOURCE_TEXT_MAX_BYTES = 65536
DISCOVERY_MOUNTINFO_RAW_MAX_BYTES = 65536
DISCOVERY_BASE64_MAX_LENGTH = (
    (DISCOVERY_SOURCE_TEXT_MAX_BYTES + 2) // 3
) * 4
DISCOVERY_MOUNT_ID_MAX = 2147483647
DISCOVERY_DEVICE_MAJOR_MAX = 4095
DISCOVERY_DEVICE_MINOR_MAX = 1048575
DISCOVERY_UID_GID_MAX = 4294967295
EQUIVALENCE_CLASS_IDENTIFIERS = (
    "EC-DEVICE-ACCESS",
    "EC-KERNEL-OOM-GROUP",
    "EC-DYNAMICUSER-SUID",
    "EC-DYNAMICUSER-IPC",
)
DIFFERENTIAL_WITNESS_ROLES = ("W+", "W-")
DISCOVERY_EC_STATUS = "declared_not_executed"
DISCOVERY_SOURCE_AUTHORING_ANCHOR = (
    "450b33c5963ba2b202e923b52cbc47a9b11d6db7"
)
DISCOVERY_F7B0_AUTHORING_TASK_SHA256 = (
    "fb03ded3feeb76610a04ff25cec3aa1acdc5c1048ce7adb7852d6510933571a2"
)
DISCOVERY_F7B1_HOSTED_AUTHORIZATION_SHA256 = (
    "bb7b706eefa105b122150645151da478146c57e5129e3a39ec69f200c43fa811"
)
DISCOVERY_IMAGE_OS_PATTERN = re.compile(r"^ubuntu24$")
DISCOVERY_IMAGE_VERSION_PATTERN = re.compile(
    r"^[0-9]{8}\.[0-9]+\.[0-9]+$"
)
DISCOVERY_POSITIVE_DECIMAL_PATTERN = re.compile(r"^[1-9][0-9]*$")
DISCOVERY_MAJOR_MINOR_PATTERN = re.compile(
    r"^(?:0|[1-9][0-9]*):(?:0|[1-9][0-9]*)$"
)
DISCOVERY_SYSTEMD_VERSION_PATTERN = re.compile(
    r"^systemd 255 "
    r"\([A-Za-z0-9][A-Za-z0-9.+:~_-]*\)$"
)
DISCOVERY_SYSTEMD_V255_FEATURE_ORDER = (
    "PAM",
    "AUDIT",
    "SELINUX",
    "APPARMOR",
    "IMA",
    "SMACK",
    "SECCOMP",
    "GCRYPT",
    "GNUTLS",
    "OPENSSL",
    "ACL",
    "BLKID",
    "CURL",
    "ELFUTILS",
    "FIDO2",
    "IDN2",
    "IDN",
    "IPTC",
    "KMOD",
    "LIBCRYPTSETUP",
    "LIBFDISK",
    "PCRE2",
    "PWQUALITY",
    "P11KIT",
    "QRENCODE",
    "TPM2",
    "BZIP2",
    "LZ4",
    "XZ",
    "ZLIB",
    "ZSTD",
    "BPF_FRAMEWORK",
    "XKBCOMMON",
    "UTMP",
    "SYSVINIT",
)
DISCOVERY_MOUNT_OPTION_ORDER = (
    "nosuid",
    "nodev",
    "noexec",
    "noatime",
    "nodiratime",
    "relatime",
    "nosymfollow",
    "idmapped",
)
DISCOVERY_SUPERBLOCK_OPTION_ORDER = (
    "sync",
    "dirsync",
    "mand",
    "lazytime",
)
LINUX_ERRNO_NAMES = {
    1: "EPERM",
    2: "ENOENT",
    3: "ESRCH",
    4: "EINTR",
    5: "EIO",
    6: "ENXIO",
    7: "E2BIG",
    8: "ENOEXEC",
    9: "EBADF",
    10: "ECHILD",
    11: "EAGAIN",
    12: "ENOMEM",
    13: "EACCES",
    14: "EFAULT",
    15: "ENOTBLK",
    16: "EBUSY",
    17: "EEXIST",
    18: "EXDEV",
    19: "ENODEV",
    20: "ENOTDIR",
    21: "EISDIR",
    22: "EINVAL",
    23: "ENFILE",
    24: "EMFILE",
    25: "ENOTTY",
    26: "ETXTBSY",
    27: "EFBIG",
    28: "ENOSPC",
    29: "ESPIPE",
    30: "EROFS",
    31: "EMLINK",
    32: "EPIPE",
    33: "EDOM",
    34: "ERANGE",
    35: "EDEADLK",
    36: "ENAMETOOLONG",
    37: "ENOLCK",
    38: "ENOSYS",
    39: "ENOTEMPTY",
    40: "ELOOP",
    42: "ENOMSG",
    43: "EIDRM",
    44: "ECHRNG",
    45: "EL2NSYNC",
    46: "EL3HLT",
    47: "EL3RST",
    48: "ELNRNG",
    49: "EUNATCH",
    50: "ENOCSI",
    51: "EL2HLT",
    52: "EBADE",
    53: "EBADR",
    54: "EXFULL",
    55: "ENOANO",
    56: "EBADRQC",
    57: "EBADSLT",
    59: "EBFONT",
    60: "ENOSTR",
    61: "ENODATA",
    62: "ETIME",
    63: "ENOSR",
    64: "ENONET",
    65: "ENOPKG",
    66: "EREMOTE",
    67: "ENOLINK",
    68: "EADV",
    69: "ESRMNT",
    70: "ECOMM",
    71: "EPROTO",
    72: "EMULTIHOP",
    73: "EDOTDOT",
    74: "EBADMSG",
    75: "EOVERFLOW",
    76: "ENOTUNIQ",
    77: "EBADFD",
    78: "EREMCHG",
    79: "ELIBACC",
    80: "ELIBBAD",
    81: "ELIBSCN",
    82: "ELIBMAX",
    83: "ELIBEXEC",
    84: "EILSEQ",
    85: "ERESTART",
    86: "ESTRPIPE",
    87: "EUSERS",
    88: "ENOTSOCK",
    89: "EDESTADDRREQ",
    90: "EMSGSIZE",
    91: "EPROTOTYPE",
    92: "ENOPROTOOPT",
    93: "EPROTONOSUPPORT",
    94: "ESOCKTNOSUPPORT",
    95: "EOPNOTSUPP",
    96: "EPFNOSUPPORT",
    97: "EAFNOSUPPORT",
    98: "EADDRINUSE",
    99: "EADDRNOTAVAIL",
    100: "ENETDOWN",
    101: "ENETUNREACH",
    102: "ENETRESET",
    103: "ECONNABORTED",
    104: "ECONNRESET",
    105: "ENOBUFS",
    106: "EISCONN",
    107: "ENOTCONN",
    108: "ESHUTDOWN",
    109: "ETOOMANYREFS",
    110: "ETIMEDOUT",
    111: "ECONNREFUSED",
    112: "EHOSTDOWN",
    113: "EHOSTUNREACH",
    114: "EALREADY",
    115: "EINPROGRESS",
    116: "ESTALE",
    117: "EUCLEAN",
    118: "ENOTNAM",
    119: "ENAVAIL",
    120: "EISNAM",
    121: "EREMOTEIO",
    122: "EDQUOT",
    123: "ENOMEDIUM",
    124: "EMEDIUMTYPE",
    125: "ECANCELED",
    126: "ENOKEY",
    127: "EKEYEXPIRED",
    128: "EKEYREVOKED",
    129: "EKEYREJECTED",
    130: "EOWNERDEAD",
    131: "ENOTRECOVERABLE",
    132: "ERFKILL",
    133: "EHWPOISON",
}
# The exact Linux-v6.8-shaped call uses a valid cgroup-v2 directory FD, a
# fully-owned 64-byte zero-initialized UAPI object, attach type
# BPF_CGROUP_INET_INGRESS, zero query flags and prog_cnt=0.  With those fixed
# inputs the only retained non-success is the explicit CAP_NET_ADMIN failure.
# EFAULT would mean the owned ABI buffer was not valid, while EINVAL would mean
# the fixed producer/UAPI/platform contract was not met; both fail closed.
DISCOVERY_BPF_PROG_QUERY_ERRNOS = frozenset({1})

# Availability is probed by opening these exact, immutable paths read-only with
# O_NOFOLLOW. Core procfs, sysctl and cgroup-v2 interface files are mandatory
# under the already-retained Linux-v6.8/ubuntu-24.04 and live-process state.
# Only controller-specific files may be absent, and only when their controller
# is absent from the already-retained cgroup.controllers record.
DISCOVERY_FIELD_OPEN_ERRNOS = {
    "cgroup.controllers": frozenset(),
    "cgroup.events": frozenset(),
    "cgroup.kill": frozenset(),
    "cgroup.subtree_control": frozenset(),
    "cpu.max": frozenset({2}),
    "etc.os-release": frozenset(),
    "kernel.core_pattern": frozenset(),
    "memory.events": frozenset({2}),
    "memory.oom.group": frozenset({2}),
    "proc.cgroup": frozenset(),
    "proc.mountinfo": frozenset(),
    "proc.status": frozenset(),
}
DISCOVERY_CONTROLLER_GATED_FIELDS = {
    "cpu.max": "cpu",
    "memory.events": "memory",
    "memory.oom.group": "memory",
}
DISCOVERY_UUID4_HEX_PATTERN = re.compile(
    r"^[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$"
)
DISCOVERY_UUID4_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
DISCOVERY_WORKFLOW_NAME = "P0 v2 runner feasibility Gate 1"

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
    "finalizer_started",
    "finalizer_bound",
    "cgroup_kill_written",
    "cgroup_empty_observed",
    "stream_eof_observed",
    "unit_unloaded",
    "host_sentinel_verified",
    "host_sentinel_consumed",
    "core_pattern_restored",
    "evidence_sealed",
}
RELEASE_MARKER_VERSION = 1
# Phases in which no durable post-release marker may exist for a bound case: the
# hostile fixture has not yet been released (initialized/core_pattern_*/
# case_bound). Finalizer phases may retain that absence when cleanup started
# before release; such a journal is resumable but permanently proof-ineligible.
PRE_RELEASE_PHASES = frozenset(
    {
        "initialized",
        "core_pattern_original_recorded",
        "core_pattern_suppressed",
        "case_bound",
    }
)
RELEASE_MARKER_FIELDS = frozenset(
    {
        "marker_version",
        "invocation_id",
        "nonce",
        "run_id",
        "run_attempt",
        "unit",
        "released_monotonic_ns",
    }
)
CONTROL_TASK_COMMIT = "e0587c2e3134c30f761206689191f6de822c491a"
CONTROL_TASK_SHA256 = "0886b8125c66d3ad9fa22f271978ebc3e8cab726cacbaff0cab65caf0e604934"
ROOT_RUNTIME = Path("/run/p0-v2-gate1")
CGROUP_ROOT = Path("/sys/fs/cgroup")
CORE_PATTERN_PATH = Path("/proc/sys/kernel/core_pattern")
MAX_RETAINED_COMBINED = 1024 * 1024
MAX_TOTAL_COMBINED = 8 * 1024 * 1024
# Worst-case bytes a single non-blocking drain read pulls from one FIFO. The live
# loop reads at most this from stdout and this from stderr between two trigger
# checks, so the combined captured total can overshoot MAX_TOTAL_COMBINED by up
# to 2 * MAX_DRAIN_READ before OUTPUT_LIMIT is declared.
MAX_DRAIN_READ = 65536
# Kernel default pipe capacity on the x86_64 substrate (16 * 4096). A newly
# created FIFO holds at most this until resized; the trusted per-pipe ceiling is
# max(this, /proc/sys/fs/pipe-max-size) because an unprivileged child without
# CAP_SYS_RESOURCE can never grow a pipe above pipe-max-size.
DEFAULT_PIPE_CAPACITY = 65536
PIPE_MAX_SIZE_PATH = Path("/proc/sys/fs/pipe-max-size")
COREDUMP_CONFIG_ROOTS = (
    Path("/etc/systemd"),
    Path("/run/systemd"),
    Path("/usr/local/lib/systemd"),
    Path("/usr/lib/systemd"),
)
COREDUMP_JOURNAL_MAX_BYTES = 4 * 1024 * 1024
COREDUMP_COMMAND_STDOUT_MAX_BYTES = 1024 * 1024
COREDUMP_COMMAND_STDERR_MAX_BYTES = 64 * 1024
COREDUMP_JOURNAL_TIMEOUT_SECONDS = 20.0
COREDUMP_MESSAGE_ID = "fc2e22bc6ee647b6b90729ab34a250b1"
COREDUMP_SOCKET_UNIT = "systemd-coredump.socket"
COREDUMP_TEMPLATE_UNIT = "systemd-coredump@.service"
# Generic org.freedesktop.systemd1.Unit properties present for every unit type
# (socket, service template, and service instance alike). Deliberately excludes
# service-only properties such as NRestarts, which `systemctl show` omits for a
# .socket and would otherwise make the exact-set check fail closed on every run.
COREDUMP_UNIT_PROPERTIES = (
    "Id",
    "Names",
    "LoadState",
    "ActiveState",
    "SubState",
    "UnitFileState",
    "FragmentPath",
    "SourcePath",
    "InvocationID",
)
# The complete, closed set of reasons a journal entry can be classified as
# coredump-relevant, and the structured journal fields retained per relevant
# entry. Both are enforced by semantic validation so no unknown token can be
# smuggled into sealed evidence.
COREDUMP_RELEVANT_REASONS = (
    "coredump_fields",
    "coredump_instance",
    "coredump_message_id",
    "coredump_process",
    "coredump_socket",
    "coredump_template",
)
COREDUMP_JOURNAL_SELECTED_FIELDS = (
    "COREDUMP_FILENAME",
    "COREDUMP_PID",
    "COREDUMP_SIGNAL",
    "COREDUMP_UNIT",
    "MESSAGE_ID",
    "OBJECT_SYSTEMD_UNIT",
    "SYSLOG_IDENTIFIER",
    "UNIT",
    "_COMM",
    "_SYSTEMD_UNIT",
)
MAX_ROOT_STATE_BYTES = 1024 * 1024
CASE_TIMEOUT_SECONDS = 20.0
OPERATOR_CANCEL_TIMEOUT_SECONDS = 150.0
CLEANUP_TIMEOUT_SECONDS = 10.0
ROOT_RUNTIME_MODE = 0o711
EXEC_DIR_MODE = 0o711
STATE_DIR_MODE = 0o700
PRIVATE_TMPFS_SIZE = "12M"

# Exact hostile bytes the invalid-output fixture emits. stdout leads with the
# two invalid UTF-8 bytes 0xFF 0xFE, then a workflow-command-looking payload;
# stderr carries a legacy ::set-output command and a GITHUB_ENV file-command
# sequence. The trusted supervisor must render these with errors="replace" and
# prove non-interpretation; it never echoes them to any Actions command channel.
REPLACEMENT_CHAR = "�"
INVALID_OUTPUT_STDOUT = b"\xff\xfe::warning::untrusted\n"
INVALID_OUTPUT_STDERR = b"::set-output name=x::untrusted\nGITHUB_ENV=untrusted\n"
INVALID_OUTPUT_STDOUT_RENDERED = "��::warning::untrusted\n"
INVALID_OUTPUT_STDERR_RENDERED = "::set-output name=x::untrusted\nGITHUB_ENV=untrusted\n"
INVALID_OUTPUT_STDOUT_REPLACEMENTS = 2
INVALID_OUTPUT_STDERR_REPLACEMENTS = 0
INVALID_OUTPUT_COMMAND_MARKERS = ("::warning::", "::set-output", "GITHUB_ENV=")

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA64_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
SAFE_UNIT_RE = re.compile(r"^p0-v2-g1-[a-z0-9-]{1,96}\.service$")
SAFE_CGROUP_RE = re.compile(r"^/system\.slice/p0-v2-g1-[a-z0-9-]{1,96}\.service$")
COREDUMP_INSTANCE_RE = re.compile(
    r"^systemd-coredump@[A-Za-z0-9:_.\\-]{1,220}\.service$"
)
JOURNAL_CURSOR_RE = re.compile(r"^[!-~]{1,512}$")

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

# Exact effective-control observation contract. For every hosted case the
# supervisor emits each of these observations exactly once, with the stated
# authority and the literal JSON boolean ``true``; the semantic validator rebuilds
# this set for the observed case list and rejects any missing, duplicate, unknown,
# non-boolean, or false effective control.
# ``systemd_properties_match`` is the necessary manager-equality control (the
# unit's ``systemctl show`` output equals the requested hardening). F7 requires
# that manager equality alone never stands in for a proven runtime effect, so it
# is followed by the effect-proven controls below, each derived from a distinct
# trusted kernel observation of the live child (see MANDATORY_CONTROL_INVENTORY).
EFFECTIVE_CONTROL_PER_CASE = (
    ("argv_matches", "kernel_observed"),
    ("environment_contains_no_forbidden_family", "kernel_observed"),
    ("systemd_properties_match", "systemd_observed"),
    ("dedicated_uid_effective", "kernel_observed"),
    ("no_new_privileges_effective", "kernel_observed"),
    ("capability_bounding_empty", "kernel_observed"),
    ("private_namespaces_effective", "kernel_observed"),
    ("private_uts_namespace_effective", "kernel_observed"),
    ("private_tmp_noexec_enforced", "kernel_observed"),
    ("resource_limits_effective", "kernel_observed"),
    ("umask_effective", "kernel_observed"),
    ("working_directory_effective", "kernel_observed"),
    ("tasks_max_effective", "kernel_observed"),
    ("memory_max_effective", "kernel_observed"),
    ("memory_swap_max_effective", "kernel_observed"),
    ("memory_oom_group_effective", "kernel_observed"),
    ("cpu_quota_effective", "kernel_observed"),
    ("capture_fd_identity", "kernel_observed"),
    ("direct_cgroup_kill", "kernel_observed"),
    ("recursive_populated_zero", "kernel_observed"),
    ("streams_eof_after_empty", "supervisor_observed"),
    ("unit_unloaded_after_empty", "systemd_observed"),
)
EFFECTIVE_CONTROL_GLOBAL = (
    ("host.noexec_execve_denied", "kernel_observed"),
    ("host.core_pattern_restored", "kernel_observed"),
    ("host.coredump_no_unauthorized_side_effect", "platform_file_observed"),
)
# The fixed effective-control observation contract the cancellation finalizer
# emits for the single operator-cancel case.
CANCELLATION_EFFECTIVE_CONTROLS = (
    ("bootstrap.argv_matches", "kernel_observed"),
    ("bootstrap.environment_matches", "kernel_observed"),
    ("bootstrap.capture_fd_identity", "kernel_observed"),
    ("cleanup.cgroup_kill", "kernel_observed"),
    ("cleanup.populated_zero", "kernel_observed"),
    ("cleanup.streams_eof", "supervisor_observed"),
    ("cleanup.unit_unloaded", "systemd_observed"),
    ("cleanup.core_pattern_restored", "kernel_observed"),
    ("cleanup.coredump_no_unauthorized_side_effect", "platform_file_observed"),
)

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
    f"TemporaryFileSystem=/tmp:rw,nodev,nosuid,noexec,size={PRIVATE_TMPFS_SIZE}",
    f"TemporaryFileSystem=/var/tmp:rw,nodev,nosuid,noexec,size={PRIVATE_TMPFS_SIZE}",
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

# --- F7: valid, provenance-bound noexec witness ---------------------------
#
# A noexec mount is proven by executing a *valid* ELF, not an invalid file: an
# invalid file returns ENOEXEC on an ordinary executable filesystem too, so it
# can never distinguish "denied by the noexec mount" from "not a runnable
# program". The witness therefore (1) selects a pre-existing, root-owned,
# non-writable, bounded-size host ELF through a fail-closed provenance check,
# (2) proves those exact bytes execute from an exec-allowed control location, and
# (3) stages the byte-identical bytes into a provably-noexec mount and requires
# the kernel's EACCES noexec denial. Only that exact denial, on a mount whose
# per-mount options independently show ``noexec``, is credited.
ELF_MAGIC = b"\x7fELF"
NOEXEC_WITNESS_MIN_ELF_BYTES = 64
NOEXEC_WITNESS_MAX_ELF_BYTES = 8 * 1024 * 1024
# Ordered, pre-existing host executables considered as the witness ELF. Each is
# resolved and re-validated through the provenance check before use; the first
# that passes is bound by digest. ``true`` exits 0 with no input; the interpreter
# is the guaranteed fallback and is invoked with an inert program.
NOEXEC_WITNESS_ELF_CANDIDATES = (
    "/usr/bin/true",
    "/bin/true",
    "/usr/bin/python3",
)
NOEXEC_MOUNT_TARGETS = ("/tmp", "/var/tmp")
REQUIRED_MOUNT_FLAGS = ("noexec", "nosuid", "nodev")
# The closed set of ways a trusted execve attempt can be classified. Only
# ``noexec_denied`` (EACCES) satisfies the noexec effect; every other outcome --
# an invalid format, a missing loader, an unrelated permission error, a signal,
# a timeout or an unexpected success -- fails closed.
EXECVE_NOEXEC_DENIED = "noexec_denied"
EXECVE_WRONG_FORMAT = "wrong_format"
EXECVE_PERMISSION_DENIED = "permission_denied"
EXECVE_MISSING_LOADER = "missing_loader"
EXECVE_EXECUTED = "executed"
EXECVE_TERMINATED_BY_SIGNAL = "terminated_by_signal"
EXECVE_TIMED_OUT = "timed_out"
EXECVE_OTHER_ERROR = "other_error"
EXECVE_AMBIGUOUS = "ambiguous"
# Errnos that mean the format was fine but the loader/interpreter/library was
# absent (so the attempt proves nothing about noexec). Some are Linux-only, so
# each is resolved defensively and unavailable ones simply drop out of the set.
MISSING_LOADER_ERRNOS = frozenset(
    code
    for code in (
        getattr(errno, "ENOENT", None),
        getattr(errno, "ELIBBAD", None),
        getattr(errno, "ELIBACC", None),
        getattr(errno, "EFAULT", None),
    )
    if code is not None
)

# --- F7: mandatory-control effect inventory -------------------------------
#
# Manager-reported property equality (``systemctl show`` == requested) is
# necessary but never sufficient: a unit can report a property whose runtime
# effect is absent, and one opaque child denial can be caused by several controls
# at once. This inventory is the single, mechanically cross-checked source of
# truth mapping every mandatory systemd property to how its effect is proven.
#
# Every property is in exactly one of two classes:
#   * ``effect_proven``  -- a distinct, trusted, independently interpretable
#     effect predicate mapped to exactly one effective-control record.
#   * ``effect_unproven`` -- this candidate implements no trusted hosted-runner
#     effect predicate for the property. Manager equality alone is never accepted
#     as its proof; instead each such property is a *stable blocker* that
#     mechanically makes candidate SUCCESS unreachable (see
#     mandatory_effect_blockers / candidate_run_succeeds). This is fail-closed,
#     not accounting metadata: the outcome gate, not a comment, enforces it.
#
# verify_control_inventory_synchronized() rebuilds the covered property set and
# fails closed if it ever diverges from the configured mandatory properties, so
# adding or removing a mandatory property cannot silently leave a control
# unproved -- an unaccounted property is a hard error, and any property left
# effect_unproven keeps SUCCESS unreachable.
EFFECT_UNPROVEN = "effect_unproven"


@dataclass(frozen=True)
class ControlInventoryEntry:
    """One mandatory-control accounting row. ``effect_control`` is the single
    effective-control record its effect maps to (or ``None`` for an
    ``effect_unproven`` control), ``authority`` the trusted authority for that
    effect (or ``EFFECT_UNPROVEN``), ``scope`` one of
    ``per_case``/``global``/``unproven``."""

    manager_properties: Tuple[str, ...]
    effect_control: Optional[str]
    authority: str
    scope: str
    predicate: str
    isolation: str


MANDATORY_CONTROL_INVENTORY: Tuple[ControlInventoryEntry, ...] = (
    ControlInventoryEntry(
        ("DynamicUser", "SupplementaryGroups"),
        "dedicated_uid_effective",
        "kernel_observed",
        "per_case",
        "child runs under a consistent non-root dynamic uid/gid with no "
        "supplementary groups",
        "distinct kernel authority: /proc/<pid>/status Uid/Gid/Groups",
    ),
    ControlInventoryEntry(
        ("NoNewPrivileges",),
        "no_new_privileges_effective",
        "kernel_observed",
        "per_case",
        "the no_new_privs bit is set for the child task",
        "distinct kernel authority: /proc/<pid>/status NoNewPrivs",
    ),
    ControlInventoryEntry(
        ("CapabilityBoundingSet", "AmbientCapabilities"),
        "capability_bounding_empty",
        "kernel_observed",
        "per_case",
        "every capability mask observed for the child is empty",
        "distinct kernel authority: /proc/<pid>/status Cap* masks",
    ),
    ControlInventoryEntry(
        ("PrivateMounts", "PrivateNetwork", "PrivateIPC"),
        "private_namespaces_effective",
        "kernel_observed",
        "per_case",
        "child mnt/net/ipc namespaces differ from the supervisor's",
        "distinct kernel authority: /proc/<pid>/ns vs /proc/self/ns",
    ),
    ControlInventoryEntry(
        ("TemporaryFileSystem",),
        "private_tmp_noexec_enforced",
        "kernel_observed",
        "per_case",
        "child /tmp and /var/tmp mounts carry noexec,nosuid,nodev",
        "distinct kernel authority: /proc/<pid>/mountinfo per-mount options",
    ),
    ControlInventoryEntry(
        ("LimitNOFILE", "LimitFSIZE", "LimitCORE"),
        "resource_limits_effective",
        "kernel_observed",
        "per_case",
        "child NOFILE/FSIZE/CORE rlimits equal the requested ceilings",
        "distinct kernel authority: /proc/<pid>/limits",
    ),
    # F7-A: direct-state effects derived from existing trusted procfs/cgroupfs
    # observations. Each has its own effective-control record; none rests on
    # manager equality, a composite probe, or a child-authored denial.
    ControlInventoryEntry(
        ("ProtectHostname",),
        "private_uts_namespace_effective",
        "kernel_observed",
        "per_case",
        "child UTS namespace identity differs from the supervisor's",
        "distinct kernel authority: /proc/<pid>/ns/uts vs /proc/self/ns/uts; no "
        "other requested property creates a UTS namespace",
    ),
    ControlInventoryEntry(
        ("UMask",),
        "umask_effective",
        "kernel_observed",
        "per_case",
        "child Umask is exactly 0o077",
        "distinct kernel authority: the single Umask field in /proc/<pid>/status "
        "(duplicate/malformed rejected)",
    ),
    ControlInventoryEntry(
        ("WorkingDirectory",),
        "working_directory_effective",
        "kernel_observed",
        "per_case",
        "child /proc/<pid>/cwd equals the trusted exec dir by exact path and "
        "device/inode identity",
        "distinct kernel authority: /proc/<pid>/cwd identity-bound to the "
        "supervisor-created exec directory, not a string prefix",
    ),
    ControlInventoryEntry(
        ("TasksMax",),
        "tasks_max_effective",
        "kernel_observed",
        "per_case",
        "the bound cgroup's pids.max equals 64",
        "distinct kernel authority: pids.max in the already-bound cgroup directory",
    ),
    ControlInventoryEntry(
        ("MemoryMax",),
        "memory_max_effective",
        "kernel_observed",
        "per_case",
        "the bound cgroup's memory.max equals 268435456",
        "distinct kernel authority: memory.max in the already-bound cgroup directory",
    ),
    ControlInventoryEntry(
        ("MemorySwapMax",),
        "memory_swap_max_effective",
        "kernel_observed",
        "per_case",
        "the bound cgroup's memory.swap.max equals 0",
        "distinct kernel authority: memory.swap.max in the bound cgroup directory",
    ),
    ControlInventoryEntry(
        ("MemoryOOMGroup",),
        "memory_oom_group_effective",
        "kernel_observed",
        "per_case",
        "the bound cgroup's memory.oom.group equals 1",
        "distinct kernel authority: memory.oom.group in the bound cgroup directory",
    ),
    ControlInventoryEntry(
        ("CPUQuotaPerSecUSec",),
        "cpu_quota_effective",
        "kernel_observed",
        "per_case",
        "the bound cgroup's cpu.max is a finite quota equal to its period (100% of "
        "one CPU)",
        "distinct kernel authority: normalized cpu.max in the bound cgroup "
        "directory; the unlimited 'max' form fails closed",
    ),
    ControlInventoryEntry(
        ("TemporaryFileSystem",),
        "host.noexec_execve_denied",
        "kernel_observed",
        "global",
        "a valid, positive-control-executable ELF is denied execve (EACCES) by a "
        "provably-noexec mount",
        "distinct operation from the mountinfo read: a trusted execve of a "
        "provenance-bound ELF; only EACCES on a mount whose options show noexec "
        "is credited, isolating it from an unrelated permission denial",
    ),
    ControlInventoryEntry(
        (
            "SetLoginEnvironment",
            "ProtectSystem",
            "ProtectHome",
            "PrivateDevices",
            "DevicePolicy",
            "ProtectProc",
            "ProcSubset",
            "ProtectControlGroups",
            "ProtectKernelTunables",
            "ProtectKernelModules",
            "ProtectKernelLogs",
            "ProtectClock",
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
            "KillMode",
            "SendSIGKILL",
            "TimeoutStopUSec",
            "RuntimeMaxUSec",
            "OOMPolicy",
        ),
        None,
        EFFECT_UNPROVEN,
        "unproven",
        "systemctl show equals the requested value, but no trusted runtime effect "
        "is observed",
        "this candidate implements no trusted, independently interpretable "
        "hosted-runner effect predicate for these properties. For most the effect "
        "manifests only as a child-authored denial (e.g. seccomp-specific syscall "
        "filtering, MemoryDenyWriteExecute, LockPersonality, RestrictRealtime, "
        "RestrictAddressFamilies/Namespaces, KeyringMode, ProtectKernel*, "
        "RestrictSUIDSGID), which the threat model forbids as authority; others "
        "(ProtectSystem, ProtectHome, ProtectProc, ProcSubset, ProtectControlGroups, "
        "PrivateDevices, DevicePolicy) would require an exact mountinfo/kernel "
        "topology whose representation is not established without the hosted Linux "
        "substrate, and the lifecycle-shaped ones (KillMode, SendSIGKILL, "
        "TimeoutStopUSec, RuntimeMaxUSec, OOMPolicy, RemoveIPC, SetLoginEnvironment, "
        "SystemCallArchitectures) are not distinctly isolatable from overlapping "
        "controls here. Either way no trusted effect proof exists, so manager "
        "equality is insufficient and each is a stable blocker keeping candidate "
        "SUCCESS unreachable until a trusted effect proof is added",
    ),
)

# The exact mandatory manager-property set the inventory must cover: every keyed
# REQUIRED_SYSTEMD_VALUES property plus the three enforced by shape rather than
# scalar equality (SystemCallFilter non-empty, TemporaryFileSystem substring,
# WorkingDirectory path).
MANDATORY_MANAGER_PROPERTIES = frozenset(REQUIRED_SYSTEMD_VALUES) | {
    "SystemCallFilter",
    "TemporaryFileSystem",
    "WorkingDirectory",
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


def output_limit_triggered(combined_bytes: int) -> bool:
    """The single live-loop trigger predicate: combined captured bytes exceed the
    named maximum. It is strictly ``>`` so exactly MAX_TOTAL_COMBINED does not
    trip OUTPUT_LIMIT; one byte above does."""
    return combined_bytes > MAX_TOTAL_COMBINED


def per_pipe_capacity_limit(observed_pipe_max_size: int) -> int:
    """Trusted upper bound on bytes a single FIFO can buffer for the post-kill
    drain. A pipe holds at most its capacity; the capacity is the default until
    resized and an unprivileged child can raise it only up to pipe-max-size."""
    if (
        not isinstance(observed_pipe_max_size, int)
        or isinstance(observed_pipe_max_size, bool)
        or observed_pipe_max_size <= 0
    ):
        raise ProbeError("PIPE_MAX_SIZE_INVALID", repr(observed_pipe_max_size))
    return max(DEFAULT_PIPE_CAPACITY, observed_pipe_max_size)


def combined_output_bound(per_pipe_capacity: int) -> int:
    """Hard ceiling on the final combined captured byte count for a case that
    tripped the live trigger:

        MAX_TOTAL_COMBINED            (highest pre-drain total not yet tripping)
        + 2 * MAX_DRAIN_READ         (simultaneous stdout+stderr trigger overshoot)
        + 2 * per_pipe_capacity      (both FIFOs full at kill, drained after)
    """
    return MAX_TOTAL_COMBINED + 2 * MAX_DRAIN_READ + 2 * per_pipe_capacity


def observe_pipe_max_size() -> int:
    """Read the trusted /proc/sys/fs/pipe-max-size ceiling, failing closed."""
    try:
        raw = read_text(PIPE_MAX_SIZE_PATH, 64).strip()
    except OSError as exc:
        raise ProbeError("PIPE_MAX_SIZE_UNREADABLE", repr(exc)) from exc
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise ProbeError("PIPE_MAX_SIZE_INVALID", raw) from exc
    if value <= 0:
        raise ProbeError("PIPE_MAX_SIZE_INVALID", raw)
    return value


def build_output_accounting(
    *,
    observed_pipe_max_size: int,
    trigger_bytes: int,
    combined_final_bytes: int,
) -> Dict[str, Any]:
    """Assemble the exact, independently recomputable output-accounting record."""
    limit = per_pipe_capacity_limit(observed_pipe_max_size)
    bound = combined_output_bound(limit)
    return {
        "max_total_combined": MAX_TOTAL_COMBINED,
        "max_drain_read": MAX_DRAIN_READ,
        "default_pipe_capacity": DEFAULT_PIPE_CAPACITY,
        "observed_pipe_max_size": observed_pipe_max_size,
        "per_pipe_capacity_limit": limit,
        "trigger_bytes": trigger_bytes,
        "trigger_crossed": output_limit_triggered(trigger_bytes),
        "combined_final_bytes": combined_final_bytes,
        "allowed_final_bound": bound,
        "bound_held": combined_final_bytes <= bound,
    }


OUTPUT_ACCOUNTING_FIELDS = frozenset(
    {
        "max_total_combined",
        "max_drain_read",
        "default_pipe_capacity",
        "observed_pipe_max_size",
        "per_pipe_capacity_limit",
        "trigger_bytes",
        "trigger_crossed",
        "combined_final_bytes",
        "allowed_final_bound",
        "bound_held",
    }
)


def _nonneg_int(mapping: Mapping[str, Any], key: str, context: str) -> int:
    value = mapping.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ProbeError("SCHEMA_INVALID", f"{context}: {key} is not a non-negative int")
    return value


def verify_output_accounting(
    accounting: Mapping[str, Any],
    stdout_doc: Mapping[str, Any],
    stderr_doc: Mapping[str, Any],
) -> None:
    """Recompute the OUTPUT_LIMIT accounting from first principles and fail closed
    on any inconsistency. The final combined count is taken from the case's own
    stream byte counts (all bytes, including post-kill drain), never trusting the
    record's self-reported total. OUTPUT_LIMIT stands only if the trigger was
    crossed and the final combined bytes are within the derived hard bound."""
    if not isinstance(accounting, Mapping) or set(accounting) != OUTPUT_ACCOUNTING_FIELDS:
        raise ProbeError("SCHEMA_INVALID", "output accounting fields mismatch")
    for key in (
        "max_total_combined",
        "max_drain_read",
        "default_pipe_capacity",
        "observed_pipe_max_size",
        "per_pipe_capacity_limit",
        "trigger_bytes",
        "combined_final_bytes",
        "allowed_final_bound",
    ):
        _nonneg_int(accounting, key, "output accounting")
    for key in ("trigger_crossed", "bound_held"):
        if not isinstance(accounting[key], bool):
            raise ProbeError("SCHEMA_INVALID", f"output accounting {key} not boolean")
    if accounting["max_total_combined"] != MAX_TOTAL_COMBINED:
        raise ProbeError("SCHEMA_INVALID", "output accounting max_total_combined mismatch")
    if accounting["max_drain_read"] != MAX_DRAIN_READ:
        raise ProbeError("SCHEMA_INVALID", "output accounting max_drain_read mismatch")
    if accounting["default_pipe_capacity"] != DEFAULT_PIPE_CAPACITY:
        raise ProbeError("SCHEMA_INVALID", "output accounting default_pipe_capacity mismatch")
    expected_limit = per_pipe_capacity_limit(accounting["observed_pipe_max_size"])
    if accounting["per_pipe_capacity_limit"] != expected_limit:
        raise ProbeError("SCHEMA_INVALID", "output accounting per_pipe_capacity_limit mismatch")
    expected_bound = combined_output_bound(expected_limit)
    if accounting["allowed_final_bound"] != expected_bound:
        raise ProbeError("SCHEMA_INVALID", "output accounting allowed_final_bound mismatch")
    combined = _nonneg_int(stdout_doc, "byte_count", "output accounting stdout") + _nonneg_int(
        stderr_doc, "byte_count", "output accounting stderr"
    )
    if accounting["combined_final_bytes"] != combined:
        raise ProbeError("SCHEMA_INVALID", "output accounting combined_final_bytes mismatch")
    if accounting["trigger_crossed"] != output_limit_triggered(accounting["trigger_bytes"]):
        raise ProbeError("SCHEMA_INVALID", "output accounting trigger_crossed mismatch")
    if accounting["bound_held"] != (combined <= expected_bound):
        raise ProbeError("SCHEMA_INVALID", "output accounting bound_held mismatch")
    if not accounting["trigger_crossed"]:
        raise ProbeError("SCHEMA_INVALID", "output accounting trigger not crossed")
    if not accounting["bound_held"]:
        raise ProbeError("SCHEMA_INVALID", "output accounting bound exceeded")
    if combined < accounting["trigger_bytes"]:
        raise ProbeError("SCHEMA_INVALID", "output accounting final below trigger")


def expected_invalid_output_proof() -> Dict[str, Any]:
    """The fixed, supervisor-authored proof the invalid-output contract yields."""
    return {
        "rendering": "utf-8;errors=replace",
        "replacement_codepoint": ord(REPLACEMENT_CHAR),
        "stdout_byte_count": len(INVALID_OUTPUT_STDOUT),
        "stderr_byte_count": len(INVALID_OUTPUT_STDERR),
        "stdout_sha256": sha256_bytes(INVALID_OUTPUT_STDOUT),
        "stderr_sha256": sha256_bytes(INVALID_OUTPUT_STDERR),
        "stdout_replacement_count": INVALID_OUTPUT_STDOUT_REPLACEMENTS,
        "stderr_replacement_count": INVALID_OUTPUT_STDERR_REPLACEMENTS,
        "command_markers": list(INVALID_OUTPUT_COMMAND_MARKERS),
        "non_interpreted": True,
        "verified": True,
    }


def _decode_retained_exact(doc: Mapping[str, Any], expected: bytes, label: str) -> bytes:
    """Strictly base64-decode retained child bytes and prove they are the exact
    expected untrusted payload, complete (not truncated) and digest-consistent."""
    if doc.get("truncated"):
        raise ProbeError("INVALID_OUTPUT_TRUNCATED", label)
    try:
        raw = base64.b64decode(doc["retained_base64"], validate=True)
    except (ValueError, TypeError, KeyError) as exc:
        raise ProbeError("INVALID_OUTPUT_BASE64_INVALID", label) from exc
    if raw != expected:
        raise ProbeError("INVALID_OUTPUT_BYTES_MISMATCH", label)
    if doc.get("byte_count") != len(expected) or doc.get("retained_byte_count") != len(expected):
        raise ProbeError("INVALID_OUTPUT_COUNT_MISMATCH", label)
    if doc.get("sha256") != sha256_bytes(expected):
        raise ProbeError("INVALID_OUTPUT_DIGEST_MISMATCH", label)
    return raw


def verify_invalid_output_contract(
    stdout_doc: Mapping[str, Any],
    stderr_doc: Mapping[str, Any],
) -> Dict[str, Any]:
    """Prove the invalid-output fixture's retained bytes render under UTF-8
    errors="replace" to the exact expected replacement text and carry the exact
    command-looking payloads, without ever interpreting them. Fails closed if the
    raw bytes, decoded text, replacement behavior, or command content differ."""
    raw_out = _decode_retained_exact(stdout_doc, INVALID_OUTPUT_STDOUT, "stdout")
    raw_err = _decode_retained_exact(stderr_doc, INVALID_OUTPUT_STDERR, "stderr")
    rendered_out = raw_out.decode("utf-8", "replace")
    rendered_err = raw_err.decode("utf-8", "replace")
    if (
        rendered_out != INVALID_OUTPUT_STDOUT_RENDERED
        or rendered_err != INVALID_OUTPUT_STDERR_RENDERED
    ):
        raise ProbeError("INVALID_OUTPUT_RENDER_MISMATCH", "errors=replace rendering differs")
    if (
        rendered_out.count(REPLACEMENT_CHAR) != INVALID_OUTPUT_STDOUT_REPLACEMENTS
        or rendered_err.count(REPLACEMENT_CHAR) != INVALID_OUTPUT_STDERR_REPLACEMENTS
    ):
        raise ProbeError("INVALID_OUTPUT_REPLACEMENT_MISMATCH", "replacement count differs")
    for marker in INVALID_OUTPUT_COMMAND_MARKERS:
        if marker not in rendered_out and marker not in rendered_err:
            raise ProbeError("INVALID_OUTPUT_COMMAND_PAYLOAD_MISSING", marker)
    return expected_invalid_output_proof()


def _require_supervisor_observation(case: Mapping[str, Any], name: str) -> Any:
    """Return the unique supervisor-authored observation ``name`` on ``case``,
    failing closed unless exactly one exists with supervisor authority."""
    matches = [item for item in case["observations"] if item["name"] == name]
    if len(matches) != 1:
        raise ProbeError("SCHEMA_INVALID", f"{case['id']}: exactly one {name} required")
    if matches[0]["authority"] != "supervisor_observed":
        raise ProbeError("SCHEMA_INVALID", f"{case['id']}: {name} authority invalid")
    return matches[0]["value"]


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


# Every schema keyword this engine understands: either an assertion it enforces
# below, or a known annotation with no assertion effect ($schema/$id/title/etc.,
# and $defs which is only reached through $ref). Any other keyword fails closed,
# so an unsupported assertion (a conditional, combinator, or numeric bound that
# was never implemented) can never be silently ignored into vacuous success.
_SUPPORTED_SCHEMA_KEYWORDS = frozenset(
    {
        "$schema",
        "$id",
        "title",
        "description",
        "$comment",
        "$defs",
        "default",
        "examples",
        "$ref",
        "type",
        "enum",
        "const",
        "allOf",
        "anyOf",
        "oneOf",
        "not",
        "if",
        "then",
        "else",
        "properties",
        "additionalProperties",
        "required",
        "items",
        "minItems",
        "maxItems",
        "uniqueItems",
        "pattern",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
    }
)


def _json_deep_equal(instance: Any, expected: Any) -> bool:
    """JSON equality that never conflates booleans with numbers, so a ``const`` or
    ``enum`` requiring a literal boolean can never be satisfied by ``0``/``1`` (nor
    a numeric const by ``True``/``False``)."""
    if isinstance(instance, bool) or isinstance(expected, bool):
        return type(instance) is type(expected) and instance == expected
    if isinstance(instance, dict) and isinstance(expected, dict):
        return instance.keys() == expected.keys() and all(
            _json_deep_equal(instance[key], expected[key]) for key in instance
        )
    if isinstance(instance, list) and isinstance(expected, list):
        return len(instance) == len(expected) and all(
            _json_deep_equal(left, right) for left, right in zip(instance, expected)
        )
    if isinstance(instance, (int, float)) and isinstance(expected, (int, float)):
        return instance == expected
    return type(instance) is type(expected) and instance == expected


def _schema_matches(
    instance: Any, schema: Mapping[str, Any], root: Mapping[str, Any], path: str
) -> bool:
    """True when ``instance`` satisfies ``schema``. Assertion-level failures return
    False so conditionals/combinators can branch; an unsupported schema keyword
    still fails closed by propagating rather than reading as a non-match."""
    try:
        validate_schema_instance(instance, schema, root, path)
    except ProbeError as exc:
        if exc.code == "SCHEMA_UNSUPPORTED":
            raise
        return False
    return True


def validate_schema_instance(instance: Any, schema: Mapping[str, Any], root: Mapping[str, Any], path: str = "$") -> None:
    """Validate the JSON-Schema (Draft 2020-12) subset used by Gate 1, failing
    closed on any schema keyword this engine does not implement."""

    unsupported = set(schema) - _SUPPORTED_SCHEMA_KEYWORDS
    if unsupported:
        raise ProbeError(
            "SCHEMA_UNSUPPORTED",
            f"{path}: unsupported schema keyword {','.join(sorted(unsupported))}",
        )
    if "$ref" in schema:
        ref = schema["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            raise ProbeError("SCHEMA_UNSUPPORTED", f"{path}: unsupported ref")
        target: Any = root
        for part in ref[2:].split("/"):
            target = target[part.replace("~1", "/").replace("~0", "~")]
        validate_schema_instance(instance, target, root, path)
        # Draft 2020-12 keeps keywords adjacent to $ref in force; fall through so
        # any sibling assertion is applied rather than silently dropped.
    for sub in schema.get("allOf", []):
        validate_schema_instance(instance, sub, root, path)
    if "anyOf" in schema and not any(
        _schema_matches(instance, sub, root, path) for sub in schema["anyOf"]
    ):
        raise ProbeError("SCHEMA_INVALID", f"{path}: anyOf mismatch")
    if "oneOf" in schema:
        matched = sum(
            1 for sub in schema["oneOf"] if _schema_matches(instance, sub, root, path)
        )
        if matched != 1:
            raise ProbeError("SCHEMA_INVALID", f"{path}: oneOf mismatch")
    if "not" in schema and _schema_matches(instance, schema["not"], root, path):
        raise ProbeError("SCHEMA_INVALID", f"{path}: not mismatch")
    if "if" in schema:
        branch = (
            "then"
            if _schema_matches(instance, schema["if"], root, f"{path}/if")
            else "else"
        )
        if branch in schema:
            validate_schema_instance(instance, schema[branch], root, path)
    if "const" in schema and not _json_deep_equal(instance, schema["const"]):
        raise ProbeError("SCHEMA_INVALID", f"{path}: const mismatch")
    if "enum" in schema and not any(
        _json_deep_equal(instance, option) for option in schema["enum"]
    ):
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


# --- Strict structural schemas for the coredump-effect evidence (T-F9) ---
#
# The coredump snapshot and the journal interval ride inside host-observation
# values, which the top-level JSON schema deliberately treats as opaque
# json_value.  These sub-schemas re-impose exact shape, closed key sets
# (additionalProperties: false), fixed authorities/precedence, and field
# patterns using the same validate_schema_instance engine the reviewer already
# runs, so an adversarial mutation of a sealed snapshot or interval fails
# semantic validation just as a raw hostile output fails capture-time parsing.
_SHA256_PATTERN = SHA64_RE.pattern
_CURSOR_PATTERN = JOURNAL_CURSOR_RE.pattern
_COREDUMP_INSTANCE_PATTERN = COREDUMP_INSTANCE_RE.pattern

COREDUMP_SNAPSHOT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "package",
        "configuration",
        "helper_units",
        "storage",
        "journal_cursor",
    ],
    "properties": {
        "package": {"$ref": "#/$defs/command_output_text"},
        "configuration": {"$ref": "#/$defs/configuration"},
        "helper_units": {"$ref": "#/$defs/helper_units"},
        "storage": {"type": "array", "items": {"type": "object"}},
        "journal_cursor": {"$ref": "#/$defs/journal_cursor"},
    },
    "$defs": {
        "sha256": {"type": "string", "pattern": _SHA256_PATTERN},
        "cursor": {"type": "string", "pattern": _CURSOR_PATTERN},
        "command_output_text": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "returncode",
                "stdout",
                "stdout_byte_count",
                "stdout_sha256",
                "stderr",
                "stderr_byte_count",
                "stderr_sha256",
            ],
            "properties": {
                "returncode": {"type": "integer", "minimum": 0, "maximum": 255},
                "stdout": {"type": "string"},
                "stdout_byte_count": {"type": "integer", "minimum": 0},
                "stdout_sha256": {"$ref": "#/$defs/sha256"},
                "stderr": {"type": "string"},
                "stderr_byte_count": {"type": "integer", "minimum": 0},
                "stderr_sha256": {"$ref": "#/$defs/sha256"},
            },
        },
        "command_output_hashed": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "returncode",
                "stdout_byte_count",
                "stdout_sha256",
                "stderr",
                "stderr_byte_count",
                "stderr_sha256",
            ],
            "properties": {
                "returncode": {"type": "integer", "const": 0},
                "stdout_byte_count": {"type": "integer", "minimum": 0},
                "stdout_sha256": {"$ref": "#/$defs/sha256"},
                "stderr": {"type": "string"},
                "stderr_byte_count": {"type": "integer", "minimum": 0},
                "stderr_sha256": {"$ref": "#/$defs/sha256"},
            },
        },
        "journal_cursor": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "returncode",
                "cursor",
                "stdout_byte_count",
                "stdout_sha256",
                "stderr",
                "stderr_byte_count",
                "stderr_sha256",
            ],
            "properties": {
                "returncode": {"type": "integer", "const": 0},
                "cursor": {"$ref": "#/$defs/cursor"},
                "stdout_byte_count": {"type": "integer", "minimum": 0},
                "stdout_sha256": {"$ref": "#/$defs/sha256"},
                "stderr": {"type": "string"},
                "stderr_byte_count": {"type": "integer", "minimum": 0},
                "stderr_sha256": {"$ref": "#/$defs/sha256"},
            },
        },
        "config_path": {
            "type": "object",
            "additionalProperties": False,
            "required": ["path"],
            "properties": {
                "path": {"type": "string"},
                "exists": {"type": "boolean"},
                "device": {"type": "integer"},
                "inode": {"type": "integer"},
                "mode": {"type": "integer", "minimum": 0},
                "uid": {"type": "integer"},
                "gid": {"type": "integer"},
                "size": {"type": "integer"},
                "mtime_ns": {"type": "integer"},
                "type": {"type": "integer"},
                "sha256": {"$ref": "#/$defs/sha256"},
                "symlink_target": {"type": "string"},
                "masked": {"type": "boolean"},
                "root_priority": {"type": "integer", "minimum": 0, "maximum": 3},
                "name": {"type": "string"},
            },
        },
        "dropin_directory": {
            "type": "object",
            "additionalProperties": False,
            "required": ["root", "root_priority", "directory", "entries"],
            "properties": {
                "root": {"type": "string"},
                "root_priority": {"type": "integer", "minimum": 0, "maximum": 3},
                "directory": {"$ref": "#/$defs/config_path"},
                "entries": {"type": "array", "items": {"$ref": "#/$defs/config_path"}},
            },
        },
        "effective_dropin": {
            "type": "object",
            "additionalProperties": False,
            "required": ["name", "path", "root_priority"],
            "properties": {
                "name": {"type": "string"},
                "path": {"type": "string"},
                "root_priority": {"type": "integer", "minimum": 0, "maximum": 3},
            },
        },
        "configuration": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "precedence_roots_high_to_low",
                "main_candidates",
                "effective_main",
                "dropin_directories",
                "effective_dropins",
            ],
            "properties": {
                "precedence_roots_high_to_low": {
                    "const": [str(root) for root in COREDUMP_CONFIG_ROOTS]
                },
                "main_candidates": {
                    "type": "array",
                    "minItems": len(COREDUMP_CONFIG_ROOTS),
                    "maxItems": len(COREDUMP_CONFIG_ROOTS),
                    "items": {"$ref": "#/$defs/config_path"},
                },
                "effective_main": {"type": ["string", "null"]},
                "dropin_directories": {
                    "type": "array",
                    "minItems": len(COREDUMP_CONFIG_ROOTS),
                    "maxItems": len(COREDUMP_CONFIG_ROOTS),
                    "items": {"$ref": "#/$defs/dropin_directory"},
                },
                "effective_dropins": {
                    "type": "array",
                    "uniqueItems": True,
                    "items": {"$ref": "#/$defs/effective_dropin"},
                },
            },
        },
        "unit_properties": {
            "type": "object",
            "additionalProperties": False,
            "required": list(COREDUMP_UNIT_PROPERTIES),
            "properties": {
                name: {"type": "string"} for name in COREDUMP_UNIT_PROPERTIES
            },
        },
        "unit_snapshot": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "unit",
                "returncode",
                "stdout_byte_count",
                "stdout_sha256",
                "stderr",
                "stderr_byte_count",
                "stderr_sha256",
                "properties",
            ],
            "properties": {
                "unit": {"type": "string"},
                "returncode": {"type": "integer", "const": 0},
                "stdout_byte_count": {"type": "integer", "minimum": 0},
                "stdout_sha256": {"$ref": "#/$defs/sha256"},
                "stderr": {"type": "string"},
                "stderr_byte_count": {"type": "integer", "minimum": 0},
                "stderr_sha256": {"$ref": "#/$defs/sha256"},
                "properties": {"$ref": "#/$defs/unit_properties"},
            },
        },
        "socket_snapshot": {
            "allOf": [
                {"$ref": "#/$defs/unit_snapshot"},
                {"properties": {"unit": {"const": COREDUMP_SOCKET_UNIT}}},
            ]
        },
        "template_snapshot": {
            "allOf": [
                {"$ref": "#/$defs/unit_snapshot"},
                {"properties": {"unit": {"const": COREDUMP_TEMPLATE_UNIT}}},
            ]
        },
        "instance_snapshot": {
            "allOf": [
                {"$ref": "#/$defs/unit_snapshot"},
                {
                    "properties": {
                        "unit": {"type": "string", "pattern": _COREDUMP_INSTANCE_PATTERN}
                    }
                },
            ]
        },
        "helper_units": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "list_command",
                "socket",
                "template",
                "instances",
                "instance_units",
                "instance_count",
            ],
            "properties": {
                "list_command": {"$ref": "#/$defs/command_output_hashed"},
                "socket": {"$ref": "#/$defs/socket_snapshot"},
                "template": {"$ref": "#/$defs/template_snapshot"},
                "instances": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/instance_snapshot"},
                },
                "instance_units": {
                    "type": "array",
                    "uniqueItems": True,
                    "items": {"type": "string", "pattern": _COREDUMP_INSTANCE_PATTERN},
                },
                "instance_count": {"type": "integer", "minimum": 0},
            },
        },
    },
}

COREDUMP_JOURNAL_INTERVAL_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "start_cursor",
        "terminal_cursor",
        "terminal_cursor_emitted",
        "byte_count",
        "sha256",
        "entry_count",
        "relevant_entry_count",
        "relevant_entries",
        "complete",
    ],
    "properties": {
        "start_cursor": {"$ref": "#/$defs/cursor"},
        "terminal_cursor": {"$ref": "#/$defs/cursor"},
        "terminal_cursor_emitted": {"type": "boolean"},
        "byte_count": {
            "type": "integer",
            "minimum": 0,
            "maximum": COREDUMP_JOURNAL_MAX_BYTES,
        },
        "sha256": {"$ref": "#/$defs/sha256"},
        "entry_count": {"type": "integer", "minimum": 0},
        "relevant_entry_count": {"type": "integer", "minimum": 0},
        "relevant_entries": {
            "type": "array",
            "items": {"$ref": "#/$defs/relevant_entry"},
        },
        "complete": {"type": "boolean", "const": True},
    },
    "$defs": {
        "sha256": {"type": "string", "pattern": _SHA256_PATTERN},
        "cursor": {"type": "string", "pattern": _CURSOR_PATTERN},
        "relevant_entry": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "cursor",
                "reasons",
                "coredump_field_names",
                "selected_fields",
                "record_sha256",
            ],
            "properties": {
                "cursor": {"$ref": "#/$defs/cursor"},
                "reasons": {
                    "type": "array",
                    "minItems": 1,
                    "uniqueItems": True,
                    "items": {"enum": list(COREDUMP_RELEVANT_REASONS)},
                },
                "coredump_field_names": {
                    "type": "array",
                    "uniqueItems": True,
                    "items": {"type": "string", "pattern": r"^COREDUMP_[A-Z0-9_]*$"},
                },
                "selected_fields": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        name: {} for name in COREDUMP_JOURNAL_SELECTED_FIELDS
                    },
                },
                "record_sha256": {"$ref": "#/$defs/sha256"},
            },
        },
    },
}


def validate_coredump_snapshot_value(value: Any, context: str) -> None:
    """Strictly validate one coredump-effect snapshot, shape then cross-fields."""
    validate_schema_instance(
        value, COREDUMP_SNAPSHOT_SCHEMA, COREDUMP_SNAPSHOT_SCHEMA, context
    )
    config = value["configuration"]
    for priority, root in enumerate(COREDUMP_CONFIG_ROOTS):
        main = config["main_candidates"][priority]
        if main.get("root_priority") != priority or main["path"] != str(
            root / "coredump.conf"
        ):
            raise ProbeError(
                "COREDUMP_EVIDENCE_INVALID", f"{context}: main candidate {priority}"
            )
        directory = config["dropin_directories"][priority]
        if (
            directory["root"] != str(root)
            or directory["root_priority"] != priority
            or directory["directory"]["path"] != str(root / "coredump.conf.d")
        ):
            raise ProbeError(
                "COREDUMP_EVIDENCE_INVALID", f"{context}: dropin directory {priority}"
            )
        for entry in directory["entries"]:
            if entry.get("root_priority") != priority or "name" not in entry:
                raise ProbeError(
                    "COREDUMP_EVIDENCE_INVALID", f"{context}: dropin entry {priority}"
                )
    effective_names = [item["name"] for item in config["effective_dropins"]]
    if effective_names != sorted(effective_names) or len(effective_names) != len(
        set(effective_names)
    ):
        raise ProbeError("COREDUMP_EVIDENCE_INVALID", f"{context}: effective dropins")
    helper = value["helper_units"]
    instance_units = [snapshot["unit"] for snapshot in helper["instances"]]
    if (
        helper["instance_units"] != sorted(instance_units)
        or helper["instance_count"] != len(instance_units)
        or len(set(instance_units)) != len(instance_units)
    ):
        raise ProbeError(
            "COREDUMP_EVIDENCE_INVALID", f"{context}: instance identity mismatch"
        )


def validate_coredump_journal_value(value: Any, context: str) -> None:
    """Strictly validate one journal interval, shape then cross-fields."""
    validate_schema_instance(
        value,
        COREDUMP_JOURNAL_INTERVAL_SCHEMA,
        COREDUMP_JOURNAL_INTERVAL_SCHEMA,
        context,
    )
    entries = value["relevant_entries"]
    if value["relevant_entry_count"] != len(entries):
        raise ProbeError("COREDUMP_EVIDENCE_INVALID", f"{context}: relevant count")
    if value["relevant_entry_count"] > value["entry_count"]:
        raise ProbeError(
            "COREDUMP_EVIDENCE_INVALID", f"{context}: relevant exceeds total"
        )
    cursors = [entry["cursor"] for entry in entries]
    if len(set(cursors)) != len(cursors):
        raise ProbeError(
            "COREDUMP_EVIDENCE_INVALID", f"{context}: duplicate entry cursor"
        )
    if not value["terminal_cursor_emitted"]:
        # An interval with no emitted terminal cursor is the empty interval: no
        # bytes, no entries, and a terminal position pinned to the start cursor.
        if (
            value["byte_count"] != 0
            or value["entry_count"] != 0
            or value["terminal_cursor"] != value["start_cursor"]
        ):
            raise ProbeError(
                "COREDUMP_EVIDENCE_INVALID", f"{context}: empty interval binding"
            )


def validate_coredump_evidence(evidence: Mapping[str, Any]) -> None:
    """Re-validate every coredump snapshot / journal interval carried in host.

    These records are optional (a failed snapshot is recorded as an error, never
    as SUCCESS/ACTIONS_CANCELLED), but whenever present they must carry the
    platform_file_observed authority and pass strict structural validation.
    """
    for item in evidence["host"]:
        name = item["name"]
        if name in ("host.coredump_effects_before", "host.coredump_effects_after"):
            if item["authority"] != "platform_file_observed":
                raise ProbeError("COREDUMP_EVIDENCE_INVALID", f"{name}: authority")
            validate_coredump_snapshot_value(item["value"], name)
        elif name == "host.journal_delta":
            if item["authority"] != "platform_file_observed":
                raise ProbeError("COREDUMP_EVIDENCE_INVALID", f"{name}: authority")
            validate_coredump_journal_value(item["value"], name)


def success_effective_control_authorities(case_ids: Sequence[str]) -> Dict[str, str]:
    """Exact effective-control name->authority contract for a supervisor run over
    ``case_ids``: every per-case control for each hosted case plus the two
    host-global controls."""
    expected: Dict[str, str] = {}
    for case_id in case_ids:
        for suffix, authority in EFFECTIVE_CONTROL_PER_CASE:
            expected[f"{case_id}.{suffix}"] = authority
    for name, authority in EFFECTIVE_CONTROL_GLOBAL:
        expected[name] = authority
    return expected


def cancellation_effective_control_authorities() -> Dict[str, str]:
    """Exact effective-control name->authority contract the cancellation finalizer
    emits for the single operator-cancel case."""
    return {name: authority for name, authority in CANCELLATION_EFFECTIVE_CONTROLS}


def verify_effective_controls(
    effective_observed: Sequence[Mapping[str, Any]],
    expected_authorities: Mapping[str, str],
    context: str,
) -> None:
    """Require each named effective control exactly once, with its exact authority
    and the literal JSON boolean ``True``. Missing, duplicate, unknown, false,
    numeric (``0``/``1``), string, null, list, or mapping values all fail closed;
    a non-boolean can never satisfy a proof-bearing control by being truthy."""
    seen: Dict[str, bool] = {}
    for item in effective_observed:
        name = item["name"]
        if name not in expected_authorities:
            raise ProbeError("SCHEMA_INVALID", f"{context}: unknown effective control {name}")
        if name in seen:
            raise ProbeError("SCHEMA_INVALID", f"{context}: duplicate effective control {name}")
        seen[name] = True
        if item["authority"] != expected_authorities[name]:
            raise ProbeError("SCHEMA_INVALID", f"{context}: effective control {name} authority")
        if item["value"] is not True:
            raise ProbeError(
                "SCHEMA_INVALID",
                f"{context}: effective control {name} is not the literal true",
            )
    missing = sorted(set(expected_authorities) - set(seen))
    if missing:
        raise ProbeError(
            "SCHEMA_INVALID", f"{context}: missing effective control {missing[0]}"
        )


def verify_control_inventory_synchronized() -> None:
    """Fail closed unless MANDATORY_CONTROL_INVENTORY covers exactly the mandatory
    manager properties, maps each effect to exactly one effective-control record
    that the emitted contract declares, and never both effect-proves and
    effect-unproven-classifies the same property. This is the mechanical guarantee
    that adding or removing a mandatory property cannot silently leave a control
    unproved, and that no two controls are credited from one effect record."""
    per_case_suffixes = {name for name, _ in EFFECTIVE_CONTROL_PER_CASE}
    global_names = {name for name, _ in EFFECTIVE_CONTROL_GLOBAL}
    effect_props: set = set()
    unproven_props: set = set()
    effect_names: List[str] = []
    for entry in MANDATORY_CONTROL_INVENTORY:
        if not entry.manager_properties:
            raise ProbeError("CONTROL_INVENTORY_INVALID", "empty manager_properties")
        if entry.effect_control is None:
            if entry.authority != EFFECT_UNPROVEN or entry.scope != "unproven":
                raise ProbeError(
                    "CONTROL_INVENTORY_INVALID", "effect_unproven entry malformed"
                )
            unproven_props |= set(entry.manager_properties)
            continue
        if entry.authority == EFFECT_UNPROVEN:
            raise ProbeError(
                "CONTROL_INVENTORY_INVALID",
                f"{entry.effect_control}: effect entry lacks a trusted authority",
            )
        effect_props |= set(entry.manager_properties)
        effect_names.append(entry.effect_control)
        if entry.scope == "per_case":
            if entry.effect_control not in per_case_suffixes:
                raise ProbeError(
                    "CONTROL_INVENTORY_INVALID",
                    f"per-case effect {entry.effect_control} is not in the contract",
                )
        elif entry.scope == "global":
            if entry.effect_control not in global_names:
                raise ProbeError(
                    "CONTROL_INVENTORY_INVALID",
                    f"global effect {entry.effect_control} is not in the contract",
                )
        else:
            raise ProbeError("CONTROL_INVENTORY_INVALID", f"bad scope {entry.scope}")
    if len(effect_names) != len(set(effect_names)):
        raise ProbeError(
            "CONTROL_INVENTORY_INVALID", "one effect record credited to two controls"
        )
    overlap = effect_props & unproven_props
    if overlap:
        raise ProbeError(
            "CONTROL_INVENTORY_INVALID",
            f"property is both effect-proven and effect-unproven: {sorted(overlap)}",
        )
    covered = effect_props | unproven_props
    if covered != MANDATORY_MANAGER_PROPERTIES:
        missing = sorted(MANDATORY_MANAGER_PROPERTIES - covered)
        extra = sorted(covered - MANDATORY_MANAGER_PROPERTIES)
        raise ProbeError(
            "CONTROL_INVENTORY_DESYNC", f"missing={missing} extra={extra}"
        )


def mandatory_effect_blockers() -> List[str]:
    """The ordered, stable list of mandatory manager properties this candidate
    does not prove with a trusted, independently interpretable effect predicate
    (the ``effect_unproven`` inventory class). It is non-empty by construction, so
    candidate SUCCESS is fail-closed-unreachable: manager equality alone is never
    accepted, and each listed property is an explicit blocker. A property gains a
    trusted effect predicate only by moving to an ``effect_proven`` inventory row,
    which mechanically removes it from this list."""
    blockers: List[str] = []
    for entry in MANDATORY_CONTROL_INVENTORY:
        if entry.effect_control is None:
            blockers.extend(entry.manager_properties)
    return sorted(blockers)


def candidate_run_succeeds(
    *,
    cases: Sequence[Mapping[str, Any]],
    requested_case_ids: Sequence[str],
    errors: Sequence[Any],
    witness_ok: bool,
    mandatory_blockers: Sequence[str],
) -> bool:
    """The single, pure candidate-SUCCESS decision the supervisor's outcome gate
    uses. SUCCESS requires, in addition to every per-case proof, that there are
    zero unproven mandatory controls: manager property equality can never stand in
    for a missing effect proof. Any unproven mandatory control, run-level error, or
    unproven noexec substrate makes SUCCESS unreachable. This is the function the
    adversarial tests exercise directly, not just via schema fixtures."""
    if mandatory_blockers:
        return False
    if errors:
        return False
    if not witness_ok:
        return False
    observed_ids = [case["id"] for case in cases]
    if observed_ids != list(requested_case_ids):
        return False
    if len(set(observed_ids)) != len(requested_case_ids):
        return False
    for case in cases:
        if case["errors"]:
            return False
        if case["outcome"] != EXPECTED_CASE_OUTCOMES[case["id"]]:
            return False
        if case["requested_argv"] != case["kernel_observed_argv"]:
            return False
        if not environment_contract_satisfied(
            case["requested_environment"], case["kernel_observed_environment"]
        ):
            return False
        cleanup = case["cleanup"]
        if not (
            cleanup["direct_cgroup_kill_written"]
            and cleanup["recursive_populated_zero_observed"]
            and cleanup["streams_eof_after_empty"]
            and cleanup["unit_unloaded_after_empty"]
        ):
            return False
        if not all(derive_bootstrap_effect_controls(case).values()):
            return False
    return True


# --- F7-B0: proof-ineligible discovery evidence ---------------------------

_DISCOVERY_TEXT = {"type": "string", "maxLength": 65536}
_DISCOVERY_HEX64 = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_DISCOVERY_RAW_BASE64 = {
    "type": "string",
    "maxLength": DISCOVERY_BASE64_MAX_LENGTH,
    "pattern": "^[A-Za-z0-9+/]*={0,2}$",
}
_DISCOVERY_MOUNT_TOKEN = {
    "type": "string",
    "minLength": 1,
    "maxLength": 65536,
    "pattern": r"^[^, \t\r\n\v\f]+$",
}
_DISCOVERY_MOUNT_FIELD = {
    "type": "string",
    "minLength": 1,
    "maxLength": 65536,
    "pattern": r"^[^ \t\r\n\v\f]+$",
}
_DISCOVERY_VALUE_SCHEMAS: Dict[str, Mapping[str, Any]] = {
    "runner_image": {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "runner_label",
            "image_os",
            "image_version",
            "image_release",
            "arch",
            "os_release",
            "os_release_raw_base64",
        ],
        "properties": {
            "runner_label": {"const": "ubuntu-24.04"},
            "image_os": _DISCOVERY_TEXT,
            "image_version": _DISCOVERY_TEXT,
            "image_release": _DISCOVERY_TEXT,
            "arch": _DISCOVERY_TEXT,
            "os_release": _DISCOVERY_TEXT,
            "os_release_raw_base64": _DISCOVERY_RAW_BASE64,
        },
    },
    "kernel": {
        "type": "object",
        "additionalProperties": False,
        "required": ["release", "version"],
        "properties": {
            "release": {"type": "string", "minLength": 1, "maxLength": 64},
            "version": {"type": "string", "minLength": 1, "maxLength": 64},
        },
    },
    "systemd": {
        "type": "object",
        "additionalProperties": False,
        "required": ["version_output", "feature_output", "stdout_raw_base64"],
        "properties": {
            "version_output": _DISCOVERY_TEXT,
            "feature_output": _DISCOVERY_TEXT,
            "stdout_raw_base64": _DISCOVERY_RAW_BASE64,
        },
    },
    "cgroup_topology": {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "unified",
            "controllers",
            "controllers_raw_base64",
            "proc_cgroup",
            "proc_cgroup_raw_base64",
        ],
        "properties": {
            "unified": {"type": "boolean"},
            "controllers": {
                "type": "array",
                "maxItems": 256,
                "uniqueItems": True,
                "items": {"type": "string", "pattern": "^[a-z][a-z0-9_]*$"},
            },
            "controllers_raw_base64": _DISCOVERY_RAW_BASE64,
            "proc_cgroup": _DISCOVERY_TEXT,
            "proc_cgroup_raw_base64": _DISCOVERY_RAW_BASE64,
        },
    },
    "mountinfo_topology": {
        "type": "object",
        "additionalProperties": False,
        "required": ["entries", "raw_base64"],
        "properties": {
            "raw_base64": _DISCOVERY_RAW_BASE64,
            "entries": {
                "type": "array",
                "maxItems": DISCOVERY_MAX_MOUNTS,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "mount_id",
                        "parent_id",
                        "major_minor",
                        "root",
                        "mount_point",
                        "mount_options",
                        "optional_fields",
                        "fs_type",
                        "mount_source",
                        "super_options",
                    ],
                    "properties": {
                        "mount_id": {
                            "type": "string",
                            "pattern": "^[1-9][0-9]*$",
                            "maxLength": 10,
                        },
                        "parent_id": {
                            "type": "string",
                            "pattern": "^[1-9][0-9]*$",
                            "maxLength": 10,
                        },
                        "major_minor": {
                            "type": "string",
                            "pattern": "^(0|[1-9][0-9]*):(0|[1-9][0-9]*)$",
                            "maxLength": 12,
                        },
                        "root": _DISCOVERY_TEXT,
                        "mount_point": _DISCOVERY_TEXT,
                        "mount_options": {
                            "type": "array",
                            "minItems": 1,
                            "uniqueItems": True,
                            "items": _DISCOVERY_MOUNT_TOKEN,
                        },
                        "optional_fields": {
                            "type": "array",
                            "items": _DISCOVERY_MOUNT_FIELD,
                        },
                        "fs_type": _DISCOVERY_MOUNT_FIELD,
                        "mount_source": _DISCOVERY_TEXT,
                        "super_options": {
                            "type": "array",
                            "minItems": 1,
                            "uniqueItems": True,
                            "items": _DISCOVERY_MOUNT_TOKEN,
                        },
                    },
                },
            }
        },
    },
    "bpf_prog_query": {
        "type": "object",
        "additionalProperties": False,
        "required": ["attempted", "success", "errno", "errno_name"],
        "properties": {
            "attempted": {"const": True},
            "success": {"type": "boolean"},
            "errno": {"type": ["null", "integer"], "minimum": 1},
            "errno_name": {
                "type": ["null", "string"],
                "pattern": "^[A-Z][A-Z0-9_]*$",
            },
        },
    },
    "device_nodes": {
        "type": "object",
        "additionalProperties": False,
        "required": ["candidates"],
        "properties": {
            "candidates": {
                "type": "array",
                "maxItems": DISCOVERY_MAX_DEVICE_NODES,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "path",
                        "type",
                        "major",
                        "minor",
                        "uid",
                        "gid",
                        "mode",
                    ],
                    "properties": {
                        "path": _DISCOVERY_TEXT,
                        "type": {"enum": ["char", "block"]},
                        "major": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": DISCOVERY_DEVICE_MAJOR_MAX,
                        },
                        "minor": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": DISCOVERY_DEVICE_MINOR_MAX,
                        },
                        "uid": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": DISCOVERY_UID_GID_MAX,
                        },
                        "gid": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": DISCOVERY_UID_GID_MAX,
                        },
                        "mode": {"type": "integer", "minimum": 0, "maximum": 4095},
                    },
                },
            }
        },
    },
    "executable_abis": {
        "type": "object",
        "additionalProperties": False,
        "required": ["binaries", "absence_unresolved"],
        "properties": {
            "binaries": {
                "type": "array",
                "maxItems": DISCOVERY_MAX_ABIS,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "path",
                        "sha256",
                        "elf_class",
                        "endianness",
                        "machine",
                    ],
                    "properties": {
                        "path": _DISCOVERY_TEXT,
                        "sha256": _DISCOVERY_HEX64,
                        "elf_class": {"enum": [32, 64]},
                        "endianness": {"enum": ["little", "big"]},
                        "machine": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 65535,
                        },
                    },
                },
            },
            "absence_unresolved": {"const": True},
        },
    },
    "field_availability": {
        "type": "object",
        "additionalProperties": False,
        "required": ["fields"],
        "properties": {
            "fields": {
                "type": "array",
                "maxItems": DISCOVERY_MAX_FIELDS,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["name", "path", "available", "errno"],
                    "properties": {
                        "name": {
                            "type": "string",
                            "pattern": "^[a-z][a-z0-9_.-]*$",
                        },
                        "path": _DISCOVERY_TEXT,
                        "available": {"type": "boolean"},
                        "errno": {"type": ["null", "integer"], "minimum": 1},
                    },
                },
            }
        },
    },
}

DISCOVERY_SCHEMA: Mapping[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version",
        "evidence_kind",
        "discovery_notice",
        "mode",
        "outcome",
        "outcome_authority",
        "proof_eligible",
        "proof_ineligible_reason",
        "identity",
        "source",
        "records",
        "future_witnesses",
        "mandatory_effect_blockers",
        "errors",
    ],
    "properties": {
        "schema_version": {"const": SCHEMA_VERSION},
        "evidence_kind": {"const": DISCOVERY_EVIDENCE_KIND},
        "discovery_notice": {"const": DISCOVERY_NOTICE},
        "mode": {"const": "hosted_discovery"},
        "outcome": {"const": "DISCOVERY_ONLY"},
        "outcome_authority": {"const": "supervisor_observed"},
        "proof_eligible": {"const": False},
        "proof_ineligible_reason": {"const": DISCOVERY_PROOF_INELIGIBLE_REASON},
        "identity": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "repository",
                "repository_id",
                "pr_number",
                "event_name",
                "event_action",
                "event_ref",
                "label",
                "sender_login",
                "sender_id",
                "actor_login",
                "actor_id",
                "run_id",
                "run_attempt",
                "head_sha",
                "base_sha",
                "merge_sha",
                "workflow",
                "workflow_ref",
                "workflow_sha",
                "runner_label",
                "image_os",
                "image_version",
                "image_release",
                "runner_arch",
                "boot_id",
                "invocation_id",
            ],
            "properties": {
                "repository": _DISCOVERY_TEXT,
                "repository_id": {"type": "string", "pattern": "^[1-9][0-9]*$"},
                "pr_number": {"const": "71"},
                "event_name": {"const": "pull_request"},
                "event_action": {"const": "labeled"},
                "event_ref": {"const": "refs/pull/71/merge"},
                "label": {"const": "p0-v2-discovery"},
                "sender_login": {"const": "yurikuchumov-ux"},
                "sender_id": {"const": "299144523"},
                "actor_login": {"const": "yurikuchumov-ux"},
                "actor_id": {"const": "299144523"},
                "run_id": {"type": "string", "pattern": "^[1-9][0-9]*$"},
                "run_attempt": {"const": "1"},
                "head_sha": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
                "base_sha": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
                "merge_sha": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
                "workflow": _DISCOVERY_TEXT,
                "workflow_ref": _DISCOVERY_TEXT,
                "workflow_sha": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
                "runner_label": {"const": "ubuntu-24.04"},
                "image_os": _DISCOVERY_TEXT,
                "image_version": _DISCOVERY_TEXT,
                "image_release": _DISCOVERY_TEXT,
                "runner_arch": _DISCOVERY_TEXT,
                "boot_id": {
                    "type": "string",
                    "pattern": (
                        "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
                        "[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
                    ),
                },
                "invocation_id": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$",
                },
            },
        },
        "source": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "probe_sha256",
                "schema_sha256",
                "discovery_schema_sha256",
                "workflow_sha256",
                "test_sha256",
                "implementation_commit",
                "source_authoring_anchor",
                "f7b0_authoring_task_sha256",
                "f7b1_hosted_authorization_sha256",
            ],
            "properties": {
                "probe_sha256": _DISCOVERY_HEX64,
                "schema_sha256": _DISCOVERY_HEX64,
                "discovery_schema_sha256": _DISCOVERY_HEX64,
                "workflow_sha256": _DISCOVERY_HEX64,
                "test_sha256": _DISCOVERY_HEX64,
                "implementation_commit": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{40}$",
                },
                "source_authoring_anchor": {
                    "const": DISCOVERY_SOURCE_AUTHORING_ANCHOR,
                },
                "f7b0_authoring_task_sha256": {
                    "const": DISCOVERY_F7B0_AUTHORING_TASK_SHA256,
                },
                "f7b1_hosted_authorization_sha256": {
                    "const": DISCOVERY_F7B1_HOSTED_AUTHORIZATION_SHA256,
                },
            },
        },
        "records": {
            "type": "array",
            "minItems": DISCOVERY_MAX_RECORDS,
            "maxItems": DISCOVERY_MAX_RECORDS,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "sequence",
                    "surface",
                    "authority",
                    "value",
                    "value_sha256",
                ],
                "properties": {
                    "sequence": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": DISCOVERY_MAX_RECORDS - 1,
                    },
                    "surface": {"enum": list(DISCOVERY_SURFACES)},
                    "authority": {
                        "enum": sorted(set(DISCOVERY_SURFACE_AUTHORITIES.values()))
                    },
                    "value": {
                        "type": [
                            "null",
                            "boolean",
                            "number",
                            "string",
                            "array",
                            "object",
                        ]
                    },
                    "value_sha256": _DISCOVERY_HEX64,
                },
            },
        },
        "future_witnesses": {
            "type": "array",
            "minItems": len(EQUIVALENCE_CLASS_IDENTIFIERS),
            "maxItems": len(EQUIVALENCE_CLASS_IDENTIFIERS),
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "roles", "status", "proof_eligible"],
                "properties": {
                    "id": {"enum": list(EQUIVALENCE_CLASS_IDENTIFIERS)},
                    "roles": {
                        "type": "array",
                        "minItems": 2,
                        "maxItems": 2,
                        "items": {"enum": list(DIFFERENTIAL_WITNESS_ROLES)},
                    },
                    "status": {"const": DISCOVERY_EC_STATUS},
                    "proof_eligible": {"const": False},
                },
            },
        },
        "mandatory_effect_blockers": {
            "type": "array",
            "minItems": 1,
            "uniqueItems": True,
            "items": {"type": "string"},
        },
        "errors": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["code", "authority", "detail"],
                "properties": {
                    "code": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]*$"},
                    "authority": {"const": "supervisor_observed"},
                    "detail": {"type": "string", "maxLength": 1000},
                },
            },
        },
    },
}


def discovery_record(
    sequence: int, surface: str, authority: str, value: Mapping[str, Any]
) -> Dict[str, Any]:
    """Build one digest-bound discovery record without interpreting availability
    as proof."""
    return {
        "sequence": sequence,
        "surface": surface,
        "authority": authority,
        "value": dict(value),
        "value_sha256": sha256_bytes(canonical_json_bytes(value)),
    }


def discovery_schema_sha256() -> str:
    """Digest the exact in-source schema for the separate discovery domain."""
    return sha256_bytes(canonical_json_bytes(DISCOVERY_SCHEMA))


def discovery_replay_binding(evidence: Mapping[str, Any]) -> str:
    """Stable replay/identity binding for a discovery document."""
    return sha256_bytes(
        canonical_json_bytes(
            {"identity": evidence["identity"], "source": evidence["source"]}
        )
    )


def build_discovery_evidence(
    *,
    identity: Mapping[str, Any],
    source: Mapping[str, Any],
    values: Mapping[str, Mapping[str, Any]],
    errors: Sequence[Mapping[str, Any]] = (),
) -> Dict[str, Any]:
    """Build the discovery-only document.  This function never starts a hostile
    fixture and never calls candidate_run_succeeds."""
    if set(values) != set(DISCOVERY_SURFACES):
        raise ProbeError("DISCOVERY_RECORD_SET_INVALID", "surface set mismatch")
    records = [
        discovery_record(
            index,
            surface,
            DISCOVERY_SURFACE_AUTHORITIES[surface],
            values[surface],
        )
        for index, surface in enumerate(DISCOVERY_SURFACES)
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "evidence_kind": DISCOVERY_EVIDENCE_KIND,
        "discovery_notice": DISCOVERY_NOTICE,
        "mode": "hosted_discovery",
        "outcome": "DISCOVERY_ONLY",
        "outcome_authority": "supervisor_observed",
        "proof_eligible": False,
        "proof_ineligible_reason": DISCOVERY_PROOF_INELIGIBLE_REASON,
        "identity": dict(identity),
        "source": dict(source),
        "records": records,
        "future_witnesses": [
            {
                "id": identifier,
                "roles": list(DIFFERENTIAL_WITNESS_ROLES),
                "status": DISCOVERY_EC_STATUS,
                "proof_eligible": False,
            }
            for identifier in EQUIVALENCE_CLASS_IDENTIFIERS
        ],
        "mandatory_effect_blockers": mandatory_effect_blockers(),
        "errors": [dict(item) for item in errors],
    }


def _require_canonical_unique(items: Sequence[Any], label: str) -> None:
    encoded = [canonical_json_bytes(item) for item in items]
    if len(encoded) != len(set(encoded)):
        raise ProbeError("DISCOVERY_CONTRADICTION", f"{label}: duplicate")


def expected_discovery_image_release(image_os: str, image_version: str) -> str:
    if DISCOVERY_IMAGE_OS_PATTERN.fullmatch(image_os) is None:
        raise ProbeError("DISCOVERY_IDENTITY_MISMATCH", "image OS")
    if DISCOVERY_IMAGE_VERSION_PATTERN.fullmatch(image_version) is None:
        raise ProbeError("DISCOVERY_IDENTITY_MISMATCH", "image version")
    try:
        datetime.datetime.strptime(image_version[:8], "%Y%m%d")
    except ValueError as exc:
        raise ProbeError("DISCOVERY_IDENTITY_MISMATCH", "image version date") from exc
    image_build = image_version.rsplit(".", 1)[0]
    return (
        "https://github.com/actions/runner-images/releases/tag/"
        f"{image_os}%2F{image_build}"
    )


def _parse_discovery_decimal(value: str, maximum: int, label: str) -> int:
    """Parse one canonical kernel-origin decimal without exposing ``int()`` to
    unbounded attacker-controlled input."""
    if (
        DISCOVERY_POSITIVE_DECIMAL_PATTERN.fullmatch(value) is None
        or len(value) > len(str(maximum))
    ):
        raise ProbeError("DISCOVERY_NONCANONICAL", label)
    parsed = int(value)
    if parsed > maximum:
        raise ProbeError("DISCOVERY_CONTRADICTION", label)
    return parsed


def _parse_discovery_os_release(text: str) -> Dict[str, str]:
    """Parse the two trusted image-identity keys and reject duplicates or
    malformed assignments instead of silently applying last-assignment-wins."""
    identity: Dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ProbeError("DISCOVERY_IDENTITY_MISMATCH", "os-release syntax")
        key, raw_value = line.split("=", 1)
        if not key or key.strip() != key:
            raise ProbeError("DISCOVERY_IDENTITY_MISMATCH", "os-release key")
        if key in {"ID", "VERSION_ID"}:
            if key in identity:
                raise ProbeError(
                    "DISCOVERY_IDENTITY_MISMATCH", f"os-release duplicate {key}"
                )
            value = raw_value.strip()
            if (
                len(value) >= 2
                and value[0] in {'"', "'"}
                and value[-1] == value[0]
            ):
                value = value[1:-1]
            elif value.startswith(('"', "'")) or value.endswith(('"', "'")):
                raise ProbeError(
                    "DISCOVERY_IDENTITY_MISMATCH", f"os-release malformed {key}"
                )
            identity[key] = value
    return identity


def _discovery_raw_base64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _decode_discovery_raw(
    encoded: str, maximum: int, label: str
) -> bytes:
    """Decode one canonical retained producer byte string with its original
    source-wide byte limit.  Canonical re-encoding rejects padding aliases."""
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ProbeError("DISCOVERY_NONCANONICAL", f"{label} base64") from exc
    if _discovery_raw_base64(raw) != encoded:
        raise ProbeError("DISCOVERY_NONCANONICAL", f"{label} base64")
    if len(raw) > maximum:
        raise ProbeError("DISCOVERY_RECORD_OVERSIZED", label)
    return raw


def _discovery_text_from_raw(encoded: str, maximum: int, label: str) -> str:
    return _decode_discovery_raw(encoded, maximum, label).decode(
        "utf-8", "replace"
    )


def _systemd_fields_from_raw(raw: bytes) -> Dict[str, str]:
    if not raw.endswith(b"\n") or b"\x00" in raw:
        raise ProbeError("DISCOVERY_SYSTEMD_VERSION_FAILED", "noncanonical output")
    records = raw[:-1].split(b"\n")
    if (
        len(records) != 2
        or not all(records)
        or any(
            byte < 0x20 or byte > 0x7E
            for record in records
            for byte in record
        )
    ):
        raise ProbeError(
            "DISCOVERY_SYSTEMD_VERSION_FAILED", "noncanonical output"
        )
    version_output = records[0].decode("ascii")
    feature_output = records[1].decode("ascii")
    feature_tokens = feature_output.split(" ")
    if (
        DISCOVERY_SYSTEMD_VERSION_PATTERN.fullmatch(version_output) is None
        or len(feature_tokens)
        != len(DISCOVERY_SYSTEMD_V255_FEATURE_ORDER) + 1
        or any(
            token not in {f"+{name}", f"-{name}"}
            for token, name in zip(
                feature_tokens[:-1],
                DISCOVERY_SYSTEMD_V255_FEATURE_ORDER,
            )
        )
        or feature_tokens[-1] != "default-hierarchy=unified"
    ):
        raise ProbeError(
            "DISCOVERY_SYSTEMD_VERSION_FAILED", "producer grammar"
        )
    return {
        "version_output": version_output,
        "feature_output": feature_output,
    }


def _canonical_cgroup_v2_source(raw: bytes) -> str:
    """Return one exact unified-v2 /proc/self/cgroup record.

    VFS-generated paths are absolute and canonical: root is the sole one-byte
    path, while non-root paths have no empty, dot, dot-dot, or trailing
    component.  Parsing bytes first prevents Unicode line-separator aliases.
    """
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1 or b"\x00" in raw:
        raise ProbeError("DISCOVERY_CONTRADICTION", "proc cgroup framing")
    record = raw[:-1]
    if not record.startswith(b"0::/"):
        raise ProbeError("DISCOVERY_CONTRADICTION", "proc cgroup identity")
    path = record[3:]
    if path != b"/":
        components = path[1:].split(b"/")
        if (
            not components
            or any(component in {b"", b".", b".."} for component in components)
            or any(
                byte < 0x20 or byte == 0x7F
                for component in components
                for byte in component
            )
        ):
            raise ProbeError(
                "DISCOVERY_CONTRADICTION", "proc cgroup canonical path"
            )
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProbeError(
            "DISCOVERY_CONTRADICTION", "proc cgroup encoding"
        ) from exc


def validate_discovery_evidence(
    evidence: Mapping[str, Any],
    schema_path: Path,
    *,
    source_path: Optional[Path] = None,
    expected_identity: Optional[Mapping[str, Any]] = None,
    expected_replay_binding: Optional[str] = None,
) -> None:
    """Validate the separate proof-ineligible domain and fail closed on any
    candidate/discovery mixing, replay, overclaim, or non-canonical record."""
    if evidence.get("evidence_kind") == EVIDENCE_KIND:
        raise ProbeError(
            "DISCOVERY_KIND_MISMATCH", "candidate evidence supplied to discovery validator"
        )
    validate_schema_instance(evidence, DISCOVERY_SCHEMA, DISCOVERY_SCHEMA)
    reject_gate1_namespace(evidence)
    if evidence["source"]["schema_sha256"] != sha256_path(schema_path):
        raise ProbeError("DISCOVERY_IDENTITY_MISMATCH", "schema digest")
    if (
        evidence["source"]["discovery_schema_sha256"]
        != discovery_schema_sha256()
    ):
        raise ProbeError("DISCOVERY_IDENTITY_MISMATCH", "discovery schema digest")
    if source_path is not None and evidence["source"]["probe_sha256"] != sha256_path(
        source_path
    ):
        raise ProbeError("DISCOVERY_IDENTITY_MISMATCH", "source digest")
    if (
        evidence["source"]["implementation_commit"]
        != evidence["identity"]["head_sha"]
    ):
        raise ProbeError(
            "DISCOVERY_IDENTITY_MISMATCH", "implementation commit"
        )
    if expected_identity is not None:
        for key, expected in expected_identity.items():
            if evidence["identity"].get(key) != expected:
                raise ProbeError("DISCOVERY_IDENTITY_MISMATCH", key)
    replay_binding = discovery_replay_binding(evidence)
    if (
        expected_replay_binding is not None
        and replay_binding != expected_replay_binding
    ):
        raise ProbeError("DISCOVERY_REPLAY_MISMATCH", replay_binding)

    records = evidence["records"]
    if len(records) != DISCOVERY_MAX_RECORDS:
        raise ProbeError("DISCOVERY_RECORD_SET_INVALID", "record count")
    total_bytes = 0
    for index, (record, surface) in enumerate(zip(records, DISCOVERY_SURFACES)):
        if record["sequence"] != index or record["surface"] != surface:
            raise ProbeError("DISCOVERY_NONCANONICAL", f"record {index}")
        if record["authority"] != DISCOVERY_SURFACE_AUTHORITIES[surface]:
            raise ProbeError("DISCOVERY_AUTHORITY_INVALID", surface)
        value_bytes = canonical_json_bytes(record["value"])
        if len(value_bytes) > DISCOVERY_MAX_RECORD_BYTES:
            raise ProbeError("DISCOVERY_RECORD_OVERSIZED", surface)
        total_bytes += len(value_bytes)
        if sha256_bytes(value_bytes) != record["value_sha256"]:
            raise ProbeError("DISCOVERY_RECORD_DIGEST_MISMATCH", surface)
        validate_schema_instance(
            record["value"],
            _DISCOVERY_VALUE_SCHEMAS[surface],
            _DISCOVERY_VALUE_SCHEMAS[surface],
            f"$.records[{index}].value",
        )
    if total_bytes > DISCOVERY_MAX_TOTAL_BYTES:
        raise ProbeError("DISCOVERY_TOTAL_OVERSIZED", str(total_bytes))

    by_surface = {record["surface"]: record["value"] for record in records}
    runner = by_surface["runner_image"]
    if (
        runner["runner_label"] != evidence["identity"]["runner_label"]
        or runner["image_os"] != evidence["identity"]["image_os"]
        or runner["image_version"] != evidence["identity"]["image_version"]
        or runner["image_release"] != evidence["identity"]["image_release"]
        or runner["arch"] != evidence["identity"]["runner_arch"]
    ):
        raise ProbeError("DISCOVERY_IDENTITY_MISMATCH", "runner image")
    if runner["image_release"] != expected_discovery_image_release(
        runner["image_os"], runner["image_version"]
    ):
        raise ProbeError("DISCOVERY_IDENTITY_MISMATCH", "runner image release")
    if evidence["identity"]["workflow"] != DISCOVERY_WORKFLOW_NAME or runner["arch"] != "X64":
        raise ProbeError("DISCOVERY_IDENTITY_MISMATCH", "runner platform")
    if (
        _discovery_text_from_raw(
            runner["os_release_raw_base64"],
            DISCOVERY_SOURCE_TEXT_MAX_BYTES,
            "os-release",
        )
        != runner["os_release"]
    ):
        raise ProbeError("DISCOVERY_CONTRADICTION", "os-release transformation")
    os_release = _parse_discovery_os_release(runner["os_release"])
    if os_release.get("ID") != "ubuntu" or os_release.get("VERSION_ID") != "24.04":
        raise ProbeError("DISCOVERY_IDENTITY_MISMATCH", "os-release")

    kernel = by_surface["kernel"]
    if (
        not kernel["release"]
        or not kernel["version"]
        or len(kernel["release"]) > 64
        or len(kernel["version"]) > 64
        or "\x00" in kernel["release"]
        or "\x00" in kernel["version"]
        or any(
            ord(character) < 0x20 or ord(character) > 0x7e
            for character in kernel["release"] + kernel["version"]
        )
        or any(character.isspace() for character in kernel["release"])
    ):
        raise ProbeError("DISCOVERY_CONTRADICTION", "kernel UTS identity")
    if (
        DISCOVERY_UUID4_PATTERN.fullmatch(evidence["identity"]["boot_id"])
        is None
        or DISCOVERY_UUID4_HEX_PATTERN.fullmatch(
            evidence["identity"]["invocation_id"]
        )
        is None
    ):
        raise ProbeError("DISCOVERY_CONTRADICTION", "generated UUID identity")

    systemd = by_surface["systemd"]
    systemd_raw = _decode_discovery_raw(
        systemd["stdout_raw_base64"],
        DISCOVERY_SOURCE_TEXT_MAX_BYTES,
        "systemd stdout",
    )
    expected_systemd = _systemd_fields_from_raw(systemd_raw)
    if (
        systemd["version_output"] != expected_systemd["version_output"]
        or systemd["feature_output"] != expected_systemd["feature_output"]
    ):
        raise ProbeError("DISCOVERY_CONTRADICTION", "systemd transformation")

    cgroup = by_surface["cgroup_topology"]
    if not cgroup["unified"]:
        raise ProbeError("DISCOVERY_CONTRADICTION", "cgroup v2")
    if cgroup["controllers"] != sorted(cgroup["controllers"]):
        raise ProbeError("DISCOVERY_NONCANONICAL", "cgroup controllers")
    controllers_raw = _discovery_text_from_raw(
        cgroup["controllers_raw_base64"],
        DISCOVERY_SOURCE_TEXT_MAX_BYTES,
        "cgroup controllers",
    )
    controllers_bytes = _decode_discovery_raw(
        cgroup["controllers_raw_base64"],
        DISCOVERY_SOURCE_TEXT_MAX_BYTES,
        "cgroup controllers",
    )
    if (
        not controllers_bytes.endswith(b"\n")
        or b"\x00" in controllers_bytes
        or any(ord(character) > 0x7f for character in controllers_raw)
        or controllers_bytes
        != (" ".join(controllers_raw.split()) + "\n").encode("ascii")
    ):
        raise ProbeError("DISCOVERY_CONTRADICTION", "cgroup controllers source")
    if cgroup["controllers"] != sorted(controllers_raw.split()):
        raise ProbeError("DISCOVERY_CONTRADICTION", "cgroup controllers transformation")
    proc_cgroup_bytes = _decode_discovery_raw(
        cgroup["proc_cgroup_raw_base64"],
        DISCOVERY_SOURCE_TEXT_MAX_BYTES,
        "proc cgroup",
    )
    proc_cgroup_raw = _canonical_cgroup_v2_source(proc_cgroup_bytes)
    if (
        cgroup["proc_cgroup"] != proc_cgroup_raw
    ):
        raise ProbeError("DISCOVERY_CONTRADICTION", "proc cgroup transformation")

    mount_record = by_surface["mountinfo_topology"]
    mountinfo_raw = _decode_discovery_raw(
        mount_record["raw_base64"],
        DISCOVERY_MOUNTINFO_RAW_MAX_BYTES,
        "mountinfo",
    )
    expected_mounts = parse_discovery_mountinfo(mountinfo_raw)
    mounts = mount_record["entries"]
    if mounts != expected_mounts:
        raise ProbeError("DISCOVERY_CONTRADICTION", "mountinfo transformation")
    if not mounts:
        raise ProbeError("DISCOVERY_CONTRADICTION", "empty mount topology")
    parsed_mount_ids: List[int] = []
    for item in mounts:
        if (
            DISCOVERY_POSITIVE_DECIMAL_PATTERN.fullmatch(item["mount_id"]) is None
            or DISCOVERY_POSITIVE_DECIMAL_PATTERN.fullmatch(item["parent_id"]) is None
            or DISCOVERY_MAJOR_MINOR_PATTERN.fullmatch(item["major_minor"]) is None
            or item["mount_options"] != sorted(item["mount_options"])
            or item["super_options"] != sorted(item["super_options"])
        ):
            raise ProbeError("DISCOVERY_NONCANONICAL", "mount identity")
        parsed_mount_ids.append(
            _parse_discovery_decimal(
                item["mount_id"], DISCOVERY_MOUNT_ID_MAX, "mount id"
            )
        )
        _parse_discovery_decimal(
            item["parent_id"], DISCOVERY_MOUNT_ID_MAX, "parent mount id"
        )
        raw_major, raw_minor = item["major_minor"].split(":", 1)
        if (
            len(raw_major) > len(str(DISCOVERY_DEVICE_MAJOR_MAX))
            or len(raw_minor) > len(str(DISCOVERY_DEVICE_MINOR_MAX))
            or int(raw_major) > DISCOVERY_DEVICE_MAJOR_MAX
            or int(raw_minor) > DISCOVERY_DEVICE_MINOR_MAX
        ):
            raise ProbeError("DISCOVERY_CONTRADICTION", "mount device identity")
    if parsed_mount_ids != sorted(parsed_mount_ids):
        raise ProbeError("DISCOVERY_NONCANONICAL", "mount ids")
    if len(set(parsed_mount_ids)) != len(mounts):
        raise ProbeError("DISCOVERY_CONTRADICTION", "duplicate mount id")
    _require_canonical_unique(mounts, "mount entries")

    query = by_surface["bpf_prog_query"]
    if query["success"] != (query["errno"] is None and query["errno_name"] is None):
        raise ProbeError("DISCOVERY_CONTRADICTION", "BPF_PROG_QUERY result")
    if query["errno"] is not None and (
        query["errno"] not in DISCOVERY_BPF_PROG_QUERY_ERRNOS
        or query["errno_name"] != LINUX_ERRNO_NAMES[query["errno"]]
    ):
        raise ProbeError("DISCOVERY_CONTRADICTION", "BPF_PROG_QUERY errno")

    devices = by_surface["device_nodes"]["candidates"]
    if [item["path"] for item in devices] != sorted(item["path"] for item in devices):
        raise ProbeError("DISCOVERY_NONCANONICAL", "device paths")
    if len({item["path"] for item in devices}) != len(devices):
        raise ProbeError("DISCOVERY_CONTRADICTION", "duplicate device path")
    for item in devices:
        path = Path(item["path"])
        if (
            str(path) != item["path"]
            or path.parent != Path("/dev")
            or item["path"] in _DISCOVERY_DEVICE_ALLOWLIST
            or path.name in {"", ".", ".."}
        ):
            raise ProbeError("DISCOVERY_CONTRADICTION", "device path")
        if (
            item["major"] > DISCOVERY_DEVICE_MAJOR_MAX
            or item["minor"] > DISCOVERY_DEVICE_MINOR_MAX
            or item["uid"] > DISCOVERY_UID_GID_MAX
            or item["gid"] > DISCOVERY_UID_GID_MAX
        ):
            raise ProbeError("DISCOVERY_CONTRADICTION", "device identity")
    _require_canonical_unique(devices, "device candidates")

    binaries = by_surface["executable_abis"]["binaries"]
    if [item["path"] for item in binaries] != sorted(item["path"] for item in binaries):
        raise ProbeError("DISCOVERY_NONCANONICAL", "ABI paths")
    if len({item["path"] for item in binaries}) != len(binaries):
        raise ProbeError("DISCOVERY_CONTRADICTION", "duplicate ABI path")
    if any(item["path"] not in _DISCOVERY_ABI_CANDIDATES for item in binaries):
        raise ProbeError("DISCOVERY_CONTRADICTION", "ABI path")
    if "/usr/lib/systemd/systemd" not in {
        item["path"] for item in binaries
    }:
        raise ProbeError("DISCOVERY_CONTRADICTION", "systemd ABI missing")
    if any(
        item["machine"] > 65535
        or item["elf_class"] != 64
        or item["endianness"] != "little"
        or item["machine"] != 62
        for item in binaries
    ):
        raise ProbeError("DISCOVERY_CONTRADICTION", "runner ABI")
    _require_canonical_unique(binaries, "ABI binaries")

    fields = by_surface["field_availability"]["fields"]
    if [item["name"] for item in fields] != sorted(item["name"] for item in fields):
        raise ProbeError("DISCOVERY_NONCANONICAL", "field names")
    if [(item["name"], item["path"]) for item in fields] != sorted(
        _DISCOVERY_FIELD_PATHS
    ):
        raise ProbeError("DISCOVERY_CONTRADICTION", "field identity")
    if len({item["name"] for item in fields}) != len(fields):
        raise ProbeError("DISCOVERY_CONTRADICTION", "duplicate field name")
    _require_canonical_unique(fields, "field availability")
    for item in fields:
        if item["available"] != (item["errno"] is None):
            raise ProbeError("DISCOVERY_CONTRADICTION", item["name"])
        if item["errno"] is not None and item["errno"] not in (
            DISCOVERY_FIELD_OPEN_ERRNOS.get(item["name"], frozenset())
        ):
            raise ProbeError("DISCOVERY_CONTRADICTION", f"{item['name']} errno")
    fields_by_name = {item["name"]: item for item in fields}
    for name in (
        "cgroup.controllers",
        "cgroup.events",
        "cgroup.kill",
        "cgroup.subtree_control",
        "etc.os-release",
        "kernel.core_pattern",
        "proc.cgroup",
        "proc.mountinfo",
        "proc.status",
    ):
        if not fields_by_name[name]["available"]:
            raise ProbeError("DISCOVERY_CONTRADICTION", f"{name} unavailable")
    controllers = set(by_surface["cgroup_topology"]["controllers"])
    for name, controller in DISCOVERY_CONTROLLER_GATED_FIELDS.items():
        if controller in controllers and not fields_by_name[name]["available"]:
            raise ProbeError(
                "DISCOVERY_CONTRADICTION",
                f"{name} unavailable with {controller} controller",
            )

    expected_witnesses = [
        {
            "id": identifier,
            "roles": list(DIFFERENTIAL_WITNESS_ROLES),
            "status": DISCOVERY_EC_STATUS,
            "proof_eligible": False,
        }
        for identifier in EQUIVALENCE_CLASS_IDENTIFIERS
    ]
    if evidence["future_witnesses"] != expected_witnesses:
        raise ProbeError("DISCOVERY_WITNESS_OVERCLAIM", "declarations changed")
    if evidence["mandatory_effect_blockers"] != mandatory_effect_blockers():
        raise ProbeError("DISCOVERY_BLOCKER_DRIFT", "mandatory blockers changed")
    if evidence["errors"]:
        raise ProbeError(
            "DISCOVERY_OBSERVATION_ERROR",
            "error-bearing discovery is non-accepting",
        )


def _unescape_mountinfo_field(field: str) -> str:
    """Decode the octal escapes (\\040 \\011 \\012 \\134) the kernel uses for
    space, tab, newline and backslash in mountinfo path/option fields."""
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), field)


def parse_mountinfo(text: str) -> List[Dict[str, Any]]:
    """Parse /proc/<pid>/mountinfo into per-mount records, failing closed on any
    structurally malformed line. Field 5 (0-based) is the mount point and field 6
    the per-mount option list -- the options the kernel enforces at execve time."""
    entries: List[Dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split(" ")
        if "-" not in fields:
            raise ProbeError("MOUNTINFO_MALFORMED", line[:200])
        separator = fields.index("-")
        if separator < 6 or len(fields) < separator + 3:
            raise ProbeError("MOUNTINFO_MALFORMED", line[:200])
        entries.append(
            {
                "mount_id": fields[0],
                "mount_point": _unescape_mountinfo_field(fields[4]),
                "options": tuple(fields[5].split(",")),
                "fs_type": fields[separator + 1],
            }
        )
    return entries


def mount_options_for_target(
    entries: Sequence[Mapping[str, Any]], target: str
) -> Optional[set]:
    """The effective per-mount options for ``target`` -- the last (topmost) mount
    stacked at exactly that mount point -- or ``None`` when nothing is mounted
    there. Nearest-longest-prefix parents never satisfy an exact-point control."""
    matches = [entry for entry in entries if entry["mount_point"] == target]
    if not matches:
        return None
    return set(matches[-1]["options"])


def evaluate_noexec_mounts(
    mountinfo_text: str,
    targets: Sequence[str] = NOEXEC_MOUNT_TARGETS,
    required: Sequence[str] = REQUIRED_MOUNT_FLAGS,
) -> Dict[str, Dict[str, Any]]:
    """Per-target hardening evaluation from mountinfo. A target with no mount, or
    one missing any required flag, is not hardened."""
    entries = parse_mountinfo(mountinfo_text)
    result: Dict[str, Dict[str, Any]] = {}
    for target in targets:
        options = mount_options_for_target(entries, target)
        if options is None:
            result[target] = {"present": False, "hardened": False, "options": []}
        else:
            result[target] = {
                "present": True,
                "hardened": all(flag in options for flag in required),
                "options": sorted(options),
            }
    return result


def mountinfo_noexec_enforced(
    mountinfo_text: str,
    targets: Sequence[str] = NOEXEC_MOUNT_TARGETS,
    required: Sequence[str] = REQUIRED_MOUNT_FLAGS,
) -> bool:
    """True only when every target mount is present and carries every required
    flag. Any parse failure or missing flag fails closed to False."""
    try:
        evaluation = evaluate_noexec_mounts(mountinfo_text, targets, required)
    except ProbeError:
        return False
    return bool(evaluation) and all(item["hardened"] for item in evaluation.values())


def classify_execve_witness(outcome: Mapping[str, Any]) -> str:
    """Map one trusted execve attempt to exactly one closed classification. A
    child that exec'd is EXECUTED (whatever its later exit code); an OS error is
    classified by errno so that only EACCES is a candidate noexec denial, ENOEXEC
    is a wrong format, ENOENT/ELIBBAD a missing loader, EPERM a permission
    problem; a signal, timeout or anything else is non-crediting."""
    kind = outcome.get("kind")
    if kind == "executed":
        return EXECVE_EXECUTED
    if kind == "signal":
        return EXECVE_TERMINATED_BY_SIGNAL
    if kind == "timeout":
        return EXECVE_TIMED_OUT
    if kind == "oserror":
        code = outcome.get("errno")
        if code == errno.EACCES:
            return EXECVE_NOEXEC_DENIED
        if code == errno.ENOEXEC:
            return EXECVE_WRONG_FORMAT
        if code in MISSING_LOADER_ERRNOS:
            return EXECVE_MISSING_LOADER
        if code == errno.EPERM:
            return EXECVE_PERMISSION_DENIED
        return EXECVE_OTHER_ERROR
    return EXECVE_AMBIGUOUS


def validate_witness_elf_fd(fd: int, path: str) -> Tuple[str, int]:
    """Provenance-validate an already-opened (O_NOFOLLOW) witness candidate: a
    regular, root-owned, non-group/other-writable, executable, bounded-size file
    whose bytes begin with the ELF magic. Returns (sha256, size) over the exact
    bytes read through this descriptor, so the digest binds the opened identity to
    the bytes that will be staged."""
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise ProbeError("NOEXEC_WITNESS_NOT_REGULAR", path)
    if info.st_uid != 0:
        raise ProbeError("NOEXEC_WITNESS_NOT_ROOT_OWNED", f"{path}:uid={info.st_uid}")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ProbeError("NOEXEC_WITNESS_WRITABLE", f"{path}:{oct(info.st_mode)}")
    if not info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        raise ProbeError("NOEXEC_WITNESS_NOT_EXECUTABLE", f"{path}:{oct(info.st_mode)}")
    if not NOEXEC_WITNESS_MIN_ELF_BYTES <= info.st_size <= NOEXEC_WITNESS_MAX_ELF_BYTES:
        raise ProbeError("NOEXEC_WITNESS_SIZE_OUT_OF_BOUNDS", f"{path}:{info.st_size}")
    os.lseek(fd, 0, os.SEEK_SET)
    data = b""
    while len(data) <= info.st_size:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        data += chunk
        if len(data) > NOEXEC_WITNESS_MAX_ELF_BYTES:
            raise ProbeError("NOEXEC_WITNESS_SIZE_OUT_OF_BOUNDS", f"{path}:overrun")
    if len(data) != info.st_size:
        raise ProbeError("NOEXEC_WITNESS_SIZE_UNSTABLE", f"{path}:{len(data)}!={info.st_size}")
    if data[: len(ELF_MAGIC)] != ELF_MAGIC:
        raise ProbeError("NOEXEC_WITNESS_NOT_ELF", f"{path}:{data[:4].hex()}")
    return sha256_bytes(data), info.st_size


def _require_o_nofollow() -> int:
    """Return ``os.O_NOFOLLOW`` or fail closed. A trusted read must never silently
    follow a symlink by falling back to flag 0, so a platform without O_NOFOLLOW is
    treated as unsupported rather than opening the door to symlink substitution."""
    flag = getattr(os, "O_NOFOLLOW", 0)
    if not flag:
        raise ProbeError("O_NOFOLLOW_UNSUPPORTED", "O_NOFOLLOW unavailable")
    return flag


def select_noexec_witness_elf(
    candidates: Sequence[str] = NOEXEC_WITNESS_ELF_CANDIDATES,
) -> Dict[str, Any]:
    """Provenance-validate the fixed candidate host executables in order, returning
    the first that passes as a digest-bound witness descriptor. Fails closed if
    none qualify.

    Symlink candidates are rejected fail-closed: provenance binds to a fixed,
    non-substitutable path, so a candidate that is itself a symlink -- even one
    pointing at an otherwise valid, root-owned ELF -- is never accepted, and the
    final open uses O_NOFOLLOW (required, never a flag-0 fallback) to defeat a
    TOCTOU final-component swap between the lstat and the open."""
    nofollow = _require_o_nofollow()
    cloexec = getattr(os, "O_CLOEXEC", 0)
    rejections: List[str] = []
    for candidate in candidates:
        try:
            link_stat = os.lstat(candidate)
        except OSError as exc:
            rejections.append(f"{candidate}:lstat:{exc.errno}")
            continue
        if stat.S_ISLNK(link_stat.st_mode):
            rejections.append(f"{candidate}:symlink")
            continue
        try:
            fd = os.open(candidate, os.O_RDONLY | nofollow | cloexec)
        except OSError as exc:
            # ELOOP here means the final component became a symlink after the
            # lstat -- a substitution attempt -- and O_NOFOLLOW refused it.
            rejections.append(f"{candidate}:{exc.errno}")
            continue
        try:
            digest, size = validate_witness_elf_fd(fd, candidate)
        except ProbeError as exc:
            rejections.append(f"{candidate}:{exc.code}")
            os.close(fd)
            continue
        return {
            "requested_path": candidate,
            "resolved_path": candidate,
            "fd": fd,
            "sha256": digest,
            "size": size,
        }
    raise ProbeError("NOEXEC_WITNESS_UNAVAILABLE", ";".join(rejections)[:400])


def verify_noexec_witness(record: Mapping[str, Any]) -> None:
    """Fail closed unless a noexec witness record proves, from trusted
    observations only, that a valid ELF which executes from the control location
    is denied by the noexec mount and nowhere else:

      * the source is a provenance-bound ELF bound by digest and bounded size;
      * the positive control executed the byte-identical bytes (removing the
        ENOEXEC/format ambiguity that made an invalid file useless);
      * the noexec attempt staged the byte-identical bytes and was classified
        exactly ``noexec_denied`` (EACCES);
      * the mount those bytes were staged into independently shows ``noexec`` in
        its per-mount options, isolating the denial from an unrelated EACCES.
    """
    source = record.get("source")
    if not isinstance(source, Mapping):
        raise ProbeError("NOEXEC_WITNESS_INVALID", "missing source")
    digest = source.get("sha256")
    if not isinstance(digest, str) or not SHA64_RE.fullmatch(digest):
        raise ProbeError("NOEXEC_WITNESS_INVALID", "source digest invalid")
    if not isinstance(source.get("size"), int) or isinstance(source.get("size"), bool):
        raise ProbeError("NOEXEC_WITNESS_INVALID", "source size invalid")
    if not NOEXEC_WITNESS_MIN_ELF_BYTES <= source["size"] <= NOEXEC_WITNESS_MAX_ELF_BYTES:
        raise ProbeError("NOEXEC_WITNESS_INVALID", "source size out of bounds")
    if not source.get("elf_magic") is True:
        raise ProbeError("NOEXEC_WITNESS_INVALID", "source ELF magic not confirmed")

    control = record.get("positive_control")
    if not isinstance(control, Mapping):
        raise ProbeError("NOEXEC_WITNESS_INVALID", "missing positive control")
    if control.get("staged_sha256") != digest:
        raise ProbeError("NOEXEC_WITNESS_CONTROL_DIGEST_MISMATCH", "control bytes differ")
    if control.get("classification") != EXECVE_EXECUTED:
        raise ProbeError(
            "NOEXEC_WITNESS_CONTROL_NOT_EXECUTABLE",
            str(control.get("classification")),
        )

    attempt = record.get("noexec_attempt")
    if not isinstance(attempt, Mapping):
        raise ProbeError("NOEXEC_WITNESS_INVALID", "missing noexec attempt")
    if attempt.get("staged_sha256") != digest:
        raise ProbeError("NOEXEC_WITNESS_ATTEMPT_DIGEST_MISMATCH", "staged bytes differ")
    if attempt.get("readback_sha256") != digest:
        raise ProbeError("NOEXEC_WITNESS_READBACK_MISMATCH", "readback bytes differ")
    options = attempt.get("mount_options")
    if not isinstance(options, (list, tuple)) or "noexec" not in options:
        raise ProbeError(
            "NOEXEC_WITNESS_MOUNT_NOT_NOEXEC", str(options)
        )
    if attempt.get("classification") != EXECVE_NOEXEC_DENIED:
        raise ProbeError(
            "NOEXEC_WITNESS_NOT_DENIED", str(attempt.get("classification"))
        )


def _status_dedicated_uid_effective(status: Any) -> bool:
    """DynamicUser effect: /proc/<pid>/status shows a single consistent non-root
    uid and gid across all four fields and no supplementary groups."""
    if not isinstance(status, Mapping):
        return False
    uid_values = str(status.get("Uid", "")).split()
    gid_values = str(status.get("Gid", "")).split()
    if (
        len(uid_values) != 4
        or len(set(uid_values)) != 1
        or uid_values[0] in {"", "0"}
        or len(gid_values) != 4
        or len(set(gid_values)) != 1
        or gid_values[0] in {"", "0"}
    ):
        return False
    supplementary = str(status.get("Groups", "")).split()
    return all(value == gid_values[0] for value in supplementary)


def _status_capability_bounding_empty(status: Any) -> bool:
    """CapabilityBoundingSet/AmbientCapabilities effect: every capability mask the
    kernel reports for the child is exactly zero."""
    if not isinstance(status, Mapping):
        return False
    for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        raw = status.get(field)
        if not isinstance(raw, str):
            return False
        try:
            if int(raw, 16) != 0:
                return False
        except ValueError:
            return False
    return True


def _namespaces_private(namespaces: Any, supervisor_namespaces: Any) -> bool:
    """PrivateMounts/PrivateNetwork/PrivateIPC effect: the child's mnt/net/ipc
    namespace identifiers all differ from the supervisor's."""
    if not isinstance(namespaces, Mapping) or not isinstance(supervisor_namespaces, Mapping):
        return False
    for name in ("mnt", "net", "ipc"):
        child = namespaces.get(name)
        parent = supervisor_namespaces.get(name)
        if not child or not parent or child == parent:
            return False
    return True


def _limits_effective(limits_text: Any) -> bool:
    """LimitNOFILE/LimitFSIZE/LimitCORE effect: /proc/<pid>/limits reports exactly
    the requested soft ceilings."""
    if not isinstance(limits_text, str):
        return False
    required = {
        "Max open files": "128",
        "Max file size": "8388608",
        "Max core file size": "0",
    }
    for name, expected_soft in required.items():
        matching = [line for line in limits_text.splitlines() if line.startswith(name)]
        if len(matching) != 1:
            return False
        fields = matching[0][len(name):].split()
        if not fields or fields[0] != expected_soft:
            return False
    return True


# --- F7-A: additional direct-state effect predicates ----------------------
#
# Each predicate below moves a property out of the effect_unproven blocker set by
# deriving its exact runtime effect from an observation the root supervisor
# already takes inside the reviewed TCB (procfs status/cwd/namespaces or the
# already-bound cgroup interface files). Every predicate is typed, deterministic,
# fails closed on a missing/duplicate/malformed/wrong value, and never rests on
# manager equality or a child-authored statement.


def parse_status_field(status_text: Any, field: str) -> Optional[str]:
    """The single stripped value for ``field`` in raw /proc/<pid>/status text, or
    None if the field is missing OR appears more than once. A duplicate key is an
    ambiguity/tampering signal and is never silently collapsed to a last-wins
    value."""
    if not isinstance(status_text, str):
        return None
    prefix = field + ":"
    matches = [
        line[len(prefix):].strip()
        for line in status_text.splitlines()
        if line.startswith(prefix)
    ]
    if len(matches) != 1:
        return None
    return matches[0]


def status_umask_is_0077(status_text: Any) -> bool:
    """UMask=0077 effect: /proc/<pid>/status carries exactly one Umask field whose
    octal value is 0o077. A missing, duplicate, or non-octal value fails closed."""
    value = parse_status_field(status_text, "Umask")
    if value is None or not re.fullmatch(r"[0-7]{1,4}", value):
        return False
    return int(value, 8) == 0o077


def working_directory_identity_effective(record: Any) -> bool:
    """WorkingDirectory effect: the child's /proc/<pid>/cwd resolves -- by exact
    path string and by device/inode identity -- to the trusted exec directory. A
    string prefix is never accepted; any missing or wrongly typed field, or a
    device/inode/path mismatch, fails closed."""
    if not isinstance(record, Mapping):
        return False
    for field in ("cwd_device", "cwd_inode", "exec_dir_device", "exec_dir_inode"):
        if not isinstance(record.get(field), int) or isinstance(record.get(field), bool):
            return False
    if not isinstance(record.get("cwd_path"), str) or not isinstance(
        record.get("exec_dir_path"), str
    ):
        return False
    return (
        record["cwd_path"] == record["exec_dir_path"]
        and record["cwd_device"] == record["exec_dir_device"]
        and record["cwd_inode"] == record["exec_dir_inode"]
    )


def uts_namespace_private(namespaces: Any, supervisor_namespaces: Any) -> bool:
    """ProtectHostname effect: the child's UTS namespace identity differs from the
    supervisor's. systemd creates a private UTS namespace for ProtectHostname=yes,
    and no other requested property creates one, so a distinct UTS namespace is a
    trusted, non-overlapping positive predicate for this property."""
    if not isinstance(namespaces, Mapping) or not isinstance(
        supervisor_namespaces, Mapping
    ):
        return False
    child = namespaces.get("uts")
    parent = supervisor_namespaces.get("uts")
    return bool(child) and bool(parent) and child != parent


def _cgroup_scalar(limits: Any, name: str) -> Optional[str]:
    """The single stripped token of the named cgroup interface file recorded in a
    ``cgroup.limits`` map, or None if absent, wrongly typed, empty, or multi-token
    (a multi-token or missing controller field fails closed, never a permissive
    default)."""
    if not isinstance(limits, Mapping):
        return None
    value = limits.get(name)
    if not isinstance(value, str):
        return None
    tokens = value.split()
    if len(tokens) != 1:
        return None
    return tokens[0]


def parse_cpu_max(value: Any) -> Optional[Tuple[int, int]]:
    """Parse a cgroup ``cpu.max`` value "QUOTA PERIOD" into (quota_us, period_us).
    Returns None for the unlimited form ("max ..."), a missing/extra field, a
    non-integer field, or a non-positive period."""
    if not isinstance(value, str):
        return None
    tokens = value.split()
    if len(tokens) != 2:
        return None
    quota_token, period_token = tokens
    if quota_token == "max":
        return None
    if not re.fullmatch(r"[0-9]+", quota_token) or not re.fullmatch(r"[0-9]+", period_token):
        return None
    period = int(period_token)
    if period <= 0:
        return None
    return int(quota_token), period


def cpu_quota_is_full_single_cpu(value: Any) -> bool:
    """CPUQuota=100% effect: cpu.max is a finite quota exactly equal to its period
    (100% of one CPU). The unlimited form or any other ratio fails closed."""
    parsed = parse_cpu_max(value)
    if parsed is None:
        return False
    quota, period = parsed
    return quota == period


def derive_cgroup_limit_controls(limits: Any) -> Dict[str, bool]:
    """The exact per-property cgroup-limit effect predicates, each from one
    distinct kernel interface file in the already-bound cgroup directory. Grouped
    only for extraction; each property maps to its own effective-control record."""
    return {
        "tasks_max_effective": _cgroup_scalar(limits, "pids.max") == "64",
        "memory_max_effective": _cgroup_scalar(limits, "memory.max") == "268435456",
        "memory_swap_max_effective": _cgroup_scalar(limits, "memory.swap.max") == "0",
        "memory_oom_group_effective": _cgroup_scalar(limits, "memory.oom.group") == "1",
        "cpu_quota_effective": cpu_quota_is_full_single_cpu(
            limits.get("cpu.max") if isinstance(limits, Mapping) else None
        ),
    }


def _first_observation_value(
    observations: Sequence[Mapping[str, Any]], name: str, authority: str
) -> Any:
    """The value of the unique kernel-authored observation ``name`` among
    ``observations`` with the exact authority, or ``None`` if absent/duplicated/
    wrong-authority so the derived effect fails closed."""
    matches = [
        item
        for item in observations
        if item.get("name") == name and item.get("authority") == authority
    ]
    if len(matches) != 1:
        return None
    return matches[0].get("value")


def derive_bootstrap_effect_controls(case: Mapping[str, Any]) -> Dict[str, bool]:
    """Recompute the 14 per-case effect predicates from the case's own trusted,
    kernel-authored bootstrap observations. Every predicate is independently
    interpretable from the retained raw observations and fails closed to False if
    the backing observation is missing, duplicated, wrong-authority or malformed.
    """
    observations = case.get("observations", [])
    status = _first_observation_value(observations, "bootstrap.status", "kernel_observed")
    status_raw = _first_observation_value(observations, "bootstrap.status_raw", "kernel_observed")
    mountinfo = _first_observation_value(observations, "bootstrap.mountinfo", "kernel_observed")
    namespaces = _first_observation_value(observations, "bootstrap.namespaces", "kernel_observed")
    supervisor_namespaces = _first_observation_value(
        observations, "bootstrap.supervisor_namespaces", "kernel_observed"
    )
    limits = _first_observation_value(observations, "bootstrap.limits", "kernel_observed")
    working_directory = _first_observation_value(
        observations, "bootstrap.working_directory", "kernel_observed"
    )
    cgroup_limits = _first_observation_value(
        observations, "cgroup.limits", "kernel_observed"
    )
    effects = {
        "dedicated_uid_effective": _status_dedicated_uid_effective(status),
        "no_new_privileges_effective": isinstance(status, Mapping)
        and status.get("NoNewPrivs") == "1",
        "capability_bounding_empty": _status_capability_bounding_empty(status),
        "private_namespaces_effective": _namespaces_private(
            namespaces, supervisor_namespaces
        ),
        "private_tmp_noexec_enforced": isinstance(mountinfo, str)
        and mountinfo_noexec_enforced(mountinfo),
        "resource_limits_effective": _limits_effective(limits),
        "umask_effective": status_umask_is_0077(status_raw),
        "working_directory_effective": working_directory_identity_effective(
            working_directory
        ),
        "private_uts_namespace_effective": uts_namespace_private(
            namespaces, supervisor_namespaces
        ),
    }
    effects.update(derive_cgroup_limit_controls(cgroup_limits))
    return effects


def verify_stream_document(doc: Mapping[str, Any], label: str) -> bytes:
    """Cross-bind one child stream document and return its decoded retained bytes.

    Enforces strict base64 decoding, a retained length equal to
    ``retained_byte_count`` that never exceeds the total ``byte_count``, a
    ``truncated`` flag exactly consistent with retained-versus-total bytes, and,
    for a fully retained stream, a SHA-256 taken over the decoded bytes. A
    reviewer-owned GATE1_* token in the decoded child bytes fails closed."""
    byte_count = _nonneg_int(doc, "byte_count", label)
    retained_byte_count = _nonneg_int(doc, "retained_byte_count", label)
    if not isinstance(doc.get("truncated"), bool):
        raise ProbeError("SCHEMA_INVALID", f"{label}: truncated is not boolean")
    try:
        raw = base64.b64decode(doc["retained_base64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise ProbeError("SCHEMA_INVALID", f"{label}: retained base64 invalid") from exc
    if len(raw) != retained_byte_count:
        raise ProbeError("SCHEMA_INVALID", f"{label}: retained length mismatch")
    if retained_byte_count > byte_count:
        raise ProbeError("SCHEMA_INVALID", f"{label}: retained exceeds total")
    if doc["truncated"] != (retained_byte_count < byte_count):
        raise ProbeError("SCHEMA_INVALID", f"{label}: truncated flag inconsistent")
    if not doc["truncated"] and doc.get("sha256") != sha256_bytes(raw):
        raise ProbeError("SCHEMA_INVALID", f"{label}: full-stream hash mismatch")
    if GATE1_NAMESPACE_TOKEN.encode("ascii") in raw:
        raise ProbeError("GATE1_NAMESPACE_VIOLATION", f"{label}: decoded child output")
    return raw


def _require_case_observation(case: Mapping[str, Any], name: str, authority: str) -> Any:
    """Return the unique observation ``name`` on ``case`` with the exact authority,
    failing closed unless exactly one such observation exists."""
    matches = [item for item in case["observations"] if item["name"] == name]
    if len(matches) != 1:
        raise ProbeError("SCHEMA_INVALID", f"{case['id']}: exactly one {name} required")
    if matches[0]["authority"] != authority:
        raise ProbeError("SCHEMA_INVALID", f"{case['id']}: {name} authority invalid")
    return matches[0]["value"]


def _decode_raw_kernel_records(items: Any, label: str) -> List[bytes]:
    """Strictly decode a kernel-observed base64 array into NUL-free byte records."""
    if not isinstance(items, list):
        raise ProbeError("SCHEMA_INVALID", f"{label}: raw base64 is not an array")
    decoded: List[bytes] = []
    for item in items:
        if not isinstance(item, str):
            raise ProbeError("SCHEMA_INVALID", f"{label}: raw base64 item is not a string")
        try:
            raw = base64.b64decode(item, validate=True)
        except (ValueError, TypeError) as exc:
            raise ProbeError("SCHEMA_INVALID", f"{label}: raw base64 invalid") from exc
        if b"\x00" in raw:
            raise ProbeError("SCHEMA_INVALID", f"{label}: embedded NUL in kernel record")
        decoded.append(raw)
    return decoded


def verify_argv_environment_binding(case: Mapping[str, Any]) -> None:
    """Rebind a case's structured kernel-observed argv/environment to the exact raw
    kernel-observed byte encodings and to the requested values. Structured equality
    may support success only when every raw encoding decodes and binds."""
    label = case["id"]
    raw_argv = _decode_raw_kernel_records(
        _require_case_observation(case, "bootstrap.argv_raw_base64", "kernel_observed"),
        f"{label} argv",
    )
    try:
        decoded_argv = [item.decode("utf-8") for item in raw_argv]
    except UnicodeDecodeError as exc:
        raise ProbeError("SCHEMA_INVALID", f"{label}: argv raw bytes are not utf-8") from exc
    if decoded_argv != case["kernel_observed_argv"]:
        raise ProbeError("SCHEMA_INVALID", f"{label}: argv raw/structured mismatch")
    if case["requested_argv"] != case["kernel_observed_argv"]:
        raise ProbeError("SCHEMA_INVALID", f"{label}: argv requested/observed mismatch")
    raw_environment = _decode_raw_kernel_records(
        _require_case_observation(
            case, "bootstrap.environment_raw_base64", "kernel_observed"
        ),
        f"{label} environment",
    )
    reconstructed = validate_observed_environment(
        raw_environment, case["requested_environment"]
    )
    if reconstructed != case["kernel_observed_environment"]:
        raise ProbeError("SCHEMA_INVALID", f"{label}: environment raw/structured mismatch")


def _scan_gate1_namespace(value: Any, path: str) -> None:
    """Recursively reject reviewer-owned GATE1_* tokens in candidate content."""
    if isinstance(value, str):
        if GATE1_NAMESPACE_TOKEN in value:
            raise ProbeError("GATE1_NAMESPACE_VIOLATION", path)
    elif isinstance(value, Mapping):
        for key, sub in value.items():
            if isinstance(key, str) and GATE1_NAMESPACE_TOKEN in key:
                raise ProbeError("GATE1_NAMESPACE_VIOLATION", f"{path}.{key} (key)")
            _scan_gate1_namespace(sub, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, sub in enumerate(value):
            _scan_gate1_namespace(sub, f"{path}[{index}]")


def reject_gate1_namespace(evidence: Mapping[str, Any]) -> None:
    """Fail closed on authoritative-looking GATE1_* tokens anywhere in
    candidate-controlled content -- strings, mapping keys, list items, error
    fields, observation values, argv, and environment. The one narrow exemption is
    the single fixed candidate notice whose value is exactly CANDIDATE_NOTICE; the
    same text anywhere else is rejected, so the exemption cannot be reused to
    smuggle a decision token."""
    for key, value in evidence.items():
        if isinstance(key, str) and GATE1_NAMESPACE_TOKEN in key:
            raise ProbeError("GATE1_NAMESPACE_VIOLATION", f"top-level key {key}")
        if key == "candidate_notice" and value == CANDIDATE_NOTICE:
            continue
        _scan_gate1_namespace(value, str(key))


def validate_evidence(evidence: Mapping[str, Any], schema_path: Path) -> None:
    if evidence.get("evidence_kind") == DISCOVERY_EVIDENCE_KIND:
        raise ProbeError(
            "CANDIDATE_KIND_MISMATCH",
            "discovery evidence supplied to candidate validator",
        )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validate_schema_instance(evidence, schema, schema)
    events = [item["monotonic_ns"] for item in evidence["lifecycle"]]
    if events != sorted(events):
        raise ProbeError("SCHEMA_INVALID", "lifecycle is not monotonic")
    for collection_name in ("identity", "source", "host"):
        names = [item["name"] for item in evidence[collection_name]]
        if len(names) != len(set(names)):
            raise ProbeError("SCHEMA_INVALID", f"{collection_name}: duplicate observation")
    validate_coredump_evidence(evidence)
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
    reject_gate1_namespace(evidence)
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
            verify_stream_document(case["stdout"], f"{case['id']} stdout")
            verify_stream_document(case["stderr"], f"{case['id']} stderr")
            verify_argv_environment_binding(case)
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
            if case["id"] == "invalid-output":
                # Independently recompute the hostile-output contract from this
                # case's own untrusted stream documents and require the embedded
                # supervisor proof to match it exactly.
                proof = _require_supervisor_observation(
                    case, "case.invalid_output_contract"
                )
                if proof != verify_invalid_output_contract(
                    case["stdout"], case["stderr"]
                ):
                    raise ProbeError(
                        "SCHEMA_INVALID",
                        "invalid-output: contract observation mismatch",
                    )
            if case["id"] == "output-flood":
                # Recompute the bounded-overrun accounting from this case's own
                # stream byte counts; OUTPUT_LIMIT stands only if the trigger
                # crossed and the final combined bytes are within the hard bound.
                verify_output_accounting(
                    _require_supervisor_observation(case, "case.output_accounting"),
                    case["stdout"],
                    case["stderr"],
                )
        verify_effective_controls(
            controls["effective_observed"],
            success_effective_control_authorities(CASES),
            "SUCCESS",
        )
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
            or cancelled_case["outcome"]
            != EXPECTED_CASE_OUTCOMES[cancelled_case["id"]]
            or not all(
                (
                    cancelled_cleanup["direct_cgroup_kill_written"],
                    cancelled_cleanup["recursive_populated_zero_observed"],
                    cancelled_cleanup["streams_eof_after_empty"],
                    cancelled_cleanup["unit_unloaded_after_empty"],
                )
            )
        ):
            raise ProbeError("SCHEMA_INVALID", "cancellation witness incomplete")
        verify_stream_document(cancelled_case["stdout"], "operator-cancel stdout")
        verify_stream_document(cancelled_case["stderr"], "operator-cancel stderr")
        verify_argv_environment_binding(cancelled_case)
        verify_effective_controls(
            controls["effective_observed"],
            cancellation_effective_control_authorities(),
            "ACTIONS_CANCELLED",
        )
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


def atomic_seal_discovery(
    path: Path,
    evidence: Mapping[str, Any],
    schema_path: Path,
    source_path: Path,
    uid: int,
    gid: int,
) -> str:
    """Seal discovery evidence through its separate validator and manifest."""
    validate_discovery_evidence(
        evidence,
        schema_path,
        source_path=source_path,
        expected_identity=evidence["identity"],
        expected_replay_binding=discovery_replay_binding(evidence),
    )
    payload = canonical_json_bytes(evidence)
    if len(payload) > DISCOVERY_MAX_TOTAL_BYTES + DISCOVERY_MAX_RECORD_BYTES:
        raise ProbeError("DISCOVERY_DOCUMENT_OVERSIZED", str(len(payload)))
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    digest = sha256_bytes(payload)
    manifest = {
        "manifest_version": "1.0.0",
        "evidence_kind": DISCOVERY_EVIDENCE_KIND,
        "evidence_file": path.name,
        "evidence_sha256": digest,
        "replay_binding_sha256": discovery_replay_binding(evidence),
        "identity": evidence["identity"],
        "source": evidence["source"],
        "proof_eligible": False,
    }
    write_atomic_owned(path, payload, uid, gid)
    write_atomic_owned(
        path.with_suffix(path.suffix + ".manifest.json"),
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


def _kill_and_reap(process: subprocess.Popen[bytes]) -> None:
    """Best-effort termination that never leaves a bounded-capture child alive."""
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5.0)
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            stream.close()


def run_bounded_command(
    argv: Sequence[str],
    *,
    stdout_limit: int,
    stderr_limit: int = COREDUMP_COMMAND_STDERR_MAX_BYTES,
    timeout: float = 20.0,
) -> subprocess.CompletedProcess[bytes]:
    """Capture a trusted host command incrementally with hard byte/time bounds.

    On overflow, timeout, or read failure the child is killed and reaped and no
    partial output is returned as evidence.
    """
    if stdout_limit < 0 or stderr_limit < 0 or timeout <= 0:
        raise ProbeError("HOST_COMMAND_BOUND_INVALID", repr((stdout_limit, stderr_limit, timeout)))
    try:
        process = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise ProbeError("HOST_COMMAND_START_FAILED", repr(exc)) from exc
    if process.stdout is None or process.stderr is None:
        _kill_and_reap(process)
        raise ProbeError("HOST_COMMAND_CAPTURE_FAILED", str(argv[0]))
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": stdout_limit, "stderr": stderr_limit}
    streams = {"stdout": process.stdout, "stderr": process.stderr}
    try:
        for name, stream in streams.items():
            os.set_blocking(stream.fileno(), False)
            selector.register(stream.fileno(), selectors.EVENT_READ, name)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeError("HOST_COMMAND_TIMEOUT", str(argv[0]))
            for key, _ in selector.select(min(0.1, remaining)):
                name = str(key.data)
                try:
                    chunk = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                except OSError as exc:
                    raise ProbeError("HOST_COMMAND_CAPTURE_FAILED", repr(exc)) from exc
                if not chunk:
                    selector.unregister(key.fd)
                    streams[name].close()
                    continue
                if len(buffers[name]) + len(chunk) > limits[name]:
                    raise ProbeError(
                        "HOST_COMMAND_OUTPUT_TOO_LARGE",
                        f"{argv[0]}:{name}:{len(buffers[name]) + len(chunk)}>{limits[name]}",
                    )
                buffers[name].extend(chunk)
        remaining = max(0.001, deadline - time.monotonic())
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise ProbeError("HOST_COMMAND_TIMEOUT", str(argv[0])) from exc
        return subprocess.CompletedProcess(
            args=list(argv),
            returncode=returncode,
            stdout=bytes(buffers["stdout"]),
            stderr=bytes(buffers["stderr"]),
        )
    except BaseException:
        _kill_and_reap(process)
        raise
    finally:
        selector.close()


def read_bytes(path: Path, limit: int = 1024 * 1024) -> bytes:
    if limit < 0:
        raise ValueError("limit must be non-negative")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        chunks: List[bytes] = []
        retained = 0
        while retained <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - retained))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            retained += len(chunk)
            if retained > limit:
                raise ProbeError("HOST_OBSERVATION_TOO_LARGE", str(path))
        raise ProbeError("HOST_OBSERVATION_TOO_LARGE", str(path))
    finally:
        os.close(fd)


def read_text(path: Path, limit: int = 1024 * 1024) -> str:
    data = read_bytes(path, limit)
    return data.decode("utf-8", "replace")


_MOUNTINFO_PATH_ESCAPES = {
    r"\040": " ",
    r"\011": "\t",
    r"\012": "\n",
    r"\134": "\\",
}
_MOUNTINFO_SOURCE_ESCAPES = {
    **_MOUNTINFO_PATH_ESCAPES,
    r"\043": "#",
}
_MOUNTINFO_MANGLED_ESCAPES = _MOUNTINFO_SOURCE_ESCAPES


def _decode_discovery_mountinfo_field(
    value: str, label: str, *, mount_source: bool = False
) -> str:
    """Decode the field-specific escapes emitted by Linux mountinfo.

    Root and mount-point paths use the four path escapes.  The device/source
    field is rendered through ``mangle()`` and additionally escapes ``#`` as
    ``\\043``.  Literal whitespace, controls, NULs, and non-kernel backslash
    forms are impossible in a single source token and therefore non-accepting.
    """
    if not value or any(character.isspace() for character in value):
        raise ProbeError("DISCOVERY_MOUNTINFO_MALFORMED", label)
    escapes = (
        _MOUNTINFO_SOURCE_ESCAPES
        if mount_source
        else _MOUNTINFO_PATH_ESCAPES
    )
    result: List[str] = []
    index = 0
    while index < len(value):
        if value[index] != "\\":
            if value[index] == "\x00" or ord(value[index]) < 0x20:
                raise ProbeError("DISCOVERY_MOUNTINFO_MALFORMED", label)
            result.append(value[index])
            index += 1
            continue
        escape = value[index : index + 4]
        if escape not in escapes:
            raise ProbeError("DISCOVERY_MOUNTINFO_MALFORMED", label)
        result.append(escapes[escape])
        index += 4
    return "".join(result)


def _require_canonical_discovery_mangled_field(
    value: str, label: str
) -> None:
    """Require the exact raw token language emitted by Linux ``mangle()``.

    The transformed ``fs_type`` field intentionally retains this canonical raw
    representation.  The five escaped characters may only appear as their
    canonical octal sequences; in particular a literal ``#`` or an unknown
    backslash form cannot be producer output.
    """
    if not value or any(character.isspace() for character in value):
        raise ProbeError("DISCOVERY_MOUNTINFO_MALFORMED", label)
    index = 0
    while index < len(value):
        character = value[index]
        if character == "\\":
            if value[index : index + 4] not in _MOUNTINFO_MANGLED_ESCAPES:
                raise ProbeError("DISCOVERY_MOUNTINFO_MALFORMED", label)
            index += 4
            continue
        if character == "#" or character == "\x00" or ord(character) < 0x20:
            raise ProbeError("DISCOVERY_MOUNTINFO_MALFORMED", label)
        index += 1


def _require_discovery_mount_token(
    value: str, label: str, *, comma_forbidden: bool = False
) -> None:
    if (
        not value
        or any(character.isspace() or ord(character) < 0x20 for character in value)
        or "\x00" in value
        or (comma_forbidden and "," in value)
    ):
        raise ProbeError("DISCOVERY_MOUNTINFO_MALFORMED", label)


def _validate_discovery_mount_optional_fields(fields: Sequence[str]) -> None:
    known_order = {
        "shared": 0,
        "master": 1,
        "propagate_from": 2,
        "unbindable": 3,
    }
    seen: set[str] = set()
    known_values: Dict[str, int] = {}
    previous = -1
    for index, token in enumerate(fields):
        _require_discovery_mount_token(token, f"optional field {index}")
        name, separator, value = token.partition(":")
        if name not in known_order:
            continue
        if name in seen or known_order[name] < previous:
            raise ProbeError(
                "DISCOVERY_MOUNTINFO_MALFORMED", "optional field order"
            )
        seen.add(name)
        previous = known_order[name]
        if name == "unbindable":
            if separator or value:
                raise ProbeError(
                    "DISCOVERY_MOUNTINFO_MALFORMED", "unbindable field"
                )
        elif (
            separator != ":"
            or DISCOVERY_POSITIVE_DECIMAL_PATTERN.fullmatch(value) is None
        ):
            raise ProbeError(
                "DISCOVERY_MOUNTINFO_MALFORMED", f"{name} field"
            )
        else:
            known_values[name] = _parse_discovery_decimal(
                value, DISCOVERY_MOUNT_ID_MAX, f"{name} mount id"
            )
    if "propagate_from" in known_values and (
        "master" not in known_values
        or known_values["propagate_from"] == known_values["master"]
    ):
        raise ProbeError(
            "DISCOVERY_MOUNTINFO_MALFORMED",
            "propagate_from dependency",
        )


def _require_discovery_mount_options(options: Sequence[str]) -> None:
    if (
        not options
        or options[0] not in {"ro", "rw"}
        or tuple(options[1:])
        != tuple(
            item
            for item in DISCOVERY_MOUNT_OPTION_ORDER
            if item in options[1:]
        )
    ):
        raise ProbeError(
            "DISCOVERY_MOUNTINFO_MALFORMED", "mount option production"
        )


def _require_discovery_super_options(options: Sequence[str]) -> None:
    """Validate the ordered generic prefix before later producer options."""
    if not options or options[0] not in {"ro", "rw"}:
        raise ProbeError(
            "DISCOVERY_MOUNTINFO_MALFORMED", "super option production"
        )
    remaining = list(options[1:])
    prefix_length = 0
    fixed = set(DISCOVERY_SUPERBLOCK_OPTION_ORDER)
    while (
        prefix_length < len(remaining)
        and remaining[prefix_length] in fixed
    ):
        prefix_length += 1
    fixed_prefix = remaining[:prefix_length]
    later_options = remaining[prefix_length:]
    if (
        tuple(fixed_prefix)
        != tuple(
            item
            for item in DISCOVERY_SUPERBLOCK_OPTION_ORDER
            if item in fixed_prefix
        )
        or any(item in fixed for item in later_options)
    ):
        raise ProbeError(
            "DISCOVERY_MOUNTINFO_MALFORMED", "super option production"
        )


def _require_canonical_discovery_mount_path(value: str, label: str) -> None:
    if value == "/":
        return
    if not value.startswith("/") or value.endswith("/"):
        raise ProbeError("DISCOVERY_MOUNTINFO_MALFORMED", label)
    components = value[1:].split("/")
    if (
        not components
        or any(component in {"", ".", ".."} for component in components)
        or any(
            ord(character) < 0x20 or ord(character) == 0x7F
            for component in components
            for character in component
        )
    ):
        raise ProbeError("DISCOVERY_MOUNTINFO_MALFORMED", label)


def parse_discovery_mountinfo(raw: bytes) -> List[Dict[str, Any]]:
    """Preserve the complete bounded mountinfo representation needed by later
    predicate design.  The byte framing is part of the producer contract."""
    if (
        not raw
        or not raw.endswith(b"\n")
        or b"\x00" in raw
        or b"\r" in raw
    ):
        raise ProbeError("DISCOVERY_MOUNTINFO_MALFORMED", "source framing")
    raw_lines = raw[:-1].split(b"\n")
    if not raw_lines or any(not line for line in raw_lines):
        raise ProbeError("DISCOVERY_MOUNTINFO_MALFORMED", "empty record")
    result: List[Dict[str, Any]] = []
    for raw_line in raw_lines:
        try:
            line = raw_line.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProbeError(
                "DISCOVERY_MOUNTINFO_MALFORMED", "source encoding"
            ) from exc
        fields = line.split(" ")
        if any(not field for field in fields) or fields.count("-") != 1:
            raise ProbeError("DISCOVERY_MOUNTINFO_MALFORMED", line[:200])
        separator = fields.index("-")
        if separator < 6 or len(fields) != separator + 4:
            raise ProbeError("DISCOVERY_MOUNTINFO_MALFORMED", line[:200])
        mount_id = fields[0]
        parent_id = fields[1]
        major_minor = fields[2]
        _parse_discovery_decimal(
            mount_id, DISCOVERY_MOUNT_ID_MAX, "mount id"
        )
        _parse_discovery_decimal(
            parent_id, DISCOVERY_MOUNT_ID_MAX, "parent mount id"
        )
        if DISCOVERY_MAJOR_MINOR_PATTERN.fullmatch(major_minor) is None:
            raise ProbeError("DISCOVERY_MOUNTINFO_MALFORMED", "major:minor")
        raw_major, raw_minor = major_minor.split(":", 1)
        if (
            len(raw_major) > len(str(DISCOVERY_DEVICE_MAJOR_MAX))
            or len(raw_minor) > len(str(DISCOVERY_DEVICE_MINOR_MAX))
            or int(raw_major) > DISCOVERY_DEVICE_MAJOR_MAX
            or int(raw_minor) > DISCOVERY_DEVICE_MINOR_MAX
        ):
            raise ProbeError("DISCOVERY_MOUNTINFO_MALFORMED", "major:minor")
        mount_options = fields[5].split(",")
        super_options = fields[separator + 3].split(",")
        if (
            len(mount_options) != len(set(mount_options))
            or len(super_options) != len(set(super_options))
            or mount_options[0] not in {"ro", "rw"}
            or super_options[0] not in {"ro", "rw"}
            or sum(token in {"ro", "rw"} for token in mount_options) != 1
            or sum(token in {"ro", "rw"} for token in super_options) != 1
        ):
            raise ProbeError("DISCOVERY_MOUNTINFO_MALFORMED", "duplicate option")
        for index, token in enumerate(mount_options):
            _require_discovery_mount_token(
                token, f"mount option {index}", comma_forbidden=True
            )
        for index, token in enumerate(super_options):
            _require_discovery_mount_token(
                token, f"super option {index}", comma_forbidden=True
            )
        _require_discovery_mount_options(mount_options)
        _require_discovery_super_options(super_options)
        _validate_discovery_mount_optional_fields(fields[6:separator])
        _require_canonical_discovery_mangled_field(
            fields[separator + 1], "filesystem type"
        )
        root = _decode_discovery_mountinfo_field(fields[3], "root")
        mount_point = _decode_discovery_mountinfo_field(
            fields[4], "mount point"
        )
        mount_source = _decode_discovery_mountinfo_field(
            fields[separator + 2], "mount source", mount_source=True
        )
        _require_canonical_discovery_mount_path(root, "root path")
        _require_canonical_discovery_mount_path(
            mount_point, "mount point path"
        )
        result.append(
            {
                "mount_id": mount_id,
                "parent_id": parent_id,
                "major_minor": major_minor,
                "root": root,
                "mount_point": mount_point,
                "mount_options": sorted(mount_options),
                "optional_fields": fields[6:separator],
                "fs_type": fields[separator + 1],
                "mount_source": mount_source,
                "super_options": sorted(super_options),
            }
        )
        if len(result) > DISCOVERY_MAX_MOUNTS:
            raise ProbeError("DISCOVERY_RECORD_OVERSIZED", "mount count")
    return sorted(result, key=lambda item: int(item["mount_id"]))


class _BpfProgQueryAttr(ctypes.Structure):
    _fields_ = [
        ("target_fd", ctypes.c_uint32),
        ("attach_type", ctypes.c_uint32),
        ("query_flags", ctypes.c_uint32),
        ("attach_flags", ctypes.c_uint32),
        ("prog_ids", ctypes.c_uint64),
        ("prog_cnt", ctypes.c_uint32),
        ("_padding", ctypes.c_uint32),
        ("prog_attach_flags", ctypes.c_uint64),
        ("link_ids", ctypes.c_uint64),
        ("link_attach_flags", ctypes.c_uint64),
        ("revision", ctypes.c_uint64),
    ]


def _assert_bpf_prog_query_attr_layout() -> None:
    expected = {
        "prog_attach_flags": 32,
        "link_ids": 40,
        "link_attach_flags": 48,
        "revision": 56,
    }
    actual_size = ctypes.sizeof(_BpfProgQueryAttr)
    actual_offsets = {
        name: getattr(_BpfProgQueryAttr, name).offset for name in expected
    }
    if actual_size != 64 or actual_offsets != expected:
        raise AssertionError(
            "BPF_PROG_QUERY UAPI layout mismatch: "
            f"size={actual_size}, offsets={actual_offsets!r}"
        )


_assert_bpf_prog_query_attr_layout()


def discover_bpf_prog_query() -> Dict[str, Any]:
    """Attempt exactly one non-mutating BPF_PROG_QUERY against the root cgroup.
    The result retains only success or the exact errno; attachment IDs are never
    requested or interpreted as policy semantics."""
    syscall_numbers = {"x86_64": 321, "aarch64": 280}
    machine = os.uname().machine
    if machine not in syscall_numbers:
        raise ProbeError("DISCOVERY_BPF_ARCH_UNSUPPORTED", machine)
    directory_fd = os.open(
        CGROUP_ROOT,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        # ctypes zero-initializes the complete UAPI object.  Assign only the
        # immutable input FD; every flag, pointer, count and revision remains
        # zero, and the syscall receives the full 64-byte extent.
        attr = _BpfProgQueryAttr()
        attr.target_fd = directory_fd
        libc = ctypes.CDLL(None, use_errno=True)
        ctypes.set_errno(0)
        result = libc.syscall(
            syscall_numbers[machine],
            16,  # BPF_PROG_QUERY
            ctypes.byref(attr),
            ctypes.sizeof(attr),
        )
        if result == 0:
            return {
                "attempted": True,
                "success": True,
                "errno": None,
                "errno_name": None,
            }
        code = ctypes.get_errno()
        if code <= 0:
            raise ProbeError("DISCOVERY_BPF_ERRNO_MISSING", str(result))
        if code not in DISCOVERY_BPF_PROG_QUERY_ERRNOS:
            raise ProbeError("DISCOVERY_BPF_ERRNO_IMPOSSIBLE", str(code))
        return {
            "attempted": True,
            "success": False,
            "errno": code,
            "errno_name": LINUX_ERRNO_NAMES[code],
        }
    finally:
        os.close(directory_fd)


_DISCOVERY_DEVICE_ALLOWLIST = frozenset(
    {
        "/dev/full",
        "/dev/null",
        "/dev/random",
        "/dev/tty",
        "/dev/urandom",
        "/dev/zero",
    }
)
_DISCOVERY_ABI_CANDIDATES = (
    "/usr/bin/bash",
    "/usr/bin/dash",
    "/usr/bin/python3",
    "/usr/lib/systemd/systemd",
)
_DISCOVERY_FIELD_PATHS = (
    ("cgroup.controllers", "/sys/fs/cgroup/cgroup.controllers"),
    ("cgroup.events", "/sys/fs/cgroup/cgroup.events"),
    ("cgroup.kill", "/sys/fs/cgroup/cgroup.kill"),
    ("cgroup.subtree_control", "/sys/fs/cgroup/cgroup.subtree_control"),
    ("cpu.max", "/sys/fs/cgroup/cpu.max"),
    ("etc.os-release", "/etc/os-release"),
    ("kernel.core_pattern", "/proc/sys/kernel/core_pattern"),
    ("memory.events", "/sys/fs/cgroup/memory.events"),
    ("memory.oom.group", "/sys/fs/cgroup/memory.oom.group"),
    ("proc.cgroup", "/proc/self/cgroup"),
    ("proc.mountinfo", "/proc/self/mountinfo"),
    ("proc.status", "/proc/self/status"),
)


def discover_device_nodes() -> Dict[str, Any]:
    """Stat, but never open or mutate, bounded top-level non-allowlisted device
    candidates."""
    candidates: List[Dict[str, Any]] = []
    try:
        entries = sorted(os.scandir("/dev"), key=lambda item: item.path)
    except OSError as exc:
        raise ProbeError("DISCOVERY_DEVICE_SCAN_FAILED", repr(exc)) from exc
    if len(entries) > 4096:
        raise ProbeError("DISCOVERY_DEVICE_SCAN_OVERSIZED", str(len(entries)))
    for entry in entries:
        if entry.path in _DISCOVERY_DEVICE_ALLOWLIST:
            continue
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        if not (stat.S_ISCHR(info.st_mode) or stat.S_ISBLK(info.st_mode)):
            continue
        candidates.append(
            {
                "path": entry.path,
                "type": "char" if stat.S_ISCHR(info.st_mode) else "block",
                "major": os.major(info.st_rdev),
                "minor": os.minor(info.st_rdev),
                "uid": info.st_uid,
                "gid": info.st_gid,
                "mode": stat.S_IMODE(info.st_mode),
            }
        )
        if len(candidates) > DISCOVERY_MAX_DEVICE_NODES:
            raise ProbeError("DISCOVERY_RECORD_OVERSIZED", "device count")
    return {"candidates": candidates}


def _read_discovery_elf(path: str) -> Optional[Dict[str, Any]]:
    """Read one fixed, already-installed ELF through O_NOFOLLOW and bind its ABI
    metadata to the exact bytes.  Absence or a symlink stays unresolved."""
    try:
        info = os.lstat(path)
    except OSError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return None
    if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return None
    flags = os.O_RDONLY | _require_o_nofollow() | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ProbeError("DISCOVERY_ABI_IDENTITY_CHANGED", path)
        if not 64 <= opened.st_size <= NOEXEC_WITNESS_MAX_ELF_BYTES:
            return None
        data = bytearray()
        while len(data) <= opened.st_size:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > NOEXEC_WITNESS_MAX_ELF_BYTES:
                raise ProbeError("DISCOVERY_ABI_OVERSIZED", path)
        raw = bytes(data)
        if len(raw) != opened.st_size or raw[:4] != ELF_MAGIC:
            return None
        elf_class = {1: 32, 2: 64}.get(raw[4])
        endianness = {1: "little", 2: "big"}.get(raw[5])
        if elf_class is None or endianness is None:
            return None
        machine = int.from_bytes(raw[18:20], endianness)
        return {
            "path": path,
            "sha256": sha256_bytes(raw),
            "elf_class": elf_class,
            "endianness": endianness,
            "machine": machine,
        }
    finally:
        os.close(fd)


def discover_executable_abis() -> Dict[str, Any]:
    binaries = [
        item
        for item in (_read_discovery_elf(path) for path in _DISCOVERY_ABI_CANDIDATES)
        if item is not None
    ]
    if len(binaries) > DISCOVERY_MAX_ABIS:
        raise ProbeError("DISCOVERY_RECORD_OVERSIZED", "ABI count")
    return {"binaries": sorted(binaries, key=lambda item: item["path"]), "absence_unresolved": True}


def discover_field_availability(
    known_available: Sequence[str] = (),
    controllers: Sequence[str] = (),
) -> Dict[str, Any]:
    known = set(known_available)
    controller_set = set(controllers)
    if not known.issubset({name for name, _ in _DISCOVERY_FIELD_PATHS}):
        raise ProbeError(
            "DISCOVERY_FIELD_IDENTITY_INVALID",
            "unknown known-available field",
        )
    if any(
        not isinstance(controller, str) or not controller
        for controller in controller_set
    ):
        raise ProbeError(
            "DISCOVERY_FIELD_IDENTITY_INVALID",
            "invalid controller identity",
        )
    fields: List[Dict[str, Any]] = []
    for name, raw_path in _DISCOVERY_FIELD_PATHS:
        if name in known:
            fields.append(
                {"name": name, "path": raw_path, "available": True, "errno": None}
            )
            continue
        path = Path(raw_path)
        try:
            fd = os.open(
                path,
                os.O_RDONLY | _require_o_nofollow() | getattr(os, "O_CLOEXEC", 0),
            )
        except OSError as exc:
            code = exc.errno or errno.EIO
            required_controller = DISCOVERY_CONTROLLER_GATED_FIELDS.get(name)
            if (
                code not in DISCOVERY_FIELD_OPEN_ERRNOS[name]
                or (
                    required_controller is not None
                    and required_controller in controller_set
                )
            ):
                raise ProbeError(
                    "DISCOVERY_FIELD_ERRNO_IMPOSSIBLE",
                    f"{name}:{code}",
                ) from exc
            fields.append(
                {
                    "name": name,
                    "path": raw_path,
                    "available": False,
                    "errno": code,
                }
            )
        else:
            os.close(fd)
            fields.append(
                {"name": name, "path": raw_path, "available": True, "errno": None}
            )
    return {"fields": sorted(fields, key=lambda item: item["name"])}


def collect_discovery_values(args: argparse.Namespace) -> Dict[str, Mapping[str, Any]]:
    """Collect only bounded, non-mutating host representation.  No hostile code
    is released and no candidate outcome function is called."""
    uname = os.uname()
    if _read_discovery_elf("/usr/lib/systemd/systemd") is None:
        raise ProbeError(
            "DISCOVERY_SYSTEMD_PROVENANCE_FAILED",
            "/usr/lib/systemd/systemd is not a fixed root-owned ELF",
        )
    systemd = run_bounded_command(
        ["/usr/lib/systemd/systemd", "--version"],
        stdout_limit=65536,
        stderr_limit=4096,
        timeout=10.0,
    )
    if systemd.returncode != 0:
        raise ProbeError(
            "DISCOVERY_SYSTEMD_VERSION_FAILED",
            systemd.stderr.decode("utf-8", "replace")[:400],
        )
    systemd_fields = _systemd_fields_from_raw(systemd.stdout)
    controllers_raw = read_bytes(
        CGROUP_ROOT / "cgroup.controllers",
        DISCOVERY_SOURCE_TEXT_MAX_BYTES,
    )
    controllers_text = controllers_raw.decode("utf-8", "replace")
    controllers = sorted(controllers_text.split())
    mountinfo_raw = read_bytes(
        Path("/proc/self/mountinfo"), DISCOVERY_MOUNTINFO_RAW_MAX_BYTES
    )
    proc_cgroup_raw = read_bytes(
        Path("/proc/self/cgroup"), DISCOVERY_SOURCE_TEXT_MAX_BYTES
    )
    proc_cgroup = _canonical_cgroup_v2_source(proc_cgroup_raw)
    os_release_raw = read_bytes(
        Path("/etc/os-release"), DISCOVERY_SOURCE_TEXT_MAX_BYTES
    )
    os_release = os_release_raw.decode("utf-8", "replace")
    return {
        "runner_image": {
            "runner_label": args.runner_label,
            "image_os": args.image_os,
            "image_version": args.image_version,
            "image_release": args.image_release,
            "arch": args.runner_arch,
            "os_release": os_release,
            "os_release_raw_base64": _discovery_raw_base64(os_release_raw),
        },
        "kernel": {"release": uname.release, "version": uname.version},
        "systemd": {
            **systemd_fields,
            "stdout_raw_base64": _discovery_raw_base64(systemd.stdout),
        },
        "cgroup_topology": {
            "unified": (CGROUP_ROOT / "cgroup.controllers").is_file(),
            "controllers": controllers,
            "controllers_raw_base64": _discovery_raw_base64(controllers_raw),
            "proc_cgroup": proc_cgroup,
            "proc_cgroup_raw_base64": _discovery_raw_base64(proc_cgroup_raw),
        },
        "mountinfo_topology": {
            "entries": parse_discovery_mountinfo(mountinfo_raw),
            "raw_base64": _discovery_raw_base64(mountinfo_raw),
        },
        "bpf_prog_query": discover_bpf_prog_query(),
        "device_nodes": discover_device_nodes(),
        "executable_abis": discover_executable_abis(),
        "field_availability": discover_field_availability(
            (
                "cgroup.controllers",
                "etc.os-release",
                "proc.cgroup",
                "proc.mountinfo",
            ),
            controllers,
        ),
    }


def discovery(args: argparse.Namespace) -> int:
    """Trusted root discovery entry point.  It has no fixture/candidate arguments
    and seals only proof-ineligible evidence."""
    if os.geteuid() != 0:
        print("P0_V2_DISCOVERY_STATUS=SETUP_ERROR")
        return 2
    if args.repository != "yurikuchumov-ux/ai-operating-system":
        raise ProbeError("GITHUB_CONTEXT_MISMATCH", "repository")
    if (
        args.pr_number != "71"
        or args.event_name != "pull_request"
        or args.event_action != "labeled"
        or args.event_ref != "refs/pull/71/merge"
        or args.label != "p0-v2-discovery"
        or args.sender_login != "yurikuchumov-ux"
        or args.sender_id != "299144523"
        or args.actor_login != "yurikuchumov-ux"
        or args.actor_id != "299144523"
        or args.run_attempt != "1"
        or args.runner_label != "ubuntu-24.04"
    ):
        raise ProbeError("GITHUB_CONTEXT_MISMATCH", "discovery event identity")
    for name in (
        "head_sha",
        "base_sha",
        "merge_sha",
        "workflow_sha",
        "implementation_commit",
        "source_authoring_anchor",
    ):
        validate_sha40(name, getattr(args, name))
    for name in (
        "f7b0_authoring_task_sha256",
        "f7b1_hosted_authorization_sha256",
    ):
        if not SHA64_RE.fullmatch(getattr(args, name)):
            raise ProbeError("INVALID_INPUT", name)
    if (
        args.implementation_commit != args.head_sha
        or args.source_authoring_anchor != DISCOVERY_SOURCE_AUTHORING_ANCHOR
        or args.f7b0_authoring_task_sha256
        != DISCOVERY_F7B0_AUTHORING_TASK_SHA256
        or args.f7b1_hosted_authorization_sha256
        != DISCOVERY_F7B1_HOSTED_AUTHORIZATION_SHA256
    ):
        raise ProbeError("DISCOVERY_IDENTITY_MISMATCH", "authority provenance")
    if not args.image_os or not args.image_version or not args.image_release:
        raise ProbeError("DISCOVERY_IMAGE_IDENTITY_MISSING", "hosted image")
    if args.evidence_uid != 0 or args.evidence_gid != 0:
        raise ProbeError("DISCOVERY_EVIDENCE_OWNER_INVALID", "must remain root-owned")
    source_path = Path(args.source_path).resolve()
    schema_path = Path(args.schema_path).resolve()
    workflow_file = Path(args.workflow_file).resolve()
    test_file = Path(args.test_file).resolve()
    evidence_dir = Path(args.evidence_dir).resolve()
    identity = {
        "repository": args.repository,
        "repository_id": args.repository_id,
        "pr_number": args.pr_number,
        "event_name": args.event_name,
        "event_action": args.event_action,
        "event_ref": args.event_ref,
        "label": args.label,
        "sender_login": args.sender_login,
        "sender_id": args.sender_id,
        "actor_login": args.actor_login,
        "actor_id": args.actor_id,
        "run_id": args.run_id,
        "run_attempt": args.run_attempt,
        "head_sha": args.head_sha,
        "base_sha": args.base_sha,
        "merge_sha": args.merge_sha,
        "workflow": args.workflow,
        "workflow_ref": args.workflow_ref,
        "workflow_sha": args.workflow_sha,
        "runner_label": args.runner_label,
        "image_os": args.image_os,
        "image_version": args.image_version,
        "image_release": args.image_release,
        "runner_arch": args.runner_arch,
        "boot_id": read_text(Path("/proc/sys/kernel/random/boot_id"), 128).strip(),
        "invocation_id": uuid.uuid4().hex,
    }
    source = {
        "probe_sha256": sha256_path(source_path),
        "schema_sha256": sha256_path(schema_path),
        "discovery_schema_sha256": discovery_schema_sha256(),
        "workflow_sha256": sha256_path(workflow_file),
        "test_sha256": sha256_path(test_file),
        "implementation_commit": args.implementation_commit,
        "source_authoring_anchor": args.source_authoring_anchor,
        "f7b0_authoring_task_sha256": args.f7b0_authoring_task_sha256,
        "f7b1_hosted_authorization_sha256": (
            args.f7b1_hosted_authorization_sha256
        ),
    }
    evidence = build_discovery_evidence(
        identity=identity,
        source=source,
        values=collect_discovery_values(args),
    )
    validate_discovery_evidence(
        evidence,
        schema_path,
        source_path=source_path,
        expected_identity=identity,
        expected_replay_binding=discovery_replay_binding(evidence),
    )
    digest = atomic_seal_discovery(
        evidence_dir / "discovery-evidence.json",
        evidence,
        schema_path,
        source_path,
        args.evidence_uid,
        args.evidence_gid,
    )
    print(f"P0_V2_DISCOVERY_STATUS=DISCOVERY_ONLY sha256={digest}")
    return 0


def systemctl_value(unit: str, property_name: str) -> str:
    return run_command(
        ["/usr/bin/systemctl", "show", unit, f"--property={property_name}", "--value"]
    ).stdout.decode("utf-8", "replace").strip()


def parse_systemd_show(raw: str) -> Dict[str, str]:
    """Parse an unambiguous systemctl-show record or fail closed."""
    properties: Dict[str, str] = {}
    for line in raw.splitlines():
        if not line:
            continue
        if "=" not in line:
            raise ProbeError(
                "SYSTEMD_SHOW_MALFORMED",
                f"expected KEY=VALUE, observed {line!r}",
            )
        name, value = line.split("=", 1)
        if not name or name in properties:
            raise ProbeError(
                "SYSTEMD_SHOW_MALFORMED",
                f"empty or duplicate property {name!r}",
            )
        properties[name] = value
    return properties


def observe_unit_load_state(
    unit: str,
    *,
    timeout: float = CLEANUP_TIMEOUT_SECONDS,
) -> str:
    try:
        completed = run_command(
            [
                "/usr/bin/systemctl",
                "show",
                unit,
                "--property=Id",
                "--property=LoadState",
            ],
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProbeError("UNIT_UNLOAD_OBSERVATION_FAILED", repr(exc)) from exc
    if completed.returncode != 0:
        raise ProbeError(
            "UNIT_UNLOAD_OBSERVATION_FAILED",
            (
                f"systemctl show exited {completed.returncode}: "
                f"{completed.stderr[:400]!r}"
            ),
        )
    try:
        properties = parse_systemd_show(completed.stdout.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ProbeError(
            "UNIT_UNLOAD_OBSERVATION_FAILED",
            "systemctl show output was not valid UTF-8",
        ) from exc
    observed_id = properties.get("Id")
    if observed_id != unit:
        raise ProbeError(
            "UNIT_UNLOAD_IDENTITY_MISMATCH",
            f"expected {unit!r}, observed {observed_id!r}",
        )
    load_state = properties.get("LoadState")
    if not load_state:
        raise ProbeError(
            "UNIT_UNLOAD_OBSERVATION_FAILED",
            "LoadState was absent or empty",
        )
    return load_state


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


def classify_memory_limit_outcome(
    systemd_outcome: str,
    systemd_result: str,
    before_events_raw: str,
    after_events_raw: str,
) -> str:
    """Fail closed unless systemd and memory.events prove a real OOM kill."""
    if not before_events_raw.strip() or not after_events_raw.strip():
        raise ProbeError("MEMORY_OOM_EVIDENCE_MISSING", "memory.events unavailable")
    before = parse_counter_file(before_events_raw)
    after = parse_counter_file(after_events_raw)
    if "oom_kill" not in before or "oom_kill" not in after:
        raise ProbeError("MEMORY_OOM_EVIDENCE_MISSING", "oom_kill counter absent")
    if after["oom_kill"] <= before["oom_kill"]:
        raise ProbeError("MEMORY_OOM_NOT_OBSERVED", "no oom_kill increment")
    if systemd_outcome != "RESOURCE_OOM" or systemd_result != "oom-kill":
        raise ProbeError(
            "MEMORY_OOM_CONTRADICTORY",
            f"systemd_outcome={systemd_outcome!r} result={systemd_result!r}",
        )
    return "RESOURCE_OOM"


def case_timeout_seconds(case_id: str) -> float:
    if case_id == "operator-cancel":
        return OPERATOR_CANCEL_TIMEOUT_SECONDS
    return CASE_TIMEOUT_SECONDS


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
    for required_mount in (
        "/tmp:",
        "/var/tmp:",
        f"size={PRIVATE_TMPFS_SIZE}",
        "noexec",
    ):
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
    if not SAFE_UNIT_RE.fullmatch(unit):
        raise ProbeError("UNIT_NAME_UNSAFE", unit)
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
        remaining = deadline - time.monotonic()
        load_state = observe_unit_load_state(
            unit,
            timeout=max(remaining, 0.001),
        )
        if load_state == "not-found":
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


def _fully_write(fd: int, data: bytes) -> None:
    """Write every byte, retrying only interrupted system calls."""
    view = memoryview(data)
    while view:
        try:
            written = os.write(fd, view)
        except InterruptedError:
            continue
        if written <= 0:
            raise ProbeError(
                "STATE_WRITE_INCOMPLETE",
                "os.write made no progress",
            )
        view = view[written:]


def _read_exact(fd: int, size: int) -> bytes:
    chunks: List[bytes] = []
    remaining = size
    while remaining:
        try:
            chunk = os.read(fd, remaining)
        except InterruptedError:
            continue
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def verify_published_root_state(path: Path, expected_payload: bytes) -> None:
    """Prove the published root journal's identity, bytes, and semantics."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ProbeError(
            "STATE_READBACK_UNTRUSTED",
            "O_NOFOLLOW is unavailable",
        )
    flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ProbeError(
                "STATE_READBACK_UNTRUSTED",
                "published state is not a regular file",
            )
        if before.st_uid != 0:
            raise ProbeError(
                "STATE_READBACK_UNTRUSTED",
                "published state is not root-owned",
            )
        if stat.S_IMODE(before.st_mode) != 0o600:
            raise ProbeError(
                "STATE_READBACK_UNTRUSTED",
                "published state is not mode 0600",
            )
        if not 0 < before.st_size <= MAX_ROOT_STATE_BYTES:
            raise ProbeError(
                "STATE_READBACK_UNTRUSTED",
                "published state size is out of bounds",
            )
        if before.st_size != len(expected_payload):
            raise ProbeError(
                "STATE_READBACK_UNTRUSTED",
                "published state size mismatch",
            )
        observed = _read_exact(fd, before.st_size)
        extra = _read_exact(fd, 1)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_uid",
        "st_gid",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if any(getattr(before, name) != getattr(after, name) for name in stable_fields):
        raise ProbeError(
            "STATE_READBACK_UNTRUSTED",
            "published state changed during readback",
        )
    if extra or observed != expected_payload:
        raise ProbeError(
            "STATE_READBACK_UNTRUSTED",
            "published state bytes mismatch",
        )
    try:
        value = json.loads(observed.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ProbeError(
            "STATE_READBACK_UNTRUSTED",
            "published state is not valid JSON",
        ) from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != observed:
        raise ProbeError(
            "STATE_READBACK_UNTRUSTED",
            "published state is not canonical JSON",
        )
    _validate_root_state_fields(value)


def write_root_state(path: Path, state: Mapping[str, Any]) -> None:
    payload = canonical_json_bytes(state)
    if not 0 < len(payload) <= MAX_ROOT_STATE_BYTES:
        raise ProbeError("STATE_WRITE_SIZE_INVALID", path.name)
    _validate_root_state_fields(state)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        try:
            _fully_write(fd, payload)
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    verify_published_root_state(path, payload)


def load_root_state(path: Path) -> Dict[str, Any]:
    st = path.stat()
    if st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600:
        raise ProbeError("STATE_UNTRUSTED", "state record is not root-owned mode 0600")
    value = json.loads(path.read_text(encoding="utf-8"))
    return _validate_root_state_fields(value)


def _validate_root_state_fields(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ProbeError("STATE_UNTRUSTED", "state record is not an object")
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
        "release_marker",
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
            "systemd_properties",
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
        systemd_properties = active_case["systemd_properties"]
        if (
            not isinstance(systemd_properties, dict)
            or set(systemd_properties) != set(SYSTEMD_SHOW_PROPERTIES)
            or not all(isinstance(item, str) for item in systemd_properties.values())
        ):
            raise ProbeError("STATE_UNTRUSTED", "invalid systemd properties")
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
    _validate_release_marker(value, active_case)
    return value


def _validate_release_marker(
    state: Mapping[str, Any],
    active_case: Optional[Mapping[str, Any]],
) -> None:
    """Fail-closed validation of the durable post-release marker.

    The marker binds one hostile-fixture release to an exact invocation, nonce,
    run id, run attempt and unit. It is required at fixture_released, is absent
    before release, and remains attached to every post-release finalizer phase.
    Marker-free finalizer phases are also valid: they are the resumable,
    proof-ineligible cleanup path entered from case_bound. When present, the
    marker is bound to both the active case identity and journal run identity.
    """
    marker = state["release_marker"]
    phase = state["phase"]
    if active_case is None:
        if marker is not None:
            raise ProbeError("STATE_UNTRUSTED", "release marker without active case")
        return
    if phase in PRE_RELEASE_PHASES:
        if marker is not None:
            raise ProbeError("STATE_UNTRUSTED", "release marker present before release")
        return
    if phase == "fixture_released" and marker is None:
        raise ProbeError("STATE_UNTRUSTED", "release marker required after release")
    # A marker-free finalizer phase represents the non-proof cleanup path that
    # started durably at case_bound. Its monotonic phase must remain loadable so
    # F5 can resume after kill/empty/EOF/unload without replaying completed work.
    if marker is None:
        return
    if not isinstance(marker, dict):
        raise ProbeError("STATE_UNTRUSTED", "release marker required after release")
    if set(marker) != RELEASE_MARKER_FIELDS:
        raise ProbeError("STATE_UNTRUSTED", "release marker fields mismatch")
    if marker["marker_version"] != RELEASE_MARKER_VERSION:
        raise ProbeError("STATE_UNTRUSTED", "unsupported release marker version")
    for text_field in ("invocation_id", "nonce", "run_id", "run_attempt", "unit"):
        if not isinstance(marker[text_field], str):
            raise ProbeError("STATE_UNTRUSTED", f"invalid release marker {text_field}")
    if not re.fullmatch(r"[0-9a-f]{32}", marker["invocation_id"]):
        raise ProbeError("STATE_UNTRUSTED", "unsafe release marker invocation id")
    if not re.fullmatch(r"[0-9a-f]{16}", marker["nonce"]):
        raise ProbeError("STATE_UNTRUSTED", "unsafe release marker nonce")
    if not SAFE_TOKEN_RE.fullmatch(marker["run_id"]) or not SAFE_TOKEN_RE.fullmatch(
        marker["run_attempt"]
    ):
        raise ProbeError("STATE_UNTRUSTED", "unsafe release marker run identity")
    if not SAFE_UNIT_RE.fullmatch(marker["unit"]):
        raise ProbeError("STATE_UNTRUSTED", "unsafe release marker unit")
    released = marker["released_monotonic_ns"]
    if not isinstance(released, int) or isinstance(released, bool) or released < 0:
        raise ProbeError("STATE_UNTRUSTED", "invalid release marker timestamp")
    if marker["run_id"] != state["run_id"] or marker["run_attempt"] != state["run_attempt"]:
        raise ProbeError("STATE_UNTRUSTED", "release marker run identity mismatch")
    if (
        marker["invocation_id"] != active_case["invocation_id"]
        or marker["nonce"] != active_case["nonce"]
        or marker["unit"] != active_case["unit"]
    ):
        raise ProbeError("STATE_UNTRUSTED", "release marker case binding mismatch")


def release_marker_matches(
    marker: Optional[Mapping[str, Any]],
    active_case: Mapping[str, Any],
    run_id: str,
    run_attempt: str,
) -> bool:
    """Exact five-way binding between a durable marker and the finalizer's job.

    Positive cancellation proof requires the marker to bind the same invocation,
    nonce, run id, run attempt and unit the finalizer is processing. A missing
    marker or any mismatch fails closed for proof; it never suppresses the
    identity-bound safety cleanup.
    """
    if not isinstance(marker, dict):
        return False
    return (
        marker.get("marker_version") == RELEASE_MARKER_VERSION
        and marker.get("run_id") == run_id
        and marker.get("run_attempt") == run_attempt
        and marker.get("invocation_id") == active_case.get("invocation_id")
        and marker.get("nonce") == active_case.get("nonce")
        and marker.get("unit") == active_case.get("unit")
    )


def release_fixture_and_record(
    *,
    barrier_fd: int,
    state_path: Path,
    journal: Dict[str, Any],
    invocation_id: str,
    nonce: str,
    run_id: str,
    run_attempt: str,
    unit: str,
) -> None:
    """Release one fixture and durably publish its exact proof marker.

    The release byte must be complete. If the hardened journal publication
    fails, restore the in-memory journal to its last durable case_bound state so
    no later supervisor cleanup or evidence path can accidentally persist a
    marker that never completed its required write/readback transaction.
    """
    if os.write(barrier_fd, b"R") != 1:
        raise ProbeError("FIXTURE_RELEASE_WRITE_INCOMPLETE", unit)
    prior_phase = journal["phase"]
    prior_marker = journal["release_marker"]
    journal["release_marker"] = {
        "marker_version": RELEASE_MARKER_VERSION,
        "invocation_id": invocation_id,
        "nonce": nonce,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "unit": unit,
        "released_monotonic_ns": time.monotonic_ns(),
    }
    journal["phase"] = "fixture_released"
    try:
        write_root_state(state_path, journal)
    except BaseException:
        journal["release_marker"] = prior_marker
        journal["phase"] = prior_phase
        raise


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
            data = os.read(key.fd, MAX_DRAIN_READ)
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


CGROUP_LIMIT_FILES = (
    "pids.max",
    "memory.max",
    "memory.swap.max",
    "memory.oom.group",
    "cpu.max",
)


def _read_trusted_cgroup_file(cgroup_dir: Path, name: str, limit: int = 4096) -> str:
    """Read one cgroup interface file from the already-bound cgroup directory with a
    required O_NOFOLLOW (never a flag-0 fallback), asserting it is a regular file
    and its content is within a small bound. A symlink, non-regular, or oversized
    read fails closed."""
    fd = os.open(
        cgroup_dir / name,
        os.O_RDONLY | _require_o_nofollow() | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ProbeError("CGROUP_FILE_NOT_REGULAR", name)
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            raise ProbeError("CGROUP_FILE_OVERSIZED", name)
    finally:
        os.close(fd)
    return data.decode("ascii", "strict").strip()


def read_cgroup_limits(cgroup_dir: Path) -> Dict[str, Any]:
    """The exact controller-limit interface files of the bound cgroup. A file that
    is missing, a symlink, non-regular, oversized, or non-ASCII is recorded as JSON
    null so the derived per-property effect fails closed rather than defaulting."""
    limits: Dict[str, Any] = {}
    for name in CGROUP_LIMIT_FILES:
        try:
            limits[name] = _read_trusted_cgroup_file(cgroup_dir, name)
        except (OSError, ProbeError, UnicodeError):
            limits[name] = None
    return limits


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


def _regular_file_sha256_nofollow(path: Path, expected: os.stat_result) -> str:
    if expected.st_size > 1024 * 1024:
        raise ProbeError("COREDUMP_CONFIG_TOO_LARGE", str(path))
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        observed = os.fstat(fd)
        if (
            observed.st_dev != expected.st_dev
            or observed.st_ino != expected.st_ino
            or not stat.S_ISREG(observed.st_mode)
        ):
            raise ProbeError("COREDUMP_CONFIG_IDENTITY_CHANGED", str(path))
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > 1024 * 1024:
                raise ProbeError("COREDUMP_CONFIG_TOO_LARGE", str(path))
            digest.update(chunk)
        if total != observed.st_size:
            raise ProbeError("COREDUMP_CONFIG_SIZE_CHANGED", str(path))
        return digest.hexdigest()
    finally:
        os.close(fd)


def coredump_config_path_snapshot(path: Path) -> Dict[str, Any]:
    """Snapshot one config candidate without following a symlink or replacement."""
    try:
        observed = path.lstat()
    except FileNotFoundError:
        return {"path": str(path), "exists": False}
    except OSError as exc:
        raise ProbeError("COREDUMP_CONFIG_STAT_FAILED", f"{path}:{exc!r}") from exc
    item: Dict[str, Any] = {
        "path": str(path),
        "exists": True,
        "device": observed.st_dev,
        "inode": observed.st_ino,
        "mode": stat.S_IMODE(observed.st_mode),
        "uid": observed.st_uid,
        "gid": observed.st_gid,
        "size": observed.st_size,
        "mtime_ns": observed.st_mtime_ns,
        "type": stat.S_IFMT(observed.st_mode),
    }
    if stat.S_ISREG(observed.st_mode):
        item["sha256"] = _regular_file_sha256_nofollow(path, observed)
    elif stat.S_ISLNK(observed.st_mode):
        target = os.readlink(path)
        if len(target.encode("utf-8", "surrogateescape")) > 4096:
            raise ProbeError("COREDUMP_CONFIG_LINK_TOO_LARGE", str(path))
        item["symlink_target"] = target
        item["masked"] = target == "/dev/null"
    return item


def coredump_configuration_snapshot() -> Dict[str, Any]:
    """Bind every main/drop-in candidate and the fixed systemd precedence."""
    roots = [str(root) for root in COREDUMP_CONFIG_ROOTS]
    main_candidates: List[Dict[str, Any]] = []
    dropin_directories: List[Dict[str, Any]] = []
    effective_by_name: Dict[str, Dict[str, Any]] = {}
    for priority, root in enumerate(COREDUMP_CONFIG_ROOTS):
        main = coredump_config_path_snapshot(root / "coredump.conf")
        main["root_priority"] = priority
        main_candidates.append(main)
        directory_path = root / "coredump.conf.d"
        directory = coredump_config_path_snapshot(directory_path)
        entries: List[Dict[str, Any]] = []
        if directory["exists"]:
            if directory["type"] != stat.S_IFDIR:
                raise ProbeError(
                    "COREDUMP_CONFIG_DIRECTORY_INVALID",
                    str(directory_path),
                )
            try:
                candidates = sorted(
                    (item for item in directory_path.iterdir() if item.name.endswith(".conf")),
                    key=lambda item: item.name,
                )
            except OSError as exc:
                raise ProbeError(
                    "COREDUMP_CONFIG_DIRECTORY_UNREADABLE",
                    f"{directory_path}:{exc!r}",
                ) from exc
            for candidate in candidates:
                entry = coredump_config_path_snapshot(candidate)
                if not entry["exists"]:
                    raise ProbeError("COREDUMP_CONFIG_ENTRY_DISAPPEARED", str(candidate))
                entry["name"] = candidate.name
                entry["root_priority"] = priority
                entries.append(entry)
                effective_by_name.setdefault(candidate.name, entry)
        dropin_directories.append(
            {
                "root": str(root),
                "root_priority": priority,
                "directory": directory,
                "entries": entries,
            }
        )
    effective_main = next(
        (item["path"] for item in main_candidates if item["exists"]),
        None,
    )
    return {
        "precedence_roots_high_to_low": roots,
        "main_candidates": main_candidates,
        "effective_main": effective_main,
        "dropin_directories": dropin_directories,
        "effective_dropins": [
            {
                "name": name,
                "path": effective_by_name[name]["path"],
                "root_priority": effective_by_name[name]["root_priority"],
            }
            for name in sorted(effective_by_name)
        ],
    }


def _strict_utf8(payload: bytes, context: str) -> str:
    try:
        return payload.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ProbeError("HOST_OUTPUT_INVALID_UTF8", context) from exc


def _systemd_unit_snapshot(unit: str) -> Dict[str, Any]:
    completed = run_bounded_command(
        [
            "/usr/bin/systemctl",
            "show",
            unit,
            f"--property={','.join(COREDUMP_UNIT_PROPERTIES)}",
            "--no-pager",
        ],
        stdout_limit=COREDUMP_COMMAND_STDOUT_MAX_BYTES,
    )
    if completed.returncode != 0:
        raise ProbeError("COREDUMP_UNIT_SHOW_FAILED", f"{unit}:{completed.returncode}")
    stdout = _strict_utf8(completed.stdout, f"{unit}:stdout")
    stderr = _strict_utf8(completed.stderr, f"{unit}:stderr")
    properties = parse_systemd_show(stdout)
    if set(properties) != set(COREDUMP_UNIT_PROPERTIES):
        raise ProbeError("COREDUMP_UNIT_SHOW_MALFORMED", unit)
    return {
        "unit": unit,
        "returncode": completed.returncode,
        "stdout_byte_count": len(completed.stdout),
        "stdout_sha256": sha256_bytes(completed.stdout),
        "stderr": stderr,
        "stderr_byte_count": len(completed.stderr),
        "stderr_sha256": sha256_bytes(completed.stderr),
        "properties": properties,
    }


def parse_coredump_instance_listing(text: str) -> List[str]:
    instances: List[str] = []
    for line in text.splitlines():
        if not line:
            continue
        fields = line.split(None, 4)
        if len(fields) != 5 or not COREDUMP_INSTANCE_RE.fullmatch(fields[0]):
            raise ProbeError("COREDUMP_INSTANCE_LIST_MALFORMED", line[:400])
        instances.append(fields[0])
    if len(instances) != len(set(instances)):
        raise ProbeError("COREDUMP_INSTANCE_LIST_DUPLICATE", ",".join(instances))
    return sorted(instances)


def coredump_helper_units_snapshot() -> Dict[str, Any]:
    completed = run_bounded_command(
        [
            "/usr/bin/systemctl",
            "list-units",
            "--all",
            "--full",
            "--plain",
            "--no-legend",
            "systemd-coredump@*.service",
        ],
        stdout_limit=COREDUMP_COMMAND_STDOUT_MAX_BYTES,
    )
    if completed.returncode != 0:
        raise ProbeError("COREDUMP_INSTANCE_LIST_FAILED", str(completed.returncode))
    stdout = _strict_utf8(completed.stdout, "coredump instance list stdout")
    stderr = _strict_utf8(completed.stderr, "coredump instance list stderr")
    # parse_coredump_instance_listing already rejected duplicates and returned a
    # sorted, unique set; instance_units mirrors it so before/after additions and
    # removals are diffable from the evidence without re-parsing the unit blobs.
    instances = parse_coredump_instance_listing(stdout)
    return {
        "list_command": {
            "returncode": completed.returncode,
            "stdout_byte_count": len(completed.stdout),
            "stdout_sha256": sha256_bytes(completed.stdout),
            "stderr": stderr,
            "stderr_byte_count": len(completed.stderr),
            "stderr_sha256": sha256_bytes(completed.stderr),
        },
        "socket": _systemd_unit_snapshot(COREDUMP_SOCKET_UNIT),
        "template": _systemd_unit_snapshot(COREDUMP_TEMPLATE_UNIT),
        "instances": [_systemd_unit_snapshot(unit) for unit in instances],
        "instance_units": list(instances),
        "instance_count": len(instances),
    }


def _extract_cursor(text: str, context: str) -> str:
    lines = [line for line in text.splitlines() if line]
    if len(lines) != 1 or not lines[0].startswith("-- cursor: "):
        raise ProbeError("JOURNAL_CURSOR_MISSING", f"{context}:{text[:200]}")
    cursor = lines[0][len("-- cursor: ") :]
    if not JOURNAL_CURSOR_RE.fullmatch(cursor):
        raise ProbeError("JOURNAL_CURSOR_INVALID", f"{context}:{cursor[:200]}")
    return cursor


def journal_cursor_snapshot() -> Dict[str, Any]:
    completed = run_bounded_command(
        ["/usr/bin/journalctl", "--show-cursor", "-n", "0", "--no-pager"],
        stdout_limit=4096,
    )
    if completed.returncode != 0:
        raise ProbeError("JOURNAL_CURSOR_FAILED", str(completed.returncode))
    stdout = _strict_utf8(completed.stdout, "journal cursor stdout")
    stderr = _strict_utf8(completed.stderr, "journal cursor stderr")
    return {
        "returncode": completed.returncode,
        "cursor": _extract_cursor(stdout, "snapshot"),
        "stdout_byte_count": len(completed.stdout),
        "stdout_sha256": sha256_bytes(completed.stdout),
        "stderr": stderr,
        "stderr_byte_count": len(completed.stderr),
        "stderr_sha256": sha256_bytes(completed.stderr),
    }


def coredump_effect_snapshot() -> Dict[str, Any]:
    package = run_bounded_command(
        ["/usr/bin/dpkg-query", "-W", "-f=${Status}\\t${Version}\\n", "systemd-coredump"],
        stdout_limit=COREDUMP_COMMAND_STDOUT_MAX_BYTES,
    )
    return {
        "package": {
            "returncode": package.returncode,
            "stdout": _strict_utf8(package.stdout, "dpkg-query stdout"),
            "stdout_byte_count": len(package.stdout),
            "stdout_sha256": sha256_bytes(package.stdout),
            "stderr": _strict_utf8(package.stderr, "dpkg-query stderr"),
            "stderr_byte_count": len(package.stderr),
            "stderr_sha256": sha256_bytes(package.stderr),
        },
        "configuration": coredump_configuration_snapshot(),
        "helper_units": coredump_helper_units_snapshot(),
        "storage": filesystem_snapshot([Path("/var/lib/systemd/coredump")]),
        "journal_cursor": journal_cursor_snapshot(),
    }


def _reject_duplicate_json_pairs(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProbeError("JOURNAL_JSON_DUPLICATE_FIELD", key)
        result[key] = value
    return result


def _journal_field_summary(value: Any) -> Any:
    if isinstance(value, (str, int, bool)) or value is None:
        payload = canonical_json_bytes(value)
        if len(payload) <= 1024:
            return value
        return {"byte_count": len(payload), "sha256": sha256_bytes(payload)}
    payload = canonical_json_bytes(value)
    return {"byte_count": len(payload), "sha256": sha256_bytes(payload)}


def parse_complete_journal_interval(
    payload: bytes,
    *,
    start_cursor: str,
) -> Dict[str, Any]:
    """Parse a complete ``journalctl --after-cursor ... --show-cursor`` interval.

    The interval is newline-delimited JSON, one entry per line, followed by
    journalctl's ``-- cursor: <terminal>`` trailer.  An empty interval (return
    code 0 with no bytes) is a valid, complete "nothing followed the start
    cursor" result: journalctl prints no trailer when zero entries are shown, so
    the terminal cursor is bound to the start cursor and marked as not emitted.
    A non-empty interval must end with the trailer, and when it carries entries
    the trailer must equal the last entry's cursor; a truncated tail, a missing
    trailer, a malformed line, a duplicate cursor, or invalid UTF-8 fails closed.
    """
    if not isinstance(start_cursor, str) or not JOURNAL_CURSOR_RE.fullmatch(start_cursor):
        raise ProbeError("JOURNAL_CURSOR_MISSING", repr(start_cursor)[:200])
    if len(payload) > COREDUMP_JOURNAL_MAX_BYTES:
        raise ProbeError("JOURNAL_DELTA_TOO_LARGE", str(len(payload)))
    byte_count = len(payload)
    payload_sha256 = sha256_bytes(payload)
    if not payload:
        return {
            "start_cursor": start_cursor,
            "terminal_cursor": start_cursor,
            "terminal_cursor_emitted": False,
            "byte_count": 0,
            "sha256": payload_sha256,
            "entry_count": 0,
            "relevant_entry_count": 0,
            "relevant_entries": [],
            "complete": True,
        }
    text = _strict_utf8(payload, "journal interval")
    lines = text.splitlines()
    if not lines or not lines[-1].startswith("-- cursor: "):
        raise ProbeError("JOURNAL_TERMINAL_CURSOR_MISSING", text[-200:])
    terminal_cursor = _extract_cursor(lines[-1], "terminal")
    entry_lines = lines[:-1]
    seen_cursors: set[str] = set()
    relevant_entries: List[Dict[str, Any]] = []
    selected_fields = set(COREDUMP_JOURNAL_SELECTED_FIELDS)
    last_entry_cursor: Optional[str] = None
    for index, line in enumerate(entry_lines):
        if not line:
            raise ProbeError("JOURNAL_JSON_EMPTY_LINE", str(index))
        try:
            record = json.loads(line, object_pairs_hook=_reject_duplicate_json_pairs)
        except (json.JSONDecodeError, ProbeError) as exc:
            raise ProbeError("JOURNAL_JSON_INVALID", f"line {index}") from exc
        if not isinstance(record, dict):
            raise ProbeError("JOURNAL_JSON_INVALID", f"line {index}:not object")
        cursor = record.get("__CURSOR")
        if not isinstance(cursor, str) or not JOURNAL_CURSOR_RE.fullmatch(cursor):
            raise ProbeError("JOURNAL_ENTRY_CURSOR_INVALID", f"line {index}")
        if cursor in seen_cursors:
            raise ProbeError("JOURNAL_ENTRY_CURSOR_DUPLICATE", cursor)
        seen_cursors.add(cursor)
        last_entry_cursor = cursor
        coredump_fields = sorted(
            key for key in record if isinstance(key, str) and key.startswith("COREDUMP_")
        )
        unit_values = [
            record.get(name)
            for name in ("_SYSTEMD_UNIT", "UNIT", "OBJECT_SYSTEMD_UNIT", "COREDUMP_UNIT")
        ]
        reasons: List[str] = []
        if record.get("MESSAGE_ID") == COREDUMP_MESSAGE_ID:
            reasons.append("coredump_message_id")
        if coredump_fields:
            reasons.append("coredump_fields")
        for value in unit_values:
            if value == COREDUMP_SOCKET_UNIT:
                reasons.append("coredump_socket")
            elif value == COREDUMP_TEMPLATE_UNIT:
                reasons.append("coredump_template")
            elif isinstance(value, str) and value.startswith("systemd-coredump@"):
                if not COREDUMP_INSTANCE_RE.fullmatch(value):
                    raise ProbeError("JOURNAL_COREDUMP_UNIT_INVALID", value[:300])
                reasons.append("coredump_instance")
        if record.get("_COMM") == "systemd-coredump" or record.get(
            "SYSLOG_IDENTIFIER"
        ) == "systemd-coredump":
            reasons.append("coredump_process")
        if reasons:
            relevant_entries.append(
                {
                    "cursor": cursor,
                    "reasons": sorted(set(reasons)),
                    "coredump_field_names": coredump_fields,
                    "selected_fields": {
                        key: _journal_field_summary(record[key])
                        for key in sorted(selected_fields & set(record))
                    },
                    "record_sha256": sha256_bytes(canonical_json_bytes(record)),
                }
            )
    if last_entry_cursor is not None and terminal_cursor != last_entry_cursor:
        raise ProbeError(
            "JOURNAL_TERMINAL_CURSOR_MISMATCH",
            f"{terminal_cursor}!={last_entry_cursor}",
        )
    return {
        "start_cursor": start_cursor,
        "terminal_cursor": terminal_cursor,
        "terminal_cursor_emitted": True,
        "byte_count": byte_count,
        "sha256": payload_sha256,
        "entry_count": len(entry_lines),
        "relevant_entry_count": len(relevant_entries),
        "relevant_entries": relevant_entries,
        "complete": True,
    }


def journal_delta_since(snapshot: Mapping[str, Any]) -> Dict[str, Any]:
    cursor = snapshot.get("journal_cursor", {}).get("cursor")
    if not isinstance(cursor, str) or not JOURNAL_CURSOR_RE.fullmatch(cursor):
        raise ProbeError("JOURNAL_CURSOR_MISSING", repr(cursor)[:200])
    completed = run_bounded_command(
        [
            "/usr/bin/journalctl",
            "--after-cursor",
            cursor,
            "--output",
            "json",
            "--no-pager",
            "--show-cursor",
        ],
        stdout_limit=COREDUMP_JOURNAL_MAX_BYTES,
        timeout=COREDUMP_JOURNAL_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        raise ProbeError(
            "JOURNAL_DELTA_FAILED",
            f"returncode={completed.returncode}",
        )
    if completed.stderr:
        raise ProbeError(
            "JOURNAL_DELTA_STDERR",
            _strict_utf8(completed.stderr, "journal interval stderr")[:400],
        )
    return parse_complete_journal_interval(completed.stdout, start_cursor=cursor)


# Linux mount(2) flags for the trusted, supervisor-owned noexec witness mount.
_MS_NOSUID = 2
_MS_NODEV = 4
_MS_NOEXEC = 8
_MNT_DETACH = 2


def _run_execve_probe(path: str, timeout: float = 5.0) -> Dict[str, Any]:
    """Fork and directly execve ``path`` in a clean child, returning a
    classification-ready outcome derived only from kernel-authored state: the
    execve errno on failure (reported to the parent through a pipe that the child
    writes before any exec), or the wait status on success. No child-authored
    output is trusted -- a successful exec replaces the image and is reported as
    ``executed`` regardless of the program's later exit code; a signal or a
    timeout is reported as such."""
    report_r, report_w = os.pipe()
    devnull = os.open(os.devnull, os.O_RDWR)
    pid = os.fork()
    if pid == 0:  # pragma: no cover - child process, hosted runner only
        try:
            os.close(report_r)
            os.dup2(devnull, 0)
            os.dup2(devnull, 1)
            os.dup2(devnull, 2)
            os.execv(path, [path])
        except OSError as exc:
            try:
                os.write(report_w, str(int(exc.errno)).encode("ascii"))
            except OSError:
                pass
            os._exit(111)
        except BaseException:
            os._exit(112)
        os._exit(113)
    os.close(report_w)
    os.close(devnull)
    try:
        os.set_blocking(report_r, False)
    except (OSError, ValueError):  # pragma: no cover - platform dependent
        pass
    reported = b""
    status = 0
    timed_out = False
    deadline = time.monotonic() + timeout
    while True:
        try:
            chunk = os.read(report_r, 64)
            if chunk:
                reported += chunk
        except (BlockingIOError, OSError):
            pass
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            break
        if time.monotonic() > deadline:
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except OSError:
                pass
            timed_out = True
            break
        time.sleep(0.02)
    try:
        while True:
            chunk = os.read(report_r, 64)
            if not chunk:
                break
            reported += chunk
    except (BlockingIOError, OSError):
        pass
    os.close(report_r)
    if timed_out:
        return {"kind": "timeout"}
    if reported:
        try:
            return {"kind": "oserror", "errno": int(reported.decode("ascii").strip())}
        except ValueError:
            return {"kind": "ambiguous"}
    if os.WIFSIGNALED(status):
        return {"kind": "signal", "signal": os.WTERMSIG(status)}
    if os.WIFEXITED(status):
        code = os.WEXITSTATUS(status)
        if code in (111, 112, 113):
            return {"kind": "ambiguous"}
        return {"kind": "executed", "exit_code": code}
    return {"kind": "ambiguous"}


def _stage_witness_bytes(path: Path, data: bytes) -> str:
    """Stage the exact witness bytes into ``path`` through a trusted, non-symlink
    descriptor, fsync them, lock them to root-owned mode 0500, and return the
    on-disk digest so the caller can bind the staged identity."""
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _require_o_nofollow(),
        0o500,
    )
    try:
        _fully_write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chown(path, 0, 0)
    os.chmod(path, 0o500)
    return sha256_path(path)


def _stage_and_readback_witness_bytes(path: Path, data: bytes) -> Tuple[str, str]:
    """Stage witness bytes and independently read them back, returning both the
    staged and the read-back digests so a silent substitution between write and
    execve fails closed."""
    staged = _stage_witness_bytes(path, data)
    rfd = os.open(path, os.O_RDONLY | _require_o_nofollow())
    try:
        readback = b""
        while True:
            chunk = os.read(rfd, 1024 * 1024)
            if not chunk:
                break
            readback += chunk
    finally:
        os.close(rfd)
    return staged, sha256_bytes(readback)


def _mount_tmpfs_noexec(target: Path) -> None:
    """Mount a fresh, private, size-bounded tmpfs at ``target`` with
    noexec,nosuid,nodev. Root-only; fails closed if the kernel refuses."""
    libc = ctypes.CDLL(None, use_errno=True)
    flags = _MS_NOSUID | _MS_NODEV | _MS_NOEXEC
    ctypes.set_errno(0)
    result = libc.mount(
        b"tmpfs",
        str(target).encode("utf-8"),
        b"tmpfs",
        ctypes.c_ulong(flags),
        b"size=1M,mode=0700",
    )
    if result != 0:
        raise ProbeError(
            "NOEXEC_WITNESS_MOUNT_FAILED", os.strerror(ctypes.get_errno())
        )


def _umount(target: Path) -> None:
    """Best-effort unmount of the witness tmpfs, falling back to a lazy detach."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.umount(str(target).encode("utf-8")) != 0:
        umount2 = getattr(libc, "umount2", None)
        if umount2 is not None:
            umount2(str(target).encode("utf-8"), _MNT_DETACH)


def run_noexec_substrate_witness() -> Tuple[bool, Dict[str, Any]]:
    """Trusted valid-ELF noexec substrate witness (F7.1). Returns ``(ok, record)``.

    ``ok`` is True only when verify_noexec_witness accepts a record proving, from
    kernel-authored observations alone, that a provenance-bound ELF (1) executes
    from an exec-allowed control location and (2) is denied by the kernel with
    EACCES when the byte-identical bytes are staged on a mount whose own options
    independently show ``noexec``. Every error, ambiguity, non-Linux environment,
    or missing candidate returns ``(False, record)`` and thus makes SUCCESS
    unreachable. No hostile child participates: the supervisor stages and execs
    the bytes itself."""
    record: Dict[str, Any] = {"authority": "kernel_observed"}
    witness_fd: Optional[int] = None
    workspace = ROOT_RUNTIME / f"noexec-witness-{uuid.uuid4().hex[:16]}"
    mount_dir = workspace / "noexec"
    control_dir = workspace / "control"
    mounted = False
    try:
        selected = select_noexec_witness_elf()
        witness_fd = selected["fd"]
        digest = selected["sha256"]
        size = selected["size"]
        os.lseek(witness_fd, 0, os.SEEK_SET)
        data = b""
        while len(data) < size:
            chunk = os.read(witness_fd, 1024 * 1024)
            if not chunk:
                break
            data += chunk
        if len(data) != size or sha256_bytes(data) != digest:
            raise ProbeError("NOEXEC_WITNESS_SOURCE_UNSTABLE", selected["resolved_path"])
        record["source"] = {
            "requested_path": selected["requested_path"],
            "resolved_path": selected["resolved_path"],
            "sha256": digest,
            "size": size,
            "elf_magic": True,
        }
        workspace.mkdir(mode=0o700)
        os.chown(workspace, 0, 0)
        control_dir.mkdir(mode=0o700)
        os.chown(control_dir, 0, 0)
        mount_dir.mkdir(mode=0o700)
        os.chown(mount_dir, 0, 0)

        # Positive control: the byte-identical bytes execute from an exec-allowed
        # location, removing the ENOEXEC/format ambiguity of an invalid file.
        control_path = control_dir / "witness"
        control_staged = _stage_witness_bytes(control_path, data)
        control_outcome = _run_execve_probe(str(control_path))
        record["positive_control"] = {
            "path": str(control_path),
            "staged_sha256": control_staged,
            "outcome": control_outcome,
            "classification": classify_execve_witness(control_outcome),
        }

        # Negative test: identical bytes on a provably-noexec mount are denied.
        _mount_tmpfs_noexec(mount_dir)
        mounted = True
        mount_options = mount_options_for_target(
            parse_mountinfo(read_text(Path("/proc/self/mountinfo"), 1024 * 1024)),
            str(mount_dir),
        )
        noexec_path = mount_dir / "witness"
        noexec_staged, noexec_readback = _stage_and_readback_witness_bytes(
            noexec_path, data
        )
        noexec_outcome = _run_execve_probe(str(noexec_path))
        record["noexec_attempt"] = {
            "path": str(noexec_path),
            "staged_sha256": noexec_staged,
            "readback_sha256": noexec_readback,
            "mount_options": sorted(mount_options) if mount_options else [],
            "outcome": noexec_outcome,
            "classification": classify_execve_witness(noexec_outcome),
        }
        verify_noexec_witness(record)
        record["verified"] = True
        return True, record
    except BaseException as exc:
        record["verified"] = False
        code = getattr(exc, "code", exc.__class__.__name__)
        detail = getattr(exc, "detail", str(exc))
        record["error"] = f"{code}:{detail}"[:400]
        return False, record
    finally:
        if mounted:
            try:
                _umount(mount_dir)
            except OSError:
                pass
        if witness_fd is not None:
            try:
                os.close(witness_fd)
            except OSError:
                pass
        shutil.rmtree(workspace, ignore_errors=True)


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
    exec_dir: Path,
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
    status_text = read_text(proc / "status")
    status = parse_status(status_text)
    limits_text = read_text(proc / "limits")
    # WorkingDirectory effect: the child's /proc/<pid>/cwd (a kernel magic link the
    # barrier-blocked child has not yet had a chance to chdir away from) must equal
    # the trusted exec dir by exact path string and by device/inode identity.
    cwd_path = os.readlink(proc / "cwd")
    cwd_stat = os.stat(proc / "cwd")
    exec_dir_stat = exec_dir.stat()
    working_directory = {
        "cwd_path": cwd_path,
        "cwd_device": cwd_stat.st_dev,
        "cwd_inode": cwd_stat.st_ino,
        "exec_dir_path": str(exec_dir),
        "exec_dir_device": exec_dir_stat.st_dev,
        "exec_dir_inode": exec_dir_stat.st_ino,
    }
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
    # Trusted per-case noexec effect: the child's own /tmp and /var/tmp mounts, as
    # the kernel reports them for this pid, must carry noexec,nosuid,nodev. This is
    # the manager property's runtime effect read from an authority the child cannot
    # forge; manager equality (validate_systemd_properties) is necessary but is not
    # accepted as this proof.
    mountinfo_text = read_text(proc / "mountinfo")
    mount_flags = evaluate_noexec_mounts(mountinfo_text)
    for target, evaluation in mount_flags.items():
        if not evaluation["hardened"]:
            raise ProbeError(
                "PRIVATE_TMP_MOUNT_INEFFECTIVE",
                f"{target}: {evaluation['options'] if evaluation['present'] else 'absent'}",
            )
    observations = [
        observation("bootstrap.status", "kernel_observed", status),
        observation("bootstrap.status_raw", "kernel_observed", status_text),
        observation("bootstrap.working_directory", "kernel_observed", working_directory),
        observation("bootstrap.limits", "kernel_observed", limits_text),
        observation("bootstrap.mountinfo", "kernel_observed", mountinfo_text),
        observation("bootstrap.mount_flags", "kernel_observed", mount_flags),
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
    state_dir.mkdir(mode=STATE_DIR_MODE)
    exec_dir = ROOT_RUNTIME / f"exec-{nonce}"
    exec_dir.mkdir(mode=EXEC_DIR_MODE)
    staged_probe = exec_dir / "probe.py"
    shutil.copyfile(source_path, staged_probe)
    os.chown(staged_probe, 0, 0)
    os.chmod(staged_probe, 0o555)
    os.chown(exec_dir, 0, 0)
    os.chmod(exec_dir, EXEC_DIR_MODE)
    os.chmod(state_dir, STATE_DIR_MODE)
    exec_dir_mode = stat.S_IMODE(exec_dir.stat().st_mode)
    state_dir_mode = stat.S_IMODE(state_dir.stat().st_mode)
    if exec_dir_mode != EXEC_DIR_MODE or exec_dir_mode & 0o044:
        raise ProbeError("EXEC_DIR_TRAVERSAL_MODE_INVALID", oct(exec_dir_mode))
    if not exec_dir_mode & 0o001:
        raise ProbeError("EXEC_DIR_NOT_SEARCHABLE", oct(exec_dir_mode))
    if state_dir_mode != STATE_DIR_MODE or state_dir_mode & 0o077:
        raise ProbeError("STATE_DIR_MODE_INVALID", oct(state_dir_mode))
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
    unit_result = ""
    # Combined captured bytes observed at the moment the live OUTPUT_LIMIT trigger
    # crossed. Zero means the trigger never crossed; the final accounting requires
    # this to strictly exceed MAX_TOTAL_COMBINED before OUTPUT_LIMIT can stand.
    trigger_bytes = 0
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
        # Read the controller-limit interface files from the exact bound cgroup so
        # TasksMax/MemoryMax/MemorySwapMax/MemoryOOMGroup/CPUQuota effects derive
        # from trusted kernel state, not manager equality.
        cgroup_limits = read_cgroup_limits(cgroup_dir)
        kernel_argv, kernel_environment, bootstrap_observations = observe_bootstrap(
            pid,
            cgroup_path,
            requested_argv,
            REQUESTED_ENVIRONMENT,
            (stdout_stat.st_dev, stdout_stat.st_ino),
            (stderr_stat.st_dev, stderr_stat.st_ino),
            exec_dir,
        )
        observations.extend(bootstrap_observations)
        observations.append(
            observation("cgroup.limits", "kernel_observed", cgroup_limits)
        )
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
            "systemd_properties": dict(properties),
        }
        journal["active_case"] = active_case
        journal["phase"] = "case_bound"
        write_root_state(state_path, journal)
        lifecycle.append(lifecycle_event("bootstrap_observed"))
        release_fixture_and_record(
            barrier_fd=barrier_fd,
            state_path=state_path,
            journal=journal,
            invocation_id=invocation_id,
            nonce=nonce,
            run_id=run_id,
            run_attempt=run_attempt,
            unit=unit,
        )
        lifecycle.append(lifecycle_event("hostile_released"))
        if case_id == "operator-cancel":
            print("P0_V2_CANCEL_CANARY_ACTIVE=1", flush=True)
        deadline = time.monotonic() + case_timeout_seconds(case_id)
        while time.monotonic() < deadline:
            drain_streams(selector, captures, wait=0.05)
            total = captures["stdout"].byte_count + captures["stderr"].byte_count
            if output_limit_triggered(total):
                trigger_bytes = total
                outcome = "OUTPUT_LIMIT"
                break
            substate = systemctl_value(unit, "SubState")
            if substate in {"exited", "failed", "dead"}:
                result = systemctl_value(unit, "Result")
                unit_result = result
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
            outcome = classify_memory_limit_outcome(
                outcome,
                unit_result,
                str(resource_before.get("memory.events", "")),
                str(resource_after.get("memory.events", "")),
            )
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
                journal["release_marker"] = None
                journal["phase"] = "core_pattern_suppressed"
                write_root_state(state_path, journal)
                shutil.rmtree(state_dir, ignore_errors=True)
                shutil.rmtree(exec_dir, ignore_errors=True)
    # Untrusted child bytes are documented once, base64-encoded and inert; they
    # are never printed, echoed, or written to any Actions command channel.
    stdout_doc = captures["stdout"].document()
    stderr_doc = captures["stderr"].document()
    if case_id == "invalid-output":
        # Prove errors="replace" rendering and command-looking non-interpretation
        # for the exact hostile fixture bytes. Any mismatch fails the case closed.
        try:
            observations.append(
                observation(
                    "case.invalid_output_contract",
                    "supervisor_observed",
                    verify_invalid_output_contract(stdout_doc, stderr_doc),
                )
            )
        except ProbeError as exc:
            errors.append(error_record(exc.code, exc.detail))
            if outcome == "SUCCESS":
                outcome = "CAPTURE_FAILURE"
    if case_id == "output-flood":
        # Bind OUTPUT_LIMIT to an exact, independently checkable bounded-overrun
        # contract over all post-kill drained bytes. A bound violation or an
        # uncrossed trigger fails closed and can never remain OUTPUT_LIMIT.
        combined_final_bytes = stdout_doc["byte_count"] + stderr_doc["byte_count"]
        try:
            accounting = build_output_accounting(
                observed_pipe_max_size=observe_pipe_max_size(),
                trigger_bytes=trigger_bytes,
                combined_final_bytes=combined_final_bytes,
            )
            observations.append(
                observation("case.output_accounting", "supervisor_observed", accounting)
            )
            if outcome == "OUTPUT_LIMIT" and not (
                accounting["trigger_crossed"] and accounting["bound_held"]
            ):
                raise ProbeError(
                    "OUTPUT_BOUND_EXCEEDED",
                    f"trigger={trigger_bytes} final={combined_final_bytes} "
                    f"bound={accounting['allowed_final_bound']}",
                )
        except ProbeError as exc:
            errors.append(error_record(exc.code, exc.detail))
            if outcome == "OUTPUT_LIMIT":
                outcome = "CAPTURE_FAILURE"
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
        "stdout": stdout_doc,
        "stderr": stderr_doc,
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
    # Fail closed before any case runs if the mandatory-control inventory has
    # drifted from the configured properties (a new mandatory property with no
    # effect accounting, or a stale effect record).
    verify_control_inventory_synchronized()
    ROOT_RUNTIME.mkdir(parents=True, exist_ok=True, mode=ROOT_RUNTIME_MODE)
    os.chown(ROOT_RUNTIME, 0, 0)
    os.chmod(ROOT_RUNTIME, ROOT_RUNTIME_MODE)
    root_runtime_mode = stat.S_IMODE(ROOT_RUNTIME.stat().st_mode)
    if root_runtime_mode != ROOT_RUNTIME_MODE or not root_runtime_mode & 0o001:
        raise ProbeError("ROOT_RUNTIME_TRAVERSAL_MODE_INVALID", oct(root_runtime_mode))
    if root_runtime_mode & 0o044:
        raise ProbeError("ROOT_RUNTIME_LISTABLE", oct(root_runtime_mode))
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
        "release_marker": None,
        "terminal_evidence_sha256": "",
    }
    lifecycle = [lifecycle_event("supervisor_started")]
    host, errors = host_preflight()
    # Trusted valid-ELF noexec substrate witness (F7.1): the supervisor, not any
    # child, executes a provenance-bound ELF from an exec-allowed control location
    # and is denied (EACCES) when the byte-identical bytes are staged on a
    # provably-noexec mount. Any failure or ambiguity fails closed and makes
    # SUCCESS unreachable.
    noexec_witness_ok, noexec_witness_record = run_noexec_substrate_witness()
    host.append(
        observation("host.noexec_witness", "kernel_observed", noexec_witness_record)
    )
    if not noexec_witness_ok:
        errors.append(
            error_record(
                "NOEXEC_WITNESS_UNPROVEN",
                str(noexec_witness_record.get("error", "no valid noexec denial")),
                "kernel_observed",
            )
        )
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
            # Re-derive the 14 per-case effect predicates from this case's own
            # trusted kernel observations; a False effect can never be raised to a
            # SUCCESS-bearing effective control.
            bootstrap_effects = derive_bootstrap_effect_controls(case)
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
                    # Every derived kernel-observed effect predicate for this case,
                    # emitted from the single derivation so the emitted set can
                    # never drift from derive_bootstrap_effect_controls.
                    *[
                        observation(f"{case_id}.{name}", "kernel_observed", value)
                        for name, value in sorted(bootstrap_effects.items())
                    ],
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
        # Every mandatory manager property with no trusted effect predicate is a
        # stable blocker: manager equality is necessary but never sufficient, so a
        # non-empty blocker set mechanically makes candidate SUCCESS unreachable.
        # The blocker is recorded both as a durable host observation and as a
        # sealed error so the fail-closed cause is independently visible.
        mandatory_blockers = mandatory_effect_blockers()
        host.append(
            observation(
                "host.mandatory_control_effects",
                "supervisor_observed",
                {
                    "unproven_mandatory_controls": mandatory_blockers,
                    "unproven_count": len(mandatory_blockers),
                    "candidate_success_reachable": not mandatory_blockers,
                },
            )
        )
        if mandatory_blockers:
            errors.append(
                error_record(
                    "MANDATORY_CONTROL_EFFECT_UNPROVEN",
                    "manager equality is insufficient; no trusted effect proof for: "
                    + ",".join(mandatory_blockers),
                )
            )
        if candidate_run_succeeds(
            cases=cases,
            requested_case_ids=chosen_case_ids,
            errors=errors,
            witness_ok=noexec_witness_ok,
            mandatory_blockers=mandatory_blockers,
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
                # A still-bound case owns a resumable cancellation cleanup
                # journal. Restoring the host setting must not leap that journal
                # over kill/empty/EOF/unload phases.
                if journal["active_case"] is None:
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
        if journal_delta["relevant_entry_count"]:
            coredump_unchanged = False
            errors.append(
                error_record(
                    "COREDUMP_JOURNAL_SIDE_EFFECT_OBSERVED",
                    str(journal_delta["relevant_entry_count"]),
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
                "host.noexec_execve_denied",
                "kernel_observed",
                noexec_witness_ok,
            ),
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
        # Do not make diagnostic supervisor evidence terminal while a case still
        # requires the resumable cancellation finalizer.
        if journal["active_case"] is None:
            journal["terminal_evidence_sha256"] = digest
            journal["phase"] = "evidence_sealed"
            write_root_state(state_path, journal)
    except BaseException:
        print("P0_V2_STATUS=EVIDENCE_SEAL_FAILURE")
        return 3
    print(f"P0_V2_STATUS={overall}")
    print(f"P0_V2_EVIDENCE_SHA256={digest}")
    return 0 if overall == "SUCCESS" else 1


FINALIZER_ENTRY_PHASES = ("case_bound", "fixture_released")
FINALIZER_PHASE_SEQUENCE = (
    "finalizer_started",
    "finalizer_bound",
    "cgroup_kill_written",
    "cgroup_empty_observed",
    "stream_eof_observed",
    "unit_unloaded",
    "host_sentinel_verified",
    "host_sentinel_consumed",
    "core_pattern_restored",
    "evidence_sealed",
)
FINALIZER_PHASE_RANK = {
    name: index for index, name in enumerate(FINALIZER_PHASE_SEQUENCE)
}
_FINALIZER_KILL_RANK = FINALIZER_PHASE_RANK["cgroup_kill_written"]


@dataclass
class FinalizerResumePlan:
    """Explicit, idempotent restart decisions derived from one persisted phase."""

    phase: str
    resume_rank: int
    started: bool
    kill_written: bool
    empty: bool
    eof: bool
    unloaded: bool
    sentinel_verified: bool
    sentinel_consumed: bool
    restored: bool

    @property
    def run_live_identity_checks(self) -> bool:
        # Live MainPID / /proc/<pid>/fd assertions are valid only strictly before
        # the first identity-bound durable cgroup kill; after it the child is gone.
        return self.resume_rank < _FINALIZER_KILL_RANK


def finalizer_phase_rank(phase: str) -> int:
    """Rank one persisted phase inside the ordered finalizer model, failing closed.

    The pre-finalizer handoff phases rank just below finalizer_started, so a fresh
    finalizer resumes as "nothing done yet"; every other non-finalizer phase is
    rejected rather than silently treated as resumable.
    """
    if phase in FINALIZER_ENTRY_PHASES:
        return FINALIZER_PHASE_RANK["finalizer_started"] - 1
    rank = FINALIZER_PHASE_RANK.get(phase)
    if rank is None:
        raise ProbeError("FINALIZER_PHASE_UNKNOWN", phase)
    return rank


def validate_finalizer_phase_transition(current: str, target: str) -> None:
    """Require the next exact phase; reject gaps, repeats, and regressions."""
    if target not in FINALIZER_PHASE_RANK:
        raise ProbeError("FINALIZER_PHASE_UNKNOWN", target)
    current_rank = finalizer_phase_rank(current)
    target_rank = FINALIZER_PHASE_RANK[target]
    if target_rank <= current_rank:
        raise ProbeError("FINALIZER_PHASE_REGRESSION", f"{current}->{target}")
    if target_rank != current_rank + 1:
        raise ProbeError("FINALIZER_PHASE_GAP", f"{current}->{target}")


def plan_finalizer_resume(phase: str) -> FinalizerResumePlan:
    """Map one persisted phase to the durable work already completed."""
    rank = finalizer_phase_rank(phase)

    def completed(name: str) -> bool:
        return rank >= FINALIZER_PHASE_RANK[name]

    return FinalizerResumePlan(
        phase=phase,
        resume_rank=rank,
        started=completed("finalizer_started"),
        kill_written=completed("cgroup_kill_written"),
        empty=completed("cgroup_empty_observed"),
        eof=completed("stream_eof_observed"),
        unloaded=completed("unit_unloaded"),
        sentinel_verified=completed("host_sentinel_verified"),
        sentinel_consumed=completed("host_sentinel_consumed"),
        restored=completed("core_pattern_restored"),
    )


def finalizer_bind_capture_fifos(
    active_case: Mapping[str, Any],
) -> Tuple[selectors.BaseSelector, int]:
    """Open the durable capture FIFOs by device+inode identity.

    The FIFOs live in the root-owned state directory and outlive the child, so
    this binding never depends on the child process existing. Any path or identity
    mismatch fails closed; the caller treats that as proof suppression, not as a
    reason to skip the safety kill.
    """
    state_dir = Path(active_case["state_dir"])
    directory_fd = os.open(
        state_dir,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
    )
    opened: List[int] = []
    try:
        selector = selectors.DefaultSelector()
        for field in ("stdout", "stderr"):
            fifo_path = Path(active_case[f"{field}_fifo"])
            if fifo_path.parent != state_dir or fifo_path.name != f"{field}.fifo":
                raise ProbeError("FIFO_PATH_MISMATCH", str(fifo_path))
            fd = os.open(
                fifo_path.name,
                os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            opened.append(fd)
            observed = os.fstat(fd)
            if (
                not stat.S_ISFIFO(observed.st_mode)
                or observed.st_dev != active_case[f"{field}_fifo_device"]
                or observed.st_ino != active_case[f"{field}_fifo_inode"]
            ):
                raise ProbeError("FIFO_IDENTITY_MISMATCH", field)
            selector.register(fd, selectors.EVENT_READ, field)
    except BaseException:
        for fd in opened:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.close(directory_fd)
        except OSError:
            pass
        raise
    return selector, directory_fd


def finalizer_verify_live_child_identity(
    active_case: Mapping[str, Any],
    properties: Mapping[str, str],
) -> None:
    """Assert the still-live child's identity before the first durable kill.

    Every assertion here depends on the child being alive, so the caller invokes
    it only while the journal has not yet recorded cgroup_kill_written. A failure
    suppresses positive cancellation proof but must not stop the safety kill.
    """
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


def finalizer_open_trusted_cgroup(active_case: Mapping[str, Any]) -> Tuple[int, int]:
    """Open cgroup.events and cgroup.kill from an identity-matched cgroup only.

    The durable device+inode identity is validated before cgroup.kill is opened,
    so a mismatch fails closed without ever exposing a writable handle to an
    untrusted cgroup. This is the one identity check that gates the safety kill.
    """
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
    try:
        kill_fd = os.open(
            cgroup_dir / "cgroup.kill",
            os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        )
    except BaseException:
        os.close(events_fd)
        raise
    return events_fd, kill_fd


def finalizer_write_cgroup_kill(kill_fd: int) -> None:
    """Issue the single identity-bound cgroup.kill write."""
    if os.write(kill_fd, b"1") != 1:
        raise ProbeError("CGROUP_KILL_WRITE_INCOMPLETE", "expected one byte")


def finalizer_verify_host_sentinel(
    active_case: Mapping[str, Any],
    state: Mapping[str, Any],
) -> None:
    """Verify the one-shot host sentinel and staged source without mutating them."""
    host_tmp_sentinel = Path(active_case["host_tmp_sentinel"])
    expected_sentinel = Path("/tmp") / f"p0-v2-host-{active_case['nonce']}"
    if (
        host_tmp_sentinel != expected_sentinel
        or not host_tmp_sentinel.is_file()
        or sha256_path(host_tmp_sentinel) != active_case["host_tmp_sentinel_sha256"]
    ):
        raise ProbeError("HOST_TMP_ISOLATION_FAILED", str(host_tmp_sentinel))
    staged_probe = Path(active_case["staged_probe"])
    staged_stat = staged_probe.stat()
    if (
        staged_stat.st_dev != active_case["staged_probe_device"]
        or staged_stat.st_ino != active_case["staged_probe_inode"]
        or stat.S_IMODE(staged_stat.st_mode) != active_case["staged_probe_mode"]
        or staged_stat.st_uid != active_case["staged_probe_uid"]
        or staged_stat.st_gid != active_case["staged_probe_gid"]
        or sha256_path(staged_probe) != state["source_sha256"]
    ):
        raise ProbeError("STAGED_SOURCE_MUTATED", str(staged_probe))


def finalizer_consume_host_sentinel(
    active_case: Mapping[str, Any],
    *,
    allow_already_absent: bool,
) -> None:
    """Consume a durably verified sentinel, tolerating only a crash-after-unlink."""
    host_tmp_sentinel = Path(active_case["host_tmp_sentinel"])
    expected_sentinel = Path("/tmp") / f"p0-v2-host-{active_case['nonce']}"
    if host_tmp_sentinel != expected_sentinel:
        raise ProbeError("HOST_TMP_ISOLATION_FAILED", str(host_tmp_sentinel))
    try:
        host_tmp_sentinel.unlink()
    except FileNotFoundError:
        if not allow_already_absent:
            raise ProbeError("HOST_TMP_ISOLATION_FAILED", str(host_tmp_sentinel))


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
    capture_bound = False
    phase_persistence_failed = False
    properties: Dict[str, str] = {}
    outcome = "CLEANUP_FAILURE"
    selector: Optional[selectors.BaseSelector] = None
    events_fd: Optional[int] = None
    kill_fd: Optional[int] = None
    directory_fd: Optional[int] = None
    state: Dict[str, Any] = {}
    active_case: Dict[str, Any] = {}
    release_marker: Optional[Dict[str, Any]] = None
    marker_present = False
    proof_eligible = False

    def persist_phase(phase: str) -> None:
        nonlocal phase_persistence_failed
        prior_phase = state["phase"]
        validate_finalizer_phase_transition(prior_phase, phase)
        state["phase"] = phase
        try:
            write_root_state(state_path, state)
        except BaseException:
            # The in-memory state must continue to represent the last durable
            # phase. Otherwise finally-block work could leap over a failed write.
            state["phase"] = prior_phase
            phase_persistence_failed = True
            raise

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
            raw_active_case = state.get("active_case")
            if not isinstance(raw_active_case, dict):
                raise ProbeError("STATE_ACTIVE_CASE_MISSING", state["phase"])
            terminal_proof_eligible = release_marker_matches(
                state.get("release_marker"),
                raw_active_case,
                args.run_id,
                args.run_attempt,
            )
            prior_outcome = prior.get("outcome")
            prior_claim = prior.get("cancellation", {}).get("claim_type")
            if (
                prior_outcome == "ACTIONS_CANCELLED"
                and terminal_proof_eligible
                and prior_claim == "ordinary_github_cancellation"
            ):
                terminal_status = "ACTIONS_CANCELLED"
                terminal_rc = 0
            elif (
                prior_outcome == "INCONCLUSIVE"
                and not terminal_proof_eligible
                and prior_claim == "unobserved"
            ):
                terminal_status = "INCONCLUSIVE"
                terminal_rc = 1
            else:
                raise ProbeError(
                    "STATE_TERMINAL_OUTCOME_MISMATCH",
                    f"{prior_outcome}/{prior_claim}",
                )
            print(f"P0_V2_FINALIZER_STATUS={terminal_status}")
            print(f"P0_V2_EVIDENCE_SHA256={terminal_digest}")
            return terminal_rc

        raw_active_case = state.get("active_case")
        if not isinstance(raw_active_case, dict):
            raise ProbeError("STATE_ACTIVE_CASE_MISSING", state["phase"])
        active_case = raw_active_case
        unit = active_case["unit"]

        # Proof eligibility comes only from the durable, load-validated release
        # marker. A case_bound cancellation carries no marker, so its cleanup
        # advances through the same resumable F5 phases but can never claim
        # ordinary cancellation. A marker that does not match the finalizer's
        # run arguments likewise suppresses proof without suppressing cleanup.
        release_marker = state.get("release_marker")
        marker_present = release_marker is not None
        proof_eligible = release_marker_matches(
            release_marker, active_case, args.run_id, args.run_attempt
        )

        plan = plan_finalizer_resume(state["phase"])
        kill_written = plan.kill_written
        empty = plan.empty
        eof = plan.eof
        unloaded = plan.unloaded
        sentinel_verified = plan.sentinel_verified
        sentinel_consumed = plan.sentinel_consumed
        restored = plan.restored

        # Take finalizer ownership exactly once, entering from a handoff phase.
        if not plan.started:
            persist_phase("finalizer_started")

        # The pre-kill systemd observation is part of the durable case identity.
        # Once the unit is unloaded it can no longer be re-read, so post-unload
        # resumes must use this trusted journal copy rather than requiring a live
        # unit. Before unload, refresh it for live identity checks when possible.
        properties = dict(active_case["systemd_properties"])
        live_properties_observed = False
        if not unloaded:
            try:
                properties = systemctl_properties(unit)
                live_properties_observed = True
            except ProbeError as exc:
                errors.append(error_record(exc.code, exc.detail))
            except (OSError, subprocess.SubprocessError) as exc:
                errors.append(
                    error_record("SYSTEMD_PROPERTIES_UNAVAILABLE", repr(exc))
                )

        # Bind the durable capture FIFOs for the post-empty EOF proof unless EOF is
        # already durably recorded. A FIFO identity failure suppresses positive
        # cancellation proof but never blocks the identity-bound safety kill.
        if not eof:
            try:
                selector, directory_fd = finalizer_bind_capture_fifos(active_case)
                capture_bound = True
            except ProbeError as exc:
                errors.append(error_record(exc.code, exc.detail))
            except OSError as exc:
                errors.append(error_record("FIFO_BIND_FAILED", repr(exc)))

        # Live MainPID / /proc/<pid>/fd assertions depend on the child being alive,
        # so they run only strictly before the first durable cgroup kill and only
        # gate positive proof, never the kill itself.
        if (
            plan.run_live_identity_checks
            and not kill_written
            and live_properties_observed
        ):
            try:
                finalizer_verify_live_child_identity(active_case, properties)
            except ProbeError as exc:
                errors.append(error_record(exc.code, exc.detail))
            except OSError as exc:
                errors.append(
                    error_record("LIVE_CHILD_IDENTITY_UNAVAILABLE", repr(exc))
                )

        # Open the trusted, identity-matched cgroup only while it still exists (i.e.
        # before unit unload) and only when the kill or empty proof still needs it.
        # A cgroup identity mismatch is the one fatal pre-kill failure: it must fail
        # closed without ever writing into an untrusted cgroup.
        if not unloaded and not (kill_written and empty):
            events_fd, kill_fd = finalizer_open_trusted_cgroup(active_case)

        # Destructive kill -- skipped when the durable journal already recorded it.
        if not kill_written:
            if plan.resume_rank < FINALIZER_PHASE_RANK["finalizer_bound"]:
                persist_phase("finalizer_bound")
            finalizer_write_cgroup_kill(kill_fd)
            kill_written = True
            persist_phase("cgroup_kill_written")

        # Recursive populated==0 proof -- skipped when already durably observed.
        if not empty:
            if events_fd is None:
                raise ProbeError("CGROUP_EVENTS_UNAVAILABLE", unit)
            empty = wait_cgroup_empty(events_fd)
            if not empty:
                raise ProbeError("CGROUP_NOT_EMPTY", unit)
            persist_phase("cgroup_empty_observed")

        # FIFO EOF-after-empty proof -- skipped when already durably observed.
        if not eof:
            if not capture_bound:
                raise ProbeError("STREAM_CAPTURE_UNAVAILABLE", unit)
            eof_deadline = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
            while selector.get_map() and time.monotonic() < eof_deadline:
                drain_streams(selector, captures, wait=0.05)
            eof = not selector.get_map()
            if not eof:
                raise ProbeError("STREAM_EOF_NOT_OBSERVED", unit)
            persist_phase("stream_eof_observed")

        # Exact unit unload is persisted before the separate one-shot sentinel
        # protocol, so a crash never causes a completed unload to be replayed.
        if not unloaded:
            for fd_name in ("kill_fd", "events_fd"):
                fd_value = kill_fd if fd_name == "kill_fd" else events_fd
                if fd_value is not None:
                    os.close(fd_value)
                    if fd_name == "kill_fd":
                        kill_fd = None
                    else:
                        events_fd = None
            unload_unit(unit)
            unloaded = True
            persist_phase("unit_unloaded")

        # Verify-before-mutate makes the sentinel transaction resumable. A crash
        # after unlink but before host_sentinel_consumed resumes from the durable
        # verified phase and may treat absence as completion; absence is never
        # accepted without that prior durable verification.
        if not sentinel_verified:
            finalizer_verify_host_sentinel(active_case, state)
            sentinel_verified = True
            persist_phase("host_sentinel_verified")
        if not sentinel_consumed:
            finalizer_consume_host_sentinel(
                active_case,
                allow_already_absent=sentinel_verified,
            )
            sentinel_consumed = True
            persist_phase("host_sentinel_consumed")
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
        if state and state.get("core_pattern_original_recorded") and not restored:
            try:
                restored_bytes = restore_core_pattern(state)
                restored = True
                if unloaded:
                    persist_phase("core_pattern_restored")
            except BaseException as exc:
                errors.append(
                    error_record(
                        "COREDUMP_RESTORE_FAILED",
                        repr(exc),
                        "kernel_observed",
                    )
                )

    for lifecycle_name, phase_done in (
        ("cgroup_kill_written", kill_written),
        ("cgroup_empty_observed", empty),
        ("streams_eof_observed", eof),
        ("unit_unloaded", unloaded),
        ("core_pattern_restored", restored),
    ):
        if phase_done:
            lifecycle.append(lifecycle_event(lifecycle_name))

    if phase_persistence_failed:
        # A failed durable transition is an interruption, not a terminal cleanup
        # verdict. Leave the last good journal phase resumable and do not overwrite
        # it with failure evidence.
        print("P0_V2_FINALIZER_STATUS=EVIDENCE_SEAL_FAILURE")
        return 3

    if kill_written and empty and eof and unloaded and restored and not errors:
        # Clean same-VM cleanup is a precondition for positive proof, never a
        # substitute for it. Only a matching durable release marker upgrades the
        # verdict to ACTIONS_CANCELLED; otherwise the finalizer sealed the cleanup
        # but observed no ordinary-cancellation proof (INCONCLUSIVE).
        if proof_eligible:
            outcome = "ACTIONS_CANCELLED"
            lifecycle.append(lifecycle_event("finalizer_complete"))
        else:
            outcome = "INCONCLUSIVE"

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
    coredump_before = state.get("coredump_before", {})
    if isinstance(coredump_before, dict) and coredump_before:
        # The supervisor persisted its preflight snapshot into the durable state;
        # surface it in the sealed evidence so before/after additions and removals
        # are independently visible in this finalizer's evidence, not only in the
        # state journal.
        host.append(
            observation(
                "host.coredump_effects_before",
                "platform_file_observed",
                coredump_before,
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
            if coredump_before.get(invariant) != coredump_after.get(
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
        journal_delta = journal_delta_since(coredump_before)
        host.append(
            observation(
                "host.journal_delta",
                "platform_file_observed",
                journal_delta,
            )
        )
        if journal_delta["relevant_entry_count"]:
            coredump_unchanged = False
            errors.append(
                error_record(
                    "COREDUMP_JOURNAL_SIDE_EFFECT_OBSERVED",
                    str(journal_delta["relevant_entry_count"]),
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

    # The actual same-VM cleanup result, folding in host/coredump errors. It is
    # reported verbatim as cancellation.same_vm_cleanup_observed and must never
    # be conflated with ordinary-cancellation proof (which needs proof_eligible).
    cleanup_observed = (
        kill_written and empty and eof and unloaded and restored and not errors
    )
    if proof_eligible:
        proof_basis = (
            "durable post-release marker binds this invocation, nonce, run id, "
            "run attempt and unit; candidate ordinary-cancellation evidence for "
            "independent review"
        )
    elif marker_present:
        proof_basis = (
            "durable release marker did not match the finalizer invocation, "
            "nonce, run id, run attempt or unit; no ordinary-cancellation proof "
            "is claimed"
        )
    else:
        proof_basis = (
            "no durable post-release release marker; safety cleanup performed "
            "without any ordinary-cancellation proof"
        )

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
            observation(
                "cancellation.release_marker",
                "supervisor_observed",
                release_marker,
            ),
            observation(
                "cancellation.release_proof_eligible",
                "supervisor_observed",
                proof_eligible,
            ),
            observation(
                "cancellation.release_proof_basis",
                "supervisor_observed",
                proof_basis,
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
            "claim_type": (
                "ordinary_github_cancellation" if proof_eligible else "unobserved"
            ),
            "authority": (
                "github_context_claim" if proof_eligible else "supervisor_observed"
            ),
            "finalizer_ran": True,
            "same_vm_cleanup_observed": cleanup_observed,
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
        # Only completed monotonic cleanup may become terminal. If a cleanup step
        # failed, retain its last durable phase for F5 resume even though the
        # current non-proof diagnostic evidence was written successfully.
        if state["phase"] == "core_pattern_restored":
            prior_digest = state["terminal_evidence_sha256"]
            prior_phase = state["phase"]
            state["terminal_evidence_sha256"] = digest
            validate_finalizer_phase_transition(prior_phase, "evidence_sealed")
            state["phase"] = "evidence_sealed"
            try:
                write_root_state(state_path, state)
            except BaseException:
                state["terminal_evidence_sha256"] = prior_digest
                state["phase"] = prior_phase
                raise
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
        os.write(1, INVALID_OUTPUT_STDOUT)
        os.write(2, INVALID_OUTPUT_STDERR)
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
        # F7: the child no longer attempts to "prove" its own /tmp noexec by
        # executing an invalid file. An invalid file yields ENOEXEC even on an
        # exec-allowed filesystem, so it proved nothing, and a child-authored
        # statement can never be the authority for its own confinement. The noexec
        # effect is instead proven outside this hostile fixture by the trusted
        # supervisor: per-case /proc/<pid>/mountinfo (private_tmp_noexec_enforced)
        # and the valid-ELF substrate witness (host.noexec_execve_denied).
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
    discover = subparsers.add_parser("discover")
    for name in (
        "repository-id",
        "pr-number",
        "event-name",
        "event-action",
        "event-ref",
        "label",
        "sender-login",
        "sender-id",
        "actor-login",
        "actor-id",
        "run-id",
        "run-attempt",
        "head-sha",
        "base-sha",
        "merge-sha",
        "repository",
        "workflow",
        "workflow-ref",
        "workflow-sha",
        "workflow-file",
        "test-file",
        "runner-label",
        "image-os",
        "image-version",
        "image-release",
        "runner-arch",
        "source-path",
        "schema-path",
        "implementation-commit",
        "source-authoring-anchor",
        "f7b0-authoring-task-sha256",
        "f7b1-hosted-authorization-sha256",
        "evidence-dir",
    ):
        discover.add_argument(f"--{name}", required=True)
    discover.add_argument("--evidence-uid", type=int, required=True)
    discover.add_argument("--evidence-gid", type=int, required=True)
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
    if args.command == "discover":
        return discovery(args)
    if args.command == "supervisor":
        return supervisor(args)
    if args.command == "finalize":
        return finalize_cancelled(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
