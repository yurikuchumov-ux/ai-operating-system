#!/usr/bin/env python3
"""Build a bounded, explicitly untrusted Partner Preview patch.

This module is not an execution verifier and never runs candidate code.  It
supports the three-job Preview workflow:

* ``prepare`` copies only immutable-task-approved UTF-8 files into a plain
  provider tree with no Git or Claude project configuration;
* ``snapshot`` serializes the provider candidate as untrusted JSON;
* ``package`` runs on a fresh runner, treats that JSON as hostile data, and
  emits exactly three deterministic, manually reviewed Preview files.

The resulting package proves only that the serialized bytes satisfy this
small structural and task-scope policy.  It does not prove correctness,
security, provenance, test success, or benign intent.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import difflib
import fnmatch
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple


LABEL = "UNTRUSTED PREVIEW"
SAFETY_STATEMENT = (
    "UNTRUSTED PREVIEW. This workflow has no repository write or publication "
    "authority. The author job and all provider-origin output are untrusted. "
    "A separate packaging job checks artifact structure and task scope only; "
    "it does not establish correctness, benign intent, provenance, "
    "verification, or test success. A human must inspect every changed byte, "
    "apply selected changes manually, and first execute them only in "
    "secretless, read-only CI."
)

SNAPSHOT_FORMAT = "p0-partner-preview-candidate.v1"
MANIFEST_FORMAT = "p0-partner-preview-package.v1"
MAX_PATHS = 64
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_PATCH_BYTES = 16 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 12 * 1024 * 1024
MAX_TASK_BYTES = 1024 * 1024
MAX_CONTEXT_PATHS = 64
FIXED_OUTPUT_FILES = (
    "UNTRUSTED-PREVIEW.json",
    "changes.patch",
    "summary.md",
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")
SECRET_MARKERS = (
    b"ghp_",
    b"github_pat_",
    b"sk-ant-",
    b"sk-proj-",
)
CONTROL_PATHS = frozenset(
    {
        ".git",
        ".mcp.json",
        ".claude",
        "CLAUDE.md",
        "output.txt",
        "TASK.json",
        "INSTRUCTIONS.md",
        "provider-input-manifest.json",
        "candidate.snapshot.json",
        "UNTRUSTED-PREVIEW.json",
        "changes.patch",
        "summary.md",
    }
)


class PreviewError(ValueError):
    """A deterministic fail-closed Preview rejection."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _fail(code: str, message: str) -> None:
    raise PreviewError(code, message)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(document: Any) -> bytes:
    return (
        json.dumps(
            document,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    ).encode("utf-8")


def _reject_duplicate_keys(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("E_DUPLICATE", "duplicate JSON key: {}".format(key))
        result[key] = value
    return result


def _load_json_bytes(raw: bytes, *, source: str) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        _fail("E_TEXT_ONLY", "{} is not UTF-8: {}".format(source, exc))
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except PreviewError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        _fail("E_JSON", "{} is not valid JSON: {}".format(source, exc))


def _read_bounded(path: Path, limit: int, *, code: str, description: str) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        _fail(code, "cannot stat {}: {}".format(description, exc))
    if size > limit:
        _fail(code, "{} exceeds {} bytes".format(description, limit))
    try:
        raw = path.read_bytes()
    except OSError as exc:
        _fail(code, "cannot read {}: {}".format(description, exc))
    if len(raw) > limit:
        _fail(code, "{} exceeds {} bytes".format(description, limit))
    return raw


def _canonical_path(value: Any) -> str:
    if not isinstance(value, str) or not value:
        _fail("E_PATH", "path must be a non-empty string")
    if (
        "\x00" in value
        or "\r" in value
        or "\n" in value
        or "\\" in value
        or value.startswith("/")
        or value.endswith("/")
        or "//" in value
    ):
        _fail("E_PATH", "unsafe path syntax: {!r}".format(value))
    if unicodedata.normalize("NFC", value) != value:
        _fail("E_PATH", "path is not NFC-normalized: {!r}".format(value))
    path = PurePosixPath(value)
    parts = path.parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        _fail("E_PATH", "unsafe path component: {!r}".format(value))
    if str(path) != value:
        _fail("E_PATH", "path is not canonical: {!r}".format(value))
    if any(not SAFE_SEGMENT_RE.fullmatch(part) for part in parts):
        _fail("E_PATH", "path contains unsupported characters: {!r}".format(value))
    return value


def _is_control_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if any(part in {".git", ".claude"} for part in parts):
        return True
    if parts and parts[-1] in CONTROL_PATHS:
        return True
    return path in CONTROL_PATHS


def _exact_path_list(values: Any, *, field: str, limit: int) -> List[str]:
    if not isinstance(values, list):
        _fail("E_TASK", "{} must be a list".format(field))
    if len(values) > limit:
        _fail("E_LIMIT", "{} exceeds {} paths".format(field, limit))
    result: List[str] = []
    folded: MutableMapping[str, str] = {}
    for value in values:
        path = _canonical_path(value)
        if any(char in path for char in "*?[]"):
            _fail("E_PATH", "{} must contain exact paths, not globs: {}".format(field, path))
        if _is_control_path(path):
            _fail("E_CONTROL_PATH", "{} contains control path: {}".format(field, path))
        folded_path = path.casefold()
        if path in result or folded_path in folded:
            _fail("E_PATH", "duplicate or case-fold-colliding path: {}".format(path))
        folded[folded_path] = path
        result.append(path)
    return sorted(result)


def _task_context_paths(task: Mapping[str, Any]) -> List[str]:
    collected: List[str] = []
    for criterion in task.get("acceptance_criteria", []):
        if not isinstance(criterion, Mapping):
            continue
        parameters = criterion.get("parameters", {})
        if isinstance(parameters, Mapping):
            values = parameters.get("preview_context_paths", [])
            if values:
                if not isinstance(values, list):
                    _fail("E_TASK", "preview_context_paths must be a list")
                collected.extend(values)
    return _exact_path_list(
        collected, field="preview_context_paths", limit=MAX_CONTEXT_PATHS
    )


def _load_task(task_path: Path, schema_path: Optional[Path]) -> Tuple[Mapping[str, Any], bytes]:
    raw = _read_bounded(task_path, MAX_TASK_BYTES, code="E_TASK", description="task")
    document = _load_json_bytes(raw, source="task")
    if not isinstance(document, Mapping):
        _fail("E_TASK", "task must be a JSON object")

    # Run path semantics before the general schema so path attacks retain one
    # exact machine-readable reason code instead of collapsing into E_TASK.
    allowed = _exact_path_list(
        document.get("allowed_paths"), field="allowed_paths", limit=MAX_PATHS
    )
    context = _task_context_paths(document)

    if schema_path is not None:
        schema_raw = _read_bounded(
            schema_path, MAX_TASK_BYTES, code="E_TASK", description="task schema"
        )
        schema = _load_json_bytes(schema_raw, source="task schema")
        try:
            from jsonschema import Draft202012Validator, FormatChecker
        except ModuleNotFoundError:
            _fail("E_TASK", "jsonschema is required for immutable-task validation")
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
        if errors:
            first = errors[0]
            _fail(
                "E_TASK",
                "task schema validation failed at {}: {}".format(
                    "/".join(str(part) for part in first.path) or "$", first.message
                ),
            )

    required_strings = ("repository", "task_id", "base_ref", "branch")
    for field in required_strings:
        if not isinstance(document.get(field), str) or not document[field]:
            _fail("E_TASK", "task field {} is missing".format(field))
    if document.get("schema_version") != "1.0.0":
        _fail("E_TASK", "unsupported task schema version")
    if not SHA_RE.fullmatch(str(document.get("base_sha", ""))):
        _fail("E_TASK", "task base_sha must be a full lowercase SHA")

    denied = document.get("denied_paths")
    if not isinstance(denied, list) or not all(isinstance(item, str) for item in denied):
        _fail("E_TASK", "denied_paths must be a string list")
    for path in allowed:
        if any(fnmatch.fnmatchcase(path, pattern) for pattern in denied):
            _fail("E_SCOPE", "allowed path is also denied: {}".format(path))
    overlap = sorted(set(allowed) & set(context))
    if overlap:
        _fail("E_TASK", "context paths overlap editable paths: {}".format(overlap))

    normalized = dict(document)
    normalized["allowed_paths"] = allowed
    normalized["_preview_context_paths"] = context
    return normalized, raw


def _lstat_path(root: Path, rel_path: str) -> Optional[os.stat_result]:
    current = root
    parts = PurePosixPath(rel_path).parts
    for index, part in enumerate(parts):
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            _fail("E_PATH_TYPE", "cannot inspect {}: {}".format(rel_path, exc))
        if stat.S_ISLNK(info.st_mode):
            _fail("E_SYMLINK", "symlink is forbidden: {}".format(rel_path))
        if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            _fail("E_PATH_TYPE", "parent is not a directory: {}".format(rel_path))
    return info


def _metadata_names(path: Path) -> List[str]:
    try:
        return list(os.listxattr(path, follow_symlinks=False))
    except (AttributeError, NotImplementedError):
        return []
    except OSError as exc:
        _fail("E_METADATA", "cannot inspect metadata for {}: {}".format(path, exc))


def _stable_regular_file(
    root: Path,
    rel_path: str,
    *,
    reject_metadata: bool,
) -> Optional[Tuple[bytes, int]]:
    info = _lstat_path(root, rel_path)
    if info is None:
        return None
    if not stat.S_ISREG(info.st_mode):
        _fail("E_SPECIAL", "path is not a regular file: {}".format(rel_path))
    if info.st_nlink != 1:
        _fail("E_HARDLINK", "hardlinks are forbidden: {}".format(rel_path))
    mode = stat.S_IMODE(info.st_mode)
    if mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
        _fail("E_MODE", "special mode bits are forbidden: {}".format(rel_path))
    full_path = root / rel_path
    if reject_metadata and _metadata_names(full_path):
        _fail("E_METADATA", "extended metadata is forbidden: {}".format(rel_path))

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(full_path, flags)
    except OSError as exc:
        _fail("E_UNSTABLE", "cannot open {} safely: {}".format(rel_path, exc))
    try:
        opened = os.fstat(descriptor)
        identity = (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
        )
        opened_identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
        )
        if opened_identity != identity:
            _fail("E_UNSTABLE", "file changed before read: {}".format(rel_path))
        if opened.st_size > MAX_FILE_BYTES:
            _fail("E_LIMIT", "file exceeds 1 MiB: {}".format(rel_path))
        chunks: List[bytes] = []
        remaining = MAX_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > MAX_FILE_BYTES:
            _fail("E_LIMIT", "file exceeds 1 MiB: {}".format(rel_path))
        after = os.fstat(descriptor)
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
        )
        if after_identity != opened_identity or len(data) != opened.st_size:
            _fail("E_UNSTABLE", "file changed during read: {}".format(rel_path))
    finally:
        os.close(descriptor)
    if b"\x00" in data:
        _fail("E_TEXT_ONLY", "NUL byte is forbidden: {}".format(rel_path))
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        _fail("E_TEXT_ONLY", "{} is not UTF-8: {}".format(rel_path, exc))
    return data, mode


def _iter_tree(root: Path) -> Iterable[str]:
    def walk(directory: Path, prefix: PurePosixPath) -> Iterable[str]:
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            _fail("E_PATH_TYPE", "cannot scan {}: {}".format(directory, exc))
        for entry in entries:
            rel = str(prefix / entry.name)
            _canonical_path(rel)
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                _fail("E_UNSTABLE", "cannot stat {}: {}".format(rel, exc))
            if stat.S_ISLNK(info.st_mode):
                _fail("E_SYMLINK", "symlink is forbidden: {}".format(rel))
            if stat.S_ISDIR(info.st_mode):
                yield from walk(Path(entry.path), prefix / entry.name)
            elif stat.S_ISREG(info.st_mode):
                yield rel
            else:
                _fail("E_SPECIAL", "special file is forbidden: {}".format(rel))

    yield from walk(root, PurePosixPath())


def _ensure_clean_output(path: Path) -> None:
    if path.exists() or path.is_symlink():
        _fail("E_OUTPUT", "output path already exists: {}".format(path))
    path.parent.mkdir(parents=True, exist_ok=True)


def _write_regular(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, mode)


def _prepare(
    *,
    task_path: Path,
    schema_path: Optional[Path],
    baseline: Path,
    output: Path,
) -> None:
    task, task_raw = _load_task(task_path, schema_path)
    _ensure_clean_output(output)
    staging = Path(tempfile.mkdtemp(prefix=".p0-preview-prepare-", dir=output.parent))
    try:
        candidate = staging / "candidate"
        context = staging / "context"
        control = staging / "control"
        candidate.mkdir(mode=0o755)
        context.mkdir(mode=0o755)
        control.mkdir(mode=0o755)

        total = 0
        copied_editable: List[str] = []
        for rel_path in task["allowed_paths"]:
            item = _stable_regular_file(baseline, rel_path, reject_metadata=False)
            if item is None:
                continue
            data, mode = item
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                _fail("E_LIMIT", "editable provider input exceeds 8 MiB")
            destination = candidate / rel_path
            _write_regular(destination, data, mode=mode)
            copied_editable.append(rel_path)

        copied_context: List[str] = []
        for rel_path in task["_preview_context_paths"]:
            item = _stable_regular_file(baseline, rel_path, reject_metadata=False)
            if item is None:
                _fail("E_TASK", "context path does not exist: {}".format(rel_path))
            data, _mode = item
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                _fail("E_LIMIT", "total provider input exceeds 8 MiB")
            destination = context / rel_path
            _write_regular(destination, data, mode=0o444)
            copied_context.append(rel_path)

        _write_regular(staging / "TASK.json", task_raw, mode=0o444)
        instructions = (
            LABEL
            + "\n\n"
            + SAFETY_STATEMENT
            + "\n\nEdit files only below candidate/ and only at the exact paths in "
            "TASK.json allowed_paths. Files below context/ are read-only context. "
            "Do not run tests, commit, push, call GitHub, change settings, or claim "
            "success. The workflow will treat every output as hostile data.\n"
        ).encode("utf-8")
        _write_regular(staging / "INSTRUCTIONS.md", instructions, mode=0o444)
        helper_bytes = Path(__file__).read_bytes()
        _write_regular(control / "p0_partner_preview.py", helper_bytes, mode=0o555)
        manifest = {
            "format": "p0-partner-preview-provider-input.v1",
            "label": LABEL,
            "allowed_paths": task["allowed_paths"],
            "base_sha": task["base_sha"],
            "context_paths": copied_context,
            "copied_editable_paths": copied_editable,
            "provider_input_is_confidential": False,
            "provider_output_is_trusted": False,
            "repository": task["repository"],
            "task_sha256": _sha256(task_raw),
        }
        _write_regular(
            staging / "provider-input-manifest.json",
            _canonical_json(manifest),
            mode=0o444,
        )
        os.replace(staging, output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _secret_values_from_environment(names: Sequence[str]) -> List[bytes]:
    result: List[bytes] = []
    for name in names:
        value = os.environ.get(name, "")
        if len(value) >= 16:
            result.append(value.encode("utf-8"))
    return result


def _reject_secrets(data: bytes, values: Sequence[bytes], *, path: str) -> None:
    for marker in SECRET_MARKERS:
        if marker in data:
            _fail("E_SECRET", "credential-like marker found in {}".format(path))
    for value in values:
        if value in data:
            _fail("E_SECRET", "forbidden environment value found in {}".format(path))


def _snapshot(
    *,
    task_path: Path,
    schema_path: Optional[Path],
    candidate: Path,
    output: Path,
    forbid_env: Sequence[str],
) -> None:
    task, task_raw = _load_task(task_path, schema_path)
    if not candidate.is_dir() or candidate.is_symlink():
        _fail("E_PATH_TYPE", "candidate must be a real directory")
    observed = list(_iter_tree(candidate))
    if len(observed) > MAX_PATHS:
        _fail("E_LIMIT", "candidate exceeds {} files".format(MAX_PATHS))
    allowed = set(task["allowed_paths"])
    for rel_path in observed:
        if _is_control_path(rel_path):
            _fail("E_CONTROL_PATH", "candidate contains control path: {}".format(rel_path))
        if rel_path not in allowed:
            _fail("E_SCOPE", "candidate contains out-of-scope path: {}".format(rel_path))

    forbidden_values = _secret_values_from_environment(forbid_env)
    entries: List[Dict[str, Any]] = []
    total = 0
    for rel_path in task["allowed_paths"]:
        item = _stable_regular_file(candidate, rel_path, reject_metadata=True)
        if item is None:
            entries.append({"path": rel_path, "present": False})
            continue
        data, mode = item
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            _fail("E_LIMIT", "candidate exceeds 8 MiB")
        _reject_secrets(data, forbidden_values, path=rel_path)
        entries.append(
            {
                "content_b64": base64.b64encode(data).decode("ascii"),
                "mode": mode,
                "path": rel_path,
                "present": True,
            }
        )
    document = {
        "entries": entries,
        "format": SNAPSHOT_FORMAT,
        "label": LABEL,
        "provider_claims_trusted": False,
        "task_sha256": _sha256(task_raw),
    }
    raw = _canonical_json(document)
    if len(raw) > MAX_SNAPSHOT_BYTES:
        _fail("E_LIMIT", "candidate snapshot exceeds size limit")
    _ensure_clean_output(output)
    _write_regular(output, raw, mode=0o644)


def _decode_snapshot(
    snapshot_path: Path,
    task: Mapping[str, Any],
    task_raw: bytes,
) -> Tuple[Dict[str, Tuple[bool, bytes, Optional[int]]], bytes]:
    raw = _read_bounded(
        snapshot_path,
        MAX_SNAPSHOT_BYTES,
        code="E_LIMIT",
        description="candidate snapshot",
    )
    document = _load_json_bytes(raw, source="candidate snapshot")
    if not isinstance(document, Mapping):
        _fail("E_JSON", "candidate snapshot must be an object")
    if set(document) != {
        "entries",
        "format",
        "label",
        "provider_claims_trusted",
        "task_sha256",
    }:
        _fail("E_JSON", "candidate snapshot has unexpected fields")
    if document.get("format") != SNAPSHOT_FORMAT or document.get("label") != LABEL:
        _fail("E_JSON", "candidate snapshot identity mismatch")
    if document.get("provider_claims_trusted") is not False:
        _fail("E_JSON", "provider claims must remain untrusted")
    if document.get("task_sha256") != _sha256(task_raw):
        _fail("E_TASK", "candidate snapshot is bound to a different task")
    entries = document.get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_PATHS:
        _fail("E_LIMIT", "candidate snapshot path count is invalid")

    decoded: Dict[str, Tuple[bool, bytes, Optional[int]]] = {}
    folded: Dict[str, str] = {}
    total = 0
    for entry in entries:
        if not isinstance(entry, Mapping):
            _fail("E_JSON", "candidate entry must be an object")
        path = _canonical_path(entry.get("path"))
        if path in decoded or path.casefold() in folded:
            _fail("E_PATH", "duplicate or colliding candidate path: {}".format(path))
        folded[path.casefold()] = path
        present = entry.get("present")
        if not isinstance(present, bool):
            _fail("E_JSON", "candidate present flag must be boolean")
        if not present:
            if set(entry) != {"path", "present"}:
                _fail("E_JSON", "deletion entry has unexpected fields")
            decoded[path] = (False, b"", None)
            continue
        if set(entry) != {"content_b64", "mode", "path", "present"}:
            _fail("E_JSON", "file entry has unexpected fields")
        encoded = entry.get("content_b64")
        mode = entry.get("mode")
        if not isinstance(encoded, str) or not isinstance(mode, int):
            _fail("E_JSON", "candidate content or mode has wrong type")
        if len(encoded) > ((MAX_FILE_BYTES + 2) // 3) * 4:
            _fail("E_LIMIT", "encoded file exceeds limit: {}".format(path))
        try:
            data = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            _fail("E_JSON", "invalid base64 content: {}".format(path))
        if len(data) > MAX_FILE_BYTES:
            _fail("E_LIMIT", "file exceeds 1 MiB: {}".format(path))
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            _fail("E_LIMIT", "candidate exceeds 8 MiB")
        if b"\x00" in data:
            _fail("E_TEXT_ONLY", "NUL byte is forbidden: {}".format(path))
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as exc:
            _fail("E_TEXT_ONLY", "{} is not UTF-8: {}".format(path, exc))
        _reject_secrets(data, (), path=path)
        decoded[path] = (True, data, mode)

    expected = set(task["allowed_paths"])
    if set(decoded) != expected:
        _fail(
            "E_SCOPE",
            "snapshot paths must exactly equal allowed_paths; missing={} extra={}".format(
                sorted(expected - set(decoded)), sorted(set(decoded) - expected)
            ),
        )
    return decoded, raw


def _diff_lines(
    old: bytes,
    new: bytes,
    *,
    fromfile: str,
    tofile: str,
) -> bytes:
    old_lines = old.decode("utf-8").splitlines(keepends=True)
    new_lines = new.decode("utf-8").splitlines(keepends=True)
    generated = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=fromfile,
        tofile=tofile,
        lineterm="\n",
    )
    rendered: List[str] = []
    for line in generated:
        if line.endswith("\n"):
            rendered.append(line)
        else:
            rendered.append(line + "\n")
            rendered.append("\\ No newline at end of file\n")
    return "".join(rendered).encode("utf-8")


def _build_patch(
    changes: Sequence[Mapping[str, Any]],
) -> bytes:
    chunks: List[bytes] = []
    for change in changes:
        path = str(change["path"])
        operation = str(change["operation"])
        old = change["old_bytes"]
        new = change["new_bytes"]
        old_mode = change.get("old_mode")
        chunks.append("diff --git a/{0} b/{0}\n".format(path).encode("utf-8"))
        if operation == "add":
            chunks.append(b"new file mode 100644\n")
            fromfile, tofile = "/dev/null", "b/" + path
        elif operation == "delete":
            chunks.append(
                "deleted file mode 100{:03o}\n".format(int(old_mode)).encode("ascii")
            )
            fromfile, tofile = "a/" + path, "/dev/null"
        else:
            fromfile, tofile = "a/" + path, "b/" + path
        chunks.append(_diff_lines(old, new, fromfile=fromfile, tofile=tofile))
    patch = b"".join(chunks)
    if len(patch) > MAX_PATCH_BYTES:
        _fail("E_LIMIT", "changes.patch exceeds 16 MiB")
    return patch


def _package(
    *,
    task_path: Path,
    schema_path: Optional[Path],
    baseline: Path,
    snapshot_path: Path,
    output: Path,
    provenance: Mapping[str, str],
) -> None:
    task, task_raw = _load_task(task_path, schema_path)
    decoded, snapshot_raw = _decode_snapshot(snapshot_path, task, task_raw)
    changes: List[Dict[str, Any]] = []
    public_changes: List[Dict[str, Any]] = []
    for rel_path in task["allowed_paths"]:
        present, candidate_bytes, candidate_mode = decoded[rel_path]
        baseline_item = _stable_regular_file(baseline, rel_path, reject_metadata=False)
        if baseline_item is None:
            if not present:
                continue
            if candidate_mode != 0o644:
                _fail("E_MODE", "new file must use mode 0644: {}".format(rel_path))
            operation = "add"
            old_bytes = b""
            old_mode = None
        else:
            old_bytes, old_mode = baseline_item
            if not present:
                operation = "delete"
                candidate_bytes = b""
            else:
                if candidate_mode != old_mode:
                    _fail("E_MODE", "mode change is forbidden: {}".format(rel_path))
                if candidate_bytes == old_bytes:
                    continue
                operation = "edit"
        change = {
            "new_bytes": candidate_bytes,
            "old_bytes": old_bytes,
            "old_mode": old_mode,
            "operation": operation,
            "path": rel_path,
        }
        changes.append(change)
        public_changes.append(
            {
                "new_sha256": _sha256(candidate_bytes) if operation != "delete" else None,
                "new_size": len(candidate_bytes) if operation != "delete" else 0,
                "old_sha256": _sha256(old_bytes) if operation != "add" else None,
                "old_size": len(old_bytes) if operation != "add" else 0,
                "operation": operation,
                "path": rel_path,
            }
        )
    if not changes:
        _fail("E_EMPTY_DIFF", "candidate contains no task-scope change")

    patch = _build_patch(changes)
    manifest = {
        "base_sha": task["base_sha"],
        "branch": task["branch"],
        "candidate_snapshot_sha256": _sha256(snapshot_raw),
        "changes": public_changes,
        "claims": {
            "correctness": False,
            "execution_verified": False,
            "provenance_verified": False,
            "scope_of_serialized_snapshot_checked": True,
            "security_verified": False,
            "tests_run": False,
        },
        "format": MANIFEST_FORMAT,
        "label": LABEL,
        "patch_sha256": _sha256(patch),
        "provenance": dict(sorted(provenance.items())),
        "repository": task["repository"],
        "safety_statement": SAFETY_STATEMENT,
        "task_sha256": _sha256(task_raw),
    }
    manifest_raw = _canonical_json(manifest)
    summary_lines = [
        "# {}".format(LABEL),
        "",
        SAFETY_STATEMENT,
        "",
        "## Package contents",
        "",
        "- `UNTRUSTED-PREVIEW.json`: descriptive provenance and structural results.",
        "- `changes.patch`: unexecuted UTF-8 patch for manual byte-by-byte inspection.",
        "- `summary.md`: this fixed operator warning.",
        "",
        "## Candidate operations",
        "",
    ]
    for change in public_changes:
        summary_lines.append(
            "- `{}` `{}` ({} bytes)".format(
                change["operation"], change["path"], change["new_size"]
            )
        )
    summary_lines.extend(
        [
            "",
            "## Mandatory human sequence",
            "",
            "1. Enumerate and inspect every package entry without executing or opening it automatically.",
            "2. Review every changed byte and path against the exact clean base.",
            "3. Apply only selected changes manually to a fresh disposable branch.",
            "4. First execute the code only in secretless, read-only CI: no write token, OIDC, secrets, deployment credentials, self-hosted runner, production network, shared writable cache, privileged container, or Docker socket.",
            "5. Use normal CI only after a human explicitly accepts the code-execution risk.",
            "",
            "Provider prose is intentionally excluded from this summary.",
            "",
        ]
    )
    summary_raw = "\n".join(summary_lines).encode("utf-8")

    _ensure_clean_output(output)
    staging = Path(tempfile.mkdtemp(prefix=".p0-preview-package-", dir=output.parent))
    try:
        _write_regular(staging / FIXED_OUTPUT_FILES[0], manifest_raw)
        _write_regular(staging / FIXED_OUTPUT_FILES[1], patch)
        _write_regular(staging / FIXED_OUTPUT_FILES[2], summary_raw)
        observed = sorted(path.name for path in staging.iterdir())
        if observed != sorted(FIXED_OUTPUT_FILES):
            _fail("E_OUTPUT", "final package has unexpected entries")
        os.replace(staging, output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _provenance_from_args(args: argparse.Namespace) -> Dict[str, str]:
    names = (
        "repository_id",
        "owner_id",
        "workflow_sha",
        "workflow_blob_sha256",
        "task_commit",
        "operator",
        "actor",
        "triggering_actor",
        "run_id",
        "run_attempt",
    )
    result: Dict[str, str] = {}
    for name in names:
        value = getattr(args, name, "")
        if value:
            result[name] = str(value)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--task", type=Path, required=True)
    prepare.add_argument("--schema", type=Path)
    prepare.add_argument("--baseline", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)

    snapshot = subparsers.add_parser("snapshot")
    snapshot.add_argument("--task", type=Path, required=True)
    snapshot.add_argument("--schema", type=Path)
    snapshot.add_argument("--candidate", type=Path, required=True)
    snapshot.add_argument("--output", type=Path, required=True)
    snapshot.add_argument(
        "--forbid-env",
        action="append",
        default=[],
        help="environment variable whose exact value must not occur in candidate bytes",
    )

    package = subparsers.add_parser("package")
    package.add_argument("--task", type=Path, required=True)
    package.add_argument("--schema", type=Path)
    package.add_argument("--baseline", type=Path, required=True)
    package.add_argument("--snapshot", type=Path, required=True)
    package.add_argument("--output", type=Path, required=True)
    for name in (
        "repository-id",
        "owner-id",
        "workflow-sha",
        "workflow-blob-sha256",
        "task-commit",
        "operator",
        "actor",
        "triggering-actor",
        "run-id",
        "run-attempt",
    ):
        package.add_argument("--" + name, default="")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "prepare":
            _prepare(
                task_path=args.task,
                schema_path=args.schema,
                baseline=args.baseline,
                output=args.output,
            )
        elif args.command == "snapshot":
            _snapshot(
                task_path=args.task,
                schema_path=args.schema,
                candidate=args.candidate,
                output=args.output,
                forbid_env=args.forbid_env,
            )
        elif args.command == "package":
            _package(
                task_path=args.task,
                schema_path=args.schema,
                baseline=args.baseline,
                snapshot_path=args.snapshot,
                output=args.output,
                provenance=_provenance_from_args(args),
            )
        else:  # pragma: no cover
            raise AssertionError(args.command)
    except PreviewError as exc:
        print(
            json.dumps(
                {
                    "code": exc.code,
                    "label": LABEL,
                    "message": exc.message,
                    "ok": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps({"label": LABEL, "ok": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
