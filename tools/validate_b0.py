#!/usr/bin/env python3
"""Offline B0 contract and immutable-fixture validator.

This tool validates data contracts only. It is not an execution verifier,
Actions adapter, trusted finalizer, or delegation proof.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ModuleNotFoundError as exc:  # pragma: no cover - exercised by CLI setup
    raise SystemExit(
        "missing dependency: install requirements-b0.txt before validation"
    ) from exc


REPO_ROOT = Path(__file__).resolve().parents[1]
MAX_FIXTURE_DOCUMENT_BYTES = 1024 * 1024
MAX_FIXTURE_MUTATIONS = 32
MAX_JSON_POINTER_DEPTH = 16
SUPPORTED_REGISTRY_VERSIONS: Mapping[str, str] = {
    "command_registry": "1.0.0",
    "fixture_coverage_registry": "1.0.0",
    "predicate_registry": "1.0.0",
}
SCHEMA_PATHS: Mapping[str, Path] = {
    "task": REPO_ROOT / "contracts/schemas/task.v1.schema.json",
    "result": REPO_ROOT / "contracts/schemas/result.v1.schema.json",
    "verification": REPO_ROOT / "contracts/schemas/verification.v1.schema.json",
    "review_attestation": REPO_ROOT
    / "contracts/schemas/review-attestation.v1.schema.json",
    "readiness_evidence": REPO_ROOT
    / "contracts/schemas/readiness-evidence.v1.schema.json",
    "fixture_manifest": REPO_ROOT
    / "contracts/schemas/fixture-manifest.v1.schema.json",
    "fixture_coverage_registry": REPO_ROOT
    / "contracts/schemas/fixture-coverage-registry.v1.schema.json",
    "predicate_registry": REPO_ROOT
    / "contracts/schemas/predicate-registry.v1.schema.json",
    "command_registry": REPO_ROOT
    / "contracts/schemas/command-registry.v1.schema.json",
}
REGISTRY_PATHS: Mapping[str, Path] = {
    "predicate_registry": REPO_ROOT / "contracts/registries/predicates.v1.json",
    "command_registry": REPO_ROOT / "contracts/registries/commands.v1.json",
    "fixture_coverage_registry": REPO_ROOT
    / "contracts/registries/fixture-coverage.v1.json",
}


@dataclass(frozen=True)
class Finding:
    code: str
    document_type: str
    path: str
    message: str

    def as_dict(self) -> Dict[str, str]:
        return {
            "code": self.code,
            "document_type": self.document_type,
            "message": self.message,
            "path": self.path,
        }


class FixtureResourceLimitError(ValueError):
    """Raised when repository fixture input exceeds the bounded B0 policy."""


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def json_document_size(document: Any) -> int:
    return len(
        json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
    )


def apply_fixture_mutation(document: Any, mutation: Mapping[str, Any]) -> None:
    """Apply a deliberately small JSON Pointer mutation language for fixtures."""
    pointer = mutation["path"]
    if not pointer.startswith("/"):
        raise ValueError("fixture mutation path must be an absolute JSON Pointer")
    tokens = [token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/")]
    if len(tokens) > MAX_JSON_POINTER_DEPTH:
        raise FixtureResourceLimitError(
            "fixture mutation exceeds maximum JSON Pointer depth of {}".format(
                MAX_JSON_POINTER_DEPTH
            )
        )
    target = document
    for token in tokens[:-1]:
        target = target[int(token)] if isinstance(target, list) else target[token]
    final = tokens[-1]
    operation = mutation["op"]
    if operation == "replace":
        if isinstance(target, list):
            target[int(final)] = mutation["value"]
        else:
            if final not in target:
                raise KeyError(final)
            target[final] = mutation["value"]
    elif operation == "append":
        if not isinstance(target, list) or final != "-":
            raise ValueError("append requires a JSON Pointer ending in /-")
        target.append(mutation["value"])
    else:
        raise ValueError("unsupported fixture mutation operation: {}".format(operation))
    mutated_size = json_document_size(document)
    if mutated_size > MAX_FIXTURE_DOCUMENT_BYTES:
        raise FixtureResourceLimitError(
            "mutated fixture exceeds maximum size of {} bytes".format(
                MAX_FIXTURE_DOCUMENT_BYTES
            )
        )


def json_path(parts: Iterable[Any]) -> str:
    rendered = "$"
    for part in parts:
        rendered += "[{}]".format(part) if isinstance(part, int) else ".{}".format(part)
    return rendered


def unique_ids(
    values: Sequence[Mapping[str, Any]], document_type: str, path: str
) -> List[Finding]:
    seen: Set[str] = set()
    findings: List[Finding] = []
    for index, value in enumerate(values):
        identifier = value.get("id")
        if identifier in seen:
            findings.append(
                Finding(
                    "duplicate_id",
                    document_type,
                    "{}[{}].id".format(path, index),
                    "identifier must be unique: {}".format(identifier),
                )
            )
        seen.add(identifier)
    return findings


def registry_semantic_findings(
    document_type: str, document: Mapping[str, Any]
) -> List[Finding]:
    findings: List[Finding] = []
    supported_version = SUPPORTED_REGISTRY_VERSIONS[document_type]
    if document.get("schema_version") != supported_version:
        findings.append(
            Finding(
                "unsupported_registry_version",
                document_type,
                "$.schema_version",
                "registry version must equal {}".format(supported_version),
            )
        )
    entries_key = (
        "required_fixtures"
        if document_type == "fixture_coverage_registry"
        else "entries"
    )
    entries = document.get(entries_key, [])
    findings.extend(unique_ids(entries, document_type, "$.{}".format(entries_key)))

    if document_type == "predicate_registry":
        seen: Dict[str, str] = {}
        for index, entry in enumerate(entries):
            signature = json.dumps(
                {
                    "evaluator": entry.get("evaluator"),
                    "evidence_types": entry.get("evidence_types"),
                    "failure_code": entry.get("failure_code"),
                    "input_types": entry.get("input_types"),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            if signature in seen:
                findings.append(
                    Finding(
                        "duplicate_predicate_semantics",
                        document_type,
                        "$.entries[{}]".format(index),
                        "predicate duplicates semantics of {}".format(seen[signature]),
                    )
                )
            seen[signature] = entry.get("id", "")
    elif document_type == "command_registry":
        seen = {}
        for index, entry in enumerate(entries):
            signature = json.dumps(
                {
                    "argv": entry.get("argv"),
                    "environment_allowlist": entry.get("environment_allowlist"),
                    "working_directory": entry.get("working_directory"),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            if signature in seen:
                findings.append(
                    Finding(
                        "duplicate_command_implementation",
                        document_type,
                        "$.entries[{}]".format(index),
                        "command duplicates implementation of {}".format(seen[signature]),
                    )
                )
            seen[signature] = entry.get("id", "")
    return findings


class ContractValidator:
    def __init__(self) -> None:
        self.schemas = {name: load_json(path) for name, path in SCHEMA_PATHS.items()}
        for schema in self.schemas.values():
            Draft202012Validator.check_schema(schema)
        self.validators = {
            name: Draft202012Validator(schema, format_checker=FormatChecker())
            for name, schema in self.schemas.items()
        }
        self.registries = {
            name: load_json(path) for name, path in REGISTRY_PATHS.items()
        }
        registry_findings: List[Finding] = []
        for name, document in self.registries.items():
            schema_findings = self._schema_findings(name, document)
            registry_findings.extend(schema_findings)
            if not schema_findings:
                registry_findings.extend(registry_semantic_findings(name, document))
        if registry_findings:
            raise ValueError(
                "invalid repository registry: {}".format(
                    json.dumps(
                        [finding.as_dict() for finding in registry_findings],
                        sort_keys=True,
                    )
                )
            )
        self.predicate_ids = {
            entry["id"] for entry in self.registries["predicate_registry"]["entries"]
        }
        self.command_ids = {
            entry["id"] for entry in self.registries["command_registry"]["entries"]
        }
        self.required_fixture_catalogue = self.registries[
            "fixture_coverage_registry"
        ]["required_fixtures"]

    def _schema_findings(
        self, document_type: str, document: Mapping[str, Any]
    ) -> List[Finding]:
        findings: List[Finding] = []
        for error in sorted(
            self.validators[document_type].iter_errors(document),
            key=lambda item: (list(item.absolute_path), item.validator, item.message),
        ):
            path = json_path(error.absolute_path)
            if path == "$.schema_version" and error.validator == "const":
                code = "unsupported_schema_version"
            elif path == "$.terminal_reason" and error.validator == "enum":
                code = "unknown_terminal_reason"
            else:
                code = "schema_validation_failed"
            findings.append(Finding(code, document_type, path, error.message))
        return findings

    def validate_document(
        self, document_type: str, document: Mapping[str, Any]
    ) -> List[Finding]:
        if document_type not in self.validators:
            return [
                Finding(
                    "unknown_document_type",
                    document_type,
                    "$",
                    "document type is not registered",
                )
            ]
        findings = self._schema_findings(document_type, document)
        if findings:
            return findings
        semantic = {
            "task": self._validate_task,
            "result": self._validate_result,
            "verification": self._validate_verification,
            "review_attestation": self._validate_review_attestation,
            "readiness_evidence": self._validate_readiness_evidence,
        }.get(document_type)
        if semantic is not None:
            findings.extend(semantic(document))
        return sorted(findings, key=lambda finding: (finding.code, finding.path))

    def _validate_task(self, task: Mapping[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        criteria = task["acceptance_criteria"]
        checks = task["required_checks"]
        findings.extend(unique_ids(criteria, "task", "$.acceptance_criteria"))
        findings.extend(unique_ids(checks, "task", "$.required_checks"))
        check_ids = {check["id"] for check in checks}

        for index, criterion in enumerate(criteria):
            predicate_id = criterion["predicate_id"]
            if predicate_id not in self.predicate_ids:
                findings.append(
                    Finding(
                        "unknown_predicate",
                        "task",
                        "$.acceptance_criteria[{}].predicate_id".format(index),
                        "predicate is not registered: {}".format(predicate_id),
                    )
                )
            linked_checks = criterion["linked_checks"]
            if not linked_checks and not predicate_id.startswith("git."):
                findings.append(
                    Finding(
                        "acceptance_evidence_unlinked",
                        "task",
                        "$.acceptance_criteria[{}].linked_checks".format(index),
                        "non-Git predicate must link to a required check",
                    )
                )
            for check_id in linked_checks:
                if check_id not in check_ids:
                    findings.append(
                        Finding(
                            "unknown_linked_check",
                            "task",
                            "$.acceptance_criteria[{}].linked_checks".format(index),
                            "linked check is not declared: {}".format(check_id),
                        )
                    )

        for check_index, check in enumerate(checks):
            if check["command_id"] not in self.command_ids:
                findings.append(
                    Finding(
                        "unknown_command",
                        "task",
                        "$.required_checks[{}].command_id".format(check_index),
                        "command is not registered: {}".format(check["command_id"]),
                    )
                )
            for post_index, postcondition in enumerate(
                check["expected_postconditions"]
            ):
                if postcondition["predicate_id"] not in self.predicate_ids:
                    findings.append(
                        Finding(
                            "unknown_predicate",
                            "task",
                            "$.required_checks[{}].expected_postconditions[{}].predicate_id".format(
                                check_index, post_index
                            ),
                            "predicate is not registered: {}".format(
                                postcondition["predicate_id"]
                            ),
                        )
                    )

        overlap = set(task["allowed_paths"]) & set(task["denied_paths"])
        if overlap:
            findings.append(
                Finding(
                    "path_policy_overlap",
                    "task",
                    "$.allowed_paths",
                    "allowed and denied paths overlap exactly: {}".format(
                        ",".join(sorted(overlap))
                    ),
                )
            )
        return findings

    def _validate_result(self, result: Mapping[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        for key in ("acceptance_results", "checks", "artifacts"):
            findings.extend(unique_ids(result[key], "result", "$.{}".format(key)))
        artifact_ids = {artifact["id"] for artifact in result["artifacts"]}
        if result["status"] in ("change_proposed", "no_change_required") and not result[
            "artifacts"
        ]:
            findings.append(
                Finding(
                    "missing_artifact",
                    "result",
                    "$.artifacts",
                    "successful result must declare at least one artifact",
                )
            )

        references: List[Tuple[str, str]] = []
        for index, acceptance in enumerate(result["acceptance_results"]):
            if acceptance["predicate_id"] not in self.predicate_ids:
                findings.append(
                    Finding(
                        "unknown_predicate",
                        "result",
                        "$.acceptance_results[{}].predicate_id".format(index),
                        "predicate is not registered: {}".format(
                            acceptance["predicate_id"]
                        ),
                    )
                )
            references.extend(
                (
                    "$.acceptance_results[{}].evidence_artifact_ids".format(index),
                    artifact_id,
                )
                for artifact_id in acceptance["evidence_artifact_ids"]
            )
        for index, check in enumerate(result["checks"]):
            if check["command_id"] not in self.command_ids:
                findings.append(
                    Finding(
                        "unknown_command",
                        "result",
                        "$.checks[{}].command_id".format(index),
                        "command is not registered: {}".format(check["command_id"]),
                    )
                )
            references.extend(
                (
                    "$.checks[{}].evidence_artifact_ids".format(index),
                    artifact_id,
                )
                for artifact_id in check["evidence_artifact_ids"]
            )
        references.extend(
            ("$.no_change_evidence", evidence["artifact_id"])
            for evidence in result["no_change_evidence"]
        )
        for path, artifact_id in references:
            if artifact_id not in artifact_ids:
                findings.append(
                    Finding(
                        "unresolved_artifact_reference",
                        "result",
                        path,
                        "artifact ID is not declared: {}".format(artifact_id),
                    )
                )
        return findings

    def _validate_verification(
        self, verification: Mapping[str, Any]
    ) -> List[Finding]:
        findings: List[Finding] = []
        evidence_ids = {item["id"] for item in verification["evidence"]}
        findings.extend(unique_ids(verification["evidence"], "verification", "$.evidence"))
        for index, result in enumerate(verification["predicate_results"]):
            if result["predicate_id"] not in self.predicate_ids:
                findings.append(
                    Finding(
                        "unknown_predicate",
                        "verification",
                        "$.predicate_results[{}].predicate_id".format(index),
                        "predicate is not registered: {}".format(result["predicate_id"]),
                    )
                )
            for artifact_id in result["evidence_artifact_ids"]:
                if artifact_id not in evidence_ids:
                    findings.append(
                        Finding(
                            "unresolved_artifact_reference",
                            "verification",
                            "$.predicate_results[{}].evidence_artifact_ids".format(index),
                            "evidence ID is not declared: {}".format(artifact_id),
                        )
                    )
        if verification["passed"] and any(
            not result["passed"] for result in verification["predicate_results"]
        ):
            findings.append(
                Finding(
                    "verification_inconsistent",
                    "verification",
                    "$.passed",
                    "verification cannot pass when a predicate failed",
                )
            )
        return findings

    @staticmethod
    def _validate_review_attestation(
        attestation: Mapping[str, Any]
    ) -> List[Finding]:
        eligibility = attestation["eligibility"]
        findings: List[Finding] = []
        if eligibility["eligible"] and any(
            result["overlap"] for result in eligibility["overlap_results"]
        ):
            findings.append(
                Finding(
                    "identity_conflict",
                    "review_attestation",
                    "$.eligibility.eligible",
                    "eligible reviewer cannot have a forbidden lineage overlap",
                )
            )
        if not eligibility["eligible"] and not eligibility["reason_codes"]:
            findings.append(
                Finding(
                    "eligibility_reason_missing",
                    "review_attestation",
                    "$.eligibility.reason_codes",
                    "ineligible review requires at least one reason code",
                )
            )
        return findings

    @staticmethod
    def _validate_readiness_evidence(
        evidence: Mapping[str, Any]
    ) -> List[Finding]:
        if evidence["status"] == "pass" and any(
            not result["passed"] for result in evidence["predicate_results"]
        ):
            return [
                Finding(
                    "gate_predicate_failed",
                    "readiness_evidence",
                    "$.status",
                    "passing gate cannot contain a failed predicate",
                )
            ]
        return []

    def validate_pair(
        self, task: Mapping[str, Any], result: Mapping[str, Any]
    ) -> List[Finding]:
        findings: List[Finding] = []
        if task["task_id"] != result["task_id"]:
            findings.append(
                Finding(
                    "task_id_mismatch",
                    "task_result_pair",
                    "$.task_id",
                    "task and result IDs differ",
                )
            )
        if task["base_sha"] != result["base_sha"]:
            findings.append(
                Finding(
                    "base_sha_mismatch",
                    "task_result_pair",
                    "$.base_sha",
                    "task and result base SHAs differ",
                )
            )

        criteria = {criterion["id"]: criterion for criterion in task["acceptance_criteria"]}
        acceptance_results: Dict[str, List[Mapping[str, Any]]] = {}
        for actual in result["acceptance_results"]:
            acceptance_results.setdefault(actual["id"], []).append(actual)
            if actual["id"] not in criteria:
                findings.append(
                    Finding(
                        "unknown_acceptance_result",
                        "task_result_pair",
                        "$.acceptance_results",
                        "acceptance result is not declared by task: {}".format(
                            actual["id"]
                        ),
                    )
                )

        check_results = {check["id"]: check for check in result["checks"]}
        for criterion_id, criterion in criteria.items():
            matches = acceptance_results.get(criterion_id, [])
            if criterion["required"] and not matches:
                findings.append(
                    Finding(
                        "acceptance_result_missing",
                        "task_result_pair",
                        "$.acceptance_results",
                        "required acceptance result is missing: {}".format(criterion_id),
                    )
                )
                continue
            if criterion["required"] and len(matches) != 1:
                findings.append(
                    Finding(
                        "acceptance_result_cardinality",
                        "task_result_pair",
                        "$.acceptance_results",
                        "required criterion must have exactly one result: {}".format(
                            criterion_id
                        ),
                    )
                )
            if not matches:
                continue
            actual = matches[0]
            if actual["predicate_id"] != criterion["predicate_id"]:
                findings.append(
                    Finding(
                        "acceptance_predicate_mismatch",
                        "task_result_pair",
                        "$.acceptance_results.{}.predicate_id".format(criterion_id),
                        "acceptance predicate differs from task contract",
                    )
                )
            if actual["parameters"] != criterion["parameters"]:
                findings.append(
                    Finding(
                        "acceptance_parameters_mismatch",
                        "task_result_pair",
                        "$.acceptance_results.{}.parameters".format(criterion_id),
                        "acceptance parameters differ from task contract",
                    )
                )
            if result["status"] in ("change_proposed", "no_change_required") and not actual[
                "passed"
            ]:
                findings.append(
                    Finding(
                        "acceptance_failed",
                        "task_result_pair",
                        "$.acceptance_results.{}.passed".format(criterion_id),
                        "successful result requires every required acceptance result to pass",
                    )
                )
            linked_evidence: Set[str] = set()
            for linked_check_id in criterion["linked_checks"]:
                linked_check = check_results.get(linked_check_id)
                if linked_check is not None:
                    linked_evidence.update(linked_check["evidence_artifact_ids"])
            if set(actual["evidence_artifact_ids"]) != linked_evidence:
                findings.append(
                    Finding(
                        "acceptance_evidence_mismatch",
                        "task_result_pair",
                        "$.acceptance_results.{}.evidence_artifact_ids".format(
                            criterion_id
                        ),
                        "acceptance evidence must equal evidence from linked checks",
                    )
                )

        checks = {check["id"]: check for check in task["required_checks"]}
        for check_id, check in checks.items():
            if not check["required"]:
                continue
            actual = check_results.get(check_id)
            if actual is None:
                findings.append(
                    Finding(
                        "required_check_missing",
                        "task_result_pair",
                        "$.checks",
                        "required check result is missing: {}".format(check_id),
                    )
                )
            elif actual["command_id"] != check["command_id"]:
                findings.append(
                    Finding(
                        "check_command_mismatch",
                        "task_result_pair",
                        "$.checks.{}.command_id".format(check_id),
                        "check command differs from task contract",
                    )
                )
            elif result["status"] in ("change_proposed", "no_change_required") and actual["exit_code"] != 0:
                findings.append(
                    Finding(
                        "check_failed",
                        "task_result_pair",
                        "$.checks.{}.exit_code".format(check_id),
                        "successful result requires zero exit code",
                    )
                )

        if result["status"] == "change_proposed":
            for changed_path in result["changed_files"]:
                allowed = any(
                    fnmatch.fnmatchcase(changed_path, pattern)
                    for pattern in task["allowed_paths"]
                )
                denied = any(
                    fnmatch.fnmatchcase(changed_path, pattern)
                    for pattern in task["denied_paths"]
                )
                if not allowed or denied:
                    findings.append(
                        Finding(
                            "scope_violation",
                            "task_result_pair",
                            "$.changed_files",
                            "changed path is outside policy: {}".format(changed_path),
                        )
                    )
        elif result["status"] == "no_change_required":
            no_change = task["change_policy"]["no_change"]
            if not no_change["allowed"]:
                findings.append(
                    Finding(
                        "no_change_not_allowed",
                        "task_result_pair",
                        "$.status",
                        "task does not permit no-change completion",
                    )
                )
            if result["no_change_reason"] not in no_change["reason_codes"]:
                findings.append(
                    Finding(
                        "no_change_reason_not_allowed",
                        "task_result_pair",
                        "$.no_change_reason",
                        "no-change reason is not allowed by task contract",
                    )
                )
            observed_types = {item["type"] for item in result["no_change_evidence"]}
            missing_types = set(no_change["required_evidence_types"]) - observed_types
            if missing_types:
                findings.append(
                    Finding(
                        "no_change_evidence_missing",
                        "task_result_pair",
                        "$.no_change_evidence",
                        "missing no-change evidence types: {}".format(
                            ",".join(sorted(missing_types))
                        ),
                    )
                )
        return findings


def validate_fixture(
    validator: ContractValidator,
    fixture: Mapping[str, Any],
    manifest_dir: Path,
) -> Dict[str, Any]:
    findings: List[Finding] = []
    loaded: Dict[str, Mapping[str, Any]] = {}
    for document_spec in fixture["documents"]:
        relative_path = Path(document_spec["path"])
        absolute_path = (manifest_dir / relative_path).resolve()
        if REPO_ROOT not in absolute_path.parents:
            findings.append(
                Finding(
                    "fixture_path_outside_repository",
                    document_spec["type"],
                    "$.documents",
                    "fixture path escapes repository",
                )
            )
            continue
        if not absolute_path.is_file():
            findings.append(
                Finding(
                    "fixture_file_missing",
                    document_spec["type"],
                    "$.documents",
                    "fixture file does not exist: {}".format(document_spec["path"]),
                )
            )
            continue
        if absolute_path.stat().st_size > MAX_FIXTURE_DOCUMENT_BYTES:
            findings.append(
                Finding(
                    "fixture_resource_limit_exceeded",
                    document_spec["type"],
                    "$.documents",
                    "fixture file exceeds maximum size of {} bytes".format(
                        MAX_FIXTURE_DOCUMENT_BYTES
                    ),
                )
            )
            continue
        actual_hash = sha256_file(absolute_path)
        if actual_hash != document_spec["sha256"]:
            findings.append(
                Finding(
                    "fixture_hash_mismatch",
                    document_spec["type"],
                    "$.documents",
                    "fixture hash does not match manifest: {}".format(
                        document_spec["path"]
                    ),
                )
            )
            continue
        try:
            document = load_json(absolute_path)
        except json.JSONDecodeError as exc:
            findings.append(
                Finding(
                    "fixture_json_invalid",
                    document_spec["type"],
                    "$.documents",
                    "fixture is not valid JSON at line {} column {}".format(
                        exc.lineno, exc.colno
                    ),
                )
            )
            continue
        if json_document_size(document) > MAX_FIXTURE_DOCUMENT_BYTES:
            findings.append(
                Finding(
                    "fixture_resource_limit_exceeded",
                    document_spec["type"],
                    "$.documents",
                    "fixture document exceeds maximum decoded size of {} bytes".format(
                        MAX_FIXTURE_DOCUMENT_BYTES
                    ),
                )
            )
            continue
        loaded[document_spec["type"]] = document
    mutations = fixture.get("mutations", [])
    if len(mutations) > MAX_FIXTURE_MUTATIONS:
        findings.append(
            Finding(
                "fixture_resource_limit_exceeded",
                "fixture_manifest",
                "$.mutations",
                "fixture exceeds maximum mutation count of {}".format(
                    MAX_FIXTURE_MUTATIONS
                ),
            )
        )
        mutations = []
    for mutation in mutations:
        document_type = mutation["document_type"]
        if document_type not in loaded:
            findings.append(
                Finding(
                    "fixture_mutation_target_missing",
                    document_type,
                    "$.mutations",
                    "mutation target document is not loaded",
                )
            )
            continue
        try:
            apply_fixture_mutation(loaded[document_type], mutation)
        except FixtureResourceLimitError as exc:
            findings.append(
                Finding(
                    "fixture_resource_limit_exceeded",
                    document_type,
                    "$.mutations",
                    str(exc),
                )
            )
        except (IndexError, KeyError, TypeError, ValueError) as exc:
            findings.append(
                Finding(
                    "fixture_mutation_invalid",
                    document_type,
                    "$.mutations",
                    str(exc),
                )
            )
    for document_type, document in loaded.items():
        findings.extend(validator.validate_document(document_type, document))
    if "task" in loaded and "result" in loaded:
        findings.extend(validator.validate_pair(loaded["task"], loaded["result"]))

    findings = sorted(findings, key=lambda finding: (finding.code, finding.path))
    actual_valid = not findings
    actual_exit_code = 0 if actual_valid else 1
    actual_codes = sorted({finding.code for finding in findings})
    expected = fixture["expected"]
    expectation_met = (
        actual_valid == expected["valid"]
        and actual_exit_code == expected["exit_code"]
        and actual_codes == sorted(expected["error_codes"])
    )
    return {
        "actual": {
            "error_codes": actual_codes,
            "exit_code": actual_exit_code,
            "findings": [finding.as_dict() for finding in findings],
            "valid": actual_valid,
        },
        "expected": expected,
        "expectation_met": expectation_met,
        "id": fixture["id"],
    }


def required_fixture_coverage(
    validator: ContractValidator, manifest: Mapping[str, Any]
) -> Tuple[List[Finding], Dict[str, Any]]:
    fixtures = {fixture.get("id"): fixture for fixture in manifest.get("fixtures", [])}
    findings: List[Finding] = []
    covered: List[str] = []
    missing: List[str] = []
    for required in validator.required_fixture_catalogue:
        fixture_id = required["id"]
        fixture = fixtures.get(fixture_id)
        if fixture is None:
            missing.append(fixture_id)
            findings.append(
                Finding(
                    "required_fixture_missing",
                    "fixture_manifest",
                    "$.fixtures",
                    "required failure-mode fixture is missing: {}".format(fixture_id),
                )
            )
            continue
        expected = fixture.get("expected", {})
        normalized_expected = {
            "valid": expected.get("valid"),
            "exit_code": expected.get("exit_code"),
            "error_codes": sorted(expected.get("error_codes", [])),
        }
        required_expected = {
            "valid": required["expected"]["valid"],
            "exit_code": required["expected"]["exit_code"],
            "error_codes": sorted(required["expected"]["error_codes"]),
        }
        if normalized_expected != required_expected:
            findings.append(
                Finding(
                    "required_fixture_expectation_mismatch",
                    "fixture_manifest",
                    "$.fixtures.{}.expected".format(fixture_id),
                    "required fixture expectation differs from coverage registry",
                )
            )
            continue
        covered.append(fixture_id)
    return findings, {
        "catalogue_id": validator.registries["fixture_coverage_registry"][
            "catalogue_id"
        ],
        "covered": sorted(covered),
        "missing": sorted(missing),
        "required": len(validator.required_fixture_catalogue),
    }


def run_suite(manifest_path: Path) -> Tuple[int, Dict[str, Any]]:
    validator = ContractValidator()
    manifest = load_json(manifest_path)
    manifest_findings = validator.validate_document("fixture_manifest", manifest)
    manifest_findings.extend(
        unique_ids(manifest.get("fixtures", []), "fixture_manifest", "$.fixtures")
    )
    coverage_findings, coverage = required_fixture_coverage(validator, manifest)
    manifest_findings.extend(coverage_findings)
    if manifest_findings:
        report = {
            "authoritative_verifier": False,
            "bootstrap_scope": "B0",
            "coverage": coverage,
            "fixtures": [],
            "manifest_findings": [
                finding.as_dict()
                for finding in sorted(
                    manifest_findings, key=lambda finding: (finding.code, finding.path)
                )
            ],
            "schema_version": "1.0.0",
            "summary": {"failed": 1, "passed": 0, "total": 1},
            "valid": False,
        }
        return 1, report
    fixture_results = [
        validate_fixture(validator, fixture, manifest_path.parent)
        for fixture in manifest["fixtures"]
    ]
    passed = sum(1 for result in fixture_results if result["expectation_met"])
    total = len(fixture_results)
    suite_valid = total > 0 and passed == total
    report = {
        "authoritative_verifier": False,
        "bootstrap_scope": "B0",
        "coverage": coverage,
        "fixtures": fixture_results,
        "manifest_findings": [],
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
        description="Validate AI OS B0 contracts and immutable fixtures offline."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    suite = subparsers.add_parser("suite", help="run immutable fixture manifest")
    suite.add_argument("--manifest", type=Path, required=True)

    validate = subparsers.add_parser("validate", help="validate one contract document")
    validate.add_argument("--type", choices=sorted(SCHEMA_PATHS), required=True)
    validate.add_argument("--document", type=Path, required=True)
    validate.add_argument("--task", type=Path)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if args.command == "suite":
        exit_code, report = run_suite(args.manifest.resolve())
        write_report(report)
        return exit_code

    validator = ContractValidator()
    document = load_json(args.document.resolve())
    findings = validator.validate_document(args.type, document)
    if args.task is not None:
        if args.type != "result":
            raise SystemExit("--task is valid only with --type result")
        task = load_json(args.task.resolve())
        findings.extend(validator.validate_document("task", task))
        if not findings:
            findings.extend(validator.validate_pair(task, document))
    findings = sorted(findings, key=lambda finding: (finding.code, finding.path))
    report = {
        "authoritative_verifier": False,
        "bootstrap_scope": "B0",
        "document_type": args.type,
        "error_codes": sorted({finding.code for finding in findings}),
        "findings": [finding.as_dict() for finding in findings],
        "schema_version": "1.0.0",
        "valid": not findings,
    }
    write_report(report)
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
