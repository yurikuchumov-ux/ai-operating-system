#!/usr/bin/env python3
"""Canonical repository registry validator.

This tool validates canonical repository registry contracts only.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ModuleNotFoundError as exc:  # pragma: no cover
    raise SystemExit(
        "missing dependency: install requirements-b0.txt before validation"
    ) from exc


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "contracts/schemas/canonical-repositories.v1.schema.json"
REGISTRY_PATH = REPO_ROOT / "contracts/canonical-repositories.v1.json"


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


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def json_path(parts: List[Any]) -> str:
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


def repository_semantic_findings(document: Mapping[str, Any]) -> List[Finding]:
    findings: List[Finding] = []

    # Check schema_version
    if document.get("schema_version") != "1.0.0":
        findings.append(
            Finding(
                "unsupported_registry_version",
                "canonical_repository_registry",
                "$.schema_version",
                "registry version must equal 1.0.0",
            )
        )

    # Check for unique IDs
    entries = document.get("entries", [])
    findings.extend(unique_ids(entries, "canonical_repository_registry", "$.entries"))

    # Check for duplicate repository specifications
    seen: Dict[str, str] = {}
    for index, entry in enumerate(entries):
        repo_key = "{}/{}".format(
            entry.get("repository_owner", ""),
            entry.get("repository_name", "")
        )
        if repo_key in seen:
            findings.append(
                Finding(
                    "duplicate_repository_specification",
                    "canonical_repository_registry",
                    "$.entries[{}]".format(index),
                    "repository specification duplicates {}".format(seen[repo_key]),
                )
            )
        seen[repo_key] = entry.get("id", "")

    # Check for lowercase SHA (semantic validation beyond schema)
    for index, entry in enumerate(entries):
        sha = entry.get("repository_sha", "")
        if sha and sha != sha.lower():
            findings.append(
                Finding(
                    "repository_sha_not_lowercase",
                    "canonical_repository_registry",
                    "$.entries[{}].repository_sha".format(index),
                    "repository SHA must be lowercase hexadecimal",
                )
            )

    return findings


class CanonicalRepositoryValidator:
    def __init__(self) -> None:
        self.schema = load_json(SCHEMA_PATH)
        Draft202012Validator.check_schema(self.schema)
        self.validator = Draft202012Validator(self.schema, format_checker=FormatChecker())

    def _schema_findings(self, document: Mapping[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        for error in sorted(
            self.validator.iter_errors(document),
            key=lambda item: (list(item.absolute_path), item.validator, item.message),
        ):
            path = json_path(list(error.absolute_path))
            if path == "$.schema_version" and error.validator == "const":
                code = "unsupported_schema_version"
            else:
                code = "schema_validation_failed"
            findings.append(
                Finding(code, "canonical_repository_registry", path, error.message)
            )
        return findings

    def validate_document(self, document: Mapping[str, Any]) -> List[Finding]:
        findings = self._schema_findings(document)
        if findings:
            return findings
        findings.extend(repository_semantic_findings(document))
        return sorted(findings, key=lambda finding: (finding.code, finding.path))


def write_report(report: Mapping[str, Any]) -> None:
    json.dump(report, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate canonical repository registry contract."
    )
    parser.add_argument("--document", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    validator = CanonicalRepositoryValidator()
    document = load_json(args.document.resolve())
    findings = validator.validate_document(document)
    findings = sorted(findings, key=lambda finding: (finding.code, finding.path))
    report = {
        "authoritative_verifier": False,
        "bootstrap_scope": "B3",
        "document_type": "canonical_repository_registry",
        "error_codes": sorted({finding.code for finding in findings}),
        "findings": [finding.as_dict() for finding in findings],
        "schema_version": "1.0.0",
        "valid": not findings,
    }
    write_report(report)
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
