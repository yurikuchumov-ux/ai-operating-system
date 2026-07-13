# B0 contract bootstrap

This directory implements only the owner-approved `B0` scope of Issue #18.
It provides versioned data contracts, versioned registries, deterministic
offline validation, and hash-pinned fixtures. It does not implement an Actions
adapter, trusted finalizer, authoritative verifier, or automated delegation.

## Canonical B0 boundary

B0 is contract bootstrap only:

- schemas, registries, fixtures, and offline contract validation are in scope;
- no component in B0 has verifier authority;
- no GitHub Actions workflow is provided or claimed;
- no adapter executes and no execution or delegation run ID is produced.

These limits are normative. Any workflow execution, authoritative verdict, or
adapter delegation belongs to a later owner-approved bootstrap step.

## Contents

- `schemas/`: Draft 2020-12 schemas for task, result, verification,
  review-attestation, readiness-evidence, fixture manifest, and registries;
- `registries/`: closed predicate and command IDs plus the required B0 failure
  coverage catalogue;
- `../fixtures/b0/manifest.v1.json`: immutable fixture definitions, expected
  exit codes, expected error codes, and SHA-256 hashes;
- `../tools/validate_b0.py`: offline schema and semantic contract validator;
- `../tests/test_b0_contracts.py`: deterministic regression tests.

Result check evidence uses direct `evidence_artifact_ids`. Path-based implicit
artifact resolution is intentionally unsupported.

## Local validation

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --disable-pip-version-check --no-input -r requirements-b0.txt
.venv/bin/python tools/validate_b0.py suite --manifest fixtures/b0/manifest.v1.json
.venv/bin/python -m unittest discover -s tests -p 'test_b0_contracts.py'
```

The fixture suite succeeds only when all positive and negative cases match
their declared validity, exit code, and exact set of error codes. A hash change
in any source fixture fails closed with `fixture_hash_mismatch`.
The coverage catalogue also makes the owner-required failure modes mandatory:
removing a required fixture or changing its expected outcome fails the suite.

Repository-owned fixture processing is bounded to 32 mutations per scenario,
JSON Pointer depth 16, and 1 MiB per decoded or mutated document. Predicate and
command registries reject unsupported versions and duplicate semantics or
implementations.

Every report contains:

```json
{
  "authoritative_verifier": false,
  "bootstrap_scope": "B0"
}
```

These flags are normative: B0 evidence must not be represented as a working
truthful execution pipeline.
