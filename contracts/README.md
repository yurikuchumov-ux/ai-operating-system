# B0 contract bootstrap

This directory implements only the owner-approved `B0` scope of Issue #18.
It provides versioned data contracts, versioned registries, deterministic
offline validation, and hash-pinned fixtures. It does not implement an Actions
adapter, trusted finalizer, authoritative verifier, or automated delegation.

## Contents

- `schemas/`: Draft 2020-12 schemas for task, result, verification,
  review-attestation, readiness-evidence, fixture manifest, and both registries;
- `registries/`: closed predicate and command IDs;
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

Every report contains:

```json
{
  "authoritative_verifier": false,
  "bootstrap_scope": "B0"
}
```

These flags are normative: B0 evidence must not be represented as a working
truthful execution pipeline.
