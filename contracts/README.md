# B0/B1 contract bootstrap

This directory (together with `../tools`, `../tests`, and `../fixtures`)
implements only the owner-approved `B0` and `B1` scope of Issue #18. `B0`
provides versioned data contracts, versioned registries, deterministic
offline validation, and hash-pinned fixtures. `B1` adds a deterministic,
human-supervised harness and a trusted always-run result finalizer that
consumes those `B0` contracts. Neither step implements a GitHub Actions
adapter, authoritative verifier, Check Run publisher, or automated
delegation.

## Canonical B0 boundary

B0 is contract bootstrap only:

- schemas, registries, fixtures, and offline contract validation are in scope;
- no component in B0 has verifier authority;
- no GitHub Actions workflow is provided or claimed;
- no adapter executes and no execution or delegation run ID is produced.

These limits are normative. Any workflow execution, authoritative verdict, or
adapter delegation belongs to a later owner-approved bootstrap step.

## Contents (B0)

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

## Canonical B1 boundary

B1 is a bounded, human-supervised harness plus a trusted, always-run result
finalizer, built entirely offline against the existing `contracts/schemas/
result.v1.schema.json`:

- the finalizer (`../tools/finalize_b1.py`) reads a trusted observation input
  (identity, timestamps, base/head SHA, Git observations, terminal
  status/reason, authored commits, changed files, and finalizer identity) and
  emits exactly one schema-valid `result.v1` artifact per finalization;
- the raw executor candidate is untrusted. It is preserved verbatim as
  hash-addressed evidence (`evidence/<sha256>.raw`) and can never override a
  trusted field; any candidate field that disagrees with the trusted
  observation is recorded as a `candidate_field_override_ignored:<field>`
  warning and otherwise discarded;
- missing, malformed, empty, or oversized candidate input still produces one
  valid `failed` result whenever the trusted observation is sufficient — the
  finalizer never blocks on a broken candidate;
- writes are append-only and fail-closed: a finalize attempt against an
  output directory that already holds a `result.json` is refused before any
  evidence is touched, and evidence is durably written and byte-for-byte
  verified before `result.json` is published, so a published result can
  never reference candidate evidence that was not actually written; a
  conflicting, unreadable, symlinked, or non-regular pre-existing evidence
  path fails closed instead of publishing;
- both `result.json` and newly created evidence are published atomically: the
  bytes are written to a private staging file in the same directory, flushed,
  and fsynced, and only that fully-durable staging file is hard-linked into
  its final, immutable name. No failure before that link step (a staging
  write error, an `fsync` error, a full disk) can leave a partially written
  or missing-but-referenced artifact at the final path, and the staging file
  is always removed afterwards; an expected filesystem failure at any
  publication step is reported as `FinalizerPolicyError` or
  `OverwriteRefused`, never an uncaught traceback;
- output is canonical JSON (sorted keys, compact separators) so the same
  trusted input always finalizes to byte-identical bytes;
- repository fixture and candidate processing is bounded by a small, explicit
  policy: 1 MiB per observation or candidate document and a maximum JSON
  nesting depth of 16;
- no component in B1 has verifier authority, no GitHub Actions workflow is
  provided or claimed, and no acceptance criterion or check result is
  evaluated by the finalizer — that belongs to the later `B2` verifier step.

These limits are normative. B1 evidence must not be represented as an
authoritative verification result or a working delegation pipeline.

## Contents (B1)

- `../tools/finalize_b1.py`: the trusted observation loader, bounded
  candidate loader, canonical result builder, and stage-then-atomically-link
  writer, plus a `suite` subcommand that runs the immutable B1 fixture
  manifest;
- `../fixtures/b1/manifest.v1.json`: immutable fixture definitions covering
  success, executor failure, timeout, malformed candidate, missing candidate,
  and overwrite refusal, with SHA-256 hashes over every fixture document;
- `../fixtures/b1/documents/`: the hash-pinned trusted observation and raw
  candidate documents referenced by the manifest;
- `../tests/test_b1_finalizer.py`: direct unit tests for the finalizer's
  trust boundary (candidate override attempts, bounded inputs, fail-closed
  trusted-input errors) and its exactly-once, append-only write behavior.

## Local validation

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --disable-pip-version-check --no-input -r requirements-b0.txt
.venv/bin/python tools/validate_b0.py suite --manifest fixtures/b0/manifest.v1.json
.venv/bin/python tools/finalize_b1.py suite --manifest fixtures/b1/manifest.v1.json
.venv/bin/python -m unittest discover -s tests -p 'test_b0_contracts.py'
.venv/bin/python -m unittest discover -s tests -p 'test_b1_finalizer.py'
```

The B0 fixture suite succeeds only when all positive and negative cases match
their declared validity, exit code, and exact set of error codes. A hash change
in any source fixture fails closed with `fixture_hash_mismatch`.
The coverage catalogue also makes the owner-required failure modes mandatory:
removing a required fixture or changing its expected outcome fails the suite.

Repository-owned fixture processing is bounded to 32 mutations per scenario,
JSON Pointer depth 16, and 1 MiB per decoded or mutated document. Predicate and
command registries reject unsupported versions and duplicate semantics or
implementations.

The B1 fixture suite succeeds only when every required scenario finalizes
with its declared sequence of exit codes and, where declared, produces a
`result.json` that validates against `contracts/schemas/result.v1.schema.json`.
A hash change in any source fixture document fails closed before any
finalize attempt runs.

Every report contains:

```json
{
  "authoritative_verifier": false,
  "bootstrap_scope": "B0"
}
```

(or `"bootstrap_scope": "B1"` for the finalizer suite). These flags are
normative: B0 and B1 evidence must not be represented as a working truthful
execution pipeline.
