# B0/B1/B2/B3 contract bootstrap

This directory (together with `../tools`, `../tests`, and `../fixtures`)
implements the owner-approved `B0`, `B1`, `B2` scope of Issue #18 and the
`B3` scope of Issue #19. `B0` provides versioned data contracts, versioned
registries, deterministic offline validation, and hash-pinned fixtures. `B1`
adds a deterministic, human-supervised harness and a trusted always-run
result finalizer that consumes those `B0` contracts. `B2` adds a bounded,
deterministic offline verifier that evaluates a fixed set of registered
predicates over `B0` contract documents and a `B1`-shaped result. `B3` adds
a deterministic terminal-reason propagator that composes the existing,
unmodified `B1` finalizer and `B2` verifier, plus the first real GitHub
Actions workflow (`../.github/workflows/b3-terminal-propagation.yml`), whose
Check Run conclusion is published only from the `B2` verifier's own
`verification.v1.passed` field.

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
  conflicting, unreadable, symlinked, non-regular, concurrently replaced, or
  path-rebound pre-existing evidence fails closed instead of publishing. The
  existing object is opened once with `O_NOFOLLOW`, inspected and read through
  that descriptor, and rebound by device/inode before result publication;
  platforms without effective no-follow support fail closed. This detects
  replacement during verification; the human-supervised B1 harness must still
  keep the output directory under exclusive control through publication;
- both `result.json` and newly created evidence are published atomically: the
  bytes are written with unbuffered OS writes to a private staging file in the
  same directory and fsynced, and only that fully-durable file is hard-linked
  into its final, immutable name. No failure before that link step (a staging
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

## Canonical B2 boundary

B2 is a bounded, deterministic, offline verifier built entirely against the
existing `contracts/schemas/task.v1.schema.json`,
`contracts/schemas/result.v1.schema.json`,
`contracts/schemas/review-attestation.v1.schema.json`, and
`contracts/schemas/verification.v1.schema.json`:

- the verifier (`../tools/verify_b2.py`) consumes trusted invocation metadata
  supplied entirely by its caller -- `verification_id`, `evaluated_at`, the
  expected task ID, execution ID, base SHA, and subject/head SHA, and the
  verifier identity -- plus a task, a finalized result, a review-attestation,
  a Git observation, and evidence bytes rooted under one evidence directory.
  It never generates time, UUIDs, or identity itself;
- it evaluates exactly the closed, ordered set of 14 predicate IDs required
  by `AC-B2-5` (`schema.instance.valid`, `binding.task_id.equals`,
  `binding.execution_id.equals`, `git.base_sha.equals`,
  `git.head_sha.equals`, `git.changed_paths.allowed`, `git.diff.non_empty`,
  `process.exit_code.equals`, `acceptance.required.passed`,
  `artifact.exists`, `artifact.sha256.matches`, `review.subject_sha.equals`,
  `review.eligibility.passed`, `identity.lineage.no_overlap`). A task or
  result reference to any predicate ID outside the repository predicate
  registry (`contracts/registries/predicates.v1.json`) fails closed with
  `unknown_predicate`;
- the report always validates against `contracts/schemas/verification.v1.schema.json`,
  whether the run is a semantic pass (`passed: true`, exit code 0) or a
  semantic or input failure (`passed: false`, exit code 1); an unreadable,
  malformed, oversized, or schema-invalid input document still produces
  exactly one schema-valid `verification.v1` report with a single failing
  `schema.instance.valid` predicate result, rather than an uncaught
  traceback;
- evidence bytes are read through one bounded, no-follow descriptor rooted
  at a caller-supplied evidence directory: paths must be relative and stay
  contained under that root, only regular files are read, symlinked or
  non-regular targets and out-of-root escapes are rejected, reads are capped
  at 1 MiB, and the file's device/inode binding is re-checked after the read
  to detect mutation or rebinding during verification;
- output is canonical JSON (sorted keys, compact separators), so identical
  trusted input -- including the trusted invocation metadata -- always
  verifies to byte-identical report bytes; the report is published by
  writing to a private staging file, fsyncing it, and only then
  hard-linking it into its final, immutable path, so a write, fsync, or
  link failure never leaves a partial or missing-but-referenced report at
  the final path, and an existing report at that path is never overwritten;
- no component in B2 has GitHub Actions, Check Run, or merge/delegation
  authority; it is a fixed, offline predicate evaluator over trusted,
  caller-supplied input only.

These limits are normative. B2 evidence must not be represented as a working
Actions adapter, Check Run publisher, or automated merge/delegation
pipeline.

## Contents (B2)

- `../tools/verify_b2.py`: the deterministic offline verifier -- trusted
  invocation loader, bounded task/result/review-attestation/Git-observation
  loader, the fixed 14-predicate evaluator, and the
  stage-then-atomically-link report publisher, plus a `suite` subcommand
  that runs the immutable B2 fixture manifest;
- `../fixtures/b2/manifest.v1.json`: immutable fixture definitions for all
  18 contract-oracle scenarios, with SHA-256 hashes over every fixture
  document and the trusted invocation metadata used to evaluate it;
- `../fixtures/b2/documents/`: the hash-pinned task, result,
  review-attestation, Git-observation, and evidence-root documents
  referenced by the manifest;
- `../tests/test_b2_verifier.py`: fixture-oracle regression tests (exit
  code, `passed`, and exact failure-code set per scenario) plus direct
  security/failure injection for symlinked and path-escaping evidence,
  evidence mutation/rebinding, output collision, and staging
  write/fsync/link failure.

## Canonical B3 boundary

B3 is a bounded, deterministic terminal-reason propagator built entirely by
composing the existing, unmodified `B1` finalizer and `B2` verifier, plus a
real GitHub Actions workflow around them:

- the propagator (`../tools/propagate_b3.py`) consumes a trusted,
  schema-validated provider signal -- cancellation, adapter/job timeout,
  max-turns exhaustion, adapter error, Git observation, required-artifact
  presence, and required-check exit code -- and deterministically classifies
  exactly one `result.v1` terminal status/reason from it, in a fixed
  priority order (`cancelled_by_owner` > `job_timed_out` > `adapter_timed_out`
  > `max_turns_exhausted` > `adapter_error` > `missing_commit` >
  `missing_artifact` (result-artifact, then required-evidence-artifact) >
  `empty_diff` > `check_failed` > `completed`). The adapter's own
  self-reported status and the Actions job's own conclusion are never read
  by this classification -- they are carried through only as untrusted,
  informational fields on the published `workflow-run-metadata` artifact;
- the trusted observation it derives is finalized into a schema-valid
  `result.v1` by calling `../tools/finalize_b1.py`'s `finalize` function
  directly, unmodified; that result is then verified against a task, a
  review-attestation, and a trusted Git observation by calling
  `../tools/verify_b2.py`'s `run_verification` function directly,
  unmodified, producing a schema-valid `verification.v1` report;
- the Check Run conclusion this tool computes -- and the only conclusion the
  workflow's `finalize-and-verify` job is permitted to publish -- is
  `success` iff `verification.v1.passed` is `true`. It is never derived from
  the adapter's self-report, the Actions job's own conclusion, or the raw
  provider terminal reason;
- `.github/workflows/b3-terminal-propagation.yml` is a real, two-job Actions
  workflow: an `execute` job bounded by `timeout-minutes` runs the executor
  adapter, and an always-run (`if: always()`) `finalize-and-verify` job
  collects the trusted provider signal from directly observable facts
  (the `execute` job's own `needs.execute.result`, Git state, and artifact
  presence -- not adapter prose), runs the propagator, uploads the
  `result-artifact`, `verification-report`, and `workflow-run-metadata`
  artifacts, and publishes the Check Run from the verifier's own report.
  Both the Actions run ID (`github.run_id`) and the trusted `execution_id`
  generated once in the `execute` job and threaded through as a job output
  are required non-null on the published `workflow-run-metadata`;
- the immutable, hash-pinned `fixtures/b3/manifest.v1.json` fixture suite
  covers all terminal failure reasons the Issue #19 B3 control contract
  requires (max-turns, adapter timeout, job timeout, missing commit, missing
  result artifact, missing required-evidence artifact, empty diff, failed
  required check, adapter error, cancellation, and the case where a green
  adapter self-report and a green Actions job conclusion cannot mask a real
  check failure), plus the immutable false-success replay of the historical
  run `29190170902` (green, `error_max_turns`, zero artifacts, no commit)
  and one genuine-success scenario that passes cleanly;
- no component in B3 has independent verifier authority beyond composing
  the existing `B1`/`B2` bootstrap tools unmodified; B3 adds exactly one
  narrow command registry entry (`repo.contracts.b3.tests`) and no new
  predicate or schema.

These limits are normative. B3 evidence must not be represented as
authoritative beyond what the composed, unmodified `B1` finalizer and `B2`
verifier already establish, and the Check Run conclusion it publishes must
never be attributable to adapter or Actions-job self-report.

## Contents (B3)

- `../tools/propagate_b3.py`: the bounded provider-signal loader, the fixed
  terminal-reason classifier, the trusted-observation builder, the pipeline
  that calls the unmodified `B1` finalizer and `B2` verifier in sequence,
  the `workflow-run-metadata` publisher, and a `suite` subcommand that runs
  the immutable B3 fixture manifest;
- `../fixtures/b3/manifest.v1.json`: immutable fixture definitions for all
  13 contract-oracle scenarios required by Issue #19's `AC-B3-1`, with
  SHA-256 hashes over every fixture document;
- `../fixtures/b3/documents/`: the hash-pinned provider-signal, task,
  review-attestation, and verifier-identity documents referenced by the
  manifest;
- `../tests/test_b3_terminal_propagation.py`: fixture-oracle regression
  tests (status, terminal reason, and Check Run conclusion per scenario),
  direct classification priority-order unit tests, override-detection,
  artifact-publication, and identity-separation coverage;
- `../.github/workflows/b3-terminal-propagation.yml`: the real, two-job
  Actions workflow described above.

## Local validation

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --disable-pip-version-check --no-input -r requirements-b0.txt
.venv/bin/python tools/validate_b0.py suite --manifest fixtures/b0/manifest.v1.json
.venv/bin/python tools/finalize_b1.py suite --manifest fixtures/b1/manifest.v1.json
.venv/bin/python tools/verify_b2.py suite --manifest fixtures/b2/manifest.v1.json
.venv/bin/python tools/propagate_b3.py suite --manifest fixtures/b3/manifest.v1.json
.venv/bin/python -m unittest discover -s tests -p 'test_b0_contracts.py'
.venv/bin/python -m unittest discover -s tests -p 'test_b1_finalizer.py'
.venv/bin/python -m unittest discover -s tests -p 'test_b2_verifier.py'
.venv/bin/python -m unittest discover -s tests -p 'test_b3_*.py'
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

The B2 fixture suite succeeds only when every one of the 18 contract-oracle
scenarios matches its declared exit code, `passed` value, and exact
failure-code set, and the `deterministic-repeat` scenario's two runs
publish byte-identical `verification.v1` reports. A hash change in any
source fixture document fails closed before any verification attempt runs.

The B3 fixture suite succeeds only when every one of the 13 required
scenarios matches its declared `result.v1` status/terminal_reason and the
Check Run conclusion the composed, unmodified B1/B2 tools force -- including
the immutable false-success replay of historical run `29190170902`, which
must fail closed on `max_turns` despite a green adapter self-report and a
green Actions job conclusion. A hash change in any source fixture document
fails closed before any pipeline attempt runs.

Every report contains:

```json
{
  "authoritative_verifier": false,
  "bootstrap_scope": "B0"
}
```

(or `"bootstrap_scope": "B1"` / `"bootstrap_scope": "B2"` / `"bootstrap_scope":
"B3"` for the finalizer, verifier, and propagator suites, respectively).
These flags are normative: B0, B1, B2, and B3 evidence must not be
represented as a working truthful execution pipeline beyond what each step
actually establishes -- B3's real Actions workflow notwithstanding, its own
Check Run conclusion is only ever as trustworthy as the composed B1/B2
tools' own evaluation of the artifacts it collects.
