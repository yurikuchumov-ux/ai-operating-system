# Changelog

## Unreleased
- Add B3 terminal-failure propagation for Issue #19: a deterministic
  propagator (`tools/propagate_b3.py`) that classifies exactly one
  `result.v1` terminal status/reason from a trusted provider signal --
  cancellation, adapter/job timeout, max-turns exhaustion, adapter error,
  missing commit, missing result/required-evidence artifact, empty diff, or
  a failed required check, in that fixed priority order -- and never reads
  the adapter's own self-reported status or the Actions job's own
  conclusion to do it. The classified observation is finalized into a
  schema-valid `result.v1` by calling the existing, unmodified B1 finalizer
  (`tools/finalize_b1.py`) directly, then verified by calling the existing,
  unmodified B2 verifier (`tools/verify_b2.py`) directly; the Check Run
  conclusion this tool computes is `success` iff `verification.v1.passed`,
  never adapter prose or raw job status. Adds the first real GitHub Actions
  workflow (`.github/workflows/b3-terminal-propagation.yml`): an
  `execute` job bounded by `timeout-minutes` runs the executor adapter, and
  an always-run `finalize-and-verify` job collects the trusted provider
  signal from directly observable facts, runs the propagator, uploads the
  `result-artifact`, `verification-report`, and `workflow-run-metadata`
  artifacts (both `github.run_id` and the trusted `execution_id` required
  non-null), and publishes the Check Run from the verifier's report alone.
  Adds the narrow `repo.contracts.b3.tests` command registry entry (no new
  predicate or schema). Adds the immutable, hash-pinned B3 fixture manifest
  and documents (`fixtures/b3/manifest.v1.json`) covering all 13 scenarios
  the Issue #19 B3 control contract requires -- including the immutable
  false-success replay of historical run `29190170902` (green,
  `error_max_turns`, zero artifacts, no commit), which fails closed on
  `max_turns` despite both the adapter and the Actions job self-reporting
  success, and one genuine-success scenario that passes cleanly -- plus
  `tests/test_b3_terminal_propagation.py` with fixture-oracle regression
  coverage, direct classification priority-order unit tests, override-
  detection, artifact-publication, and executor/reviewer/checkrun-publisher
  identity-separation coverage. B0, B1, and B2 schemas, registries,
  fixtures, and tests are untouched.
- Add the B2 deterministic offline verifier (`tools/verify_b2.py`): it
  consumes trusted invocation metadata supplied entirely by its caller
  (verification ID, evaluated-at timestamp, expected task/execution/base/
  subject SHAs, and verifier identity -- never generated internally) plus a
  `task.v1`, a finalized `result.v1`, a `review-attestation.v1`, a Git
  observation, and evidence bytes, and emits exactly one schema-valid
  `verification.v1` report. It evaluates only the fixed, ordered set of 14
  registered predicate IDs required by `AC-B2-5`, adding exactly the four
  new predicate registry entries it prescribes
  (`binding.task_id.equals`, `binding.execution_id.equals`,
  `review.subject_sha.equals`, `review.eligibility.passed`) to
  `contracts/registries/predicates.v1.json`; any task or result reference to
  a predicate ID outside that registry fails closed with `unknown_predicate`.
  Evidence bytes are read through one bounded, no-follow descriptor rooted
  at a caller-supplied evidence directory -- relative, contained, regular
  files only, capped at 1 MiB, with a post-read device/inode rebind check --
  and the report is published by staging, fsyncing, and atomically
  hard-linking it into place, so it is never overwritten and no failure
  before that link step leaves a partial or missing-but-referenced report
  behind. Output is canonical JSON, so identical trusted input (including
  the trusted invocation metadata) always verifies to byte-identical bytes.
  Adds the immutable, hash-pinned B2 fixture manifest and documents
  (`fixtures/b2/manifest.v1.json`) covering all 18 scenarios of the
  Issue #18 B2 contract oracle, plus `tests/test_b2_verifier.py` with
  fixture-oracle regression coverage and direct security/failure injection
  for symlinked/path-escaping evidence, evidence mutation and rebinding,
  output collision, and staging write/fsync/link failure. B2 is
  non-authoritative bootstrap evidence: no Actions workflow, Check Run
  publisher, or merge/delegation authority is added.
- Close the B1 pre-existing-evidence TOCTOU gap: verification now opens once
  with `O_NOFOLLOW`, uses `fstat` and descriptor-only bounded reads, rejects
  mutation during reading, and confirms the final pathname still names the
  same regular-file device/inode. Platforms without effective no-follow
  semantics fail closed. Staging now uses unbuffered `os.write` loops, with
  direct write-failure regression tests proving no final or temporary artifact
  survives a failed publication.
- Fix the B1 finalizer's publication atomicity: `result.json` and newly
  created evidence were previously written directly at their final,
  exclusive-create path, so a write or `fsync` failure partway through could
  leave a visible, partially written (or wrongly "successful" but
  un-synced) artifact at the trusted path. Both are now published by writing
  to a private staging file in the same directory, flushing and fsyncing it,
  and only then hard-linking that fully durable file into its final,
  immutable name; the staging file is always removed afterwards, and no
  failure before the link step can leave anything at the final path. Expected
  filesystem publication failures (staging write/fsync errors, a full disk)
  are now reported as `FinalizerPolicyError`, and an existing final artifact
  is still reported as `OverwriteRefused`, instead of an uncaught traceback.
- Fix the B1 finalizer's publication ordering: candidate evidence is now
  durably written and byte-for-byte verified before `result.json` is
  created, so a published result can never reference evidence that was not
  actually written. A repeat finalize attempt is refused before any evidence
  is touched, so append-only overwrite refusal never mutates or adds
  evidence. A conflicting, unreadable, symlinked, or non-regular pre-existing
  evidence path now fails closed instead of being silently trusted. Renames
  the malformed-candidate fixture to `candidate-malformed.raw` so every
  tracked `.json` fixture parses as JSON.
- Add B1 human-supervised harness support: a trusted, always-run result
  finalizer (`tools/finalize_b1.py`) that builds schema-valid `result.v1`
  artifacts from trusted observation input only, preserves the raw executor
  candidate as untrusted hash-addressed evidence, and refuses to overwrite an
  existing finalized artifact. Adds immutable, hash-pinned B1 fixtures
  (`fixtures/b1/manifest.v1.json`) covering success, executor failure,
  timeout, malformed candidate, missing candidate, and overwrite refusal, plus
  direct unit tests for the finalizer's trust boundary and exactly-once
  behavior (`tests/test_b1_finalizer.py`). B1 is non-authoritative bootstrap
  evidence: no Actions workflow, adapter, or verifier authority is added.
- Add B0 versioned contracts, closed registries, offline validators, and
  immutable positive/negative fixtures for Issue #18.
- Harden B0 review gates with mandatory failure-mode coverage, exact acceptance
  contract linkage, bounded fixture mutations, and explicit registry semantics.
- Initial bootstrap.
