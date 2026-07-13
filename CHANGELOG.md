# Changelog

## Unreleased
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
