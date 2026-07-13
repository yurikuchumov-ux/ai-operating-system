# Changelog

## Unreleased
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
