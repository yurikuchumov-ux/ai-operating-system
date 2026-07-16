# Changelog

## Unreleased
- Add the Issue #29 P0 Actions adapter/check: one thin, Actions-first
  executor adapter (`tools/p0_actions_adapter.py`) and workflow
  (`.github/workflows/p0-actions-adapter.yml`) -- not a standalone
  orchestrator service -- so a future immutable task (e.g. Issue #20's
  canary) can be executed by the pinned
  `anthropics/claude-code-action@6902c227aaa9536481b99d56f3014bbbad6c6da8`
  in a clean, permission-bounded ephemeral checkout. Every workflow input is
  untrusted (full lowercase 40-hex task commit, allowlisted `.ai/tasks/`
  path, `agent/*` non-default target branch); the immutable task is fetched
  by exact commit and validated against the unmodified `task.v1` schema, and
  base/branch are bound before any executor runs. A real Claude session id
  is preserved, otherwise a pipeline-derived UUID5 of real run facts is used
  (never a fabricated executor id). Independent review is bound to the exact
  subject SHA and fails closed when missing, ineligible, self-lineage, or
  invalidated by a new executor head. The verifier-owned Check Run (context
  `p0-actions-verifier`) is published only from this repository's own
  `verification.v1.passed`, never from Claude prose or an Actions job
  conclusion; verification-only rerun mode never invokes Claude or mutates
  the branch; the workflow never merges, force-pushes, writes the default
  branch, edits settings, or deploys. Only the executor job holds
  `contents: write`, scoped to the target branch. Deterministic AC-A2
  fixtures (`fixtures/p0/manifest.v1.json`, eight required positive/negative
  scenarios) and `tests/test_b3_p0_actions_adapter.py` prove the
  admission/verification logic offline; produced `result.v1`/`verification.v1`
  documents validate against the unmodified schemas. Registers the
  `repo.p0.actions.suite` command. Does not claim GitHub branch-protection
  or required-status enforcement -- that remains Issue #29 control-plane work
  after this PR. The B0-B3 contracts, schemas, workflows, and tools are
  unchanged.
- Correct the B3 live pipeline for Issue #27 after run 29397325438 attempt 2
  proved that a valid, independent review still produced an unverifiable
  result: `result.checks`/`result.acceptance_results` were unconditionally
  empty and the adapter's real registered-command execution failed with
  `ModuleNotFoundError: jsonschema` because dependencies were only ever
  installed in the always-run finalize job, never where the adapter itself
  ran. The `execute` job now installs the newly declared
  `requirements-b3.txt` before invoking the pinned adapter action.
  `tools/propagate_b3.py:build_checks_and_acceptance` now populates the
  required check and every required acceptance result from trusted,
  directly observed evidence only -- the adapter's own transcript (parsed
  structurally by `resolve_adapter_registered_command_result`, never its
  self-report) and this job's own directly executed check exit code --
  composed on top of, never by editing, the existing unmodified B1
  finalizer. `classify_terminal` gains one narrow, backward-compatible gate:
  a real, transcript-observed adapter command failure now also fails closed
  independently of a separately-passing direct check, closing the exact
  attempt-2 gap. The live workflow now binds Issue #27's own exact task
  control commit/path and a separate, dedicated Issue #27
  review-attestation control ref/path (never Issue #19's), and threads the
  exact fetched task/review-attestation commits through to
  `workflow-run-metadata.json`. Five new fixtures
  (`accept-live-required-evidence`, `reject-adapter-command-failure`,
  `reject-direct-check-failure`, `reject-missing-acceptance-evidence`,
  `reject-self-report-override`) exercise this path against a real,
  required-checks/acceptance task fixture, bringing the B3 fixture suite to
  20 scenarios.
- Close two remaining B3 truthful-live blockers found by architect
  postcondition review of the second corrective attempt: (1)
  `actions/checkout` on `pull_request` defaults to the synthetic merge
  ref/commit, and a Check Run keyed off `context.sha` on that event is also
  the merge commit, not the PR head -- a new `resolve-subject` job now
  resolves exactly one trusted subject SHA
  (`github.event.pull_request.head.sha` on `pull_request`, `github.sha`
  only on `workflow_dispatch`) and every downstream use (both jobs'
  `checkout` `ref:`, the Git observation's `head_sha`, the B2 verifier's
  `expected_subject_sha` binding via a new required, non-nullable
  `trusted_subject_sha` provider-signal field, the published
  `workflow-run-metadata`'s `subject_sha`, and the Check Run's `head_sha`)
  is bound to that one value, never `context.sha` directly. The
  collect-signal step also independently re-checks that the actual checkout
  matches the trusted subject SHA and refuses to proceed if not. (2) the
  live pipeline no longer verifies against the repository-owned
  `fixtures/b3/documents/task-baseline.json` / `review-baseline.json`
  fixture identities (which remain correct and necessary for the offline
  fixture suite only). It now fetches the real task read-only from the
  immutable control commit `86e2826c85ce444127cc95a8551b8570002ec6cf` at
  `.ai/tasks/19/b3-task.v1.json`, and the independent review attestation
  read-only from the separate control ref
  `control/issue-19-b3-review-attestation` at
  `.ai/reviews/19/review-attestation.v1.json`. Neither fetch step
  synthesizes, fabricates, or falls back to fixture content on failure: a
  missing ref, missing path, or unreadable file simply leaves the
  corresponding file absent, and the existing, unmodified B2 verifier's own
  fail-closed handling of an unreadable input document
  (`schema.instance.valid: false`) does the rest, with the existing,
  unmodified `review.subject_sha.equals` and `review.eligibility.passed`
  predicates rejecting a review of the wrong SHA or an ineligible review --
  no new bypass or synthesis logic is added anywhere. It is therefore
  expected, and required, that the first Draft PR run fails closed until an
  independent review attestation for the exact head SHA exists on that
  ref; re-running the same exact-head workflow afterward can then pass.
  Extends `tests/test_b3_terminal_propagation.py` with direct workflow-text
  assertions (exact-head checkout on both jobs, `context.sha` never used
  for the Check Run, the pinned control task commit and independent review
  ref/path both bound, no fixture-baseline invocation, no synthesized
  review content) and direct `run_pipeline` integration tests proving the
  fail-closed mechanism itself for a missing task document, a missing
  review-attestation document, a review of the wrong SHA, and an
  ineligible review -- plus a best-effort (network/history-independent,
  self-skipping) test that schema-validates the real control task via the
  existing B0 validator when the pinned commit happens to be locally
  reachable. All 15 offline fixture scenarios and their expected outcomes
  are unchanged. B0, B1, and B2 schemas, registries, fixtures, and tests
  remain untouched.
- Close B3 false-success gaps found by architect postcondition review of the
  first implementation attempt: (1) the workflow's `execute` job now invokes
  the real, pinned `anthropics/claude-code-action@6902c227aaa9536481b99d56f3014bbbad6c6da8`
  -- the same adapter proven working on
  `origin/design/issue-12-executor-orchestrator` -- in a bounded, read-only
  diagnostic mode (may only read the repo and run the registered B3 test
  command; granted no push/commit/merge/deploy tools), replacing the
  attempt-1 echo placeholder; (2) adds a `pull_request`
  (`opened`/`synchronize`/`reopened`) trigger guarded to this exact head
  branch so opening/updating the Draft PR produces a real pre-merge run,
  with `workflow_dispatch` retained only as supplemental; (3)
  `tools/propagate_b3.py`'s `execution_id` is no longer caller-supplied or
  `uuid.uuid4()` randomness -- `resolve_execution_identity` derives it from
  the adapter's own real `session_id`, extracted by a new bounded,
  fail-closed parser (`resolve_adapter_session_id`) from the pinned action's
  actual `execution_file`/`structured_output` text, or, only when the
  adapter never attempted to run, a UUID5 deterministically derived from
  real Actions run facts (`derive_pipeline_execution_id`); a present but
  malformed session id is treated as unresolvable and classified
  `adapter_error`, never coerced or fabricated; (4) `result_artifact_present`
  / `required_evidence_artifact_present` are now derived by the workflow
  from real, independently checked files on disk (the downloaded adapter
  execution-file artifact and a directly, deterministically executed B3 test
  log), never from Git commit existence; (5) `timeout` is now classified
  only from explicit elapsed-time-versus-budget evidence -- computed by
  `classify_terminal` itself from real execute-job start/completion
  timestamps fetched from the Actions REST API, never a blanket "the job
  failed" mapping -- and a new `runner_lost` terminal reason (the adapter
  action never attempted) is distinguished from `adapter_error` (it
  attempted but its session is unresolvable, or it reported a real error);
  (6) the Check Run conclusion remains sourced only from
  `verification.v1.passed`, and the final job step still gates this job's
  own exit code on that same value. Extends
  `tests/test_b3_terminal_propagation.py` with execution-identity
  resolution tests, corrected classification-priority tests (evidence-based
  timeout, `runner_lost`, session-resolution fail-closed behavior), and
  live-workflow-content assertions (pinned adapter action present,
  pre-merge trigger present and guarded, real execution-output parsing, real
  artifact observation, no synthetic execution ID, no blanket
  failure-to-timeout mapping). All 13 originally required offline fixture
  scenarios are preserved with unchanged expected outcomes; 2 scenarios
  (`reject-runner-lost`, `reject-adapter-session-unresolvable`) are added to
  exercise the corrected paths. B0, B1, and B2 schemas, registries,
  fixtures, and tests remain untouched.
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
