# Independent audit of AI Development Studio

**Status:** final audit for review
**Date:** 2026-07-12
**Scope:** analysis only; no product implementation or merge
**Tracking issue:** [#14](https://github.com/yurikuchumov-ux/ai-operating-system/issues/14)

## 1. Executive summary

AI Development Studio is not yet a single, reliable delivery system. It is a
set of partially connected repositories and workflows with useful governance
ideas, but with no end-to-end contract that reliably turns a request into a
reviewed, tested and traceable change.

The strongest part is the governance direction in `ai-operating-system`: work
is expected to start from an Issue, run in a branch, pass checks and receive an
independent review before merge. The reusable repository template also proves
that automated repository preparation can work. The main weakness is the gap
between declared process and machine-enforced behavior. A successful GitHub
Actions conclusion can currently mean only that an agent process exited, not
that the requested repository change was completed.

The local voice-agent implementation is a valuable prototype, but must not be
treated as production-ready. Its current security boundaries allow fail-open
authentication, unauthenticated business operations, invalid bookings and
unsafe handling of personal data. Deployment behavior can delete local logs,
and there is no durable session or replay model suitable for incident review.

The recommended v1 is deliberately smaller: GitHub Issues and Pull Requests as
the durable control plane, GitHub Actions as the execution plane, explicit
machine-readable completion contracts, least-privilege credentials, mandatory
validation, and an independent human or model reviewer before merge.

## 2. Audit method and evidence

The audit combined repository inspection, Git and GitHub state, workflow run
results, source review and local diagnostic execution. No production system was
modified. Temporary diagnostic dependencies were isolated from the project.

### 2.1 Repositories and revisions

| Component | Repository or path | Evidence revision |
| --- | --- | --- |
| Operating system | `yurikuchumov-ux/ai-operating-system` | `a36a8eefcdd06c56edeec93057a90c58a239cf22` (`main`) |
| Repository template | `yurikuchumov-ux/ai-project-template` | PR revisions listed below |
| Voice-agent prototype | `yurikuchumov-ux/ai-development-studio` and local workspace | PR #8: `a178ab...`; local working tree inspected separately |
| Audit handoff | `AI_DEVELOPMENT_STUDIO_FULL_HANDOFF_TO_CODEX.md` | user-provided local handoff |

Important Pull Request evidence:

- Operating system PR #9: `21f029...`.
- Operating system PR #11: `51939d...`.
- Operating system PR #13: `6d8304...`.
- Template PR #4: `930455...`; workflow run `29150489765` succeeded.
- Template PR #6: `fe1a18...`; workflow run `29153140146` succeeded.
- Template PR #8: `0dce59...`; workflow run `29173154471` failed.
- Voice-agent PR #8: `a178ab...`.

The identifiers above are evidence anchors, not endorsements of the changes.
Short SHAs are retained where that was the verified GitHub representation.

### 2.2 Diagnostic results

- Python compilation completed successfully for the inspected voice-agent
  source.
- HTTP smoke diagnostics showed that adapter schemas were available without
  authentication.
- The booking path accepted an invalid booking request.
- The inspected workflow run `29190170902` concluded as successful even though
  the agent reported `error_max_turns`, produced no commit, and left PR #13's
  head unchanged.

These diagnostics establish behavioral facts only. They do not constitute a
complete penetration test, load test or production-readiness certification.

## 3. Current system assessment

### 3.1 AI operating system

The operating-system repository contains the right conceptual primitives:

- Issue-backed work;
- isolated branches;
- Pull Requests as the review boundary;
- explicit verification;
- independent review;
- separation between authoring and approval.

However, several of these are documentary rules rather than enforceable
contracts. The system has no canonical schema for a task request, agent output,
verification evidence or terminal state. This makes it possible for the prose,
the workflow status and the actual Git state to disagree.

The repository should remain the source of governance and shared standards,
but it should not become a monorepo for product implementations. Product code
must stay in product repositories, while reusable workflow contracts may be
versioned and consumed from the operating-system repository.

### 3.2 Project template

The template demonstrates that repository bootstrapping and basic automated
changes can succeed. Runs `29150489765` and `29153140146` are useful positive
evidence. Template PR #8 and run `29173154471` show that the path is not yet
stable enough to advertise as a dependable autonomous loop.

The template needs a versioned acceptance contract. A generated repository is
not complete merely because files were written; it must also satisfy structural
checks, security defaults, ownership rules and a deterministic smoke test.

### 3.3 Voice-agent prototype

The prototype provides concrete domain behavior and therefore exposes the most
important operational risks. It is useful as a test product for the studio, but
not as its control plane. The control plane must be able to reject or quarantine
unsafe product changes independently of the product's own code.

The local working tree also contained unrelated user files and untracked
artifacts. They were not modified during this audit. This confirms that future
automation must always establish a clean, isolated checkout rather than operate
directly in a user's working directory.

## 4. Critical findings

### 4.1 Security boundary is fail-open

Authentication behavior can fall back to allowing a request when expected
configuration is missing or incomplete. A missing security configuration must
never silently convert a protected path into a public path.

**Required state:** fail closed by default; startup must reject invalid security
configuration; public endpoints must be explicitly enumerated.

### 4.2 Business endpoints are reachable without authentication

The inspected service exposed adapter and business behavior without a reliable
authorization boundary. Schema exposure also makes discovery of the reachable
surface easier.

**Required state:** authenticate every non-health endpoint, authorize each
business action, and disable or protect interactive schema endpoints outside
explicit development mode.

### 4.3 Booking validation is insufficient

An invalid booking was accepted by the diagnostic path. This can corrupt
availability, create impossible reservations and trigger downstream messages or
charges based on invalid state.

**Required state:** server-side validation of time, duration, resource,
availability, identity and idempotency before persistence or side effects.

### 4.4 Personal data is written to JSONL logs

The inspected design can persist conversation or customer data in line-based
local logs without an adequate retention, access-control or redaction model.
Such files are easy to copy, commit, upload or retain indefinitely.

**Required state:** structured redacted telemetry; explicit data classification;
short retention; access logging; encryption where durable personal data is
necessary; no secrets or raw conversation payloads in normal application logs.

### 4.5 Deployment may delete logs

Deployment behavior can remove local log data. This is simultaneously a data
loss risk and an incident-response risk because evidence disappears during the
operation most likely to precede a failure.

**Required state:** immutable or externally retained operational logs, with
deployment separated from retention and deletion policies.

### 4.6 No durable session and replay model

There is no trustworthy model for reconstructing a conversation, tool call,
decision and side effect. Without correlation IDs and append-only event records,
failures cannot be reliably investigated or replayed safely.

**Required state:** stable session, turn, tool-call and request identifiers;
idempotency keys; explicit event versions; redacted append-only audit events;
controlled replay that cannot duplicate side effects.

### 4.7 Tool exposure is broader than necessary

Tools are not filtered by role, tenant, channel and task. A model must not be
able to discover or invoke capabilities merely because an adapter registered
them.

**Required state:** deny by default, per-task allowlists, scoped credentials,
argument validation, rate limits and auditable authorization decisions.

## 5. Workflow reliability findings

### 5.1 Successful workflow does not guarantee successful task

Run `29190170902` is the clearest counterexample. GitHub reported success, but
the agent reported `error_max_turns`; no commit was created and PR #13 did not
advance. This is a false-success condition at the control-plane level.

A task workflow must fail unless all required postconditions are independently
verified. The agent's natural-language answer is evidence, not the authority.

Minimum postconditions for a change task:

1. the expected branch exists;
2. the head SHA changed when a change was required;
3. the diff is within the declared scope;
4. required checks ran and passed;
5. an artifact contains the result schema and verification evidence;
6. the PR or Issue contains an unambiguous terminal status;
7. failures such as timeouts, maximum turns and empty diffs propagate as failed
   workflow conclusions.

### 5.2 There is no canonical task state machine

Issue labels, comments, workflow jobs and PR state can drift. Introduce a small
state machine:

`requested -> validated -> running -> change_proposed -> verifying -> review -> done`

Terminal exceptions are `failed`, `cancelled` and `blocked`. Every transition
must record actor, timestamp, source SHA and evidence URL. Only the orchestrator
may publish the authoritative machine state.

### 5.3 Independent review is not technically enforced

The authoring agent must not approve its own result. Repository protection
should require a different actor for approval, and high-risk areas should
require CODEOWNERS or a named human reviewer.

### 5.4 Retry and idempotency semantics are undefined

Rerunning a workflow may repeat comments, commits or external effects. Every
task needs a stable execution ID and operations must be idempotent or explicitly
non-retriable.

## 6. Repository boundaries

Keep the boundaries explicit:

| Repository | Owns | Must not own |
| --- | --- | --- |
| `ai-operating-system` | governance, schemas, reusable workflows, audit guidance | product-specific runtime code and customer data |
| `ai-project-template` | minimal compliant repository skeleton and its acceptance tests | orchestration state or product-specific secrets |
| `ai-development-studio` | voice-agent/product implementation and its tests | global governance authority |

Shared contracts should be released by immutable tag or commit SHA. Consumers
must pin a version, and upgrades must arrive through reviewable Pull Requests.

## 7. Recommended v1 architecture

The v1 should use existing GitHub primitives before introducing a separate
orchestrator service.

### 7.1 Control plane

- A GitHub Issue is the durable task request.
- A validated Issue form supplies repository, objective, allowed paths, risk
  class, acceptance checks and required reviewer class.
- A GitHub Action validates the request and creates an isolated branch.
- The execution agent receives only the repository checkout, task contract and
  credentials required for that task.
- The agent emits a machine-readable result artifact.
- A separate verification job checks Git state and runs declared tests.
- A Draft PR is created only when a reviewable diff exists.
- A different reviewer approves or requests changes.
- Merge remains a human-controlled action in v1.

### 7.2 Result contract

At minimum, the result artifact should contain:

```json
{
  "schema_version": "1",
  "task_id": "owner/repo#123",
  "execution_id": "uuid",
  "base_sha": "...",
  "head_sha": "...",
  "status": "change_proposed",
  "changed_files": ["path"],
  "checks": [
    {"name": "test", "command": "...", "exit_code": 0}
  ],
  "warnings": [],
  "artifacts": []
}
```

The verifier must reject unknown schema versions, a missing head SHA, an empty
diff for a task that requires a change, undeclared file modifications and any
required check without a successful exit code.

### 7.3 Credential model

- Prefer GitHub App installation tokens over personal access tokens.
- Mint short-lived, repository-scoped credentials per execution.
- Separate read, write, PR and deployment permissions.
- Never pass production credentials to an authoring job.
- Use protected environments and explicit approval for deployment.
- Record credential class and permission set, never the secret value.

### 7.4 Isolation

Each execution must start from a clean ephemeral checkout at a recorded base
SHA. It must not reuse the user's desktop working tree. Network access should be
disabled unless declared, and any enabled destinations should be allowlisted.
Artifacts must be scanned for secrets before upload.

## 8. Verification strategy

Verification must be proportional to risk and independent of the agent report.

### Level 0: document-only

- `git diff --check`;
- link and Markdown checks where configured;
- scope check for allowed paths;
- secret scan.

### Level 1: normal code change

- all Level 0 checks;
- formatter, linter, type checks and unit tests;
- changed-file and dependency review;
- deterministic build or smoke test.

### Level 2: security or data boundary

- all Level 1 checks;
- negative authorization tests;
- dependency and static security scans;
- data-retention and logging tests;
- explicit human security review.

### Level 3: deployment or external side effects

- all Level 2 checks;
- protected environment approval;
- dry run or staging validation;
- rollback plan and post-deploy checks;
- immutable deployment and audit evidence.

For the voice-agent prototype, the first mandatory regression suite should cover
fail-closed startup, unauthenticated rejection, authorization by action, invalid
booking rejection, idempotent booking, PII redaction, safe log retention and
replay without repeated side effects.

## 9. Phased implementation plan

### Phase 0 — stop unsafe claims

1. Mark the voice-agent prototype as non-production.
2. Disable any public deployment until authentication and validation are fixed.
3. Treat agent workflow success as provisional unless repository postconditions
   are verified.
4. Preserve current evidence and do not delete logs during deployment.

**Exit criterion:** documentation and repository UI no longer imply unsupported
production readiness or autonomous completion.

### Phase 1 — make the loop truthful

1. Define Issue and result JSON schemas.
2. Add the task state machine.
3. Make maximum-turn, timeout, empty-diff and missing-commit outcomes fail.
4. Verify base/head SHAs and changed paths outside the agent process.
5. Upload result and test evidence as workflow artifacts.

**Exit criterion:** workflow conclusion, task state and Git state cannot disagree
without the verifier failing.

### Phase 2 — secure execution

1. Introduce GitHub App credentials and per-job permissions.
2. Use ephemeral clean checkouts.
3. Restrict network and tools by task.
4. Add secret scanning and artifact redaction.
5. Enforce protected branches, required checks and independent review.

**Exit criterion:** an authoring job cannot self-approve, access unrelated
repositories or deploy to production.

### Phase 3 — harden the reference product

1. Make authentication fail closed.
2. Protect schemas and all business endpoints.
3. Validate and make booking idempotent.
4. Replace raw JSONL personal-data logs with classified, redacted telemetry.
5. Add durable identifiers and safe replay.
6. Prevent deployment from deleting audit evidence.

**Exit criterion:** the security and data-boundary regression suite passes under
Level 2 review.

### Phase 4 — prove repeatability

1. Run the same contract against the template and voice-agent repositories.
2. Collect reliability metrics: false-success rate, retry rate, review rework,
   time to verified PR and escaped defects.
3. Require a sustained zero false-success rate before considering automated
   merge for low-risk work.

**Exit criterion:** repeated tasks produce traceable PRs with reproducible checks
and no ambiguous terminal states.

## 10. Ownership and review roles

| Role | Responsibility |
| --- | --- |
| Owner | defines outcome, risk tolerance and merge decision |
| Orchestrator | validates requests, controls state and verifies postconditions |
| Authoring agent | proposes scoped changes and reports evidence |
| Verification job | independently executes checks and validates Git state |
| Independent reviewer | reviews correctness, security and scope; never the author |
| Repository maintainer | owns branch rules, CODEOWNERS and release policy |

The same model instance may assist more than one role only if the repository
still enforces actor separation for approval and merge. For high-risk work, use
a human reviewer with domain authority.

## 11. Disposition of existing work

No existing Pull Request should be merged solely because an agent or workflow
declared success.

- **Template PR #8:** keep unmerged. Replace or update it only after its failed
  run and review findings are resolved and the template acceptance contract
  passes.
- **Voice-agent PR #8:** keep unmerged as production work. Its useful prototype
  changes may be recovered into smaller PRs after security boundaries and tests
  are established.
- **Operating-system PR #13:** do not treat run `29190170902` as completion.
  Re-run under the truthful completion contract or replace the PR with a clean,
  independently verified change.

Closing or replacing these PRs should be a repository-owner decision. This
audit does not close, merge or modify them.

## 12. Acceptance criteria for the studio

AI Development Studio can be considered operational only when all of the
following are true:

- every task has a validated, durable request and execution ID;
- execution starts from an isolated recorded SHA;
- credentials and tools are least-privilege and task-scoped;
- the result is machine-readable and independently verified;
- workflow success implies all declared postconditions passed;
- a reviewable change produces a Draft PR with evidence;
- the author cannot approve or merge its own work;
- security-sensitive product behavior fails closed;
- personal data handling has classification, redaction and retention rules;
- failures are replayable for diagnosis without repeating external side effects;
- merge and deployment remain explicitly controlled.

## 13. Final decision

Proceed with the project, but narrow the promise. The immediate product is not
an autonomous software company; it is a truthful, secure pipeline that converts
a structured GitHub Issue into an independently verified Draft PR.

Build reliability and security around that loop first. Use the template as the
repeatability fixture and the voice agent as the adversarial reference product.
Do not enable autonomous merge or public production deployment until the
postcondition verifier, actor separation and voice-agent security regression
suite are all enforced.

This document is intentionally analysis-only. It creates no authorization to
merge existing PRs, deploy services, delete data or change production systems.
