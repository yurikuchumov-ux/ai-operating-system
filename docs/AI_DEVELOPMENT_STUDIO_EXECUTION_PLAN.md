# AI Development Studio execution plan

**Status:** planning baseline for independent review

**Issue:** [#16](https://github.com/yurikuchumov-ux/ai-operating-system/issues/16)

**Evidence snapshot:** 2026-07-12, Europe/Moscow

**Base revision:** `a36a8eefcdd06c56edeec93057a90c58a239cf22`

## 1. Authority and evidence rules

This document is the repository-backed execution plan for AI Development
Studio. It does not authorize merge, deployment, repository rename, branch-rule
changes, or product implementation.

Statements use these classifications:

- **VERIFIED FACT** — directly observed in a repository, GitHub API response,
  workflow log, Git revision, or executable diagnostic.
- **DECISION** — the active architecture or delivery rule for v1.
- **RECOMMENDATION** — a proposed owner action that is not yet executed.
- **BLOCKER** — a missing technical or owner-controlled precondition.

Chat history, model memory, handoff prose, workflow color, and agent narrative
are not completion evidence. Where they conflict, repository and GitHub
evidence win.

## 2. The only active v1 objective

**DECISION:** v1 builds one truthful Actions-first delivery loop:

```text
GitHub Issue
  -> validated task contract
  -> clean ephemeral checkout at an exact base SHA
  -> execution agent
  -> versioned machine-readable result artifact
  -> independent deterministic verifier
  -> Draft Pull Request
  -> independent reviewer
  -> human merge decision
```

### 2.1 Definition of truthful

A task is truthful when the authoritative task state, Git state, result
artifact, verifier conclusion, PR state, and reported outcome agree. A green
agent step is never sufficient by itself.

### 2.2 Explicit v1 non-goals

The following are frozen until the v1 loop meets the readiness gates in this
document:

- a standalone orchestrator service;
- an autonomous software company abstraction;
- automatic merge;
- automatic production deployment;
- agent-selected expansion of task scope;
- production claims for the voice-agent prototype;
- capability-aware routing beyond the minimum explicit adapter selection;
- diagnostic replay that can trigger external side effects.

## 3. Canonical repository inventory

### 3.1 Verified names and boundaries

| Role | Canonical repository | Visibility | `main` SHA | Boundary |
| --- | --- | --- | --- | --- |
| Governance and shared contracts | [`yurikuchumov-ux/ai-operating-system`](https://github.com/yurikuchumov-ux/ai-operating-system) | public | `a36a8eefcdd06c56edeec93057a90c58a239cf22` | owns governance, schemas, reusable workflows and evidence contracts |
| Compliant repository fixture | [`yurikuchumov-ux/ai-development-studio-template`](https://github.com/yurikuchumov-ux/ai-development-studio-template) | public | `ec088bf2e95e048ce1f5b69d969542b516afbc8b` | owns the minimal downstream skeleton and repeatability tests |
| Voice reference product | [`yurikuchumov-ux/-ai-development-studio`](https://github.com/yurikuchumov-ux/-ai-development-studio) | private | `f6550d4078ffccc952db269081619fdfe57e598c` | owns product runtime, domain tests and product deployment |

**VERIFIED FACT:** `ai-project-template` does not exist in the verified owner
repository list. The correct template name is
`ai-development-studio-template`.

**VERIFIED FACT:** the voice repository currently includes a leading hyphen:
`-ai-development-studio`. References to `ai-development-studio` without the
hyphen are not the canonical current GitHub name.

**DECISION:** all new task contracts use the exact canonical names above.
Renaming `-ai-development-studio` is a separate owner-controlled migration and
is not performed by this planning PR.

### 3.2 Branch and protection baseline

**VERIFIED FACT:** all three repositories use `main` as the default branch.

**VERIFIED FACT:** no returned branch is protected. GitHub returns `404 Branch
not protected` for both public repositories. For the private voice repository,
GitHub returns `403` and states that the current plan or public visibility is
required for branch protection.

Remote branch counts at the evidence snapshot:

- operating system: 9 branches;
- template: 5 branches;
- voice product: 5 branches.

**BLOCKER:** author/reviewer/merger separation is documentary, not enforced by
branch rules. No production-readiness credit can be earned for actor separation
until required reviews and checks are technically enforced, or an equivalent
owner-approved control is proven for the private repository.

## 4. Issue, Pull Request, and workflow baseline

### 4.1 Operating-system Issues

| Issue | State | Disposition |
| --- | --- | --- |
| [#2 Template Repository v1](https://github.com/yurikuchumov-ux/ai-operating-system/issues/2) | open | historical scope; reconcile with canonical template repository after v1 contracts exist |
| [#4 Fix markdownlint baseline](https://github.com/yurikuchumov-ux/ai-operating-system/issues/4) | open | replace with a scoped maintenance Issue if lint becomes a required v1 check |
| [#6 AI Development Studio v1](https://github.com/yurikuchumov-ux/ai-operating-system/issues/6) | closed | historical; superseded by this plan |
| [#8 Automation First](https://github.com/yurikuchumov-ux/ai-operating-system/issues/8) | open | retain as research; v1 is narrower and governed by #16 |
| [#10 AI OS inheritance](https://github.com/yurikuchumov-ux/ai-operating-system/issues/10) | open | hold for P1 after truthful verifier P0 |
| [#12 Executor Orchestrator](https://github.com/yurikuchumov-ux/ai-operating-system/issues/12) | open | freeze standalone orchestrator implementation; retain research evidence |
| [#14 Independent audit](https://github.com/yurikuchumov-ux/ai-operating-system/issues/14) | open | keep linked to Draft audit PR #15 |
| [#16 Execution plan](https://github.com/yurikuchumov-ux/ai-operating-system/issues/16) | open | active planning Issue for this document |

### 4.2 Operating-system Pull Requests

| PR | Verified state | Decision |
| --- | --- | --- |
| [#1 Bootstrap v1](https://github.com/yurikuchumov-ux/ai-operating-system/pull/1) | merged | historical baseline; no action |
| [#3 Template Repository v1](https://github.com/yurikuchumov-ux/ai-operating-system/pull/3) | closed, not merged | historical; no resurrection |
| [#5 Markdown lint baseline](https://github.com/yurikuchumov-ux/ai-operating-system/pull/5) | closed, not merged | historical; no resurrection |
| [#7 AI Development Studio v1 plan](https://github.com/yurikuchumov-ux/ai-operating-system/pull/7) | closed, not merged | superseded by #16 and this plan |
| [#9 Automation First](https://github.com/yurikuchumov-ux/ai-operating-system/pull/9) | open, ready, failing check | do not merge; extract only v1-compatible rules into clean scoped PRs after P0 |
| [#11 AI OS inheritance](https://github.com/yurikuchumov-ux/ai-operating-system/pull/11) | open Draft, latest check green | hold; revalidate action pins, enforcement and Actions-first compatibility after P0; green review is not merge authority |
| [#13 Executor Orchestrator](https://github.com/yurikuchumov-ux/ai-operating-system/pull/13) | open Draft, check shown green | freeze; do not merge; retain as architecture research because standalone orchestration is a v1 non-goal |
| [#15 Independent audit](https://github.com/yurikuchumov-ux/ai-operating-system/pull/15) | open Draft, no checks | keep Draft; correct repository names, add evidence classification and supply-chain/runner/prompt-injection risks before independent review |

No PR in this table is closed or merged by this plan.

### 4.3 Template Issues and Pull Requests

Issues #1, #3, #5 and #7 are all open at the snapshot.

| PR | Verified state | Decision |
| --- | --- | --- |
| [#2 v1 plan](https://github.com/yurikuchumov-ux/ai-development-studio-template/pull/2) | merged | historical baseline; its broad plan is superseded by this execution plan |
| [#4 Codex POC](https://github.com/yurikuchumov-ux/ai-development-studio-template/pull/4) | open, check green | retain as POC evidence; do not treat as production adapter; owner may close after the mechanism is recovered into a versioned workflow |
| [#6 Claude review POC](https://github.com/yurikuchumov-ux/ai-development-studio-template/pull/6) | open, check green | retain as POC evidence; no independent-review readiness credit until identity separation and verdict enforcement are proven |
| [#8 AI OS inheritance](https://github.com/yurikuchumov-ux/ai-development-studio-template/pull/8) | open Draft, latest check failed | do not merge; replace with a clean PR after the inheritance contract and acceptance tests are fixed |

### 4.4 Voice-product Issues and Pull Requests

Issues #2, #4 and #7 are open; Issue #6 is closed.

| PR | Verified state | Decision |
| --- | --- | --- |
| [#1 MCP write test](https://github.com/yurikuchumov-ux/-ai-development-studio/pull/1) | open Draft, no checks | obsolete test evidence; do not merge; owner may close separately |
| [#3 root README](https://github.com/yurikuchumov-ux/-ai-development-studio/pull/3) | open Draft, no checks | do not merge from the stale branch; recreate current non-production entry documentation in a clean security-baseline PR |
| [#5 v1 plan](https://github.com/yurikuchumov-ux/-ai-development-studio/pull/5) | closed, not merged | historical; no resurrection |
| [#8 GitHub App architecture](https://github.com/yurikuchumov-ux/-ai-development-studio/pull/8) | open Draft, no checks | freeze as research; do not merge into the product repository while standalone orchestration is a v1 non-goal |

### 4.5 Workflow inventory and reliability evidence

| Repository | Active workflows | Runs observed | Conclusions |
| --- | --- | --- | --- |
| operating system | 4 | 29 | 9 success, 20 failure |
| template | 3 | 22 | 13 success, 8 failure, 1 skipped |
| voice product | 0 | 0 | none |

The counts include all runs returned by GitHub at the snapshot, not a selected
sample.

**VERIFIED FACT:** operating-system run
[`29190170902`](https://github.com/yurikuchumov-ux/ai-operating-system/actions/runs/29190170902)
has GitHub conclusion `success` at head
`6d8304ac732dd7973ae84b2705391e1a07af4f43`, but its log contains result subtype
`error_max_turns`. It uploaded zero artifacts and created no later PR commit.

**VERIFIED FACT:** the PR #13 workflow delegates success semantics to
`anthropics/claude-code-action`; it contains no independent postcondition step
for a new commit, allowed diff, result artifact, or exact terminal result.

**DECISION:** run `29190170902` is the canonical false-success regression
fixture. The P0 verifier must make an equivalent fixture fail.

Template runs
[`29150489765`](https://github.com/yurikuchumov-ux/ai-development-studio-template/actions/runs/29150489765)
and
[`29153140146`](https://github.com/yurikuchumov-ux/ai-development-studio-template/actions/runs/29153140146)
prove API/action reachability only. They do not prove the v1 delivery contract.
Template run
[`29173154471`](https://github.com/yurikuchumov-ux/ai-development-studio-template/actions/runs/29173154471)
is the current failed head check for PR #8.

## 5. Verified discrepancies

| Source claim | Repository evidence | Resolution |
| --- | --- | --- |
| template is `ai-project-template` | owner repository list contains `ai-development-studio-template` | use the verified canonical name |
| voice product is `ai-development-studio` | repository URL contains `-ai-development-studio` | retain the leading hyphen until a separate rename migration |
| current PR inventory focuses on #8, #11, #13 and #15 | open PRs also include AI OS #9, template #4/#6 and voice #1/#3 | execution plan gives every open PR a disposition |
| independent review is a required gate | no `main` branch is protected | classify actor separation as blocked, not complete |
| voice adapters are protected by a token | missing token returns without rejection; an environment flag explicitly bypasses auth | classify authentication as fail-open |
| voice agent is ready for wider testing | public adapter mode, unauthenticated core business routes, no CI and unsafe data handling exist | freeze production claims |
| successful run means requested change completed | run `29190170902` is green with `error_max_turns`, no artifact and no new commit | build deterministic postcondition verification first |

The previous audit's repository naming rows are incorrect. Its security and
false-success conclusions are supported by current evidence, but the audit PR
must be corrected before it can be considered merge-ready.

## 6. Versioned task contract

The canonical task artifact is `.ai/tasks/<issue-number>/task.v1.json` or an
equivalent immutable workflow input generated from a validated Issue form.

```json
{
  "$schema": "https://example.invalid/ai-os/task.v1.schema.json",
  "schema_version": "1.0.0",
  "task_id": "yurikuchumov-ux/ai-operating-system#123",
  "repository": "yurikuchumov-ux/ai-operating-system",
  "issue_number": 123,
  "objective": "One testable outcome",
  "change_required": true,
  "base_ref": "main",
  "base_sha": "40-character-lowercase-sha",
  "branch": "agent/issue-123-short-name",
  "allowed_paths": ["path/**"],
  "denied_paths": [".github/workflows/**"],
  "risk_class": "L1",
  "executor": {
    "adapter": "claude-code-actions",
    "version": "immutable-version",
    "max_attempts": 3,
    "timeout_seconds": 1200
  },
  "required_checks": [
    {"id": "unit", "command_id": "repo.unit", "required": true}
  ],
  "reviewer_class": "independent-engineering",
  "external_side_effects": "forbidden",
  "created_by": "github-login",
  "created_at": "RFC3339 timestamp"
}
```

### 6.1 Task validation rules

The validator fails before execution when:

- the schema version is unsupported;
- repository is not an explicit allowlisted canonical name;
- `base_sha` is not the resolved commit for `base_ref`;
- objective or acceptance checks are empty;
- allowed paths are empty for a change task;
- allowed and denied paths overlap ambiguously;
- workflow, security, deployment or governance paths are writable under an
  insufficient risk class;
- the executor adapter or immutable version is unknown;
- timeout or attempts exceed policy;
- external side effects are not explicitly forbidden or separately approved;
- author and required reviewer identity classes cannot be separated.

The Issue text is user input. It must never be interpolated into a shell command
or granted authority to override workflow policy.

## 7. Versioned execution result contract

Every executor invocation must produce exactly one `result.v1.json`, even on
failure. The orchestrator job, not the model, supplies immutable identity and
Git fields where possible.

```json
{
  "$schema": "https://example.invalid/ai-os/result.v1.schema.json",
  "schema_version": "1.0.0",
  "task_id": "yurikuchumov-ux/ai-operating-system#123",
  "execution_id": "uuid",
  "attempt": 1,
  "executor": {
    "adapter": "claude-code-actions",
    "actor_id": "verified-identity",
    "adapter_version": "immutable-version"
  },
  "started_at": "RFC3339 timestamp",
  "finished_at": "RFC3339 timestamp",
  "base_sha": "40-character-lowercase-sha",
  "head_sha": "40-character-lowercase-sha-or-null",
  "status": "change_proposed",
  "terminal_reason": "completed",
  "changed_files": ["path/file"],
  "checks": [
    {
      "id": "unit",
      "command_id": "repo.unit",
      "exit_code": 0,
      "evidence_path": "artifacts/unit.txt"
    }
  ],
  "artifacts": [
    {"path": "artifacts/unit.txt", "sha256": "64-character-hash"}
  ],
  "warnings": [],
  "error": null
}
```

Allowed `status` values are `change_proposed`, `no_change_required`, `failed`,
`cancelled`, and `blocked`. Natural-language summaries are optional and never
authoritative.

Allowed `terminal_reason` values include `completed`, `max_turns`, `timeout`,
`missing_commit`, `missing_artifact`, `empty_diff`, `scope_violation`,
`check_failed`, `cancelled_by_owner`, `adapter_error`, and
`reviewer_unavailable`.

## 8. Canonical task state machine

The workflow publishes one authoritative Check Run plus an append-only result
artifact. Comments are projections only.

| Source | Event and guard | Target | Required evidence |
| --- | --- | --- | --- |
| `REQUESTED` | task schema passes | `VALIDATED` | normalized task artifact and resolved base SHA |
| `REQUESTED` | validation fails | `FAILED` | validation error list |
| `VALIDATED` | checkout is clean and exactly at base SHA | `RUNNING` | execution ID and runner metadata |
| `VALIDATED` | checkout or adapter cannot start | `FAILED` | terminal reason |
| `RUNNING` | executor returns candidate result | `VERIFYING` | raw result artifact, branch ref |
| `RUNNING` | max turns, timeout, cancellation or adapter error | `FAILED` or `CANCELLED` | terminal result artifact |
| `VERIFYING` | every deterministic postcondition passes | `CHANGE_PROPOSED` or `NO_CHANGE_REQUIRED` | verifier report and evidence hashes |
| `VERIFYING` | any required postcondition fails | `FAILED` | failing invariant and observed value |
| `CHANGE_PROPOSED` | Draft PR created at verified head SHA | `REVIEW_REQUIRED` | PR URL and head SHA |
| `REVIEW_REQUIRED` | eligible independent reviewer approves exact head SHA | `OWNER_DECISION` | review ID, actor and reviewed SHA |
| `REVIEW_REQUIRED` | reviewer requests changes | `CHANGES_REQUESTED` | review ID and findings |
| `CHANGES_REQUESTED` | next attempt is below policy limit and uses new evidence | `RUNNING` | new execution ID and attempt number |
| `CHANGES_REQUESTED` | three attempts failed | `BLOCKED` | handoff artifact and replacement executor requirement |
| `OWNER_DECISION` | owner merges exact reviewed SHA | `DONE` | merge commit and owner actor |
| `OWNER_DECISION` | owner declines or closes | `CANCELLED` | owner event |

`FAILED`, `BLOCKED`, `CANCELLED`, and `DONE` are terminal for an execution ID.
A retry always receives a new execution ID. A fourth attempt is forbidden unless
the owner records new material evidence and selects a replacement executor.

## 9. Truthful verifier requirements

The verifier is deterministic code in a separate job. It must not use the
authoring model's conclusion as a pass condition.

### 9.1 Required inputs

- validated task artifact and its SHA-256 hash;
- GitHub event payload;
- immutable base SHA;
- executor result artifact;
- checked-out repository and candidate branch;
- required check evidence;
- verified author identity and reviewer policy.

### 9.2 Mandatory postconditions

The verifier must independently prove:

1. task and result schemas are supported and valid;
2. execution ID is unique and belongs to the task;
3. checkout started clean at the exact base SHA;
4. candidate branch exists;
5. result `base_sha` equals the validated base SHA;
6. observed branch head equals result `head_sha`;
7. a change task has a new commit and non-empty diff;
8. a no-change task explicitly permits `no_change_required` and provides a
   deterministic reason;
9. every changed path is allowed and no denied path changed;
10. commits contain no merge commit or force-push evidence unless policy allows
    it;
11. every required command ID ran through a repository-defined command map;
12. every required check exited zero and its evidence hash matches;
13. required artifacts exist, are non-empty, scanned, and hash-valid;
14. no secret or prohibited personal data is present in diff or artifacts;
15. max-turns, timeout, missing commit, missing artifact, empty required diff,
    adapter error, and check failure produce a failed workflow conclusion;
16. the Draft PR, when created, points to the verified head SHA;
17. reviewer identity differs from every authoring identity in execution
    lineage;
18. owner merge is possible only for the exact reviewed SHA.

The verifier writes `verification.v1.json` and fails the job on any violated
invariant. Its exit code, not an agent message, controls the Check Run.

### 9.3 P0 regression fixtures

At minimum, tests must cover:

- successful scoped documentation change;
- `error_max_turns` modeled on run `29190170902`;
- job timeout;
- executor exit zero with no commit;
- commit exists but result artifact is absent;
- result artifact exists but required evidence file is absent;
- empty diff when `change_required=true`;
- changed file outside `allowed_paths`;
- forged `head_sha`;
- failing required command hidden by a green agent step;
- author attempting to review its own head SHA;
- a new commit pushed after approval and before merge.

## 10. Actor separation and trust boundaries

| Actor | May | Must not |
| --- | --- | --- |
| Product Owner | define outcome and risk tolerance; decide exact reviewed merge | act as message bus between agents; provide secrets in comments |
| Chief Architect | define contracts and roadmap; create planning tasks; verify evidence | approve own planning or implementation as independent reviewer |
| Execution adapter | modify only task branch within allowed paths; emit result artifact | approve, merge, deploy, change branch rules or widen its own permissions |
| Deterministic verifier | read repository and artifacts; publish required check | modify candidate code or accept model narrative as proof |
| Independent reviewer | review exact verified SHA and risk evidence | share authoring lineage or approve a newer unreviewed SHA |
| Deterministic publisher | create branch/commit/Draft PR from verified output | interpret prompts, approve or merge |
| Human merger | merge exact reviewed SHA | bypass failed/missing required checks |

Credentials are short-lived, repository-scoped and job-specific. Authoring jobs
do not receive merge, administration, environment deployment, or unrelated
repository access. Workflow-file changes require a higher risk class and human
review.

**BLOCKER:** current branch settings do not enforce these rules. P0 must either
enable enforceable protection on the public control repositories or prove an
equivalent ruleset. The private voice repository requires an owner decision on
plan/visibility or a different enforceable merge gate before production.

## 11. Voice-agent P0 security baseline

The voice repository is an adversarial reference product and remains
non-production until every mandatory gate below has evidence.

### 11.1 Verified current risks

- `require_adapter_auth` returns successfully when
  `VOICE_AGENT_ADAPTER_TOKEN` is missing: fail-open authentication.
- `VOICE_AGENT_ALLOW_UNAUTHENTICATED_ADAPTERS` explicitly bypasses adapter
  authentication.
- session, context, prompt-contract and all direct `/voice/tools/*` business
  routes have no authentication dependency.
- generated Vapi assistant responses attach every global `TOOL_SCHEMAS` entry,
  not the client-specific allowlist returned by `allowed_tools_for_client`.
- booking fields are optional and only presence-checked; date, time, phone,
  session ownership, availability and idempotency are not proven.
- booking success returns a synthetic ID without persistence, concurrency
  control or double-booking protection.
- event payloads containing phone, transcript, questions and tool arguments are
  written unredacted to local JSONL files.
- deployment executes `rm -rf "$REMOTE_DIR"`; runtime logs inside that directory
  can be destroyed during deployment.
- no test suite or GitHub Actions workflow exists in the voice repository.
- FastAPI interactive schema exposure is not explicitly disabled outside
  development.

### 11.2 Required security evidence pack

Every finding or fix must include:

- repository, full SHA, path and line range;
- configuration precondition;
- reproducible request or test fixture;
- observed response or failing assertion;
- risk and affected data/action;
- regression test ID;
- fixed evidence at a new SHA;
- independent reviewer identity and exact reviewed SHA.

Secrets, live customer payloads and raw personal data are prohibited from the
pack.

### 11.3 Production hard gates

Production claims and public business endpoints remain frozen until all are
proven:

- fail-closed startup when auth configuration is absent or invalid;
- explicit public endpoint allowlist limited to a minimal health endpoint;
- authentication and action/object-level authorization for every other route;
- tenant isolation and client/session ownership checks;
- docs/schema protection outside explicit development mode;
- per-client and per-task tool allowlists enforced at exposure and invocation;
- strict date, time, timezone, DST, party-size, phone and required-field
  validation;
- transactional availability and double-booking protection;
- idempotency keys and safe retries for every external effect;
- PII inventory, redaction, access control, retention and deletion policy;
- deployment that preserves independently retained audit evidence;
- correlation IDs and append-only versioned events;
- replay that cannot repeat booking, messaging or payment side effects;
- rate limits, abuse controls and prompt-injection defenses;
- human confirmation for irreversible or high-risk actions;
- negative security tests in an independently verified PR.

## 12. Delivery priorities

### P0 — make claims safe and the loop truthful

1. Publish the versioned task and result schemas with validators and fixtures.
2. Implement the deterministic truthful verifier and false-success regression
   suite.
3. Propagate max-turns, timeout, missing commit, missing artifact, required empty
   diff and failed checks to a failed workflow conclusion.
4. Publish a non-production voice-agent notice and prohibit public production
   claims.
5. Produce the fail-closed security evidence pack without changing production.
6. Preserve audit evidence across deployments and define retention ownership.
7. Replace incorrect repository names in active planning/audit documentation.
8. Establish objective readiness gates and stop reporting subjective completion
   percentages.

P0 implementation is decomposed into separate Issues. Each Issue has its own
branch, result artifact, verifier evidence and Draft PR. No combined P0 mega-PR
is permitted.

### P1 — secure and repeatable MVP

- independent verifier workflow consumed by immutable version;
- clean ephemeral checkout and controlled publisher;
- branch/ruleset enforcement and CODEOWNERS-equivalent actor separation;
- task state projection into Check Runs and Issues;
- template inheritance contract and deterministic acceptance suite;
- fail-closed voice authentication and complete authorization boundaries;
- tenant isolation, safe bookings, idempotency and concurrency control;
- PII-safe observability and deployment evidence preservation;
- secret scanning, artifact redaction and immutable third-party action pins.

### P2 — capabilities after proof

- side-effect-safe diagnostic replay;
- unified Claude/Codex adapter contract;
- capability-aware routing from declared adapter metadata;
- reliability trend reporting across repositories;
- standalone orchestration service only if Actions-first limits are demonstrated
  with measured failure modes that cannot be solved within the existing plane.

## 13. Failure escalation and delegation

Delegation is confirmed only when all exist:

- validated task ID;
- real adapter invocation;
- GitHub run ID and execution ID;
- acknowledged executor identity;
- immutable base SHA;
- repository-backed result artifact location.

A comment, prompt, assignment, reaction, or claimed handoff is not delegation.

Success is confirmed only after independent deterministic verification. After
three failed attempts, the current executor stops, produces a handoff artifact,
and is replaced. A fourth attempt is forbidden without new material evidence
recorded by the owner.

## 14. Measurable readiness model

Readiness uses fixed binary evidence gates. A category earns either all assigned
points or zero; partial or subjective credit is forbidden. An evidence URL must
identify an immutable SHA, workflow run, artifact, review, or repository rule.

| Category | Points | Pass condition | Baseline |
| --- | ---: | --- | --- |
| versioned task/result contracts | 10 | schemas, validators, positive and negative fixtures pass | 0 — not implemented on `main` |
| truthful execution loop | 20 | three change tasks complete with no state/Git disagreement | 0 — false-success fixture exists |
| independent verifier | 15 | all P0 failure fixtures produce correct conclusions | 0 — no verifier |
| actor separation | 10 | author cannot satisfy review/merge gate for own SHA | 0 — branches unprotected |
| clean checkout and credentials | 10 | exact base SHA, ephemeral runner and least privilege proven | 0 — no end-to-end contract |
| template repeatability | 8 | three fresh template tasks produce verified Draft PRs | 0 — POCs only |
| AI OS inheritance | 7 | immutable contract consumption and acceptance tests pass | 0 — PRs unmerged/failed |
| voice authentication/authorization | 8 | all negative auth and tenant tests pass | 0 — fail-open paths exist |
| booking safety | 5 | invariant, idempotency and concurrency tests pass | 0 — not implemented |
| PII and observability | 4 | inventory, redaction, retention and safe event tests pass | 0 — raw JSONL payloads |
| deployment and audit evidence | 3 | deployment preserves immutable evidence and rollback proof | 0 — destructive directory replacement |

Current verified readiness is **0 of 100 evidence points**. This is not an
estimate of engineering effort. It means none of the target categories has yet
passed its complete acceptance condition on a protected, independently verified
path.

### 14.1 Mandatory release gates

Point totals never override a hard gate. MVP readiness additionally requires:

- all P0 Issues closed by merged, independently reviewed evidence;
- zero unexplained false-success runs across three consecutive end-to-end tasks;
- actor separation enforced;
- no critical/high unresolved voice security finding for any exposed endpoint;
- human-only merge decision retained;
- rollback and evidence-retention owner identified.

## 15. P0 implementation Issue map

The plan requires these independent implementation tasks:

1. task/result schemas and validators;
2. truthful verifier plus failure propagation;
3. voice-agent non-production freeze and canonical naming corrections;
4. voice-agent fail-closed security evidence pack;
5. deployment/audit-evidence preservation;
6. enforceable actor separation and repository protection decision;
7. readiness evidence registry and reporting.

Issue creation does not count as delegation. Implementation starts only when a
real Actions adapter returns a run ID and execution ID. At this snapshot, no
merged reusable implementation adapter satisfies this contract, so execution is
blocked pending P0 verifier bootstrap through an explicitly owner-approved,
human-supervised workflow.

## 16. Owner decisions required

The Product Owner is not middleware. The owner is required only for decisions
that change risk or repository policy:

- accept or request changes to this execution plan and its PR dispositions;
- select an eligible independent reviewer for the exact planning PR SHA;
- decide whether the private voice repository will change plan/visibility or
  use an alternative enforceable merge gate;
- authorize any future repository rename migration;
- make every merge and production decision.

No existing PR is merged or closed by implication. Each recommended closure or
replacement requires a separate owner decision recorded on the relevant Issue
or PR.

## 17. Next verifiable milestone

The next milestone after independent approval of this plan is a P0 schema and
truthful-verifier Draft PR with:

- a real GitHub run ID and execution ID;
- validated task and result artifacts;
- regression evidence proving `error_max_turns`, timeout, missing commit,
  missing artifact and required empty diff all fail;
- an independent review at the exact verified head SHA;
- no merge without the Product Owner.

Until that evidence exists, the project remains in planning/P0 bootstrap and
must not claim a working autonomous delivery pipeline.
