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
| [#17 Execution plan](https://github.com/yurikuchumov-ux/ai-operating-system/pull/17) | open Draft; external review requested changes at `0677b5338ddc9b0a3424874d5a12ab3dd8db108b` | address findings in a new commit; no merge; repeat independent review at the new exact head SHA |

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
  "change_policy": {
    "change_required": true,
    "no_change": {
      "allowed": false,
      "reason_codes": [],
      "required_evidence_types": []
    }
  },
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
  "acceptance_criteria": [
    {
      "id": "AC-1",
      "predicate_id": "git.diff.non_empty",
      "parameters": {},
      "required": true,
      "linked_checks": ["unit"]
    }
  ],
  "required_checks": [
    {
      "id": "unit",
      "command_id": "repo.unit",
      "required": true,
      "expected_postconditions": [
        {
          "predicate_id": "process.exit_code.equals",
          "parameters": {"value": 0}
        },
        {
          "predicate_id": "artifact.sha256.matches",
          "parameters": {"artifact_id": "unit-output"}
        }
      ]
    }
  ],
  "review_policy": {
    "reviewer_class": "independent-engineering",
    "policy_id": "review-independence.v1",
    "forbidden_lineage_overlaps": [
      "agent_runtime_id",
      "credential_principal"
    ],
    "minimum_distinct_human_operators": 0
  },
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
- objective or `acceptance_criteria` are empty;
- an acceptance criterion uses an unknown `predicate_id`, lacks deterministic
  parameters, or is not linked to the checks that produce its evidence;
- a required check lacks closed, deterministic `expected_postconditions`;
- `change_policy.change_required=true` while
  `change_policy.no_change.allowed=true` without a policy exception;
- no-change is allowed but its reason-code enum or required evidence types are
  empty;
- allowed paths are empty for a change task;
- allowed and denied paths overlap ambiguously;
- workflow, security, deployment or governance paths are writable under an
  insufficient risk class;
- the executor adapter or immutable version is unknown;
- timeout or attempts exceed policy;
- external side effects are not explicitly forbidden or separately approved;
- author and required reviewer lineage cannot satisfy `review_policy` for the
  declared risk class.

The Issue text is user input. It must never be interpolated into a shell command
or granted authority to override workflow policy.

### 6.2 Predicate and command registries

`predicate_id` and `command_id` values come from versioned, repository-owned
registries. Free text cannot define pass conditions. Each predicate declares
input types, deterministic evaluation, failure code and evidence requirements.
Unknown identifiers fail closed.

Acceptance is conjunctive for all required criteria. A criterion result must be
traceable to one or more required checks or to a verifier-owned Git predicate.

## 7. Versioned execution result contract

Every started execution must end with exactly one `result.v1.json`. A trusted
always-run wrapper/finalizer outside the model process owns this artifact and
supplies identity, timing and Git observations. The executor only writes a raw
candidate output. If the finalizer cannot run because of runner or platform
loss, the missing artifact is itself a terminal verification failure and can
never produce success.

```json
{
  "$schema": "https://example.invalid/ai-os/result.v1.schema.json",
  "schema_version": "1.0.0",
  "task_id": "yurikuchumov-ux/ai-operating-system#123",
  "execution_id": "uuid",
  "attempt": 1,
  "executor": {
    "adapter": "claude-code-actions",
    "adapter_version": "immutable-version",
    "identity": {
      "operator_principal": "github:user-id",
      "agent_runtime_id": "provider:model:session-id",
      "credential_principal": "github-app:installation-id",
      "delegation_parent": "execution-or-owner-event-id",
      "role": "author"
    }
  },
  "started_at": "RFC3339 timestamp",
  "finished_at": "RFC3339 timestamp",
  "base_sha": "40-character-lowercase-sha",
  "head_sha": "40-character-lowercase-sha-or-null",
  "status": "change_proposed",
  "terminal_reason": "completed",
  "no_change_reason": null,
  "no_change_evidence": [],
  "authored_commits": ["40-character-lowercase-sha"],
  "changed_files": ["path/file"],
  "acceptance_results": [
    {
      "id": "AC-1",
      "predicate_id": "git.diff.non_empty",
      "passed": true,
      "observed": {"changed_file_count": 1},
      "evidence_artifact_ids": ["unit-output"]
    }
  ],
  "checks": [
    {
      "id": "unit",
      "command_id": "repo.unit",
      "exit_code": 0,
      "evidence_path": "artifacts/unit.txt"
    }
  ],
  "artifacts": [
    {
      "id": "unit-output",
      "path": "artifacts/unit.txt",
      "sha256": "64-character-hash"
    }
  ],
  "finalized_by": {
    "component_id": "result-finalizer.v1",
    "credential_principal": "github-actions:job-identity"
  },
  "warnings": [],
  "error": null
}
```

`status` is a closed enum: `change_proposed`, `no_change_required`, `failed`,
`cancelled`, or `blocked`. Natural-language summaries are optional and never
authoritative.

`terminal_reason` is a closed enum: `completed`, `approved_no_change`,
`max_turns`, `timeout`, `missing_commit`, `missing_artifact`, `empty_diff`,
`scope_violation`, `ref_history_unverifiable`, `acceptance_failed`,
`identity_unverifiable`, `check_failed`, `cancelled_by_owner`, `adapter_error`,
`runner_lost`, or `reviewer_unavailable`. An unknown value is represented only
as `adapter_error` with the raw provider value in a non-authoritative diagnostic
field; unknown values fail closed.

`no_change_reason` must be null unless `status=no_change_required`. When set, it
must be one of the task's allowed reason codes and every required no-change
evidence type must be represented in `no_change_evidence` and linked to a
hash-addressed artifact. Every required acceptance criterion has exactly one
result with its predicate ID, observed value and deterministic evidence.

## 8. Canonical task and execution state machines

Task lifecycle and execution-attempt lifecycle are separate. A task publishes
one aggregate Check Run named `task/<task_id>`. Every attempt publishes its own
immutable Check Run named `execution/<execution_id>` and one append-only result
artifact. Comments are projections only and are never authoritative state.

### 8.1 TaskState

`TaskState` is a closed enum: `REQUESTED`, `VALIDATED`, `ACTIVE`,
`REVIEW_REQUIRED`, `CHANGES_REQUESTED`, `OWNER_DECISION`, `DONE`, `CANCELLED`,
`BLOCKED`, or `REJECTED`.

| Source | Event and guard | Target | Required evidence |
| --- | --- | --- | --- |
| `REQUESTED` | task contract passes validation | `VALIDATED` | normalized task artifact, task hash and resolved base SHA |
| `REQUESTED` | validation fails | `REJECTED` | closed validation error codes |
| `VALIDATED` | first execution is created | `ACTIVE` | new execution ID and attempt number |
| `ACTIVE` | execution succeeds with verified change or allowed no-change | `REVIEW_REQUIRED` | execution check, verifier report, Draft PR or no-change review artifact |
| `ACTIVE` | execution fails and retry policy permits a new attempt with material evidence | `ACTIVE` | terminal result plus a different execution ID |
| `ACTIVE` | three attempts fail, or a non-retryable invariant fails | `BLOCKED` | aggregate attempt history and handoff requirement |
| `REVIEW_REQUIRED` | eligible reviewer approves exact verified SHA or no-change result | `OWNER_DECISION` | review attestation and reviewed subject hash |
| `REVIEW_REQUIRED` | eligible reviewer requests changes | `CHANGES_REQUESTED` | review attestation and closed finding IDs |
| `CHANGES_REQUESTED` | a new attempt is authorized within retry policy | `ACTIVE` | new execution ID, new material evidence and updated base/head binding |
| `CHANGES_REQUESTED` | retry policy is exhausted | `BLOCKED` | aggregate attempt history and replacement-executor requirement |
| `OWNER_DECISION` | owner merges exact reviewed SHA or accepts reviewed no-change | `DONE` | owner event and merge commit or accepted result hash |
| `OWNER_DECISION` | owner declines or closes | `CANCELLED` | owner event |

`DONE`, `CANCELLED`, `BLOCKED`, and `REJECTED` are terminal TaskStates. A failed
execution never directly marks a task `DONE` or `REJECTED`.

### 8.2 ExecutionState

`ExecutionState` is a closed enum: `CREATED`, `RUNNING`, `FINALIZING`,
`VERIFYING`, `SUCCEEDED`, `FAILED`, `CANCELLED`, or `BLOCKED`.

| Source | Event and guard | Target | Required evidence |
| --- | --- | --- | --- |
| `CREATED` | clean ephemeral checkout is exactly at task base SHA | `RUNNING` | runner identity, checkout observation and execution ID |
| `CREATED` | checkout or adapter cannot start | `FINALIZING` | closed terminal reason candidate |
| `RUNNING` | executor exits or is interrupted | `FINALIZING` | raw candidate output and trusted observations available so far |
| `FINALIZING` | trusted wrapper writes exactly one result artifact | `VERIFYING` | result hash and finalizer identity |
| `FINALIZING` | finalizer or runner is lost | `FAILED` | platform job conclusion plus `missing_artifact` or `runner_lost` projection |
| `VERIFYING` | every required invariant and acceptance predicate passes | `SUCCEEDED` | `verification.v1.json` and evidence hashes |
| `VERIFYING` | any required invariant fails | `FAILED` | failed predicate ID, observed value and terminal reason |
| `VERIFYING` | owner cancellation is authenticated | `CANCELLED` | owner event |
| `VERIFYING` | required external prerequisite is unavailable and non-retryable | `BLOCKED` | prerequisite ID and evidence |

`SUCCEEDED`, `FAILED`, `CANCELLED`, and `BLOCKED` are terminal for one immutable
execution ID. A retry always receives a new execution ID, result artifact and
execution Check Run; prior checks are never overwritten. The task Check Run
aggregates attempt checks and is the authoritative task projection. A fourth
attempt is forbidden unless the owner records new material evidence and selects
a replacement executor.

### 8.3 Result-to-state aggregation

| Result status | ExecutionState | TaskState projection |
| --- | --- | --- |
| `change_proposed` | `SUCCEEDED` | `REVIEW_REQUIRED` |
| `no_change_required` | `SUCCEEDED` | `REVIEW_REQUIRED` |
| `failed` | `FAILED` | `ACTIVE` when a policy-compliant retry exists; otherwise `BLOCKED` |
| `cancelled` | `CANCELLED` | `CANCELLED` only for an authenticated owner cancellation; otherwise `ACTIVE` or `BLOCKED` |
| `blocked` | `BLOCKED` | `BLOCKED` |

## 9. Truthful verifier requirements

The verifier is deterministic code in a separate job. It must not use the
authoring model's conclusion as a pass condition.

### 9.1 Required inputs

- validated task artifact, acceptance criteria, no-change policy and SHA-256
  hash;
- persisted GitHub event payload and before/after ref observations;
- immutable base SHA;
- executor result artifact;
- checked-out repository and candidate branch;
- required check and acceptance evidence;
- verified author identity lineage, reviewer policy and applicable risk class.

### 9.2 Mandatory postconditions

The verifier must independently prove:

1. task and result schemas are supported and valid;
2. execution ID is unique and belongs to the task;
3. checkout started clean at the exact base SHA;
4. candidate branch exists;
5. result `base_sha` equals the validated base SHA;
6. observed branch head equals result `head_sha`;
7. a change task has a new commit and non-empty diff;
8. a no-change task explicitly permits `no_change_required`, uses an allowed
   reason code and supplies every required evidence type;
9. every changed path is allowed and no denied path changed;
10. branch history contains no merge commit or prohibited force push, proven
    from persisted event before/after SHAs, Git ancestry and GitHub audit/event
    telemetry when available;
11. every required command ID ran through a repository-defined command map;
12. every required check exited zero and its evidence hash matches;
13. every required acceptance criterion has exactly one passing result linked to
    valid check or verifier-owned Git evidence;
14. required artifacts exist, are non-empty, scanned, and hash-valid;
15. no secret or prohibited personal data is present in diff or artifacts;
16. max-turns, timeout, missing commit, missing artifact, empty required diff,
    adapter error, and check failure produce a failed workflow conclusion;
17. executor and reviewer identity records contain verifiable operator,
    runtime, credential, delegation-parent and authored-commit lineage;
18. the Draft PR, when created, points to the verified head SHA;
19. reviewer eligibility passes the machine-readable policy for the risk class;
20. owner merge is possible only for the exact reviewed SHA.

The verifier writes `verification.v1.json` and fails the job on any violated
invariant. It records the evaluated predicate IDs, observed values and evidence
hashes. Its exit code, not an agent message, controls the Check Run. When
force-push telemetry is missing, stale or inconsistent, a task that forbids
force pushes fails closed with `ref_history_unverifiable`.

### 9.3 P0 regression fixtures

At minimum, tests must cover:

- successful scoped documentation change;
- `error_max_turns` modeled on run `29190170902`;
- job timeout;
- executor exit zero with no commit;
- commit exists but result artifact is absent;
- result artifact exists but required evidence file is absent;
- empty diff when `change_required=true`;
- allowed no-change with complete reason/evidence and disallowed no-change;
- missing or duplicate acceptance result;
- changed file outside `allowed_paths`;
- forged `head_sha`;
- failing required command hidden by a green agent step;
- runner loss before the trusted finalizer writes an artifact;
- unknown `terminal_reason`;
- task retry where one failed execution is followed by a distinct successful
  execution without overwriting the first check;
- author attempting to review its own head SHA;
- reviewer with unverifiable credential or delegation lineage;
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

### 10.1 Machine-readable identity and review attestation

Every author, verifier, reviewer and merger event records:

- `operator_principal`: stable human or service owner identity;
- `agent_runtime_id`: provider, model/tool and immutable execution/session ID;
- `credential_principal`: GitHub App, workflow OIDC subject or user credential;
- `delegation_parent`: authenticated owner event or prior execution ID;
- `role`: one closed role value;
- `authored_commits`: commits attributable to that lineage.

An independent review produces `review-attestation.v1.json`:

```json
{
  "task_id": "yurikuchumov-ux/ai-operating-system#123",
  "review_id": "immutable-review-id",
  "reviewed_sha": "40-character-lowercase-sha",
  "reviewer_identity": {
    "operator_principal": "human-or-service-principal",
    "agent_runtime_id": "provider:model:session-id",
    "credential_principal": "github-or-oidc-principal",
    "delegation_parent": "owner-event-id",
    "role": "reviewer"
  },
  "eligibility": {
    "policy_id": "review-independence.v1",
    "risk_class": "L1",
    "overlap_results": [],
    "eligible": true,
    "reason_codes": []
  }
}
```

Missing or unknown identity fields make the reviewer ineligible. The verifier
recomputes overlap against all execution lineage and authored commits; a model
or human assertion of independence is not proof.

### 10.2 Risk-class separation rules

| Risk | Minimum eligible separation |
| --- | --- |
| `L0` planning/documentation | reviewer uses a different agent runtime/context, authored no commits under review and has read-only review authority; the same human operator is allowed only with explicit manual provenance |
| `L1` normal code | different runtime/session and credential principal, no authored commits, read-only reviewer, deterministic verifier and enforced branch gates; same operator is allowed only when repository protection prevents self-approval and bypass |
| `L2` security, identity, data or workflow policy | distinct qualified human operator plus separate runtime and credential lineage |
| `L3` deployment, production or irreversible effects | all `L2` controls plus a different human merger and protected environment approval |

The external GPT review of this planning PR is evidence for an `L0` manual
review only after its exact reviewed SHA and provenance are recorded. It is not
evidence of automated delegation, verifier implementation or repository branch
enforcement.

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

### 11.4 Threat-model boundary and severity policy

The security boundary is explicit. Conditionally trusted components are the
GitHub control plane, pinned deterministic verifier/finalizer code and
authenticated owner events. Untrusted inputs include Issue and PR text, model
output, public callers, vendor callbacks, external artifacts, dependency
output, transcripts and tool arguments. Protected assets are credentials,
repository write authority, tenant and personal data, booking/message/payment
actions and audit evidence.

Threat actors include anonymous callers, authenticated cross-tenant callers,
malicious prompt or transcript content, compromised dependencies or runners,
stale/replayed callbacks and credential misuse by an insider. Exposure modes
are closed values: `local`, `development`, `tunnel`, `public_test`, and
`production`. A control proven in one mode is not inherited by a more exposed
mode without explicit evidence.

| Severity | Reproducible impact threshold |
| --- | --- |
| `critical` | unauthenticated irreversible action, cross-tenant control, secret compromise, or broad personal-data disclosure |
| `high` | authentication/authorization bypass, meaningful personal-data exposure or loss, or corruption of booking/audit integrity |
| `medium` | limited tenant, availability, rate-limit or observability impact with effective compensating controls |
| `low` | documentation or user-experience defect that crosses no security boundary |

Unknown severity is treated as `high` until triaged. Any unresolved `critical`
or `high` finding affecting an exposed route fails readiness. Residual risk
requires an owner acceptance record with finding IDs, compensating controls,
scope, expiry and immutable evidence; expiry returns the gate to failed.

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

### 12.1 Explicit bootstrap protocol

The verifier cannot truthfully prove itself before its contracts, fixtures and
trusted wrapper exist. Bootstrap is therefore a bounded, owner-approved
exception protocol, not a claim that the normal delivery loop already works.

| Phase | Issue | Deliverable | Temporary exception | Compensating controls | Exit criterion |
| --- | --- | --- | --- | --- | --- |
| `B0` | AI OS #18 | schemas, registries, offline validators and immutable fixtures | no real adapter or verifier run is claimed | clean manual checkout, exact SHA, hashes, owner authorization and independent read-only review | positive/negative schema fixtures pass at one exact SHA |
| `B1` | AI OS #18 | human-supervised harness and trusted always-run finalizer | independent verifier is not yet authoritative | restricted credentials, append-only raw/result artifacts, manual Git postconditions; no merge until `B2` | finalizer emits one valid artifact for success, executor failure and timeout fixtures |
| `B2` | AI OS #18 | deterministic verifier evaluated against bootstrap fixtures | verifier is not yet self-hosted by the normal loop | independent exact-SHA review and fixture oracle defined outside author output | all normative verifier fixtures pass and review attestation is eligible |
| `B3` | AI OS #19 | end-to-end terminal failure propagation | no additional exception beyond reviewed bootstrap components | real run/execution IDs and immutable artifacts | max-turns, timeout, missing commit/artifact and empty diff all make execution and task checks fail correctly |
| `B4` | AI OS #20 | canonical naming change as first low-risk canary | none | full task/result/verifier/review contract | canary reaches owner decision with no state/Git disagreement |

The dependency DAG is `PR #17 approval -> B0 -> B1 -> B2 -> B3 -> B4 -> normal
self-hosted P0 work`. AI OS #18 is limited to `B0`–`B2`; #19 owns `B3`; #20
owns `B4`. The owner must record the bootstrap exception before `B0`. It expires
automatically after `B4`, and it never permits production deployment, merge
without independent review, or a claim of real adapter delegation before a run
and execution ID exist.

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

| Gate ID | Category | Points | Reproducible pass predicate | Freshness and invalidation |
| --- | --- | ---: | --- | --- |
| `G-CONTRACT-01` | versioned task/result contracts | 10 | schemas, registries and validators at the subject SHA pass 100% of positive and negative fixtures | evidence ≤30 days; expires on schema, registry or validator change |
| `G-LOOP-01` | truthful execution loop | 20 | three consecutive change tasks across at least two repositories have distinct execution IDs and no state/Git disagreement | last run ≤30 days; expires on loop policy/code change or any later false success |
| `G-VERIFY-01` | independent verifier | 15 | every normative P0 fixture, including run `29190170902`, produces its declared terminal result at the verifier SHA | evidence ≤30 days; expires on verifier or predicate change |
| `G-ACTOR-01` | actor separation | 10 | ruleset/branch API evidence plus negative self-review and post-approval-push tests prove bypass is impossible | settings evidence ≤7 days; expires on ruleset or review-policy change |
| `G-ISOLATION-01` | clean checkout and credentials | 10 | declared permission manifest equals observed job permissions; exact base SHA, clean ephemeral workspace and network policy fixtures pass | evidence ≤30 days; expires on workflow or action-pin change |
| `G-TEMPLATE-01` | template repeatability | 8 | three tasks with distinct task/execution IDs use fresh ephemeral checkouts from recorded `main` SHAs and produce verified Draft PRs | evidence ≤30 days; expires on template/workflow change |
| `G-INHERIT-01` | AI OS inheritance | 7 | pinned contract SHA is reachable and compatibility/precedence fixtures pass in every consumer | evidence ≤30 days; expires on contract or consumer-ref change |
| `G-VOICE-AUTH-01` | voice authentication/authorization | 8 | negative authentication, action/object authorization and tenant-isolation tests cover every non-health route across at least two synthetic tenants | evidence ≤14 days; expires on route or auth-code change |
| `G-BOOKING-01` | booking safety | 5 | validation, idempotency, concurrent double-booking, timezone and DST fixtures all pass | evidence ≤14 days; expires on booking schema/storage change |
| `G-PII-01` | PII and observability | 4 | inventory, redaction, retention/deletion/access fixtures pass and a synthetic scan finds no prohibited data | evidence ≤14 days; expires on logging or data-policy change |
| `G-DEPLOY-01` | deployment and audit evidence | 3 | two deploy-and-rollback fixtures preserve hash-addressed evidence and contain no raw personal data or secrets | evidence ≤30 days; expires on deployment or evidence-storage change |

Current verified readiness is **0 of 100 evidence points**. This is not an
estimate of engineering effort. It means none of the target categories has yet
passed its complete acceptance condition on a protected, independently verified
path.

### 14.1 Evidence registry contract

Every score is derived from an append-only `readiness-evidence.v1.json` record:

```json
{
  "gate_id": "G-CONTRACT-01",
  "policy_version": "readiness.v1",
  "subject_sha": "40-character-lowercase-sha",
  "status": "pass",
  "predicate_results": [
    {"predicate_id": "fixture.pass_rate.equals", "observed": 1.0, "passed": true}
  ],
  "evidence": [
    {"type": "workflow_artifact", "url": "immutable-url", "sha256": "64-character-hash"}
  ],
  "evaluated_at": "RFC3339 timestamp",
  "expires_at": "RFC3339 timestamp",
  "owner": "credential-principal"
}
```

Gate status is a closed enum: `pass`, `fail`, or `expired`. Every declared
predicate must pass; missing, mutable, stale or hash-mismatched evidence yields
zero points. Fixture diversity requirements in the gate table are conjunctive.
A “protected, independently verified path” means the exact subject SHA is bound
to an enforced ruleset, required verifier Check Run, eligible review
attestation and immutable evidence hashes.

### 14.2 Mandatory release gates

Point totals never override a hard gate. MVP readiness additionally requires:

- all P0 Issues closed by merged, independently reviewed evidence;
- zero unexplained false-success runs across three consecutive end-to-end tasks;
- actor separation enforced;
- no critical/high unresolved voice security finding for any exposed endpoint;
- human-only merge decision retained;
- rollback and evidence-retention owner identified.

## 15. P0 implementation Issue map

| Work item | `depends_on` | Owner role / prerequisite | `unblocks` | Required completion evidence |
| --- | --- | --- | --- | --- |
| AI OS #18 (`B0`–`B2`) schemas, finalizer and verifier | PR #17 approved; owner records bootstrap exception | architect authors; eligible independent reviewer | AI OS #19 and evidence-registry implementation | fixture runs, artifact hashes and exact-SHA review attestation |
| AI OS #19 (`B3`) terminal propagation | #18 merged and immutable verifier version selected | execution adapter author separate from reviewer | AI OS #20 canary | real run/execution IDs and all terminal fixtures fail correctly |
| AI OS #20 (`B4`) canonical repository naming | #19 merged; `G-ACTOR-01` enforcement available | low-risk executor plus independent reviewer | normal self-hosted P0 delivery | first full-contract canary at exact reviewed SHA |
| voice #11 claim freeze | approved plan; human-supervised `L0` path allowed | voice repository owner can publish notice | truthful non-production posture | notice at exact SHA and eligible review |
| voice #9 security evidence pack | voice #11; threat boundary and severity policy | qualified security reviewer distinct from author | prioritized fail-closed fixes | finding registry with reproducible fixtures and immutable hashes |
| voice #10 audit-evidence preservation | voice #9 data classes; owner retention decision | data/evidence owner identified | `G-PII-01` and `G-DEPLOY-01` | two deploy/rollback fixtures plus retention evidence |
| AI OS #21 readiness evidence registry | #18 registry schema; #20 canary | deterministic publisher, no scoring discretion | automated cockpit/readiness projection | schema validation and recomputed zero-or-full gate scores |
| new `P0-ACTOR` Issue | owner decides public/private repository enforcement approach | repository administrator; separate verifier of settings | `G-ACTOR-01`, #20 and any production claim | ruleset API snapshot and negative bypass fixtures |

`P0-ACTOR` does not yet have an Issue ID and must be created as a separate
owner-visible planning action before `B4`; this document does not pretend that
the missing enforcement work is already delegated.

Enforceable actor separation and the private-repository protection decision are
acceptance dependencies across these Issues. They require a Product Owner
policy decision before implementation can claim readiness.

Issue creation does not count as delegation. Normal implementation delegation
starts only when a real Actions adapter returns a run ID and execution ID. At
this snapshot, no merged reusable implementation adapter satisfies this
contract, so only the bounded `B0`–`B2` human-supervised bootstrap may proceed
after its explicit owner approval; it must not be labeled delegation.

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

The immediate milestone is a new independent review of this corrected plan at
its exact Draft PR #17 head SHA. No bootstrap implementation starts while the
review disposition is `REQUEST_CHANGES`.

After independent approval and an explicit owner bootstrap-exception record,
the next milestone is `B0` of AI OS #18: a schema-and-fixture Draft PR with:

- validated task and result artifacts;
- offline positive and negative fixture evidence at an immutable SHA;
- an independent review at the exact verified head SHA;
- no merge without the Product Owner.

Real adapter run and execution IDs become mandatory at `B3`; the bootstrap
exception cannot be used to represent `B0`–`B2` as automated delegation.

Until that evidence exists, the project remains in planning/P0 bootstrap and
must not claim a working autonomous delivery pipeline.
