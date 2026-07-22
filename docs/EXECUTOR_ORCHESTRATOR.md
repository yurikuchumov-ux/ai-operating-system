# Executor Orchestrator

## Status

Proposed architecture for Issue #12. This document defines the autonomous handoff mechanism between implementation agents after the Failure Escalation Rule is triggered.

## Objective

The Executor Orchestrator coordinates implementation work across AI agents without using the Product Owner as middleware. GitHub remains the source of truth. The orchestrator does not merge changes and does not replace independent review.

## Core invariants

1. Repository, active branch, Issue, Draft PR, checks, and project documents are authoritative.
2. Chat history and model memory are not required for continuation.
3. One active implementation lease exists per task and branch.
4. An executor cannot independently review its own implementation.
5. A handoff is triggered only by an auditable policy event.
6. Every command and state transition is idempotent.
7. Duplicate webhook events cannot start duplicate work.
8. Automatic merge is prohibited.
9. Credentials are adapter-local and never included in task packages or comments.
10. The Product Owner is informed of state but is not used as a router between agents.

## Responsibilities

The orchestrator:

- reads task state from GitHub;
- validates Failure Escalation Rule triggers;
- selects the next eligible executor;
- creates a deterministic handoff package;
- invokes an executor adapter;
- maintains leases and attempt counters;
- records progress and completion evidence;
- routes completed implementation to an independent reviewer;
- pauses safely when no eligible executor or adapter is available.

The orchestrator does not:

- decide product priorities;
- rewrite acceptance criteria;
- approve its own changes;
- merge pull requests;
- use private chat history as task context;
- conceal adapter or execution failures.

## Components

### 1. Event Intake

Receives GitHub events and scheduled reconciliation ticks. Supported events:

- Issue created or updated;
- PR opened or synchronized;
- check completed;
- review submitted;
- orchestrator command comment;
- lease timeout;
- scheduled reconciliation.

All events are normalized into an `OrchestratorEvent` and assigned an idempotency key.

### 2. State Reconciler

Builds desired task state from GitHub and compares it with recorded orchestration state. It is the only component allowed to transition the state machine.

### 3. Policy Engine

Evaluates:

- Failure Escalation Rule;
- executor eligibility;
- reviewer independence;
- maximum attempts;
- branch and PR preconditions;
- adapter availability;
- security and repository policy.

### 4. Executor Registry

Stores capabilities and constraints for each executor adapter.

Example capabilities:

- read repository and Issue;
- commit to an existing branch;
- open or update a Draft PR;
- run checks;
- post a completion report;
- modify workflow files;
- access private repositories.

### 5. Selector

Chooses one executor deterministically from eligible candidates.

Selection order:

1. exclude the current failed executor;
2. exclude agents that already implemented the current attempt lineage;
3. require capabilities needed by the task;
4. require adapter health;
5. prefer the project-defined executor order;
6. break ties by stable executor ID.

Default Development Studio order:

1. Claude Code;
2. Codex;
3. human executor.

GPT remains Chief Architect and Reviewer unless explicitly assigned as implementer.

### 6. Handoff Builder

Creates a repository-backed `HandoffPackage` containing only verified context:

- repository and branch;
- Issue and Draft PR numbers;
- task objective;
- acceptance criteria;
- current head SHA;
- failed attempt summaries;
- confirmed logs and check results;
- rejected hypotheses;
- known constraints;
- required commands and expected evidence;
- prohibited actions;
- completion report contract.

The package must not contain secrets or rely on chat history.

### 7. Adapter Layer

Each executor is integrated through an adapter with the same contract:

- `canAccept(task)`;
- `start(handoffPackage)`;
- `status(executionId)`;
- `cancel(executionId)`;
- `collectResult(executionId)`.

Adapters may be implemented using a GitHub App, GitHub Actions, MCP, vendor API, or self-hosted runner. The orchestrator must not pretend an adapter exists. An unavailable adapter produces a visible `BLOCKED_NO_ADAPTER` state.

### 8. Lease Manager

A lease prevents concurrent executors from modifying the same task branch.

Lease fields:

- task ID;
- executor ID;
- execution ID;
- branch;
- acquired time;
- heartbeat time;
- expiry time;
- idempotency key.

A lease can be renewed only by the active execution. Expired leases are reclaimed through reconciliation, never through blind retry.

### 9. Evidence Collector

Collects and validates completion evidence:

- new commit SHA;
- changed files;
- check results;
- Draft PR state;
- executor report;
- unresolved review findings.

An executor is not considered complete because an API call returned successfully. Completion requires repository evidence.

### 10. Review Router

After implementation completion, selects an independent reviewer. The implementation executor is excluded. The reviewer receives the Issue, diff, checks, prior findings, and completion report.

## State model

### Task states

- `NEW` — Issue exists, orchestration not started.
- `READY` — prerequisites and acceptance criteria are sufficient.
- `ASSIGNED` — executor selected, lease not yet acknowledged.
- `RUNNING` — executor acknowledged and holds active lease.
- `VERIFYING` — implementation reported complete; evidence is being validated.
- `REVIEW_PENDING` — implementation evidence is valid; reviewer not yet active.
- `REVIEWING` — independent review in progress.
- `CHANGES_REQUESTED` — reviewer found blocking issues.
- `READY_FOR_OWNER` — checks and independent review passed; human merge decision remains.
- `BLOCKED` — manual decision or unavailable capability is required.
- `CANCELLED` — task intentionally stopped.
- `DONE` — merged and Issue completed.

### Attempt states

- `CREATED`;
- `STARTING`;
- `ACTIVE`;
- `SUCCEEDED`;
- `FAILED`;
- `TIMED_OUT`;
- `CANCELLED`;
- `HANDED_OFF`.

## Failure Escalation integration

An engineering iteration is counted only when the repository contains evidence of:

1. a stated hypothesis;
2. a change or controlled experiment;
3. a check or factual validation;
4. a recorded result.

The orchestrator triggers handoff when three consecutive iterations by the same executor have no measurable progress.

Measurable progress is one of:

- a blocking cause is removed;
- an acceptance criterion is satisfied;
- a previously failing check passes;
- new material evidence changes the implementation direction.

A prompt rewrite, cosmetic refactor, duplicate retry, or minor variation does not reset the counter.

## Handoff protocol

1. Freeze new commands for the current executor.
2. Reconcile repository state.
3. Record the failed attempt and evidence.
4. Release or expire the old lease.
5. Build the handoff package.
6. Select the next eligible executor.
7. Acquire a new lease with an idempotency key.
8. Start the adapter.
9. Record execution ID and startup evidence.
10. Move the previous executor to reviewer-ineligible-for-current-lineage status until implementation completes.

## Data contracts

### OrchestratorEvent

```json
{
  "event_id": "github-delivery-id",
  "type": "check.completed",
  "repository": "owner/repo",
  "issue": 12,
  "pull_request": 13,
  "head_sha": "40-char-sha",
  "occurred_at": "RFC3339"
}
```

### HandoffPackage

```json
{
  "schema_version": 1,
  "task_id": "owner/repo#12",
  "repository": "owner/repo",
  "branch": "feature/issue-12",
  "issue": 12,
  "pull_request": 13,
  "head_sha": "40-char-sha",
  "objective": "string",
  "acceptance_criteria": ["string"],
  "constraints": ["string"],
  "failed_attempts": [
    {
      "executor": "claude-code",
      "iterations": 3,
      "rejected_hypotheses": ["string"],
      "evidence_urls": ["string"]
    }
  ],
  "prohibited_actions": ["merge", "rewrite-history", "expose-secrets"],
  "required_evidence": ["commit_sha", "checks", "completion_report"]
}
```

### ExecutionResult

```json
{
  "execution_id": "string",
  "executor": "codex",
  "status": "SUCCEEDED",
  "head_sha": "40-char-sha",
  "checks": [{"name": "string", "conclusion": "success"}],
  "report_url": "string",
  "remaining_risks": ["string"]
}
```

## Persistence

MVP persistence uses GitHub-native records:

- Issue body for task contract;
- PR for implementation state;
- check runs for machine status;
- one orchestrator status comment updated in place;
- repository file `.ai-os/orchestrator/tasks/<issue>.json` or an external store keyed by repository and Issue;
- GitHub App database for leases and event idempotency.

The Git repository remains the durable project record; the database stores operational coordination data only.

## Security model

- GitHub App uses least-privilege repository permissions.
- Executor credentials are isolated per adapter.
- Handoff packages contain references, not credentials.
- Logs are redacted before publication.
- Workflow changes require an adapter with explicit workflow permission.
- Fork PRs are read-only unless project policy allows otherwise.
- Adapter callbacks are authenticated and replay-protected.
- Every executor invocation is bound to repository, branch, head SHA, and lease ID.

## Concurrency and idempotency

Idempotency key:

`repository + issue + branch + head_sha + transition + attempt_number`

Before starting work, the orchestrator must verify:

- no active lease exists;
- the head SHA still matches the handoff package;
- the Issue and PR are still open;
- the task is not cancelled or merged;
- the executor is still eligible.

Any mismatch causes reconciliation rather than execution.

## Failure handling

- Adapter unavailable: `BLOCKED_NO_ADAPTER`.
- Executor startup timeout: mark attempt `TIMED_OUT`, release lease, select next executor if policy permits.
- Lost heartbeat: reconcile GitHub evidence before reclaiming lease.
- Branch advanced externally: invalidate current package and rebuild.
- Duplicate webhook: ignore using idempotency key.
- Invalid completion report: remain in `VERIFYING` and request adapter correction.
- No eligible reviewer: `BLOCKED_NO_REVIEWER`.
- Repeated cross-executor failure: stop after project-defined global attempt limit and escalate to human architecture decision.

## GitHub interaction model

The orchestrator maintains one status comment per Issue or PR:

```text
Executor Orchestrator
State: RUNNING
Current executor: Codex
Attempt: 2
Lease expires: 2026-07-12T12:00:00Z
Head SHA: abcdef...
Previous executor: Claude Code
Reason for handoff: Failure Escalation Rule
Next transition: VERIFYING after completion evidence
```

The comment is informational. Machine state is stored separately and reconciled with GitHub.

## MVP

### Phase 1 — GitHub-native control plane

- GitHub App receives events;
- state reconciler and policy engine;
- task state and leases;
- one real executor adapter;
- one independent reviewer adapter;
- repository-backed handoff package;
- status comment and check run;
- no automatic merge.

Recommended first pair:

- Implementer: Claude Code GitHub Action or App adapter;
- Reviewer: Codex adapter when a supported programmatic entry point is available, otherwise GPT/manual reviewer adapter marked as non-autonomous.

The design must report unsupported adapters as blocked, not simulate delegation through comments.

### Phase 2 — Multi-executor routing

- Codex implementation adapter;
- capability-aware selection;
- retry budgets;
- branch/worktree isolation;
- metrics and operator dashboard.

### Phase 3 — Cross-project orchestration

- shared project registry;
- inherited AI OS policy;
- organization-level executor pools;
- cost, latency, and reliability policy;
- human escalation queues.

## Implementation boundaries

The orchestrator should be implemented as a standalone service with a GitHub App identity. GitHub Actions may execute adapter jobs, but Actions alone should not own durable leases or global routing because workflow retries and duplicate events do not provide sufficient coordination guarantees.

Recommended modules:

- `event-ingress`;
- `reconciler`;
- `policy-engine`;
- `executor-registry`;
- `selector`;
- `handoff-builder`;
- `lease-store`;
- `github-adapter`;
- executor adapters;
- `evidence-validator`;
- `review-router`;
- `audit-log`.

## Observability

Required metrics:

- tasks by state;
- attempts per task;
- handoffs by reason;
- executor startup success rate;
- lease timeouts;
- duplicate events suppressed;
- median time to verified implementation;
- review pass rate by executor;
- human escalations.

Every transition emits a structured audit event with previous state, next state, policy decision, executor, head SHA, and evidence references.

## Acceptance tests for implementation

1. Three failed iterations trigger exactly one handoff.
2. Duplicate webhook deliveries do not start a second executor.
3. The previous executor cannot become the independent reviewer.
4. A stale head SHA invalidates the handoff package.
5. An expired lease is reconciled before reassignment.
6. An unavailable Codex adapter produces `BLOCKED_NO_ADAPTER`, not a false success.
7. Completion without a new commit or valid evidence is rejected.
8. No path performs automatic merge.
9. The process can resume from GitHub and operational state without chat history.
10. The Product Owner receives status only and is not required to relay instructions.

## Follow-up implementation Issues

1. Build the GitHub App control plane and event reconciler.
2. Implement task state, idempotency, and lease storage.
3. Implement the Claude Code executor adapter.
4. Implement the Codex adapter when a supported invocation API is available.
5. Implement evidence validation and independent review routing.
6. Add integration tests for duplicate events, lease expiry, and executor handoff.
7. Add project-level executor policy configuration.

## Decision

Adopt a standalone GitHub App-based orchestrator with durable operational state, GitHub as project source of truth, adapter-based executor invocation, mandatory leases, deterministic handoff, evidence-based completion, and independent review. Do not model a GitHub comment as successful delegation unless an adapter returns a verifiable execution ID and repository evidence.