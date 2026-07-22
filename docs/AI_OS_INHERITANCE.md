# AI OS Inheritance Contract

## Status

Proposed standard for downstream projects.

## Canonical source

The canonical AI Operating System is:

- repository: `yurikuchumov-ux/ai-operating-system`;
- document: `AI_OS.md`;
- canonical URL: `https://github.com/yurikuchumov-ux/ai-operating-system/blob/main/AI_OS.md`.

Downstream projects must not copy the complete text of `AI_OS.md` into their own repositories or project instructions.

## Inheritance model

Every downstream project must contain a small reference document named `AI_OS_REFERENCE.md` or an equivalent project-specific file that declares:

1. the canonical repository and document;
2. the inheritance mode;
3. the inherited revision;
4. the local project-rules document;
5. the precedence model;
6. the update procedure.

The reference document is metadata and navigation. It is not a copy of the constitution.

## Inheritance modes

### Tracking mode

The project inherits the current `main` revision of `AI_OS.md`.

Use tracking mode for early-stage projects where rapid adoption of AI OS improvements is more important than strict reproducibility.

A tracking project must review changes before relying on newly introduced behavior in a release-critical workflow.

### Pinned mode

The project inherits a specific commit SHA from `ai-operating-system`.

Use pinned mode for production, regulated, security-sensitive, or reproducibility-sensitive projects.

The pinned SHA must be explicit. Branch names and tags alone are not sufficient for the inherited revision record.

## Precedence

Unless a higher-level safety, legal, platform, or owner instruction applies, precedence is:

1. AI Operating System;
2. project-specific rules;
3. repository documents and architecture decisions;
4. Issue or Task Contract;
5. chat instructions.

Project-specific rules may specialize AI OS but must not silently weaken or contradict it.

A deliberate exception requires:

- an explicit statement of the conflicting AI OS rule;
- a documented reason;
- owner approval;
- an ADR or equivalent repository record;
- a defined review or expiry condition.

## Required downstream files

A downstream project should contain:

- `AI_OS_REFERENCE.md` — inheritance metadata;
- `PROJECT_RULES.md` — project-specific additions only;
- project ADRs — explicit exceptions or architecture decisions.

The full AI OS text must not appear in `PROJECT_RULES.md`.

## Minimal reference format

```markdown
# AI Operating System Reference

Canonical source: https://github.com/yurikuchumov-ux/ai-operating-system/blob/main/AI_OS.md

Inheritance mode: pinned
Inherited revision: <40-character commit SHA>
Project rules: ./PROJECT_RULES.md

Precedence:
1. AI Operating System
2. Project Rules
3. Repository documentation and ADRs
4. Issue or Task Contract
5. Chat

This repository does not duplicate AI_OS.md. Project-specific rules may specialize but must not silently weaken it.
```

For tracking mode, use:

```text
Inheritance mode: tracking
Inherited revision: main
```

## Compatibility policy

AI OS changes fall into three classes.

### Clarification

A clarification makes an existing rule more precise without materially changing required behavior.

Tracking projects inherit it immediately. Pinned projects may adopt it through a normal update PR.

### Additive rule

An additive rule introduces a new obligation without invalidating existing project-specific rules.

Tracking projects inherit it immediately but must evaluate operational impact. Pinned projects adopt it through an update PR.

### Breaking rule

A breaking rule changes precedence, removes an accepted behavior, changes required roles, or invalidates an existing project process.

Breaking changes require:

- an explicit migration note in `ai-operating-system`;
- a compatibility or transition period where practical;
- a downstream update PR;
- independent review before production adoption.

## Update process

A downstream update must:

1. identify the old and new AI OS revisions;
2. summarize relevant AI OS changes;
3. check project-specific rules for conflicts;
4. update the pinned SHA or confirm tracking mode;
5. run repository validation;
6. open a Draft PR;
7. receive independent review;
8. merge only after owner approval.

AI OS updates must never silently rewrite local project rules.

## Validation requirements

A downstream validation check should verify:

- the canonical URL is reachable;
- the referenced commit exists for pinned mode;
- the SHA has exactly 40 hexadecimal characters;
- `PROJECT_RULES.md` exists;
- the project does not contain a copied `AI_OS.md` unless explicitly approved for an offline or archival use case;
- the reference declares precedence;
- pinned mode reports whether a newer canonical revision exists.

A stale pin is informational by default. It becomes blocking only when the project explicitly adopts that policy.

## Security and trust boundaries

- The canonical repository remains the source of truth.
- A downstream workflow may read AI OS but must not receive write access to `ai-operating-system`.
- Automatic update PRs may be proposed but must remain Draft until reviewed.
- No workflow may automatically merge an AI OS update.
- Remote content must not be executed as code.
- Validation actions must be pinned to immutable commit SHAs.

## Adoption sequence

1. Merge this inheritance contract into `ai-operating-system`.
2. Add a reusable `AI_OS_REFERENCE.md` template and validation workflow to `ai-development-studio-template`.
3. Adopt the reference in one pilot downstream repository.
4. Validate tracking and pinned modes.
5. Adopt in Health OS and future projects.

## Definition of done

The inheritance mechanism is complete when:

- `AI_OS.md` remains the only canonical constitution;
- the template repository provides reusable adoption assets;
- at least one downstream project passes validation;
- project-specific rules contain only local additions;
- an AI OS update can be adopted through a reviewed Draft PR without copying the constitution.