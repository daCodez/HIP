# ADR-007: Use simulation-bound impact-based rule approval workflows

## Status

Accepted

## Date

2026-07-20

## Context

HIP rules can materially change user-facing safety decisions. A mutable approval
flag or a creator's self-approval would not prove that reviewers evaluated the
exact rule version and simulation evidence being activated. Concurrent review
also must not lose either approval or create unaudited transitions.

## Decision

- Every workflow is bound to one immutable rule version and one passing,
  immutable simulation result. Its identifier is a deterministic SHA-256 digest
  of that binding, so the same evidence cannot open replay workflows.
- Low-impact rules need no approver, medium-impact rules need one independent
  approver, and high- and critical-impact rules need two distinct independent
  approvers. A creator cannot approve their own version.
- Critical workflows remain blocked after approval until the separate rollback
  test and manual deployment controls are completed by HIP-0405.
- Workflow state is validated at application and persistence boundaries. Updates
  use optimistic concurrency so simultaneous approvals are retained or retried.
- Each create or approval transition and its actor-bound audit event are written
  atomically. Actor identifiers remain inside encrypted workflow state; public-
  safe audit payloads contain only a SHA-256 actor digest.
- Admin APIs expose policy status and aggregate approval counts, never creator or
  approver identities.

## Consequences

- Approval evidence cannot be reused for another rule version or simulation.
- High-impact activation can be gated on two independent human decisions without
  a lost-update race.
- HIP-0405 can add controlled activation, rollback-test completion, and rollback
  transitions on top of a validated, versioned workflow record.
- Existing legacy rule paths must not bypass this workflow when they are migrated
  to the versioned rule activation service.
