# ADR-008: Persist authoritative rule deployments with one-action rollback

## Status

Accepted

## Date

2026-07-20

## Context

An approval record alone does not make a rule safely deployable. HIP needs one
authoritative runtime version, an exact rollback target that cannot disappear
when the editable rule is overwritten, and concurrency controls that prevent
activation, promotion, or rollback replay.

## Decision

- A deployment stores the exact active rule snapshot and exactly one rollback
  snapshot, or an explicit disabled fallback for the first deployment.
- Activation consumes an exact HIP-0404 workflow. The encrypted workflow retains
  the immutable approved rule snapshot; a newer or changed repository definition
  makes the workflow stale.
- High-impact rules enter Watch first and require a separate version-checked
  promotion. Critical rules require completed rollback-test evidence and explicit
  manual-deployment authorization before activation.
- Activation, promotion, and rollback are reason-bound compare-and-swap actions.
  Each state transition and its privacy-safe actor/reason-digest audit event are
  committed atomically.
- Rollback restores the retained snapshot or disables the rule in one action,
  then consumes the target so the request cannot be replayed.
- Default JSON-rule evaluation reads authoritative deployments. Once deployment
  state exists, a disabled rollback does not silently fall back to sample rules.
- The legacy Site Safety service rejects high/critical single-person approval and
  activation, preventing it from bypassing the versioned workflow.

## Consequences

- Rollback remains possible even if the editable latest-rule record changes.
- Concurrent transitions preserve one winner and its corresponding audit event.
- Admin responses expose versions and transition status, but never actor IDs or
  reason text.
- HIP-0406 AI suggestions can produce drafts and simulations but cannot write
  approval or deployment transitions.
