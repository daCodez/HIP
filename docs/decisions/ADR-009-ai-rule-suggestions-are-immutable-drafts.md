# ADR-009: Treat AI rule suggestions as immutable draft evidence packages

## Status

Accepted

## Date

2026-07-20

## Context

AI output is untrusted supporting evidence. The previous development analyzer
could return a low-impact rule as enabled and Active without approval, and its
suggestion response was neither persisted nor bound to normal HIP simulation and
approval evidence.

## Decision

- `TrustRule` records carry explicit creator provenance. AI-origin rules use the
  reserved `AiSuggested` type and an opaque `ai:` provider identity.
- Every AI suggestion is forced to disabled mode, approval-pending state, and a
  simulation-required posture regardless of the model's recommendation.
- Drafts contain bounded evidence summaries, expected benefit, risks, confidence,
  provider provenance, synthetic test results, and a disabled-state rollback plan.
- Draft creation runs and immutably stores a normal HIP-0403 simulation before the
  encrypted create-only draft is persisted.
- Typed fields, operators, actions, scalar JSON, privacy-sensitive terms, sizes,
  counts, and draft lifecycle invariants are revalidated at persistence boundaries.
- Submission requires a human actor and enters the normal HIP-0404 workflow. Even
  low-impact AI drafts require at least one independent human approval.
- The application approval and deployment services reject all reserved `ai:`
  actors. AI routes expose no approval, activation, promotion, or rollback action.

## Consequences

- AI can recommend an eventual mode but cannot create a live-capable rule.
- Suggestions are reviewable and reproducible without retaining raw URL content,
  private messages, credentials, or secret-bearing evidence.
- Human approval and controlled deployment remain the only path from AI draft to
  runtime evaluation.
- Production AI providers can replace the deterministic placeholder without
  changing the authority boundary.
