# ADR-005: Introduce an immutable versioned rule domain schema

## Status

Accepted

## Date

2026-07-20

## Context

HIP already has an application-level admin Site Safety rule contract used by
the API, UI, persistence adapters, and scanner. It predates the complete rule
lifecycle and does not provide one domain-owned shape for schema version,
impact-derived approval policy, effective time, immutable approvals, and
rollback metadata.

Changing that public contract in place would combine schema, workflow,
persistence, and client migration risk. Phase 4 needs a stable domain boundary
before approval, simulation persistence, and rollback behavior are expanded.

## Decision

HIP defines immutable `HipRuleVersion` schema `hip-rule/1` in the domain layer.

- Every snapshot has stable rule and version identifiers, a positive version,
  and an exact prior-version link after version one.
- Status and runtime mode are separate and validated for consistency.
- Impact is explicit and derives the required approval policy: none, one person,
  two people, or manual two-person approval.
- Creator type and creator identity are retained independently from approvals.
  Approval identities and approval IDs are unique case-insensitively, cannot be
  the creator, and cannot predate creation.
- Conditions and actions are immutable, bounded JSON-first records. HIP-0402
  owns the typed field/operator catalog; application services retain action
  allow-list responsibility.
- Active versions require an effective time. Expiry cannot precede effectiveness.
- Rollback identifies exactly one prior-version target or a known disabled
  fallback. Critical impact records whether an explicit rollback test is needed.
- The existing admin rule API remains unchanged. An explicit application mapper
  projects that compatibility contract into `hip-rule/1`; later Phase 4 packages
  can migrate storage and workflows deliberately.

## Alternatives Considered

### Add more optional fields directly to the existing API record

Rejected as the first step. It would make a compatibility-sensitive transport
record the source of domain lifecycle invariants and couple every caller to a
partially implemented workflow.

### Replace the existing rule contract immediately

Rejected. The admin UI, API tests, persistence, and scanner already depend on
that shape. A staged mapping keeps the change additive and rollback-safe.

### Store unvalidated arbitrary rule JSON

Rejected. JSON-first does not mean schema-free. HIP still bounds collection
sizes, identifiers, text, JSON depth, lifecycle state, and time ordering before
a version can cross the domain boundary.

## Consequences

- Rule lifecycle work now has a UI- and storage-independent domain contract.
- Existing APIs remain source- and wire-compatible during migration.
- HIP-0402 can add typed field and operator validation without redesigning
  version identity, approval metadata, or rollback shape.
- Approval-count sufficiency, simulation evidence, activation, persistence, and
  executing rollback remain separate HIP-0403 through HIP-0405 responsibilities.
