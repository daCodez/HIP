# HIP Audit Trail MVP Plan (Locked)

Status: **In progress (P2.1 + P2.2 applied, P2.3a applied)**
Phase: **P2 — Integrity and observability**
Date: 2026-03-01

## Decision
We will implement a durable, queryable audit trail in the API first, then expose controlled audit retrieval via a privileged SDK admin surface.

## Implementation sequence

### Progress update
- ✅ P2.1 complete: durable DB-backed audit trail + filterable admin endpoint.
- ✅ P2.2 complete: rate-limit and token/proof lifecycle audit event coverage.
- ✅ P2.3a complete: shared audit contracts extracted into new `HIP.Audit` project (`HIP.Audit.Models` + `HIP.Audit.Abstractions`).
- 🔜 Next: P2.3b SDK admin audit access surface.

1. **API first (P2.1)**
   - Replace in-memory-only audit trail with DB-backed persistence.
   - Keep existing admin audit endpoint and extend with bounded filters.
   - Ensure all audit payloads are sanitized (no secrets/tokens/passwords).

2. **Security event coverage (P2.2)**
   - Ensure invalid signatures, replay, throttling, policy deny/review, and token lifecycle events are persisted with reason codes.

3. **SDK admin access (P2.3)**
   - Add privileged admin client surface for audit retrieval.
   - Do not expose audit retrieval in default/general SDK flows.

## Guardrails
- Audit access is privileged and permission-gated.
- Responses are metadata-only, sanitized, and bounded.
- Retention policy enforced (time- or volume-based).
- Keep rollback path explicit and easy.

## Proposed audit event fields
- id
- createdAtUtc
- eventType
- category
- identityId (nullable)
- route (nullable)
- outcome
- reasonCode (nullable)
- correlationId
- source
- detail (sanitized)
- latencyMs (nullable)

## Verification (after apply)
- Build/tests pass
- Events persist across API restart
- Filtered retrieval works as expected
- Security-relevant events are present with reason codes
- No sensitive data leaks in audit output

## Rollback
- Revert changed files
- Switch DI back to `InMemoryAuditTrail`
- Keep new tables dormant or remove via migration rollback
- Re-run tests to confirm baseline behavior
