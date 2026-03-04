# HIP Priority 2 — Endpoint Cap Exceptions Plan

This document defines how HIP decides whether an endpoint may exceed the default payload cap and what controls are required before approval.

## Objective
Keep strict default payload limits while allowing explicit, justified exceptions for legitimate large payload use cases.

## Current baseline (already implemented)
- Global request-body safety net: **512 KB**
- Endpoint-specific caps for current POST routes (128 KB / 256 KB tiers)
- Standardized `413 payload.tooLarge` response
- Standardized `429 rateLimit.exceeded` response

## Exception approval criteria (must pass all)
1. **Business necessity**
   - Endpoint has a documented user/business flow requiring larger bodies.
2. **Observed evidence**
   - Real payload distribution available (at least p95/p99 estimates from logs/tests).
3. **Authentication strength**
   - Endpoint is authenticated/authorized or envelope-gated when exposed cross-boundary.
4. **Abuse controls**
   - Endpoint has tight rate limits relative to baseline.
5. **Operational safety**
   - Timeout/cancellation behavior is verified under large-payload scenarios.
6. **Test coverage**
   - Boundary tests exist (`below`, `at`, `above` cap).

If any criterion fails, keep current cap and route caller to a dedicated upload/bulk flow instead.

---

## Endpoint inventory with exception recommendation

| Endpoint | Method | Auth/Gate Profile | Current Cap | Exception Candidate? | Recommendation |
|---|---|---|---:|---|---|
| `/api/status` | GET | public read | global only | No | Keep strict default; no body expected. |
| `/health` | GET | public read | global only | No | Keep strict default; liveness probe only, no body expected. |
| `/api/identity/{id}` | GET | envelope check when `x-hip-origin=bff` | global only | No | Keep strict default + existing tighter rate limit. |
| `/api/reputation/{identityId}` | GET | envelope check when `x-hip-origin=bff` | global only | No | Keep strict default + existing tighter rate limit. |
| `/api/jarvis/context/{identityId}` | GET | app-level validation | global only | No | Keep strict default. |
| `/api/admin/security-status` | GET | admin access policy + envelope checks | global only | No | Keep strict default. |
| `/api/admin/security-events` | GET | admin access policy + envelope checks | global only | No | Keep strict default. |
| `/api/admin/audit` | GET | admin access policy + envelope checks | global only | No | Keep strict default. |
| `/api/messages/sign` | POST | validator limits body to 4096 chars | 128 KB | No | Keep 128 KB; already generous vs validator. |
| `/api/messages/verify` | POST | validator limits body/signature fields | 256 KB | No | Keep 256 KB; no evidence for larger payloads. |
| `/api/messages/verify-readonly` | POST | same DTO constraints as verify | 256 KB | No | Keep 256 KB. |
| `/api/jarvis/tool-access` | POST | validator constrained DTO | 128 KB | No | Keep 128 KB. |
| `/api/jarvis/policy/evaluate` | POST | validator limits `UserText` to 8000 chars | 256 KB | No (for now) | Keep 256 KB unless policy-eval use case proves larger need. |
| `/api/jarvis/token/issue` | POST | token service request | 128 KB | No | Keep 128 KB. |
| `/api/jarvis/token/validate` | POST | token service request | 256 KB | No | Keep 256 KB. |
| `/api/jarvis/token/refresh` | POST | token service request | 128 KB | No | Keep 128 KB. |
| `/api/jarvis/token/revoke` | POST | token service request | 128 KB | No | Keep 128 KB. |
| `/api/jarvis/proof/issue` | POST | token service request | 128 KB | No | Keep 128 KB. |
| `/api/jarvis/proof/consume` | POST | token service request | 128 KB | No | Keep 128 KB. |

### Conclusion
**No current endpoint qualifies for a larger cap exception based on existing DTO/validator constraints and endpoint purpose.**

---

## Priority-2 implementation tasks
1. Add explicit comments in endpoint files indicating why each cap is intentionally conservative.
2. Add a small ops note in docs for exception request process.
3. Add targeted telemetry for request content length by endpoint (sampled) to support future p95/p99 evidence.
4. Add dedicated design placeholder for future large-payload path (upload/bulk endpoint), instead of raising general API caps.

## Future exception workflow
When a large payload request appears:
1. Capture endpoint + business flow.
2. Gather size stats for 1–2 weeks (or controlled test data).
3. Propose cap increase + tighter per-endpoint rate limit.
4. Add boundary/load tests.
5. Roll out behind config flag if risk is medium/high.
6. Reassess after deployment with telemetry.
