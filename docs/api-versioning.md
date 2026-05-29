# HIP API Versioning

Current API version: `v1`.

HIP API routes must be versioned from day one. The preferred route format is:

- `/api/v1/public/...`
- `/api/v1/admin/...`
- `/api/v1/identity/...`

Only `v1` is implemented right now. Future versions such as `v2` should be added beside `v1` without breaking existing clients.

## Current v1 Route Groups

Public:

- `GET /api/v1/public/lookup/domain/{domain}`
- `GET /api/v1/public/badge/domain/{domain}`
- `POST /api/v1/public/appeals`
- `POST /api/v1/public/feedback`
- `POST /api/v1/public/risk-findings`
- `POST /api/v1/public/sl-hud/activate`
- `POST /api/v1/public/sl-hud/report-finding`

Admin:

- `POST /api/v1/admin/rules/simulate`
- `POST /api/v1/admin/self-healing/detect-patterns`
- `POST /api/v1/admin/self-healing/generate-rule`
- `POST /api/v1/admin/self-healing/analyze-findings`
- `GET /api/v1/admin/review`
- `GET /api/v1/admin/review/{id}`
- `POST /api/v1/admin/review`
- `POST /api/v1/admin/review/{id}/approve`
- `POST /api/v1/admin/review/{id}/reject`
- `POST /api/v1/admin/review/{id}/needs-more-info`
- `POST /api/v1/admin/review/{id}/assign`
- `GET /api/v1/admin/appeals`
- `POST /api/v1/admin/appeals/{id}/approve`
- `POST /api/v1/admin/appeals/{id}/reject`
- `POST /api/v1/admin/appeals/{id}/needs-more-info`
- `GET /api/v1/admin/reputation-overrides`
- `POST /api/v1/admin/reputation-overrides`
- `POST /api/v1/admin/reputation-overrides/{id}/approve`
- `POST /api/v1/admin/reputation-overrides/{id}/reject`
- `GET /api/v1/admin/reputation/{targetType}/{targetId}`
- `POST /api/v1/admin/reputation/events`
- `POST /api/v1/admin/reputation/{targetType}/{targetId}/recalculate`
- `GET /api/v1/admin/audit-logs`

## Compatibility Aliases

Existing unversioned `/api/public/...` and `/api/admin/...` routes are currently kept as backwards-compatible aliases. New clients should use `/api/v1/...`.

Unversioned public APIs should not be added unless they are temporary aliases or redirects.

## Future Version Rules

- Add new route groups such as `/api/v2/public` beside `v1`.
- Keep `v1` stable for existing clients.
- Do not silently change response shapes in `v1`.
- Prefer additive fields over breaking changes.
- Document any planned deprecation before removing an alias.
