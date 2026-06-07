# HIP Admin Authentication and Authorization

HIP admin routes are protected by role-based authorization policies. This is an MVP foundation, not a production identity platform.

## Auth Approach

The current implementation uses a development-only header authentication scheme:

- header: `X-HIP-Admin-Role`
- optional header: `X-HIP-Admin-User`

This scheme only authenticates in the Development environment. It is not production-safe and must be replaced with production authentication before deployment.

The development scheme is also local-only. HIP rejects development admin cookies, `X-HIP-Admin-Role`, and `/dev/admin-login/{role}` attempts when the request host is not loopback (`localhost`, `127.0.0.1`, or `::1`). This keeps the MVP convenience path from becoming a remote administrative backdoor during local tunneling or accidental exposure.

Example development API request:

```powershell
curl -H "X-HIP-Admin-Role: Owner" https://localhost:7001/api/v1/admin/audit-logs
```

## Roles

- Owner: full control, manage admins, system settings, major overrides, delete/export data.
- Admin: manage rules, review reports, manage licenses, view reputation, approve appeals, manage domains.
- Moderator: review reports, handle appeals, mark false positives, suggest reputation changes.
- Support: look up license status, reset setup codes, help users activate, escalate issues.
- ReadOnly: view dashboards, reports, reputation, and logs only.

## Permission Model

The MVP exposes a permission catalog through `AdminRoleCatalog` and `GET /api/v1/admin/roles`.

Current permissions:

- `Rules.View`
- `Rules.Edit`
- `Rules.Simulate`
- `Reputation.View`
- `Reputation.OverrideRequest`
- `Review.View`
- `Review.Decide`
- `Appeals.View`
- `Appeals.Decide`
- `Licenses.View`
- `Licenses.Manage`
- `Audit.View`
- `Admins.Manage`
- `System.Manage`

Owner has every permission. Admin has operational edit permissions for rules, review, appeals, reputation requests, licenses, and audit viewing. Moderator can review and decide reports/appeals but cannot manage the system. Support can view and manage license support flows but cannot request reputation overrides. ReadOnly can view but cannot change state.

## Policies

- `CanManageRules`: Owner, Admin
- `CanReviewReports`: Owner, Admin, Moderator
- `CanApproveOverrides`: Owner, Admin
- `CanViewAuditLogs`: Owner, Admin, ReadOnly
- `CanManageLicenses`: Owner, Admin, Support
- `CanViewAdminDashboard`: Owner, Admin, Moderator, Support, ReadOnly

## Protected Routes

Protected API route groups:

- `/api/v1/admin/rules/...`
- `/api/v1/admin/self-healing/...`
- `/api/v1/admin/review/...`
- `/api/v1/admin/appeals/...`
- `/api/v1/admin/reputation-overrides/...`
- `/api/v1/admin/reputation/...`
- `/api/v1/admin/dashboard/summary`
- `/api/v1/admin/audit-logs`
- `/api/v1/admin/audit`
- `/api/v1/admin/audit/query`
- `/api/v1/admin/roles`

Protected UI routes:

- `/admin/rules`
- `/admin`
- `/admin/self-healing`
- `/admin/review`
- `/admin/appeals`
- `/admin/reputation-overrides`
- `/admin/audit-logs`
- `/admin/audit`
- `/admin/roles`

## Audit Log

Audit entries are privacy-safe records for serious admin actions, including:

- rule created or changed
- rule enabled or disabled
- simulation run
- reputation override requested, approved, or rejected
- review decision made
- appeal decision made
- license reset or revoked
- admin role changed

Each audit entry includes an ID, timestamp, actor placeholder, actor role placeholder, action, target type, target ID, summary, safe metadata, optional before/after metadata, severity, and optional correlation ID.

Audit logging must not store full private chat logs, raw private messages, form contents, or unrelated private evidence. The MVP sanitizer drops private-content metadata keys and redacts obvious private-content markers in summaries.

Public routes remain public:

- `/api/v1/public/...`
- `/api/v1/sl-hud/...`
- `/lookup`
- `/lookup/domain/{domain}`
- `/safety`

Identity read/verification routes under `/api/v1/identity/...` remain public-safe for the current identity-signing foundation. Development identity registration and signing routes are restricted to local Development requests and rate limited, because the current signing provider is a non-production placeholder.

## Production Warning

Before production, replace development header auth with a real authentication system such as ASP.NET Core Identity, external OIDC, or another audited identity provider. Production auth must include secure password handling or federated login, session controls, role management, audit logging, and administrative recovery procedures.
