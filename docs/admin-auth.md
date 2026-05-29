# HIP Admin Authentication and Authorization

HIP admin routes are protected by role-based authorization policies. This is an MVP foundation, not a production identity platform.

## Auth Approach

The current implementation uses a development-only header authentication scheme:

- header: `X-HIP-Admin-Role`
- optional header: `X-HIP-Admin-User`

This scheme only authenticates in the Development environment. It is not production-safe and must be replaced with production authentication before deployment.

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
- `/api/v1/admin/audit-logs`

Protected UI routes:

- `/admin/rules`
- `/admin/self-healing`
- `/admin/review`
- `/admin/appeals`
- `/admin/reputation-overrides`
- `/admin/audit-logs`

Public routes remain public:

- `/api/v1/public/...`
- `/api/v1/sl-hud/...`
- `/lookup`
- `/lookup/domain/{domain}`
- `/safety`

Identity routes under `/api/v1/identity/...` remain public for the current identity-signing foundation.

## Production Warning

Before production, replace development header auth with a real authentication system such as ASP.NET Core Identity, external OIDC, or another audited identity provider. Production auth must include secure password handling or federated login, session controls, role management, audit logging, and administrative recovery procedures.
