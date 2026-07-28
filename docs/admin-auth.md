# HIP Admin Authentication and Authorization

HIP admin routes are protected by role-based authorization policies. Production
Web authentication uses the provider-neutral OIDC, MFA, step-up, and protected
session design in [`authentication.md`](authentication.md); Development retains
a separate local convenience scheme.

## Auth Approach

The Development environment can use this header authentication scheme:

- header: `X-HIP-Admin-Role`
- optional header: `X-HIP-Admin-User`

This scheme only authenticates in the Development environment and is never a
production or service-client credential. Every other environment uses the HIP
production Web authentication stack. The standalone API's `HIP-Service` scheme
does not accept this header or a HIP Web session cookie as a service-client
credential.

The development scheme is also direct-loopback-only. HIP requires the request host and the network peer address to be loopback (`localhost`, `127.0.0.1`, or `::1`) and rejects requests containing `Forwarded`, `X-Forwarded-For`, or `X-Real-IP`. The same boundary protects development admin cookies, `X-HIP-Admin-Role`, sign-in, and sign-out. This keeps the MVP convenience path from becoming a remote administrative backdoor through local tunneling, reverse proxies, spoofed host values, or accidental exposure.

Example development API request:

```powershell
curl -H "X-HIP-Admin-Role: Owner" https://localhost:7001/api/v1/admin/audit-logs
```

## Roles

- Owner: full control, manage admins, system settings, major overrides, delete/export data.
- Admin: manage rules, review reports, create and administer licenses, view reputation, approve appeals, manage domains.
- Moderator: review reports, handle appeals, mark false positives, suggest reputation changes.
- Support: look up license status, reset device activation, run the HUD simulator, help users activate, and escalate issues.
- ReadOnly: view dashboards, reports, reputation, license status, and logs without changing state.

## Permission Model

The V1 application exposes a permission catalog through `AdminRoleCatalog` and
`GET /api/v1/admin/roles`. Administrator assignments are stored as one bounded,
versioned encrypted directory. The directory contains only the privacy-safe HIP
actor ID, a non-email operator label, role, status, and lifecycle timestamps; HIP
does not store an administrator password, token, raw OIDC subject, issuer, or
email in this directory.

Before the first directory write, the configured OIDC role mapping supplies the
bootstrap Owner. After that write, HIP replaces external administrative role
claims on each request with the active persisted assignment. Missing, disabled,
or unassigned actors receive no HIP admin role. If the directory cannot be read,
HIP removes administrative roles for that request. Changes require an active
persisted Owner, recent MFA outside Development, optimistic concurrency, an
explicit privacy-safe reason, and an atomic append-only audit record. HIP rejects
self-demotion/self-disable and any change that would leave no active Owner.

Authenticated people open `/access` to submit a privacy-safe access request.
HIP captures the actor ID from the authenticated session; the requester never
copies or edits it. Owners review the pending queue in **Users and roles**, choose
the least-privileged role, and explicitly approve or deny the request. The
request workflow assigns HIP authorization only; production identity-provider
account creation remains outside HIP.

Development can opt into `HipAdminLogin:AllowTestPersonas`. With that local-only
setting, a unique test email plus the configured bootstrap Owner password creates
an unprivileged test persona with its own stable actor ID. The same test email
keeps the same identity across browsers, while different test emails create
distinct identities. This convenience is protected by the loopback-only
Development boundary and is never registered in deployed environments.

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
- `Licenses.Support`
- `Licenses.Manage`
- `Audit.View`
- `ServiceClients.View`
- `ServiceClients.Manage`
- `Admins.Manage`
- `System.Manage`

Owner has every permission. Admin has operational edit permissions for rules,
review, appeals, reputation requests, license support and administration,
service-client view/management, and audit viewing. Moderator can review and
decide reports/appeals but cannot access license or service-client operations.
Support has `Licenses.View` and `Licenses.Support`, which permit lookup,
activation reset, and HUD simulation but not license creation, status changes,
or service-client access. ReadOnly has `Licenses.View` and can inspect license
summaries and details without changing state.

## Policies

- `CanViewOwnAdminAccess`: any authenticated identity with one HIP actor claim (self only)
- `CanViewAdminUsers`: Owner
- `CanManageAdmins`: Owner with recent MFA-backed authentication outside Development
- `CanManageRules`: Owner, Admin
- `CanReviewReports`: Owner, Admin, Moderator (legacy compatibility policy)
- `CanViewReviews`: Owner, Admin, Moderator, Support, ReadOnly
- `CanDecideReviews`: Owner, Admin, Moderator
- `CanViewAppeals`: Owner, Admin, Moderator, ReadOnly
- `CanDecideAppeals`: Owner, Admin, Moderator
- `CanApproveOverrides`: Owner, Admin
- `CanManageReputation`: Owner, Admin
- `CanViewAuditLogs`: Owner, Admin, ReadOnly
- `CanManageLicenses`: Owner, Admin, Support (legacy compatibility policy)
- `CanViewLicenses`: Owner, Admin, Support, ReadOnly
- `CanSupportLicenses`: Owner, Admin, Support
- `CanAdministerLicenses`: Owner, Admin
- `CanManagePlatforms`: Owner, Admin
- `CanViewServiceClients`: Owner, Admin
- `CanManageServiceClients`: Owner, Admin
- `RecentPrivilegedAuthentication`: Owner, Admin with recent MFA-backed authentication outside Development
- `CanViewAdminDashboard`: Owner, Admin, Moderator, Support, ReadOnly
- `CanManageDomainVerifications`: Owner, Admin
- `CanRevokeDomainVerifications`: Owner
- `CanRequestPrivilegedStepUp`: Owner, Admin

`CanManageLicenses` remains registered for compatibility with older internal callers, but current license routes and pages use the narrower view, support, and administration policies above. Setup-code creation and status changes require both `CanAdministerLicenses` and `RecentPrivilegedAuthentication`; activation reset requires `CanSupportLicenses`; list and detail reads require `CanViewLicenses`.

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
- `GET /api/v1/admin/access/me` (`CanViewOwnAdminAccess`; self only; no-store)
- `GET /api/v1/admin/users` (`CanViewAdminUsers`)
- `PUT /api/v1/admin/users` (`CanManageAdmins`)
- `GET /api/v1/admin/service-clients/` (`CanViewServiceClients`)
- `POST /api/v1/admin/service-clients/` (`CanManageServiceClients` plus recent privileged authentication)
- `POST /api/v1/admin/service-clients/{clientId}/credentials/rotate` (`CanManageServiceClients` plus recent privileged authentication)
- `POST /api/v1/admin/service-clients/{clientId}/revoke` (`CanManageServiceClients` plus recent privileged authentication)
- `GET /api/v1/licenses/` and `GET /api/v1/licenses/{licenseId}` (`CanViewLicenses`)
- `POST /api/v1/licenses/{licenseId}/reset` (`CanSupportLicenses`)
- `POST /api/v1/licenses/setup-codes` and license status mutations (`CanAdministerLicenses` plus recent privileged authentication)

Protected UI routes:

- `/admin/rules`
- `/admin`
- `/admin/self-healing`
- `/admin/review`
- `/admin/appeals`
- `/admin/reputation-overrides`
- `/admin/audit-logs`
- `/admin/audit`
- `/access` (`CanViewOwnAdminAccess`; self only)
- `/admin/roles` (`CanViewAdminUsers`; mutations reauthorize `CanManageAdmins`)
- `/admin/api` (`CanViewServiceClients`; mutations reauthorize `CanManageServiceClients` plus recent privileged authentication)
- `/admin/licenses` and `/admin/licenses/{licenseId}` (`CanViewLicenses`)
- `/admin/licenses/new` (`CanAdministerLicenses`; creation also rechecks recent authentication)
- `/admin/sl-hud-simulator` (`CanSupportLicenses`)

## Service-Client Management

HIP-0205 makes `/admin/api` a working owner-scoped service-client inventory and
lifecycle surface. The unique authenticated `hip_actor_id` supplies both the
audit actor and the input to a versioned HMAC owner scope. Callers cannot submit
another owner identifier, and cross-owner identifiers receive non-disclosing
failures.

Registrations accept exactly one of `domain-verification:check` or
`site-safety:external-evidence:check` and one to sixteen exact canonical domain
grants. Domain control or successful credential authorization does not establish
safety, reputation, or trustworthiness.

List operations return bounded public metadata only. Create and rotate return a
full `clientId.secret` credential once and mark the HTTP response no-store; the
secret and verifier never appear in lists. Rotation preserves the original
expiry and invalidates the old secret. Revocation is terminal. Every mutation
requires the current aggregate version, rechecks management plus recent
authentication immediately before the operation, and consumes the same
Redis-backed, privacy-HMAC-keyed actor budget whether it originated from the
HTTP API or the interactive Blazor page. Exhaustion returns a bounded retry
message; distributed-state failure closes before credential or repository work.
Cookie-authenticated management API mutations also require antiforgery
validation.

See [`service-client-credentials.md`](service-client-credentials.md) for the
standalone `Authorization: HIP-Service <clientId>.<secret>` contract, exact
scope/resource enforcement, PBKDF2 verifier, distributed pre-verification rate
limits, and operational guidance.

## Audit Log

Audit entries are privacy-safe records for serious admin actions, including:

- rule created or changed
- rule enabled or disabled
- simulation run
- reputation override requested, approved, or rejected
- review decision made
- appeal decision made
- license reset or revoked
- service client created, credential rotated, or terminally revoked
- admin role changed

Each audit entry includes an ID, timestamp, actor placeholder, actor role placeholder, action, target type, target ID, summary, safe metadata, optional before/after metadata, severity, and optional correlation ID.

Audit logging must not store full private chat logs, raw private messages, form contents, or unrelated private evidence. The MVP sanitizer drops private-content metadata keys and redacts obvious private-content markers in summaries.

Public routes remain public:

- `/api/v1/public/...`
- `POST /api/v1/sl-hud/activate`
- `/lookup`
- `/lookup/domain/{domain}`
- `/safety`

HUD scan, settings, and report routes require the named `CanUseActiveDevice` policy, which validates an opaque credential against the exact active license/device binding. `POST /api/v1/sl-hud/simulate` requires `CanSupportLicenses`.

Identity read/verification routes under `/api/v1/identity/...` remain public-safe for the current identity-signing foundation. Domain-verification mutations and Development identity registration/signing require `CanManageDomainVerifications`; the Development routes also remain local-only and rate limited because the current signing provider is a non-production placeholder.

## Production Operations

Deployment must validate the configured identity provider, shared protected
session key ring, recovery procedures, role mappings, MFA semantics, and
security-event monitoring. Development headers remain local-only and must never
be enabled as a remote convenience path.

Service-client credentials are replayable bearer material. Production operation
requires HTTPS, secret-manager distribution, reliable shared Redis for the
fail-closed pre-PBKDF2 limiter, lifecycle/audit monitoring, and prompt rotation
or revocation after suspected exposure.
