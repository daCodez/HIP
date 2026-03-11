# HIP.Admin UI Shell

Rebuilt admin UI shell for HIP using Blazor Server (`net10.0`) with a Bootstrap 5 visual baseline and custom theme variables.

## Run

```bash
cd /home/jarvis_bot/.openclaw/workspace/HIP
DOTNET_ENVIRONMENT=Development dotnet run --project HIP.Admin/HIP.Admin.csproj
```

If running the full Aspire stack, access through existing proxy route:
- `https://<host>/admin`

Direct app URL in local dev (from launch profile):
- `http://localhost:5099` (or assigned port)

## Architecture

- `Components/Layout`
  - `AdminShell`: shell scaffold with skip-link, landmarks, sidebar + context + main regions
  - `AdminTopbar`, `AdminSidebar`, `AdminContextBar`: reusable shell regions
  - Legacy `AppLayout`/`SidebarMenuItem` kept for compatibility during transition
- `Components/Common`
  - Phase 0 primitives: `StateView`, `PageHeader`, `StatusBadge`, `AlertBanner`
  - Phase 1 reusable data components: `FilterBar`, `DataTable<TItem>` (typed columns + a11y sorting), `MetricCard`, `Tabs`, `ModalDialog`
  - Legacy compatibility components retained: `StatCard`, `BadgeStatus`, `ConfirmModal`, `DropdownMenu`, `ToastHost`
- `Navigation`
  - `AdminRoutes`: typed route registry with required roles + feature flag metadata
  - `BreadcrumbService`: route/path-based breadcrumb builder for header/context wiring
- `Pages`
  - Dashboard, Security Status, Users & Devices, Reputation, Security Policies, Authorization Policies, Audit Logs
- Simulator page (`/simulator`) with quick run mode and campaign mode (profile + duration + wave interval), including a live run progress bar (% + processed/total)
  - Campaign profiles now use plain-language labels + helper subtitles (Balanced, High-pressure, Low-noise, Insider risk)
  - Run/coverage summaries use aligned label/value rows for clearer readability
  - Suggested policy section now falls back to draft-safe recommendations generated from uncovered taxonomy threats when scenario-level suggestions are empty
  - Added **Auto-Fix All (Draft)** flow for run-based bulk policy creation with explicit summary (attempted/created/skipped/failed) plus top failure reasons in UI when failures occur
  - Added **Generate Scenarios (Draft)** and **Add Telemetry (Draft)** actions wired to simulator automation backend (no placeholder-only behavior)
  - Safe default is enforced: simulator-created rules are stored as draft/disabled (`Enabled=false`) and require manual review before activation
- New simulator backend endpoints (HIP.Admin host):
  - `GET /api/admin/simulator/{runId}/recommendations`
  - `POST /api/admin/simulator/{runId}/auto-fix-all`
  - `POST /api/admin/simulator/{runId}/generate-scenarios`
  - `POST /api/admin/simulator/{runId}/add-telemetry`
  - `POST /api/admin/simulator/{runId}/auto-harden-system` (alias of auto-fix-all)
  - In-memory idempotency guard keyed by run + idempotency key (durable storage intentionally deferred)
- Threat coverage now shows two plain-language views from `HIP.Simulator.Cli/scenarios/threat-catalog.json`:
  - **Run-scope coverage** (in-scope, out-of-scope, covered/partial/uncovered in-scope)
  - **Full taxonomy coverage** (covered/partial/uncovered across the full catalog)
  - Uncovered threat lists are explicitly labeled `in scope` vs `out of scope` for the current run
  - Draft-safe fallback recommendations prioritize uncovered **in-scope** threats before out-of-scope items
  - Attack graph/timeline section is rendered in summary-first grouped form (by final action) to reduce visual noise
  - Optional read-only pages: Tokens & Sessions, System Health, Admin Settings
- `Services`
  - `ThemeService`: localStorage persistence + CSS variable application
  - `HipAdminApiClient`: typed client + mock fallback
  - `AdminContextService`: role + mock mode
  - `ActionLogService`: admin action hook
  - `ToastService`: app notifications
- `Models`
  - Role model, menu model, theme state/presets, page DTOs
- `Styles`
  - source style sheet (`Styles/admin.css`) mirrored to `wwwroot/css/admin.css`
- `wwwroot/css`
  - `tokens.css`, `tokens-light.css`, `tokens-dark.css` loaded first in `_Host.cshtml`
  - `admin.css` consumes semantic tokens for shell/primitives
- `_Host.cshtml`
  - local CSS/JS assets are versioned with a shared query suffix to keep cache behavior consistent across shell assets

## Theme controls

Theme mode switcher is available in the top-right of the admin topbar with three options:
- System (follows OS/browser `prefers-color-scheme`)
- Light
- Dark

Theme state persists in `localStorage` key: `hip.admin.theme`. Theme presets continue to apply brand color tokens.

Shared data-table surfaces (frame/header/cells/hover states) now consume semantic tokens so they follow light/dark/system mode consistently.
Dark-mode table contrast was tightened for Incident Queue/DataTable surfaces (row/background balance, text/border contrast, hover/selected states, and pagination control visibility) while keeping light mode unchanged.
Widget headers were also shifted to a lighter token-based background in both light and dark themes to reduce heavy visual weight while keeping readable contrast.
Breadcrumb presentation was polished with token-driven styling (clearer link/current-page hierarchy, softer separators, and subtle current-crumb emphasis) while preserving semantic nav/ordered-list accessibility.

## Dashboard (Security Overview)

The `/` page is restored as **Security Overview** using reusable primitives (`PageHeader`, `FilterBar`, `MetricCard`, `DataTable<TItem>`, `StateView`) with explicit loading/empty/error/success states.

Current behavior and labels (live-data-only):
- Page title + header: **Security Overview**
- Top KPI cards are API-backed only:
  - Active Protections (`/api/v1/admin/policy`)
  - Threats Blocked (`/api/admin/security-status`)
  - Replay / Expired (`/api/admin/security-status`)
  - Active Alerts (`/api/v1/admin/audit`, fallback `/api/admin/audit`)
- No synthetic/fabricated dashboard numbers or mock dashboard fallbacks
- Cards without mapped backend endpoints are explicitly marked unavailable
- Device Trust panel now uses `/api/v1/admin/users-devices`
- Protection checks derive directly from replay/expired/blocked counters in `/api/admin/security-status`
- Security Activity table uses live audit events with story-friendly labels and semantic badges
- Time column shows relative timestamps with absolute secondary timestamp for operator context

## Alerts & Incidents (MVP shell)

The `/alerts` page now ships as a split list/detail work-queue workflow built with shared components (`PageHeader`, `FilterBar`, `DataTable<TItem>`, `StatusBadge`, `StateView`, `AlertBanner`, `ModalDialog`). It includes:
- explicit loading/empty/error/success states with retry behavior,
- separate Severity and Status indicators (text + icon + machine-readable attributes),
- role-aware queue action controls (acknowledge/escalate/resolve) with rationale capture,
- safe placeholders for linked records where deep APIs are not yet available.

Legacy security dashboard details are retained below and can be reintroduced inside the reusable shell as business logic is finalized:
- Security Health score card with status color bands
- Clear "Demo Data" badge when mock mode is enabled
- Reputation page follows summary-first layout with deep-dive tabs (Summary, Activity, History, Risk, Network)
- Policy & Rules page includes a visual policy builder and AI-draft assist bones (draft generation + save path)
- Added Authorization Policies page and sandbox (separate from Security Policies)
- Added provider-agnostic OIDC sign-in flow (`/login` → `/auth/login`) with optional enforcement.
- Added pluggable OIDC config under `HipAdmin:Auth` (Authentik first, swappable provider model).
- Added claim normalization (`role`/`roles`/`groups` → `app:role`) and policy-based authorization.
- Removed manual topbar role-switch dropdown; role context now comes from authentication/authorization claims.
- Tokens & Sessions page now supports live token issue/validate/refresh/revoke operations and event feed from admin audit trail
- Policy API now exposes schema/bootstrap assets for locked contracts (legacy + v1 aliases): `/api/admin/policy/schema`, `/api/admin/policy/starter`, `/api/admin/policy/context-sample`, `/api/v1/admin/policy/schema`, `/api/v1/admin/policy/starter`, `/api/v1/admin/policy/context-sample`
- Security event taxonomy + validation contracts exposed for timeline tooling (legacy + v1 aliases): `/api/admin/security/events/types`, `/api/admin/security/events/schema`, `/api/admin/security/events/validate`, `/api/admin/security/risk/evaluate`, `/api/v1/admin/security/events/types`, `/api/v1/admin/security/events/schema`, `/api/v1/admin/security/events/validate`, `/api/v1/admin/security/risk/evaluate`
- Recent Security Events feed (icon-driven)
- Threat Monitor (24h) with compact bar chart
- Reputation Watch with quick jump to Reputation page
- Activity (24h) mini graph panel
- Security Insights + Quick Actions panel

## Policy Management (MVP shell)

The `/policy-rules` page now follows the shared component shell pattern (`PageHeader`, `FilterBar`, `StateView`, `DataTable<TItem>`, `StatusBadge`, `AlertBanner`, `ModalDialog`) and includes:
- explicit loading/empty/error/success + retry states,
- policy list/detail with separate Severity vs Workflow Status indicators,
- role-aware action gating (read-only vs draft/edit/confirm paths),
- a safe draft → edit → preview-impact → confirm modal flow using non-destructive placeholders.

## MVP UI readiness checklist (hardening pass)

Status key: ✅ done, ⚠️ partial, ⏳ pending

| Area | Dashboard | Alerts | Audit Logs | Policy Management | Notes |
| --- | --- | --- | --- | --- | --- |
| Shared shell primitives (`PageHeader`, `FilterBar`, `StateView`, `DataTable`) | ✅ | ✅ | ✅ | ✅ | Consistent reusable shell pattern across MVP pages |
| Severity vs workflow status semantics (separate badges + matching logic) | ✅ | ✅ | ✅ | ✅ | Shared semantic helper now used for parse/match/display behavior |
| Tabs keyboard behavior (arrow/home/end/enter/space) | ✅ | n/a | n/a | n/a | `Tabs` now supports roving tabindex + keyboard navigation |
| Data table keyboard row activation (Enter/Space) | ✅ | ✅ | ✅ | ✅ | Row select now available by keyboard, not mouse-only |
| Modal dialog keyboard/focus behavior | n/a | ✅ | ✅ | ✅ | Dialog now captures opener focus, traps Tab/Shift+Tab focus cycling (top-most dialog wins when nested modals are open), marks non-modal background regions inert + `aria-hidden` while open (body-level first, parent-sibling fallback), supports Escape close, and returns focus on close |
| Build validation (`dotnet build HIP.Admin/HIP.Admin.csproj`) | ✅ | ✅ | ✅ | ✅ | Verified in this pass |

Remaining gaps before release:
- ⏳ Replace placeholder export/action workflows with backend-backed APIs (non-destructive shells are still in place).
- ⏳ Add automated UI accessibility checks (axe/playwright) to CI.
- ⚠️ Add deterministic IDs for non-hashed correlation references once backend emits canonical correlation IDs.

## Accessibility updates (2026-03-08)

This pass focused on high-impact keyboard/form/navigation issues in user-facing pages.

- Added explicit accessible names for icon-only menu buttons (`DropdownMenu` + `AppLayout` usage for messages, notifications, user menu, sidebar toggle).
- Fixed label/input associations on key forms:
  - `Login` (email/password/remember me)
  - `Tokens & Sessions` token operation fields and token text areas
  - `Simulator` suite/scenario/campaign controls
  - `Security Status` auto-refresh switch
- Improved `Reputation Risks` table accessibility:
  - sortable headers now use real `<button>` controls (keyboard accessible by default) with `aria-sort`
  - filter row inputs now have explicit labels (visually hidden) and clearer placeholder text
- Kept copy plain-language where text changed (e.g., filter prompts and field labels).

Validation in this pass:
- `dotnet build HIP.Admin/HIP.Admin.csproj` ✅

## Authentication + authorization (OIDC)

`HipAdmin:Auth` supports local auth + provider-agnostic OIDC integration (Authentik-compatible by default):

- `EnableLocalAuth` (bool): enables local cookie sign-in via `/auth/local-login` (Development default: true, base/prod default: false).
- `LocalAdmin` (`Username`/`Password`/`Roles`): break-glass default account config.
- `EnableOidc` (bool): enables OIDC handler and `/auth/login` challenge flow.
- `EnforceLogin` (bool): applies authenticated fallback policy across the app.
- `Provider` (string): display/provider label only (e.g., `Authentik`, `Keycloak`).
- `Authority`, `ClientId`, `ClientSecret`, `CallbackPath`, `SignedOutCallbackPath`, `Scopes`.
- `RoleClaimSources` (string[]): provider claim names to normalize into `app:role`.

Built-in authorization policies:
- `AdminOnly` → requires `app:role=Admin`
- `SupportOrAdmin` → requires `app:role in {Admin, Support}`

API alignment:
- `HIP.ApiService` now supports matching OIDC JWT validation via `HIP:AdminAuth` (EnableOidcJwt/Authority/Audience/RoleClaimSources).
- Keep role mapping provider-agnostic by emitting/normalizing into `app:role` on both UI and API paths.

Current protected pages:
- `/admin-settings` (`AdminOnly`)
- `/users-devices`, `/simulator` (`SupportOrAdmin`)

Default local admin (dev bootstrap):
- Username: `admin`
- Password: set via local config/env (not committed)
- Production safety guard: startup fails outside Development if local auth is enabled with empty/default password.

Auth observability:
- Login/logout events are logged from `AuthController` (`auth.local.login.*`, `auth.oidc.*`, `auth.logout.*`) for audit trail ingestion.
- `/admin/login` uses a standalone auth layout (no admin topbar/sidebar/navigation chrome).

## Mock mode + API integration
- `HipAdminApiClient` endpoints to wire:
  - `api/v1/admin/dashboard/metrics`
  - `api/v1/admin/audit/latest`
  - `api/v1/admin/security`
  - `api/v1/admin/users-devices`
  - `api/v1/admin/policy`
  - `api/v1/admin/audit`
- Set optional API base URL via config key `HipAdmin:ApiBaseUrl`.
- Friendly fallback behavior:
  - Mock mode ON => uses local sample data
  - Mock mode OFF + API failure => returns friendly error payloads

## Notes for phase 2

- Replace placeholder charts with real components.
- Expand policy catalog as endpoints harden (current built-ins: `AdminOnly`, `SupportOrAdmin`).
- Connect policy sandbox and audit export to backend endpoints.
- Add server-side paging/filtering for large tables.

## Alerts page SOC upgrade (current)

`/alerts` now presents a SOC-oriented layout with:
- Threat overview widgets (alerts/hour, severity counts, active incidents, blocked attempts, user trust)
- Active incident correlation (`INC-*`) and queue-level deduplication (e.g., `reputation.read (3)`)
- Color-coded severity (Critical/High/Medium/Low/Info), risk score column (0-100), and source tagging
- Event icons + humanized titles while preserving raw event names in the detail panel
- Investigation pane sections: actor, risk factors, trigger reasons, related alerts, suggested actions, and vertical timeline
- Quick actions for triage + response (`Block IP`, `Lock Account`, `Require MFA`, etc.)
- Live mode toggle for periodic queue refresh and keyboard shortcuts (`J/K`, `Enter`, `A`, `R`, `E`)

Notes:
- Some action flows are UI-first placeholders until backend enforcement APIs are fully wired.
- Existing status workflows remain compatible; additional SOC states (`Investigating`, `Mitigated`, `False Positive`) are supported in UI semantics.

### Security Overview language pass

Batch-1 dashboard updates for non-technical readability:
- Relative time format standardized to plain language (`2 minutes ago`, `3 hours ago`)
- KPI cards aligned to product terms: `Active Policies`, `Threats Blocked`, `Active Alerts`, `Reputation Signals`
- KPI cards now include inline tooltip help (`ⓘ`) with plain-English meanings
- Event names in the activity table are humanized for common technical events

### Batch-2: Audit Logs + Incident detail readability

- Audit table updated to plain-language event wording with iconized event labels.
- Relative time in audit rows now uses natural language (`minutes ago`, `hours ago`).
- Incident detail panel expanded with user/target/correlation/system action/policy fields.
- Added "Why this happened" explanation bullets and vertical timeline narrative per selected event.
- Correlation IDs now use incident-style `INC-####` formatting for faster analyst scanning.

### Simulator live validation UI

Simulator page now includes a **Live Validation Drift Report** section when scenarios include live comparisons.
It summarizes:
- matched vs mismatched live scenarios
- expected vs actual action
- expected vs actual HTTP status
- expected vs actual audit event
- expected vs actual reputation impact
- mismatch reasons per scenario

### Wave A dashboard shell upgrades

Security Overview now includes:
- Global security status banner (Secure / Warning / Critical) with live counters
- Threat/coverage snapshot details (active protections, threats blocked, critical threats, last event)
- Incident Alerts panel for urgent denied/suspicious events
- Real-Time Event Feed with plain-language event labels and relative timestamps

### Wave B investigation + trust clarity

Implemented:
- Audit Logs incident detail now includes a Trust Decision Explainer block
  - trust signals
  - risk signals
  - decision math (base + trust - risk)
- Audit Logs timeline renamed to Security Story Timeline with investigation-oriented steps
- Reputation page now includes:
  - Trust Decision Explainer panel
  - Trust Score Bands (Trusted/Watch/Risk/Dangerous)
  - Security Story Timeline framing

### Wave C visual security intelligence

Security Overview now includes:
- Attack Visualization panel (country attempt distribution)
- Risk Heatmap panel (Messaging/Login/API/Device risk levels)
- User Trust Radar panel (login/device/messaging/history factor bars)
- Security Trends naming alignment for trend chart block

### Wave D control surfaces

Implemented:
- Users & Devices page upgraded with a Device Trust Panel and richer selected-device details.
- Policy Management page now includes a Policy Status Panel (active/critical/triggered/last-triggered).
- Policy detail now renders a readable IF/THEN visual builder view of each rule.

### Wave E advanced scaffolding

Implemented:
- Simulator page now has a What-If Attack Simulator panel with instant hypothetical response output.
- Admin Settings now includes scaffolding toggles for:
  - External Account Monitoring framework (consent-first)
  - Behavior Fingerprinting pipeline
- Reputation page now includes a Behavior Fingerprinting Signals scaffold panel.

### UI consistency cleanup pass

- Standardized panel naming for dashboard sections:
  - `Device Trust Panel`
  - `Simulator Quick Actions`
- Removed legacy icon-style heading from Reputation to align with text-first SOC styling.
- Renamed Reputation details section to `Investigation Details` for consistency with incident/audit language.

### Simulator framework coverage card

Simulator run results now render a **Framework Coverage** card when `Result.Coverage.FrameworkCoverage` is present.
The card displays control-level rollups for MITRE, OWASP, and NIST with totals and covered/uncovered/invalid counts.

### Device registration phase 1

Users & Devices now supports phase-1 registration flow:
- New registration form (user/email/device) on `/users-devices`
- Calls `api/v1/admin/users-devices/register`
- Refreshes grid after successful registration
- New registrations enter `Pending` trust state by default

### Device registration phase 2

Added trust-state action flow for registered devices:
- New API endpoint: `POST /api/v1/admin/users-devices/action`
  - Actions: `approve` -> Trusted, `challenge` -> Pending, `block` -> Blocked
- Users & Devices detail panel now includes action buttons (Approve / Challenge / Block)
- UI calls action endpoint and refreshes the grid with feedback banner
- Device status transitions are audit-logged (`device.registration.status_updated`)

### Device registration phase 3

Added required analyst rationale for device trust-state actions:
- Device action endpoint now accepts required `note`
- Approve/Challenge/Block actions are rejected without note
- Users & Devices detail panel includes "Analyst note" textarea
- Status-change audit entries now include the analyst note in `Detail`

### Device registration phase 4

Added per-device action history timeline:
- New API endpoint: `GET /api/v1/admin/users-devices/history?email=...&device=...`
- Store now tracks action history entries (register/approve/challenge/block + note + timestamp)
- Users & Devices detail panel now shows Action Timeline for selected device
- Timeline updates after status actions and registration events

### Device registration phase 5

Added actor attribution and timeline filtering:
- Device registration/action payloads now include `actor` (derived from current admin role in UI)
- Device action history entries now store actor name/role
- Action Timeline shows "by <actor>" for each event
- Added timeline filter box (action/actor/status/note text search)
