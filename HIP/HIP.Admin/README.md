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
- Simulator page (`/simulator`) with quick run mode and campaign mode (profile + duration + wave interval)
- Threat-coverage-first reporting via `HIP.Simulator.Cli/scenarios/threat-catalog.json` (covered/partial/uncovered + critical uncovered)
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

## Dashboard (MVP shell)

The `/` Dashboard page now uses reusable primitives (`PageHeader`, `FilterBar`, `MetricCard`, `Tabs`, `DataTable<TItem>`, `StateView`) and explicit loading/empty/error/success states.

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
- Added login page scaffold (`/login`) without enforcement yet
- Added pluggable OIDC config scaffold under `HipAdmin:Auth` (provider-agnostic, enforcement optional)
- Removed manual topbar role-switch dropdown; role context is intended to come from authentication/authorization flow
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
- Add real auth integration and role claims mapping.
- Connect policy sandbox and audit export to backend endpoints.
- Add server-side paging/filtering for large tables.
