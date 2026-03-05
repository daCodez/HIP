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
  - `AppLayout`: fixed logo header + sidebar + breadcrumb + style drawer
  - `SidebarMenuItem`: recursive menu rendering up to 3 levels with active route highlighting
- `Components/Common`
  - `StatCard`, `BadgeStatus`, `ConfirmModal`, `DataTable`, `DropdownMenu`, `ToastHost`
- `Pages`
  - Dashboard, Security Status, Users & Devices, Reputation, Security Policies, Authorization Policies, Audit Logs
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

## Theme controls

Theme controls remain available in the style drawer component.

Theme state persists in `localStorage` key: `hip.admin.theme`.

## Dashboard (Security-first)

The dashboard is optimized for a 5-second health read:
- Security Health score card with status color bands
- Clear "Demo Data" badge when mock mode is enabled
- Reputation page follows summary-first layout with deep-dive tabs (Summary, Activity, History, Risk, Network)
- Policy & Rules page includes a visual policy builder and AI-draft assist bones (draft generation + save path)
- Added Authorization Policies page and sandbox (separate from Security Policies)
- Added login page scaffold (`/login`) without enforcement yet
- Added pluggable OIDC config scaffold under `HipAdmin:Auth` (provider-agnostic, enforcement optional)
- Tokens & Sessions page now supports live token issue/validate/refresh/revoke operations and event feed from admin audit trail
- Recent Security Events feed (icon-driven)
- Threat Monitor (24h) with compact bar chart
- Reputation Watch with quick jump to Reputation page
- Activity (24h) mini graph panel
- Security Insights + Quick Actions panel

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
