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
  - `AppLayout`: fixed sidebar + topbar + breadcrumb + style drawer
  - `SidebarMenuItem`: recursive menu rendering up to 3 levels with active route highlighting
- `Components/Common`
  - `StatCard`, `BadgeStatus`, `ConfirmModal`, `DataTable`, `DropdownMenu`, `ToastHost`
- `Pages`
  - Dashboard, Security Status, Users & Devices, Reputation, Policy & Rules, Audit Logs
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

Open **Styles** button in topbar:
- 6 skin presets: Ocean, Violet, Emerald, Sunset, Graphite, Royal
- Full Dark toggle
- Full Bright toggle
- Reset Style button

Theme state persists in `localStorage` key: `hip.admin.theme`.

## Mock mode + API integration

- Mock mode toggle is in topbar and defaults ON.
- `HipAdminApiClient` endpoints to wire:
  - `api/admin/dashboard/metrics`
  - `api/admin/audit/latest`
  - `api/admin/security`
  - `api/admin/users-devices`
  - `api/admin/policy`
  - `api/admin/audit`
- Set optional API base URL via config key `HipAdmin:ApiBaseUrl`.
- Friendly fallback behavior:
  - Mock mode ON => uses local sample data
  - Mock mode OFF + API failure => returns friendly error payloads

## Notes for phase 2

- Replace placeholder charts with real components.
- Add real auth integration and role claims mapping.
- Connect policy sandbox and audit export to backend endpoints.
- Add server-side paging/filtering for large tables.
