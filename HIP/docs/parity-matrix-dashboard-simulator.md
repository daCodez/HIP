# HIP.Admin Dashboard + Simulator Parity Matrix

Status legend: **COMPLETE** / **MISSING**

## Dashboard parity

| Expected feature | Status | Evidence (code truth) |
|---|---|---|
| Security Overview heading and plain-language KPI/status cards | **COMPLETE** | `HIP.Admin/Pages/Index.razor` (`<PageTitle>Security Overview</PageTitle>`, `<PageHeader Title="Security Overview" ...>`, `_topKpis` in `HydrateKpis`, `BuildStatusBanner`) |
| Section cards (activity trend / device / reputation / risk / protection / simulator) | **COMPLETE** | `HIP.Admin/Pages/Index.razor` sections inside `<section class="dashboard-security-grid">` with headings: `Security Activity trend`, `Device Trust`, `Reputation Overview`, `Overall Risk Level`, `Protection Checks`, `Simulator quick access` |
| Story-friendly Security Activity table | **COMPLETE** | `HIP.Admin/Pages/Index.razor` `DataTable` title/caption and `_incidentColumns` (`When`, `Who`, `What happened`, `Severity`, `Outcome`, `Story note`) |
| Relative time + absolute secondary timestamps | **COMPLETE** | `HIP.Admin/Pages/Index.razor` `_incidentColumns` `When` cell template using `FormatRelativeTime(...)` + `FormatAbsoluteTime(...)` |
| Readable typography/spacing and dark-mode contrast | **COMPLETE** | `HIP.Admin/wwwroot/css/admin.css` tokenized table/card styles (`.table-widget-frame`, `.widget-table .table ...`, `.hip-overview-metrics`) and dark-mode overrides (`body.hip-dark .widget-table .table ...`) |

## Simulator parity

| Expected feature | Status | Evidence (code truth) |
|---|---|---|
| Profile labels/subtitles | **COMPLETE** | `HIP.Admin/Pages/Simulator.razor` campaign profile select labels + `GetCampaignProfileSubtitle(...)` helper text |
| Run scope heading | **COMPLETE** | `HIP.Admin/Pages/Simulator.razor` card heading `Run Scope & Taxonomy Coverage` |
| Progress bar with percent | **COMPLETE** | `HIP.Admin/Pages/Simulator.razor` progress section with `.progress-bar`, `ProgressPercent`, `ProgressPercentDisplay` |
| Run summary alignment | **COMPLETE** | `HIP.Admin/Pages/Simulator.razor` `Run Summary` using consistent `d-flex justify-content-between` rows |
| Run-scope vs full-taxonomy coverage split | **COMPLETE** | `HIP.Admin/Pages/Simulator.razor` sections `Run-scope coverage` and `Full taxonomy coverage`; coverage model fields in `HIP.Simulator.Core/Models/SimulatorModels.cs` (`ThreatCoverageSummary`) |
| In-scope / out-of-scope labels | **COMPLETE** | `HIP.Admin/Pages/Simulator.razor` uncovered list badge text `in scope` / `out of scope` based on `ThreatCoverageListItem.IsInScope`; model in `HIP.Simulator.Core/Models/SimulatorModels.cs` |
| Uncovered-threat recommendation bridge + Add Policy fallback | **COMPLETE** | `HIP.Admin/Pages/Simulator.razor` `GetDisplayedSuggestions()` fallback to threat-derived suggestions when scenario suggestions are empty; `AddSuggestionAsync(...)` provides `Add Policy` behavior |
| Auto-Fix All (Draft) with failure reasons | **COMPLETE** | `HIP.Admin/Pages/Simulator.razor` `AutoFixAllAsync()`, `HandleApplySummary(...)`, failure list rendering; `HIP.Admin/Services/SimulatorAutoHardeningService.cs` draft-safe apply + failure details |
| Generate Scenarios / Add Telemetry backend wiring | **COMPLETE** | UI buttons in `HIP.Admin/Pages/Simulator.razor`; service calls in `HIP.Admin/Services/SimulatorAutoHardeningService.cs`; API endpoints in `HIP.Admin/Controllers/SimulatorAutomationController.cs` |
| Attack graph/timeline summary-first non-noisy presentation | **COMPLETE** | `HIP.Admin/Pages/Simulator.razor` card `Attack Graph / Timeline (summary-first)` grouped by `FinalAction` |

## Backend endpoint & safety parity

| Expected feature | Status | Evidence (code truth) |
|---|---|---|
| Backend controller/service endpoints used by simulator buttons exist and compile | **COMPLETE** | `HIP.Admin/Controllers/SimulatorAutomationController.cs` routes for recommendations/auto-fix/generate-scenarios/add-telemetry/auto-harden-system; services registered in `HIP.Admin/Startup.cs` |
| Draft-safe policy behavior (no unsafe auto-activation) | **COMPLETE** | `HIP.Admin/Services/SimulatorAutoHardeningService.cs` `BuildDraftSafeRule(...)` sets `Enabled = false`; `HIP.Admin/Pages/Simulator.razor` `AddSuggestionAsync(...)` sets `Enabled = false` |
| Docs sync for HIP.Admin behavior | **COMPLETE** | `HIP.Admin/README.md` updated with dashboard/simulator behavior and simulator automation endpoints |

## Validation commands

- `dotnet build HIP.Admin/HIP.Admin.csproj` ✅
- `dotnet build HIP.sln` ✅
- `dotnet test HIP.Simulator.Tests/HIP.Simulator.Tests.csproj --no-build` ✅
