using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using HIP.ServiceDefaults;
using HIP.Shared.Contracts;
using HIP.Simulator.Core.Extensions;
using HIP.Simulator.Core.Interfaces;
using HIP.Simulator.Core.Models;
using HIP.Web.Components;
using HIP.Web.Hubs;
using HIP.Web.Services;
using HIP.Web.Services.Simulator;
using Microsoft.AspNetCore.SignalR;
using System.Collections.Concurrent;

var builder = WebApplication.CreateBuilder(args);
builder.AddServiceDefaults();

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();
builder.Services.AddSignalR();

builder.Services.AddServiceDiscovery();

builder.Services.AddHttpClient("hip-api", client =>
{
    client.BaseAddress = new Uri("http://127.0.0.1:44985");
});

builder.Services.AddHttpClient("hip-bff", client =>
{
    // BFF routes are served by HIP.Web itself, not HIP.ApiService.
    client.BaseAddress = new Uri("http://127.0.0.1:45727");
});

builder.Services.AddSingleton<HipEnvelopeSigner>();
builder.Services.AddScoped<HipApiClient>();
builder.Services.AddScoped<SimulatorBffClient>();
builder.Services.AddSingleton<SimulatorRunStateStore>();
builder.Services.AddHipSimulatorCore();

var app = builder.Build();

var frameworkProxyClient = new HttpClient(new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
});

async Task<IResult> ProxyAspireFrameworkAsset(string? assetPath, HttpContext httpContext, CancellationToken cancellationToken)
{
    var normalized = (assetPath ?? string.Empty).TrimStart('/');
    if (!normalized.StartsWith("blazor.web", StringComparison.OrdinalIgnoreCase))
    {
        return Results.NotFound();
    }

    var upstream = new Uri($"https://127.0.0.1:17193/framework/{normalized}{httpContext.Request.QueryString}");
    using var upstreamRequest = new HttpRequestMessage(new HttpMethod(httpContext.Request.Method), upstream);
    using var upstreamResponse = await frameworkProxyClient.SendAsync(
        upstreamRequest,
        HttpCompletionOption.ResponseHeadersRead,
        cancellationToken);

    var response = httpContext.Response;
    response.StatusCode = (int)upstreamResponse.StatusCode;

    foreach (var header in upstreamResponse.Headers)
    {
        response.Headers[header.Key] = header.Value.ToArray();
    }

    foreach (var header in upstreamResponse.Content.Headers)
    {
        response.Headers[header.Key] = header.Value.ToArray();
    }

    response.Headers.Remove("transfer-encoding");

    if (HttpMethods.IsHead(httpContext.Request.Method))
    {
        return Results.Empty;
    }

    await upstreamResponse.Content.CopyToAsync(response.Body, cancellationToken);
    return Results.Empty;
}

app.MapMethods("/_framework/{**assetPath}", new[] { "GET", "HEAD" }, ProxyAspireFrameworkAsset);
app.MapMethods("/framework/{**assetPath}", new[] { "GET", "HEAD" }, ProxyAspireFrameworkAsset);

app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();
app.MapHub<SimulatorRunHub>("/hubs/simulator-runs");

app.MapGet("/bff/status", async (HipApiClient api, CancellationToken cancellationToken) =>
{
    var (status, body) = await api.GetAsync("/api/status", cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapGet("/bff/security-status", async (HipApiClient api, CancellationToken cancellationToken) =>
{
    var (status, body) = await api.GetAsync("/api/admin/security-status", cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapGet("/bff/security-events", async (int? take, HipApiClient api, CancellationToken cancellationToken) =>
{
    var count = Math.Clamp(take ?? 10, 1, 100);
    var (status, body) = await api.GetAsync($"/api/admin/security-events?take={count}", cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapGet("/bff/identity/{id}", async (string id, HipApiClient api, CancellationToken cancellationToken) =>
{
    var (status, body) = await api.GetAsync($"/api/identity/{Uri.EscapeDataString(id)}", cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapGet("/bff/reputation/{id}", async (string id, HipApiClient api, CancellationToken cancellationToken) =>
{
    var (status, body) = await api.GetAsync($"/api/reputation/{Uri.EscapeDataString(id)}", cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapGet("/bff/audit", async (int? take, HipApiClient api, CancellationToken cancellationToken) =>
{
    var count = Math.Clamp(take ?? 50, 1, 200);
    var (status, body) = await api.GetAsync($"/api/admin/audit?take={count}", cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapGet("/bff/plugins/nav", async (HipApiClient api, CancellationToken cancellationToken) =>
{
    var (status, body) = await api.GetAsync("/api/plugins/nav", cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapGet("/bff/plugins/widgets", async (HipApiClient api, CancellationToken cancellationToken) =>
{
    var (status, body) = await api.GetAsync("/api/plugins/widgets", cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapGet("/bff/policy/current", async (HipApiClient api, CancellationToken cancellationToken) =>
{
    var (status, body) = await api.GetAsync("/api/plugins/policy/current", cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapGet("/bff/policy/strict", async (HipApiClient api, CancellationToken cancellationToken) =>
{
    var (status, body) = await api.GetAsync("/api/plugins/policy/strict", cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapGet("/bff/feedback/stats", async (HipApiClient api, CancellationToken cancellationToken) =>
{
    var (status, body) = await api.GetAsync("/api/plugins/reputation/feedback/stats", cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapGet("/bff/identity/oidc/info", async (HipApiClient api, CancellationToken cancellationToken) =>
{
    var (status, body) = await api.GetAsync("/api/plugins/identity/oidc/info", cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapPost("/bff/identity/oidc/resolve", async (OidcIdentityRequest request, HipApiClient api, CancellationToken cancellationToken) =>
{
    var payload = System.Text.Json.JsonSerializer.Serialize(request);
    var (status, body) = await api.PostAsync("/api/plugins/identity/oidc/resolve", payload, cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapPost("/bff/identity/oidc/sync", async (OidcIdentityRequest request, HipApiClient api, CancellationToken cancellationToken) =>
{
    var payload = System.Text.Json.JsonSerializer.Serialize(request);
    var (status, body) = await api.PostAsync("/api/plugins/identity/oidc/sync", payload, cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapPost("/bff/feedback", async (ReputationFeedbackRequest request, HipApiClient api, CancellationToken cancellationToken) =>
{
    var payload = System.Text.Json.JsonSerializer.Serialize(request);
    var (status, body) = await api.PostAsync("/api/plugins/reputation/feedback", payload, cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapGet("/bff/system-metrics", async (int? take, HipApiClient api, CancellationToken cancellationToken) =>
{
    var count = Math.Clamp(take ?? 60, 5, 120);
    var (status, body) = await api.GetAsync($"/api/plugins/system-metrics?take={count}", cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapGet("/bff/identity/insights/top-risk", async (int? take, HipApiClient api, CancellationToken cancellationToken) =>
{
    var count = Math.Clamp(take ?? 10, 1, 50);
    var (status, body) = await api.GetAsync($"/api/plugins/identity/insights/top-risk?take={count}", cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapGet("/bff/identity/insights/{identityId}", async (string identityId, HipApiClient api, CancellationToken cancellationToken) =>
{
    var (status, body) = await api.GetAsync($"/api/plugins/identity/insights/{Uri.EscapeDataString(identityId)}", cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapGet("/bff/chat/providers", async (HipApiClient api, CancellationToken cancellationToken) =>
{
    var (status, body) = await api.GetAsync("/api/plugins/chat/providers", cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapGet("/bff/chat/oauth/status", async (HipApiClient api, CancellationToken cancellationToken) =>
{
    var (status, body) = await api.GetAsync("/api/plugins/chat/oauth/status", cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapGet("/bff/chat/oauth/start", async (HipApiClient api, CancellationToken cancellationToken) =>
{
    var (status, body) = await api.GetAsync("/api/plugins/chat/oauth/start", cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapPost("/bff/chat/query", async (ChatQueryRequest request, HipApiClient api, CancellationToken cancellationToken) =>
{
    var payload = System.Text.Json.JsonSerializer.Serialize(request);
    var (status, body) = await api.PostAsync("/api/plugins/chat/query", payload, cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapGet("/bff/admin/shell-config", (HttpContext httpContext) =>
{
    var correlationId = ResolveCorrelationId(httpContext);
    var userRoles = ResolveUserRoles(httpContext.User);

    var enabledModules = new List<string>
    {
        "overview",
        "alerts",
        "audit-logs",
        "policy-management"
    };

    if (IsSimulatorAdmin(httpContext))
    {
        enabledModules.Add("simulator");
    }

    var response = new AdminShellConfigResponse(
        EnabledModules: enabledModules,
        UserRoles: userRoles,
        Metadata: new AdminShellConfigMetadata(
            CorrelationId: correlationId,
            ServerTimestampUtc: DateTimeOffset.UtcNow,
            ConfigVersion: "phase0-v1"));

    app.Logger.LogDebug(
        "Resolved admin shell config with {ModuleCount} modules and {RoleCount} roles (CorrelationId: {CorrelationId})",
        response.EnabledModules.Count,
        response.UserRoles.Count,
        response.Metadata.CorrelationId);

    return Results.Ok(response);
});

app.MapGet("/bff/admin/settings", () =>
{
    var path = ResolveApiSettingsPath();
    if (!File.Exists(path))
    {
        return Results.NotFound(new { code = "settings.notFound", path });
    }

    var node = JsonNode.Parse(File.ReadAllText(path))?.AsObject() ?? new JsonObject();
    var hip = node["HIP"]?.AsObject() ?? new JsonObject();
    var plugins = hip["Plugins"]?.AsObject() ?? new JsonObject();
    var enabled = plugins["Enabled"]?.AsArray()?.Select(x => x?.GetValue<string>() ?? string.Empty).Where(x => !string.IsNullOrWhiteSpace(x)).ToArray() ?? Array.Empty<string>();
    var chat = hip["Chat"]?.AsObject() ?? new JsonObject();

    var audit = hip["Audit"]?.AsObject() ?? new JsonObject();

    return Results.Ok(new
    {
        exposeInternalApis = hip["ExposeInternalApis"]?.GetValue<bool>() ?? true,
        chatMode = chat["Mode"]?.GetValue<string>() ?? "mock",
        enabledPlugins = enabled,
        auditRetentionDays = audit["RetentionDays"]?.GetValue<int>() ?? 30,
        auditExportMaxRows = audit["ExportMaxRows"]?.GetValue<int>() ?? 2000
    });
});

app.MapGet("/bff/admin/settings/audit", async (HipApiClient api, CancellationToken cancellationToken) =>
{
    var (status, body) = await api.GetAsync("/api/admin/audit?take=25&eventType=policy.config.change", cancellationToken);
    return Results.Content(body, "application/json", Encoding.UTF8, status);
});

app.MapPost("/bff/admin/settings", async (AdminSettingsRequest request, HipApiClient api, CancellationToken cancellationToken) =>
{
    var path = ResolveApiSettingsPath();
    if (!File.Exists(path))
    {
        return Results.NotFound(new { code = "settings.notFound", path });
    }

    var root = JsonNode.Parse(File.ReadAllText(path))?.AsObject() ?? new JsonObject();
    var hip = root["HIP"] as JsonObject ?? new JsonObject();
    root["HIP"] = hip;

    hip["ExposeInternalApis"] = request.ExposeInternalApis;

    var plugins = hip["Plugins"] as JsonObject ?? new JsonObject();
    hip["Plugins"] = plugins;
    var enabled = new JsonArray();
    foreach (var p in request.EnabledPlugins.Distinct(StringComparer.OrdinalIgnoreCase))
    {
        enabled.Add(p);
    }
    plugins["Enabled"] = enabled;

    var chat = hip["Chat"] as JsonObject ?? new JsonObject();
    hip["Chat"] = chat;
    chat["Mode"] = string.IsNullOrWhiteSpace(request.ChatMode) ? "mock" : request.ChatMode;

    var audit = hip["Audit"] as JsonObject ?? new JsonObject();
    hip["Audit"] = audit;
    audit["RetentionDays"] = Math.Clamp(request.AuditRetentionDays, 1, 3650);
    audit["ExportMaxRows"] = Math.Clamp(request.AuditExportMaxRows, 100, 10000);

    File.WriteAllText(path, root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));

    var detail = $"chatMode={request.ChatMode};exposeInternal={request.ExposeInternalApis};plugins={string.Join('|', request.EnabledPlugins)};retention={request.AuditRetentionDays};exportMax={request.AuditExportMaxRows}";
    var payload = JsonSerializer.Serialize(new { actor = "settings-ui", detail });
    await api.PostAsync("/api/admin/policy/audit-change", payload, cancellationToken);

    return Results.Ok(new { saved = true, restartRequired = true, path });
});

app.MapGet("/bff/extensions/hip-mail-bridge", () =>
{
    var path = "/home/jarvis_bot/.openclaw/workspace/HIP/extensions/hip-mail-bridge.tar.gz";
    if (!File.Exists(path))
    {
        return Results.NotFound(new { code = "extension_not_found" });
    }

    return Results.File(path, "application/gzip", "hip-mail-bridge.tar.gz");
});

var simulatorRuns = new ConcurrentDictionary<string, SimulationRunResult>();
var simulatorStatuses = new ConcurrentDictionary<string, string>();
var simulatorRunHistory = new ConcurrentDictionary<string, SimulatorRunHistoryItem>();
var simulatorRunCancellation = new ConcurrentDictionary<string, CancellationTokenSource>();

var simulatorStateStore = app.Services.GetRequiredService<SimulatorRunStateStore>();
foreach (var item in simulatorStateStore.Load())
{
    simulatorRunHistory[item.RunId] = item;
    simulatorStatuses[item.RunId] = item.Status;
}

app.MapGet("/bff/simulator/suites", async (IScenarioLoader loader, HttpContext httpContext, CancellationToken cancellationToken) =>
{
    if (!IsSimulatorAdmin(httpContext)) return Results.StatusCode(StatusCodes.Status403Forbidden);
    var suites = await loader.ListSuitesAsync(GetSimulatorScenarioRoot(), cancellationToken);
    return Results.Ok(suites);
});

app.MapGet("/bff/simulator/scenarios", async (string? suite, IScenarioLoader loader, HttpContext httpContext, CancellationToken cancellationToken) =>
{
    if (!IsSimulatorAdmin(httpContext)) return Results.StatusCode(StatusCodes.Status403Forbidden);
    var scenarios = await loader.ListScenariosAsync(GetSimulatorScenarioRoot(), cancellationToken);
    if (!string.IsNullOrWhiteSpace(suite))
    {
        scenarios = scenarios.Where(x => x.Suite.Equals(suite, StringComparison.OrdinalIgnoreCase)).ToArray();
    }
    return Results.Ok(scenarios);
});

app.MapPost("/bff/simulator/run", async (SimulatorRunRequest request, ISimulationRunner runner, IScenarioLoader loader, HipApiClient api, IHubContext<SimulatorRunHub> hub, HttpContext httpContext) =>
{
    if (!IsSimulatorAdmin(httpContext)) return Results.StatusCode(StatusCodes.Status403Forbidden);

    var knownSuites = await loader.ListSuitesAsync(GetSimulatorScenarioRoot());
    if (!string.IsNullOrWhiteSpace(request.Suite) && !knownSuites.Contains(request.Suite, StringComparer.OrdinalIgnoreCase))
    {
        return Results.BadRequest(new { code = "simulator.invalid_suite" });
    }

    var knownScenarios = await loader.ListScenariosAsync(GetSimulatorScenarioRoot());
    if (!string.IsNullOrWhiteSpace(request.ScenarioId) && !knownScenarios.Any(x => x.Id.Equals(request.ScenarioId, StringComparison.OrdinalIgnoreCase)))
    {
        return Results.BadRequest(new { code = "simulator.invalid_scenario" });
    }

    var safeSuite = request.Suite is null ? null : request.Suite.Trim();
    var safeScenario = request.ScenarioId is null ? null : request.ScenarioId.Trim();

    SimulationExecutionMode? modeOverride = request.Mode?.Trim().ToLowerInvariant() switch
    {
        "application" => SimulationExecutionMode.Application,
        "protocol" => SimulationExecutionMode.Protocol,
        "hybrid" => SimulationExecutionMode.Hybrid,
        null or "" => null,
        _ => null
    };

    var runId = Guid.NewGuid().ToString("N");
    simulatorStatuses[runId] = "running";
    simulatorRunHistory[runId] = new SimulatorRunHistoryItem(runId, "running", DateTimeOffset.UtcNow, null, safeSuite, safeScenario, modeOverride?.ToString() ?? "scenario-default", null, null, null, null, null, null, null, null);
    simulatorStateStore.Upsert(simulatorRunHistory[runId]);

    var progress = new Progress<SimulationProgressUpdate>(update =>
    {
        _ = hub.Clients.All.SendAsync("runProgress", new
        {
            runId,
            stage = update.Stage,
            processedScenarios = update.ProcessedScenarios,
            totalScenarios = update.TotalScenarios,
            scenarioId = update.ScenarioId,
            message = update.Message
        });
    });


    var options = new SimulationRunOptions
    {
        InputFolder = GetSimulatorScenarioRoot(),
        ReportFolder = Path.Combine(GetSimulatorReportRoot(), runId),
        Suite = string.IsNullOrWhiteSpace(safeSuite) ? null : safeSuite,
        ScenarioId = string.IsNullOrWhiteSpace(safeScenario) ? null : safeScenario,
        RandomSeed = request.Seed,
        ExecutionModeOverride = modeOverride,
        Progress = progress
    };

    var runCts = new CancellationTokenSource();
    simulatorRunCancellation[runId] = runCts;

    await hub.Clients.All.SendAsync("runStatusChanged", new { runId, status = "running" });
    await api.PostAsync("/api/admin/policy/audit-change", JsonSerializer.Serialize(new { actor = "simulator-ui", detail = $"simulator_run_started:{runId}:{safeSuite ?? "all"}:{safeScenario ?? "all"}" }), CancellationToken.None);

    _ = Task.Run(async () =>
    {
        try
        {
            var result = await runner.RunAsync(options, runCts.Token);
            simulatorRuns[runId] = result;
            simulatorStatuses[runId] = "completed";
            simulatorRunHistory[runId] = simulatorRunHistory[runId] with
            {
                Status = "completed",
                CompletedUtc = DateTimeOffset.UtcNow,
                Total = result.TotalScenarios,
                Passed = result.Passed,
                Failed = result.Failed,
                EventTypes = result.Coverage.EventCoverage.Count,
                Rules = result.Coverage.RuleCoverage.Count,
                Fields = result.Coverage.FieldCoverage.Count,
                Uncovered = result.Uncovered,
                Invalid = result.Invalid
            };
            simulatorStateStore.Upsert(simulatorRunHistory[runId]);
            await hub.Clients.All.SendAsync("runStatusChanged", new { runId, status = "completed" });
            await api.PostAsync("/api/admin/policy/audit-change", JsonSerializer.Serialize(new { actor = "simulator-ui", detail = $"simulator_run_completed:{runId}:passed={result.Passed}:failed={result.Failed}" }), CancellationToken.None);
        }
        catch (OperationCanceledException)
        {
            simulatorStatuses[runId] = "cancelled";
            simulatorRunHistory[runId] = simulatorRunHistory[runId] with { Status = "cancelled", CompletedUtc = DateTimeOffset.UtcNow };
            simulatorStateStore.Upsert(simulatorRunHistory[runId]);
            await hub.Clients.All.SendAsync("runStatusChanged", new { runId, status = "cancelled" });
            await api.PostAsync("/api/admin/policy/audit-change", JsonSerializer.Serialize(new { actor = "simulator-ui", detail = $"simulator_run_cancelled:{runId}" }), CancellationToken.None);
        }
        catch
        {
            simulatorStatuses[runId] = "failed";
            simulatorRunHistory[runId] = simulatorRunHistory[runId] with { Status = "failed", CompletedUtc = DateTimeOffset.UtcNow };
            simulatorStateStore.Upsert(simulatorRunHistory[runId]);
            await hub.Clients.All.SendAsync("runStatusChanged", new { runId, status = "failed" });
            await api.PostAsync("/api/admin/policy/audit-change", JsonSerializer.Serialize(new { actor = "simulator-ui", detail = $"simulator_run_failed:{runId}" }), CancellationToken.None);
        }
        finally
        {
            simulatorRunCancellation.TryRemove(runId, out _);
        }
    }, CancellationToken.None);

    return Results.Accepted($"/bff/simulator/runs/{runId}", new { runId, status = "running" });
});

app.MapGet("/bff/simulator/runs", (HttpContext httpContext) =>
{
    if (!IsSimulatorAdmin(httpContext)) return Results.StatusCode(StatusCodes.Status403Forbidden);
    return Results.Ok(simulatorRunHistory.Values.OrderByDescending(x => x.StartedUtc).Take(100));
});

app.MapGet("/bff/simulator/runs/{runId}", (string runId, HttpContext httpContext) =>
{
    if (!IsSimulatorAdmin(httpContext)) return Results.StatusCode(StatusCodes.Status403Forbidden);

    var status = simulatorStatuses.TryGetValue(runId, out var s) ? s : "not_found";
    if (status == "not_found") return Results.NotFound();
    if (status != "completed") return Results.Ok(new { runId, status, history = simulatorRunHistory.GetValueOrDefault(runId) });
    return Results.Ok(new { runId, status, history = simulatorRunHistory.GetValueOrDefault(runId), result = simulatorRuns[runId] });
});

app.MapPost("/bff/simulator/runs/{runId}/cancel", async (string runId, HipApiClient api, IHubContext<SimulatorRunHub> hub, HttpContext httpContext) =>
{
    if (!IsSimulatorAdmin(httpContext)) return Results.StatusCode(StatusCodes.Status403Forbidden);
    if (!simulatorRunCancellation.TryGetValue(runId, out var cts)) return Results.NotFound();
    cts.Cancel();
    simulatorStatuses[runId] = "cancelling";
    if (simulatorRunHistory.TryGetValue(runId, out var history))
    {
        simulatorRunHistory[runId] = history with { Status = "cancelling" };
        simulatorStateStore.Upsert(simulatorRunHistory[runId]);
    }

    await hub.Clients.All.SendAsync("runStatusChanged", new { runId, status = "cancelling" });
    await api.PostAsync("/api/admin/policy/audit-change", JsonSerializer.Serialize(new { actor = "simulator-ui", detail = $"simulator_run_cancelling:{runId}" }), CancellationToken.None);
    return Results.Accepted($"/bff/simulator/runs/{runId}", new { runId, status = "cancelling" });
});

app.MapGet("/bff/simulator/runs/{runId}/report/json", (string runId, HttpContext httpContext) =>
{
    if (!IsSimulatorAdmin(httpContext)) return Results.StatusCode(StatusCodes.Status403Forbidden);
    if (simulatorRuns.TryGetValue(runId, out var result)) return Results.Json(result);

    var reportDir = Path.Combine(GetSimulatorReportRoot(), runId);
    if (!Directory.Exists(reportDir)) return Results.NotFound();
    var file = Directory.GetFiles(reportDir, "simulation-report-*.json").OrderByDescending(x => x).FirstOrDefault();
    if (file is null) return Results.NotFound();
    return Results.File(file, "application/json", Path.GetFileName(file));
});

app.MapGet("/bff/simulator/runs/{runId}/report/html", (string runId, HttpContext httpContext) =>
{
    if (!IsSimulatorAdmin(httpContext)) return Results.StatusCode(StatusCodes.Status403Forbidden);
    if (simulatorRuns.TryGetValue(runId, out var result))
    {
        var html = $"<html><body><h1>HIP Simulator Run {runId}</h1><p>Total={result.TotalScenarios}, Passed={result.Passed}, Failed={result.Failed}</p></body></html>";
        return Results.Content(html, "text/html");
    }

    var reportDir = Path.Combine(GetSimulatorReportRoot(), runId);
    if (!Directory.Exists(reportDir)) return Results.NotFound();
    var file = Directory.GetFiles(reportDir, "simulation-report-*.html").OrderByDescending(x => x).FirstOrDefault();
    if (file is null) return Results.NotFound();
    return Results.File(file, "text/html", Path.GetFileName(file));
});

app.MapPost("/bff/simulator/cleanup", (HttpContext httpContext) =>
{
    if (!IsSimulatorAdmin(httpContext)) return Results.StatusCode(StatusCodes.Status403Forbidden);
    var removed = CleanupOldSimulatorArtifacts();
    return Results.Ok(new { removed });
});

var startupRemoved = CleanupOldSimulatorArtifacts();
if (startupRemoved > 0)
{
    app.Logger.LogInformation("Simulator retention cleanup removed {Count} old run folders", startupRemoved);
}

app.MapDefaultEndpoints();

app.Run();

string ResolveApiSettingsPath()
    => "/home/jarvis_bot/.openclaw/workspace/HIP/HIP.ApiService/appsettings.Development.json";

bool IsSimulatorAdmin(HttpContext httpContext)
{
    if (httpContext.User?.Identity?.IsAuthenticated == true && httpContext.User.IsInRole("Admin"))
    {
        return true;
    }

    var allowFallback = app.Configuration.GetValue("HipSimulator:AllowLoopbackAdminFallback", false);
    if (!allowFallback)
    {
        return false;
    }

    return httpContext.Connection.RemoteIpAddress is not null &&
           (IPAddress.IsLoopback(httpContext.Connection.RemoteIpAddress) || httpContext.Request.Host.Host is "localhost" or "127.0.0.1");
}

string GetSimulatorScenarioRoot()
    => "/home/jarvis_bot/.openclaw/workspace/HIP/HIP.Simulator.Cli/scenarios";

string GetSimulatorReportRoot()
    => "/home/jarvis_bot/.openclaw/workspace/HIP/HIP.Simulator.Cli/out";

int CleanupOldSimulatorArtifacts()
{
    var root = GetSimulatorReportRoot();
    Directory.CreateDirectory(root);
    var retentionDays = Math.Clamp(app.Configuration.GetValue("HipSimulator:RunRetentionDays", 14), 1, 180);
    var cutoff = DateTimeOffset.UtcNow.AddDays(-retentionDays);
    var removed = 0;

    foreach (var dir in Directory.GetDirectories(root))
    {
        var name = Path.GetFileName(dir);
        if (!Guid.TryParseExact(name, "N", out _)) continue;
        var modified = Directory.GetLastWriteTimeUtc(dir);
        if (modified >= cutoff.UtcDateTime) continue;
        Directory.Delete(dir, recursive: true);
        removed++;
        simulatorRuns.TryRemove(name, out _);
        simulatorStatuses.TryRemove(name, out _);
        simulatorRunHistory.TryRemove(name, out _);
    }

    foreach (var item in simulatorRunHistory.Values)
    {
        simulatorStateStore.Upsert(item);
    }

    return removed;
}

string ResolveCorrelationId(HttpContext httpContext)
{
    var headerCorrelationId = httpContext.Request.Headers["X-Correlation-ID"].FirstOrDefault();
    return string.IsNullOrWhiteSpace(headerCorrelationId)
        ? httpContext.TraceIdentifier
        : headerCorrelationId;
}

IReadOnlyList<string> ResolveUserRoles(ClaimsPrincipal user)
{
    var roles = user
        .Claims
        .Where(c => c.Type is ClaimTypes.Role or "role" or "roles")
        .Select(c => c.Value)
        .Where(value => !string.IsNullOrWhiteSpace(value))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
        .ToArray();

    return roles;
}

public sealed record ReputationFeedbackRequest(string IdentityId, string Feedback, string? Source = null, string? Note = null);
public sealed record OidcIdentityRequest(string Issuer, string Subject, string? Email = null, bool? EmailVerified = null);
public sealed record ChatQueryRequest(string Question);
public sealed record AdminSettingsRequest(bool ExposeInternalApis, string ChatMode, string[] EnabledPlugins, int AuditRetentionDays, int AuditExportMaxRows);
public sealed record SimulatorRunRequest(string? Suite, string? ScenarioId, int? Seed, string? Mode);
