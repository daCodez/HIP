using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using HIP.ServiceDefaults;
using HIP.Web.Components;
using HIP.Web.Services;

var builder = WebApplication.CreateBuilder(args);
builder.AddServiceDefaults();

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddServiceDiscovery();

builder.Services.AddHttpClient("hip-api", client =>
{
    client.BaseAddress = new Uri("https+http://hip-api");
}).AddServiceDiscovery();

builder.Services.AddHttpClient("hip-bff", client =>
{
    client.BaseAddress = new Uri("http://100.67.76.107:5102");
});

builder.Services.AddSingleton<HipEnvelopeSigner>();
builder.Services.AddScoped<HipApiClient>();

var app = builder.Build();

app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

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

app.MapDefaultEndpoints();

app.Run();

string ResolveApiSettingsPath()
    => "/home/jarvis_bot/.openclaw/workspace/HIP/HIP.ApiService/appsettings.Development.json";

public sealed record ReputationFeedbackRequest(string IdentityId, string Feedback, string? Source = null, string? Note = null);
public sealed record OidcIdentityRequest(string Issuer, string Subject, string? Email = null, bool? EmailVerified = null);
public sealed record ChatQueryRequest(string Question);
public sealed record AdminSettingsRequest(bool ExposeInternalApis, string ChatMode, string[] EnabledPlugins, int AuditRetentionDays, int AuditExportMaxRows);
