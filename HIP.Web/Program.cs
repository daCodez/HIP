using System.Text;
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

public sealed record ReputationFeedbackRequest(string IdentityId, string Feedback, string? Source = null, string? Note = null);
public sealed record OidcIdentityRequest(string Issuer, string Subject, string? Email = null, bool? EmailVerified = null);
