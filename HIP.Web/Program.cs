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
    client.BaseAddress = new Uri("https+http://hip-web");
}).AddServiceDiscovery();

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

app.MapDefaultEndpoints();

app.Run();
