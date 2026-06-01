using HIP.Application;
using HIP.Application.Browser;
using HIP.Application.PublicLookup;
using HIP.Infrastructure;
using HIP.Infrastructure.Persistence;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();
builder.Services.AddHipApplication();
builder.Services.AddHipInfrastructure(builder.Configuration);
builder.Services.AddCors(options =>
{
    options.AddPolicy("PublicHipReadOnly", policy =>
        policy.AllowAnyOrigin()
            .WithMethods("GET", "POST")
            .AllowAnyHeader());
});
builder.Services.AddOpenApi();

var app = builder.Build();

await HipDatabaseInitializer.EnsureCreatedAsync(app.Services);

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseCors("PublicHipReadOnly");
app.MapDefaultEndpoints();

var publicApi = app.MapGroup("/api/v1/public");
var browserApi = app.MapGroup("/api/v1/browser");

publicApi.MapGet("/lookup/domain/{domain}", async (
    string domain,
    IPublicDomainLookupService lookupService,
    CancellationToken cancellationToken) =>
{
    try
    {
        return Results.Ok(await lookupService.LookupDomainAsync(domain, cancellationToken));
    }
    catch (ArgumentException ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
})
.WithName("PublicDomainLookup");

publicApi.MapGet("/badge/domain/{domain}", async (
    string domain,
    ITrustBadgeService badgeService,
    CancellationToken cancellationToken) =>
{
    try
    {
        return Results.Ok(await badgeService.GetDomainBadgeAsync(domain, cancellationToken));
    }
    catch (ArgumentException ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
})
.WithName("PublicDomainBadge");

MapBrowserApis(browserApi);

app.Run();

/// <summary>
/// Maps browser-extension endpoints on the standalone API service.
/// </summary>
/// <param name="browserApi">The versioned browser route group.</param>
/// <remarks>
/// Aspire exposes HIP.ApiService as the API host, so these routes must exist here as well as in HIP.Web.
/// Requests remain privacy-safe: they accept URLs, domains, link lists, and scan counts, but not page text,
/// form values, passwords, or private message content.
/// </remarks>
static void MapBrowserApis(RouteGroupBuilder browserApi)
{
    browserApi.MapPost("/score-site", async (
        BrowserScoreSiteRequest request,
        IBrowserPluginService browserPluginService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await browserPluginService.ScoreSiteAsync(request, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
    .WithName("BrowserScoreSite");

    browserApi.MapPost("/scan-links", async (
        BrowserScanLinksRequest request,
        IBrowserPluginService browserPluginService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await browserPluginService.ScanLinksAsync(request, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
    .WithName("BrowserScanLinks");

    browserApi.MapPost("/scan-results", async (
        BrowserScanResultSaveRequest request,
        IBrowserScanResultService scanResultService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await scanResultService.SaveAsync(request, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new BrowserScanResultErrorResponse(ex.Message));
        }
    })
    .WithName("BrowserSaveScanResult");

    browserApi.MapGet("/scan-results/{domain}", async (
        string domain,
        IBrowserScanResultService scanResultService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            var result = await scanResultService.GetLatestByDomainAsync(domain, cancellationToken);
            return result is null ? Results.NotFound() : Results.Ok(result);
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new BrowserScanResultErrorResponse(ex.Message));
        }
    })
    .WithName("BrowserGetScanResult");
}

/// <summary>
/// Marker type used by integration tests to boot the standalone HIP API service.
/// </summary>
public partial class ApiServiceProgram;
