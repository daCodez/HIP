using HIP.Application;
using HIP.Application.Browser;
using HIP.Application.PublicLookup;
using HIP.Application.Reputation;
using HIP.Application.Review;
using HIP.Application.SiteSafety;
using HIP.Domain.Reputation;
using HIP.Infrastructure;
using HIP.Infrastructure.Persistence;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();
builder.Services.AddHipApplication();
builder.Services.AddSingleton(BindExternalSiteEvidenceOptions(builder.Configuration));
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

if (ShouldUseHttpsRedirection(app))
{
    app.UseHttpsRedirection();
}
app.UseCors("PublicHipReadOnly");
app.MapDefaultEndpoints();

var publicApi = app.MapGroup("/api/v1/public");
var browserApi = app.MapGroup("/api/v1/browser");
var siteSafetyApi = app.MapGroup("/api/v1/site-safety");

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

publicApi.MapPost("/feedback", async (
    ReputationFeedbackRequest feedback,
    IReputationService reputationService,
    IWeightedFeedbackAggregationService weightedFeedbackService,
    IAdminReviewQueueService reviewQueueService,
    CancellationToken cancellationToken) =>
{
    try
    {
        await StoreWeightedFeedbackIfDomainAsync(feedback, weightedFeedbackService, reviewQueueService, cancellationToken);
        return Results.Ok(await reputationService.SubmitFeedbackAsync(feedback, cancellationToken));
    }
    catch (ArgumentException ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
})
.WithName("PublicFeedback");

MapBrowserApis(browserApi);
MapSiteSafetyApis(siteSafetyApi);

app.Run();

/// <summary>
/// Determines whether HTTPS redirection should be enabled for this host.
/// </summary>
/// <param name="app">The built web application.</param>
/// <returns>True when HIP should redirect HTTP requests to HTTPS.</returns>
/// <remarks>
/// Aspire can launch the API service with HTTP-only localhost endpoints for local development.
/// Disabling redirect middleware in Development avoids the "failed to determine HTTPS port" warning
/// without weakening production deployments, where redirection remains enabled.
/// </remarks>
static bool ShouldUseHttpsRedirection(WebApplication app) =>
    !app.Environment.IsDevelopment();

/// <summary>
/// Stores public feedback as weak weighted site-safety evidence when the target is a domain-like HIP target.
/// </summary>
/// <param name="feedback">Existing reputation feedback payload.</param>
/// <param name="weightedFeedbackService">Weighted feedback aggregation service.</param>
/// <param name="reviewQueueService">Admin review queue service.</param>
/// <param name="cancellationToken">Token used to cancel feedback storage.</param>
/// <returns>Completed task.</returns>
static async Task StoreWeightedFeedbackIfDomainAsync(
    ReputationFeedbackRequest feedback,
    IWeightedFeedbackAggregationService weightedFeedbackService,
    IAdminReviewQueueService reviewQueueService,
    CancellationToken cancellationToken)
{
    if (feedback.TargetType is ReputationSubjectType.Domain or ReputationSubjectType.Website)
    {
        var summary = await weightedFeedbackService.SubmitAsync(WeightedFeedbackAggregationService.FromReputationFeedback(feedback), cancellationToken);
        await reviewQueueService.CreateSignalsFromFeedbackAsync(summary, cancellationToken);
    }
}

/// <summary>
/// Binds external evidence provider options from configuration without enabling providers by default.
/// </summary>
/// <param name="configuration">Application configuration.</param>
/// <returns>Configured external evidence options.</returns>
static ExternalSiteEvidenceOptions BindExternalSiteEvidenceOptions(IConfiguration configuration)
{
    var options = new ExternalSiteEvidenceOptions();
    configuration.GetSection("ExternalSiteEvidence").Bind(options);
    return options;
}

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
/// Maps the site safety scan endpoint on HIP.ApiService so browser clients can use one API base URL.
/// </summary>
/// <param name="siteSafetyApi">The versioned site-safety route group.</param>
/// <remarks>
/// The request accepts only the current URL and privacy-safe observed counts/lists. It does not accept page
/// text, form values, cookies, tokens, passwords, or private message bodies.
/// </remarks>
static void MapSiteSafetyApis(RouteGroupBuilder siteSafetyApi)
{
    siteSafetyApi.MapPost("/scan", async (
        SiteSafetyScanRequest request,
        ISiteSafetyScanner scanner,
        IAdminReviewQueueService reviewQueueService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            var result = await scanner.ScanAsync(request, cancellationToken);
            await reviewQueueService.CreateSignalsFromScanAsync(result, cancellationToken);
            return Results.Ok(ToSiteSafetyScanResponse(result));
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
    .WithName("ApiServiceSiteSafetyScan");
}

/// <summary>
/// Converts application site safety results to public-safe JSON with enum values rendered as readable strings.
/// </summary>
/// <param name="result">The application-layer scan result.</param>
/// <returns>A privacy-safe response for browser clients and public tools.</returns>
static object ToSiteSafetyScanResponse(SiteSafetyScanResult result) => new
{
    result.ScanId,
    result.Url,
    result.Domain,
    result.ScannedAtUtc,
    result.MalwareRiskScore,
    result.PhishingRiskScore,
    result.RedirectRiskScore,
    result.ScriptRiskScore,
    result.DownloadRiskScore,
    result.FormRiskScore,
    result.ReputationRiskScore,
    result.OverallSafetyRiskScore,
    Status = result.Status.ToString(),
    result.Summary,
    result.Reasons,
    result.Warnings,
    result.PositiveSignals,
    result.NegativeSignals,
    result.ConfidenceLevel,
    result.DomainTrustScore,
    result.PageTrustScore,
    result.ContentRiskScore,
    result.FinalHipScore,
    ProviderEvidence = result.ProviderEvidence.Select(evidence => new
    {
        evidence.ProviderName,
        ProviderType = evidence.ProviderType.ToString(),
        TargetType = evidence.TargetType.ToString(),
        evidence.Domain,
        evidence.UrlHash,
        evidence.Confidence,
        evidence.CheckedAtUtc,
        evidence.ExpiresAtUtc,
        evidence.Errors,
        evidence.IsAuthoritativeForRisk,
        evidence.IsAuthoritativeForTrust,
        EvidenceItems = evidence.EvidenceItems.Select(item => new
        {
            item.Category,
            item.Value,
            Status = item.Status.ToString(),
            item.RiskImpact,
            item.TrustImpact,
            item.Summary
        }).ToArray()
    }).ToArray(),
    result.ScoreImpact
};

/// <summary>
/// Marker type used by integration tests to boot the standalone HIP API service.
/// </summary>
public partial class ApiServiceProgram;
