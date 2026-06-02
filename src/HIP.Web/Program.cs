using System.Text.Encodings.Web;
using System.Text.Json;
using HIP.Application;
using HIP.Application.Ai;
using HIP.Application.Browser;
using HIP.Application.Consumer;
using HIP.Application.Dashboard;
using HIP.Application.Identity;
using HIP.Application.PublicLookup;
using HIP.Application.Reporting;
using HIP.Application.Reputation;
using HIP.Application.Review;
using HIP.Application.Rules;
using HIP.Application.Safety;
using HIP.Application.SelfHealing;
using HIP.Application.SecondLife;
using HIP.Application.SiteSafety;
using HIP.Application.Simulation;
using HIP.Domain.Audit;
using HIP.Domain.Review;
using HIP.Domain.Reporting;
using HIP.Domain.Reputation;
using HIP.Domain.Identity;
using HIP.Domain.Rules;
using HIP.Domain.Safety;
using HIP.Domain.SelfHealing;
using HIP.Infrastructure;
using HIP.Infrastructure.Persistence;
using HIP.Web;
using HIP.Web.Components;
using HIP.Web.Security;

var builder = WebApplication.CreateBuilder(args);

builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

builder.AddServiceDefaults();
builder.Services.AddHipApplication();
builder.Services.AddSingleton(BindExternalSiteEvidenceOptions(builder.Configuration));
builder.Services.AddHipInfrastructure(builder.Configuration);
builder.Services.AddHipAdminAuthorization();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddCors(options =>
{
    options.AddPolicy("PublicHipReadOnly", policy =>
        policy.AllowAnyOrigin()
            .WithMethods("GET", "POST")
            .AllowAnyHeader());
});
// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

var app = builder.Build();

await HipDatabaseInitializer.EnsureCreatedAsync(app.Services);

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
app.UseWhen(
    context => !context.Request.Path.StartsWithSegments("/api"),
    branch => branch.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true));
app.UseHttpsRedirection();
app.UseCors("PublicHipReadOnly");
app.UseAuthentication();
app.UseAuthorization();

app.UseAntiforgery();

MapPublicApis(app.MapGroup(ApiRoutes.Public));
MapReportApis(app.MapGroup($"{ApiRoutes.V1}/reports"));
MapBadgeApis(app.MapGroup(ApiRoutes.Badge));
MapBrowserApis(app.MapGroup(ApiRoutes.Browser));
MapSafetyApis(app.MapGroup(ApiRoutes.Safety));
MapSiteSafetyApis(app.MapGroup(ApiRoutes.SiteSafety));
Program.MapJsonRulesApis(app.MapGroup(ApiRoutes.Rules));
MapAiApis(app.MapGroup(ApiRoutes.Ai).RequireAuthorization(AdminPolicies.CanManageRules));
MapSelfHealingPatternApis(app.MapGroup(ApiRoutes.SelfHealing).RequireAuthorization(AdminPolicies.CanManageRules));
MapSecondLifeHudApis(app.MapGroup(ApiRoutes.SecondLifeHud));
MapLicenseApis(app.MapGroup(ApiRoutes.Licenses).RequireAuthorization(AdminPolicies.CanManageLicenses));
MapRulesApis(app.MapGroup($"{ApiRoutes.Admin}/rules").RequireAuthorization(AdminPolicies.CanManageRules));
MapSelfHealingApis(app.MapGroup($"{ApiRoutes.Admin}/self-healing").RequireAuthorization(AdminPolicies.CanManageRules));
MapReviewApis(app.MapGroup($"{ApiRoutes.Admin}/review").RequireAuthorization(AdminPolicies.CanReviewReports));
MapAppealApis(app.MapGroup($"{ApiRoutes.Admin}/appeals").RequireAuthorization(AdminPolicies.CanReviewReports));
MapReputationOverrideApis(app.MapGroup($"{ApiRoutes.Admin}/reputation-overrides").RequireAuthorization(AdminPolicies.CanApproveOverrides));
MapReputationApis(app.MapGroup($"{ApiRoutes.Admin}/reputation").RequireAuthorization(AdminPolicies.CanViewAdminDashboard));
MapDashboardApis(app.MapGroup($"{ApiRoutes.Admin}/dashboard").RequireAuthorization(AdminPolicies.CanViewAdminDashboard));
MapConsumerApis(app.MapGroup(ApiRoutes.Consumer).RequireAuthorization(ConsumerPolicies.CanUseConsumerPortal));
MapIdentityApis(app.MapGroup(ApiRoutes.Identity));
app.MapGet($"{ApiRoutes.Admin}/audit-logs", (IAuditLogService auditLogService) => Results.Ok(auditLogService.List()))
    .RequireAuthorization(AdminPolicies.CanViewAuditLogs);
app.MapGet($"{ApiRoutes.Admin}/audit", (IAuditLogService auditLogService) => Results.Ok(auditLogService.List()))
    .RequireAuthorization(AdminPolicies.CanViewAuditLogs);
app.MapPost($"{ApiRoutes.Admin}/audit/query", (AuditQueryRequest request, IAuditLogService auditLogService) =>
{
    var entries = auditLogService.List()
        .Where(entry => string.IsNullOrWhiteSpace(request.Action) || entry.Action.Contains(request.Action, StringComparison.OrdinalIgnoreCase))
        .Where(entry => request.TargetType is null || entry.TargetType == request.TargetType)
        .Where(entry => string.IsNullOrWhiteSpace(request.TargetId) || string.Equals(entry.TargetId, request.TargetId, StringComparison.OrdinalIgnoreCase))
        .Where(entry => request.Severity is null || entry.Severity == request.Severity)
        .Take(request.Limit is > 0 and <= 500 ? request.Limit.Value : 100)
        .ToArray();

    return Results.Ok(entries);
})
    .RequireAuthorization(AdminPolicies.CanViewAuditLogs);
app.MapGet($"{ApiRoutes.Admin}/roles", (HttpContext httpContext) => Results.Ok(AdminRoleCatalog.Roles))
    .RequireAuthorization(AdminPolicies.CanViewAdminDashboard);
app.MapGet($"{ApiRoutes.Admin}/reports", async (
    IPrivacySafeReportService reportService,
    CancellationToken cancellationToken) =>
    Results.Ok((await reportService.ListAsync(cancellationToken)).Select(PrivacySafeReportListItem.From).ToArray()))
    .RequireAuthorization(AdminPolicies.CanReviewReports);
app.MapGet($"{ApiRoutes.Admin}/site-safety/external-providers", (ExternalSiteEvidenceOptions options) =>
    Results.Ok(ExternalProviderSettingsResponse.From(options)))
    .RequireAuthorization(AdminPolicies.CanViewAdminDashboard);
app.MapPost($"{ApiRoutes.Admin}/site-safety/external-providers", (
    ExternalProviderSettingsUpdateRequest request,
    ExternalSiteEvidenceOptions options) =>
{
    ApplyExternalProviderSettings(options, request);
    return Results.Ok(ExternalProviderSettingsResponse.From(options));
})
    .RequireAuthorization(AdminPolicies.CanManageRules);

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.MapDefaultEndpoints();

app.Run();

/// <summary>
/// Binds external evidence provider options from configuration without requiring providers to be enabled.
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
/// Applies admin-managed external evidence provider settings to the runtime options object.
/// </summary>
/// <param name="options">Runtime options used by Site Safety providers.</param>
/// <param name="request">Requested settings from an authorized admin.</param>
static void ApplyExternalProviderSettings(ExternalSiteEvidenceOptions options, ExternalProviderSettingsUpdateRequest request)
{
    options.ExternalProvidersEnabled = request.ExternalProvidersEnabled;
    options.AllowFullUrlChecks = request.AllowFullUrlChecks;
    options.ProviderTimeout = request.ProviderTimeout is { Ticks: > 0 } ? request.ProviderTimeout.Value : TimeSpan.FromSeconds(2);
    options.DefaultCacheDuration = request.DefaultCacheDuration is { Ticks: > 0 } ? request.DefaultCacheDuration.Value : TimeSpan.FromHours(6);
    ApplyProvider(options.SslLabs, request.SslLabs);
    ApplyProvider(options.GoogleWebRisk, request.GoogleWebRisk);
    ApplyProvider(options.VirusTotal, request.VirusTotal);
}

/// <summary>
/// Applies one provider's safe runtime settings without logging or exposing secrets.
/// </summary>
/// <param name="options">Provider options to mutate.</param>
/// <param name="request">Provider settings requested by the admin.</param>
static void ApplyProvider(ExternalProviderOptions options, ExternalProviderSettings request)
{
    options.Enabled = request.Enabled;
    options.Endpoint = string.IsNullOrWhiteSpace(request.Endpoint) ? null : request.Endpoint.Trim();
    options.ApiKey = string.IsNullOrWhiteSpace(request.ApiKey) ? null : request.ApiKey.Trim();
    options.AllowFullUrl = request.AllowFullUrl;
    options.CacheDuration = request.CacheDuration is { Ticks: > 0 } ? request.CacheDuration : null;
}

static void MapPublicApis(RouteGroupBuilder publicApi)
{
    publicApi.MapGet("/lookup/{domain}", async (
        string domain,
        IPublicDomainLookupService lookupService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(PublicLookupApiResponse.From(await lookupService.LookupDomainAsync(domain, cancellationToken)));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    publicApi.MapGet("/lookup/domain/{domain}", async (
        string domain,
        IPublicDomainLookupService lookupService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(PublicLookupApiResponse.From(await lookupService.LookupDomainAsync(domain, cancellationToken)));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    publicApi.MapPost("/lookup", async (
        PublicLookupRequest request,
        IPublicDomainLookupService lookupService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(PublicLookupApiResponse.From(await lookupService.LookupDomainAsync(request.Domain, cancellationToken)));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

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
    });

    publicApi.MapPost("/appeals", (
        AppealRequest appeal,
        IAppealService appealService) =>
    {
        try
        {
            return Results.Ok(appealService.Submit(appeal));
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    publicApi.MapPost("/feedback", async (
        ReputationFeedbackRequest feedback,
        IReputationService reputationService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await reputationService.SubmitFeedbackAsync(feedback, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    publicApi.MapPost("/risk-findings", async (
        RiskFindingReport report,
        IRiskFindingIngestionService ingestionService,
        CancellationToken cancellationToken) =>
    {
        var response = await ingestionService.IngestAsync(report, cancellationToken);
        return response.Accepted ? Results.Ok(response) : Results.BadRequest(response);
    });
}

static void MapReportApis(RouteGroupBuilder reportApi)
{
    reportApi.MapPost("/", async (
        PrivacySafeReport report,
        IPrivacySafeReportService reportService,
        CancellationToken cancellationToken) =>
    {
        var result = await reportService.SubmitAsync(report, cancellationToken);
        return result.Accepted ? Results.Ok(result) : Results.BadRequest(result);
    });
}

/// <summary>
/// Maps protected admin dashboard endpoints using privacy-safe aggregate data.
/// </summary>
/// <param name="dashboardApi">Versioned dashboard route group.</param>
static void MapDashboardApis(RouteGroupBuilder dashboardApi)
{
    dashboardApi.MapGet("/summary", async (
        IAdminDashboardService dashboardService,
        CancellationToken cancellationToken) =>
        Results.Ok(await dashboardService.GetSummaryAsync(cancellationToken)));

    dashboardApi.MapGet("/risky-domains", async (
        IAdminDashboardService dashboardService,
        CancellationToken cancellationToken) =>
        Results.Ok((await dashboardService.GetSummaryAsync(cancellationToken)).TopRiskyDomains));

    dashboardApi.MapGet("/recent-scans", async (
        IAdminDashboardService dashboardService,
        CancellationToken cancellationToken) =>
        Results.Ok((await dashboardService.GetSummaryAsync(cancellationToken)).RecentScans));
}

static void MapBadgeApis(RouteGroupBuilder badgeApi)
{
    badgeApi.MapGet("/{domain}", async (
        string domain,
        ITrustBadgeService badgeService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(PublicBadgeApiResponse.From(await badgeService.GetDomainBadgeAsync(domain, cancellationToken)));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    badgeApi.MapGet("/{domain}/script", (
        string domain) =>
    {
        try
        {
            var normalized = DomainInputValidator.ValidateAndNormalize(domain);
            return Results.Text(Program.BuildBadgeScript(normalized), "application/javascript");
        }
        catch (ArgumentException ex)
        {
            return Results.Text($"console.warn('HIP badge unavailable: {JavaScriptEncoder.Default.Encode(ex.Message)}');", "application/javascript");
        }
    });
}

/// <summary>
/// Maps browser plugin endpoints for site scoring, link scanning, and privacy-safe scan result persistence.
/// </summary>
/// <param name="browserApi">Versioned browser plugin route group.</param>
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
    });

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
    });

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
    });

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
    });
}

static void MapSafetyApis(RouteGroupBuilder safetyApi)
{
    safetyApi.MapPost("/evaluate", (
        SafetyEvaluateRequest request,
        ISafetyRoutingService safetyRoutingService) =>
    {
        try
        {
            return Results.Ok(SafetyEvaluateResponse.From(safetyRoutingService.EvaluateUrl(request.Url, request.Source)));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    safetyApi.MapPost("/report-safe", (SafetyReportRequest request) =>
        Results.Ok(SafetyReportResponse.CreateAccepted(request.Url, request.Source, "Report as safe was accepted for MVP review.")));

    safetyApi.MapPost("/report-dangerous", (SafetyReportRequest request) =>
        Results.Ok(SafetyReportResponse.CreateAccepted(request.Url, request.Source, "Report as dangerous was accepted for MVP review.")));
}

/// <summary>
/// Maps the versioned Site Safety Scan endpoint used by HIP clients and public tools.
/// </summary>
/// <param name="siteSafetyApi">Versioned site safety route group.</param>
static void MapSiteSafetyApis(RouteGroupBuilder siteSafetyApi)
{
    siteSafetyApi.MapPost("/scan", async (
        SiteSafetyScanRequest request,
        ISiteSafetyScanner scanner,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(ToSiteSafetyScanResponse(await scanner.ScanAsync(request, cancellationToken)));
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });
}

/// <summary>
/// Converts the domain scan result into an API response with readable enum labels.
/// </summary>
/// <param name="result">Application-layer scan result.</param>
/// <returns>Public-safe Site Safety API response.</returns>
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

static void MapAiApis(RouteGroupBuilder aiApi)
{
    aiApi.MapPost("/analyze-url", async (
        HipAiUrlRiskAnalysisRequest request,
        IHipAiRiskAnalyzer analyzer,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await analyzer.AnalyzeUrlRiskAsync(request, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    aiApi.MapPost("/analyze-content", async (
        HipAiContentRiskAnalysisRequest request,
        IHipAiRiskAnalyzer analyzer,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await analyzer.AnalyzeContentRiskAsync(request, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    aiApi.MapPost("/suggest-rule", async (
        HipAiRuleSuggestionRequest request,
        IHipAiRiskAnalyzer analyzer,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await analyzer.SuggestRuleAsync(request, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });
}

static void MapConsumerApis(RouteGroupBuilder consumerApi)
{
    consumerApi.MapGet("/status", async (
        HttpContext httpContext,
        IConsumerPortalService consumerPortalService,
        CancellationToken cancellationToken) =>
        Results.Ok(await consumerPortalService.GetStatusAsync(ConsumerId(httpContext), cancellationToken)));

    consumerApi.MapGet("/scans", async (
        HttpContext httpContext,
        IConsumerPortalService consumerPortalService,
        CancellationToken cancellationToken) =>
        Results.Ok(await consumerPortalService.GetScansAsync(ConsumerId(httpContext), cancellationToken)));

    consumerApi.MapGet("/reports", async (
        HttpContext httpContext,
        IConsumerPortalService consumerPortalService,
        CancellationToken cancellationToken) =>
        Results.Ok(await consumerPortalService.GetReportsAsync(ConsumerId(httpContext), cancellationToken)));

    consumerApi.MapGet("/appeals", async (
        HttpContext httpContext,
        IConsumerPortalService consumerPortalService,
        CancellationToken cancellationToken) =>
        Results.Ok(await consumerPortalService.GetAppealsAsync(ConsumerId(httpContext), cancellationToken)));

    consumerApi.MapPost("/appeals", (
        HttpContext httpContext,
        ConsumerAppealSubmissionRequest request,
        IConsumerPortalService consumerPortalService) =>
    {
        var result = consumerPortalService.SubmitAppeal(ConsumerId(httpContext), request);
        return result.Accepted ? Results.Ok(result) : Results.BadRequest(result);
    });

    consumerApi.MapGet("/settings", (
        HttpContext httpContext,
        IConsumerPortalService consumerPortalService) =>
        Results.Ok(consumerPortalService.GetSettings(ConsumerId(httpContext))));

    consumerApi.MapPost("/settings", (
        HttpContext httpContext,
        ConsumerSettings settings,
        IConsumerPortalService consumerPortalService) =>
    {
        var result = consumerPortalService.SaveSettings(ConsumerId(httpContext), settings);
        return result.Saved ? Results.Ok(result) : Results.BadRequest(result);
    });
}

static string ConsumerId(HttpContext httpContext) =>
    httpContext.User.FindFirst("hip_consumer_id")?.Value
    ?? httpContext.User.Identity?.Name
    ?? "development-consumer";

static void MapSecondLifeHudApis(RouteGroupBuilder slHudApi)
{
    slHudApi.MapPost("/activate", (
        SecondLifeHudActivationRequest request,
        ISecondLifeHudService hudService) =>
    {
        var response = hudService.Activate(request);
        return response.Activated ? Results.Ok(response) : Results.BadRequest(response);
    });

    slHudApi.MapPost("/scan", (
        SecondLifeHudScanRequest request,
        ISecondLifeHudService hudService) =>
    {
        try
        {
            return Results.Ok(hudService.Scan(request));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    slHudApi.MapPost("/simulate", (
        SecondLifeHudSimulationApiRequest request,
        ISecondLifeHudSimulationService simulationService) =>
    {
        try
        {
            return Results.Ok(SecondLifeHudSimulationApiResponse.From(simulationService.Simulate(request.ToApplicationRequest())));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    slHudApi.MapGet("/settings/{deviceId}", (
        string deviceId,
        ISecondLifeHudService hudService) =>
    {
        try
        {
            return Results.Ok(hudService.GetSettings(deviceId));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    slHudApi.MapPost("/settings/{deviceId}", (
        string deviceId,
        SecondLifeHudSettings settings,
        ISecondLifeHudService hudService) =>
    {
        try
        {
            var response = hudService.SaveSettings(deviceId, settings);
            return response.Saved ? Results.Ok(response) : Results.BadRequest(response);
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    slHudApi.MapPost("/report", async (
        SecondLifeHudFindingReport report,
        ISecondLifeHudService hudService,
        CancellationToken cancellationToken) =>
    {
        var response = await hudService.ReportFindingAsync(report, cancellationToken);
        return response.Accepted ? Results.Ok(response) : Results.BadRequest(response);
    });

    slHudApi.MapPost("/report-finding", async (
        SecondLifeHudFindingReport report,
        ISecondLifeHudService hudService,
        CancellationToken cancellationToken) =>
    {
        var response = await hudService.ReportFindingAsync(report, cancellationToken);
        return response.Accepted ? Results.Ok(response) : Results.BadRequest(response);
    });
}

/// <summary>
/// Maps protected setup code and license support endpoints for the Second Life HUD marketplace flow.
/// </summary>
/// <param name="licenseApi">The protected license route group.</param>
static void MapLicenseApis(RouteGroupBuilder licenseApi)
{
    licenseApi.MapPost("/setup-codes", (
        CreateSetupCodeRequest request,
        ISetupCodeLicenseService licenseService) =>
        Results.Ok(licenseService.CreateSetupCode(request)));

    licenseApi.MapGet("/", (ISetupCodeLicenseService licenseService) =>
        Results.Ok(licenseService.ListLicenses()));

    licenseApi.MapGet("/{licenseId}", (
        string licenseId,
        ISetupCodeLicenseService licenseService) =>
        licenseService.GetLicense(licenseId) is { } license
            ? Results.Ok(license)
            : Results.NotFound(new { error = "License was not found." }));

    licenseApi.MapPost("/{licenseId}/reset", (
        string licenseId,
        ISetupCodeLicenseService licenseService) =>
        licenseService.ResetActivation(licenseId) is { } license
            ? Results.Ok(license)
            : Results.NotFound(new { error = "License was not found." }));

    licenseApi.MapPost("/{licenseId}/revoke", (
        string licenseId,
        ISetupCodeLicenseService licenseService) =>
        licenseService.SetStatus(licenseId, LicenseStatus.Revoked) is { } license
            ? Results.Ok(license)
            : Results.NotFound(new { error = "License was not found." }));

    licenseApi.MapPost("/{licenseId}/suspend", (
        string licenseId,
        ISetupCodeLicenseService licenseService) =>
        licenseService.SetStatus(licenseId, LicenseStatus.Suspended) is { } license
            ? Results.Ok(license)
            : Results.NotFound(new { error = "License was not found." }));

    licenseApi.MapPost("/{licenseId}/reactivate", (
        string licenseId,
        ISetupCodeLicenseService licenseService) =>
        licenseService.SetStatus(licenseId, LicenseStatus.Active) is { } license
            ? Results.Ok(license)
            : Results.NotFound(new { error = "License was not found." }));
}

static void MapRulesApis(RouteGroupBuilder adminApi)
{
    adminApi.MapPost("/simulate", (
        AdminRuleSimulationRequest request,
        IAdminRuleService adminRuleService) =>
    {
        try
        {
            var result = adminRuleService.Simulate(request.Rule, request.TestCases);
            return Results.Ok(result);
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });
}

static void MapSelfHealingApis(RouteGroupBuilder selfHealingApi)
{
    selfHealingApi.MapPost("/detect-patterns", (
        IReadOnlyCollection<SuspiciousFinding> findings,
        IPatternDetectionService patternDetectionService) =>
    {
        try
        {
            return Results.Ok(patternDetectionService.DetectPatterns(findings));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    selfHealingApi.MapPost("/generate-rule", (
        PatternCluster cluster,
        IRuleCandidateGenerator ruleCandidateGenerator) =>
    {
        try
        {
            return Results.Ok(ruleCandidateGenerator.Generate(cluster));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    selfHealingApi.MapPost("/analyze-findings", (
        IReadOnlyCollection<SuspiciousFinding> findings,
        ISelfHealingAnalysisService selfHealingAnalysisService) =>
    {
        try
        {
            return Results.Ok(selfHealingAnalysisService.Analyze(findings));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });
}

static void MapSelfHealingPatternApis(RouteGroupBuilder selfHealingApi)
{
    selfHealingApi.MapPost("/detect-patterns", async (
        IReadOnlyCollection<SuspiciousFinding> findings,
        ISelfHealingPatternDetectionService selfHealingPatternDetectionService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await selfHealingPatternDetectionService.DetectAsync(findings, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    selfHealingApi.MapPost("/generate-rule", async (
        PatternCluster cluster,
        ISelfHealingPatternDetectionService selfHealingPatternDetectionService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await selfHealingPatternDetectionService.GenerateRuleAsync(cluster, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    selfHealingApi.MapGet("/suggestions", async (
        ISelfHealingPatternDetectionService selfHealingPatternDetectionService,
        CancellationToken cancellationToken) =>
        Results.Ok(await selfHealingPatternDetectionService.ListSuggestionsAsync(cancellationToken)));

    selfHealingApi.MapPost("/suggestions/{id}/approve", async (
        string id,
        ISelfHealingPatternDetectionService selfHealingPatternDetectionService,
        CancellationToken cancellationToken) =>
    {
        var candidate = await selfHealingPatternDetectionService.ApproveSuggestionAsync(id, cancellationToken);
        return candidate is null ? Results.NotFound() : Results.Ok(candidate);
    });

    selfHealingApi.MapPost("/suggestions/{id}/reject", async (
        string id,
        ISelfHealingPatternDetectionService selfHealingPatternDetectionService,
        CancellationToken cancellationToken) =>
    {
        var candidate = await selfHealingPatternDetectionService.RejectSuggestionAsync(id, cancellationToken);
        return candidate is null ? Results.NotFound() : Results.Ok(candidate);
    });
}

static void MapReviewApis(RouteGroupBuilder reviewApi)
{
    reviewApi.MapGet("/", (IReviewQueueService reviewQueueService) => Results.Ok(reviewQueueService.List()));

    reviewApi.MapGet("/{id}", (string id, IReviewQueueService reviewQueueService) =>
        reviewQueueService.Get(id) is { } item ? Results.Ok(item) : Results.NotFound());

    reviewApi.MapPost("/", (ReviewItem item, IReviewQueueService reviewQueueService) =>
    {
        try
        {
            return Results.Ok(reviewQueueService.Create(item));
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    reviewApi.MapPost("/{id}/approve", (string id, AdminDecisionRequest request, IReviewQueueService reviewQueueService) =>
        Results.Ok(reviewQueueService.Approve(id, request.ActorId, request.Reason)));

    reviewApi.MapPost("/{id}/reject", (string id, AdminDecisionRequest request, IReviewQueueService reviewQueueService) =>
        Results.Ok(reviewQueueService.Reject(id, request.ActorId, request.Reason)));

    reviewApi.MapPost("/{id}/needs-more-info", (string id, AdminDecisionRequest request, IReviewQueueService reviewQueueService) =>
        Results.Ok(reviewQueueService.RequestMoreInfo(id, request.ActorId, request.Reason)));

    reviewApi.MapPost("/{id}/decision", (string id, AdminReviewDecisionRequest request, IReviewQueueService reviewQueueService) =>
        ReviewDecision(id, request, reviewQueueService));

    reviewApi.MapPost("/{id}/assign", (string id, AdminAssignRequest request, IReviewQueueService reviewQueueService) =>
        Results.Ok(reviewQueueService.Assign(id, request.AssignedTo, request.ActorId)));
}

static void MapAppealApis(RouteGroupBuilder appealApi)
{
    appealApi.MapGet("/", (IAppealService appealService) => Results.Ok(appealService.List()));
    appealApi.MapGet("/{id}", (string id, IAppealService appealService) =>
        appealService.Get(id) is { } appeal ? Results.Ok(appeal) : Results.NotFound());
    appealApi.MapPost("/{id}/approve", (string id, AdminDecisionRequest request, IAppealService appealService) =>
        Results.Ok(appealService.Approve(id, request.ActorId, request.Reason)));
    appealApi.MapPost("/{id}/reject", (string id, AdminDecisionRequest request, IAppealService appealService) =>
        Results.Ok(appealService.Reject(id, request.ActorId, request.Reason)));
    appealApi.MapPost("/{id}/needs-more-info", (string id, AdminDecisionRequest request, IAppealService appealService) =>
        Results.Ok(appealService.RequestMoreInfo(id, request.ActorId, request.Reason)));
    appealApi.MapPost("/{id}/decision", (string id, AdminAppealDecisionRequest request, IAppealService appealService) =>
        AppealDecision(id, request, appealService));
}

static IResult ReviewDecision(string id, AdminReviewDecisionRequest request, IReviewQueueService reviewQueueService) =>
    request.Status switch
    {
        ReviewStatus.Confirmed or ReviewStatus.Approved => Results.Ok(reviewQueueService.Approve(id, request.ActorId, request.Reason)),
        ReviewStatus.Rejected => Results.Ok(reviewQueueService.Reject(id, request.ActorId, request.Reason)),
        ReviewStatus.NeedsMoreInfo => Results.Ok(reviewQueueService.RequestMoreInfo(id, request.ActorId, request.Reason)),
        ReviewStatus.Closed => Results.Ok(reviewQueueService.Close(id, request.ActorId, request.Reason)),
        ReviewStatus.InReview => Results.Ok(reviewQueueService.UpdateStatus(id, ReviewStatus.InReview, request.ActorId, request.Reason)),
        _ => Results.BadRequest(new { error = "Decision status must be InReview, Confirmed, Rejected, NeedsMoreInfo, or Closed." })
    };

static IResult AppealDecision(string id, AdminAppealDecisionRequest request, IAppealService appealService) =>
    request.Status switch
    {
        AppealStatus.Approved => Results.Ok(appealService.Approve(id, request.ActorId, request.Reason)),
        AppealStatus.Rejected => Results.Ok(appealService.Reject(id, request.ActorId, request.Reason)),
        AppealStatus.NeedsMoreInfo => Results.Ok(appealService.RequestMoreInfo(id, request.ActorId, request.Reason)),
        _ => Results.BadRequest(new { error = "Decision status must be Approved, Rejected, or NeedsMoreInfo." })
    };

static void MapReputationOverrideApis(RouteGroupBuilder overrideApi)
{
    overrideApi.MapGet("/", (IReputationOverrideService reputationOverrideService) => Results.Ok(reputationOverrideService.List()));
    overrideApi.MapPost("/", (ReputationOverrideRequest request, IReputationOverrideService reputationOverrideService) =>
    {
        try
        {
            return Results.Ok(reputationOverrideService.Request(request));
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });
    overrideApi.MapPost("/{id}/approve", (string id, AdminDecisionRequest request, IReputationOverrideService reputationOverrideService) =>
        Results.Ok(reputationOverrideService.Approve(id, request.ActorId, request.Reason)));
    overrideApi.MapPost("/{id}/reject", (string id, AdminDecisionRequest request, IReputationOverrideService reputationOverrideService) =>
        Results.Ok(reputationOverrideService.Reject(id, request.ActorId, request.Reason)));
}

static void MapReputationApis(RouteGroupBuilder reputationApi)
{
    reputationApi.MapGet("/{targetType}/{targetId}", async (
        ReputationSubjectType targetType,
        string targetId,
        IReputationService reputationService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await reputationService.GetProfileAsync(targetType, targetId, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    reputationApi.MapPost("/events", async (
        ReputationEvent reputationEvent,
        IReputationService reputationService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await reputationService.ApplyEventAsync(reputationEvent, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    reputationApi.MapPost("/{targetType}/{targetId}/recalculate", async (
        ReputationSubjectType targetType,
        string targetId,
        IReputationService reputationService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await reputationService.RecalculateAsync(targetType, targetId, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });
}

static void MapIdentityApis(RouteGroupBuilder identityApi)
{
    identityApi.MapPost("/register", async (
        IdentityRegistrationRequest request,
        IHipIdentityService identityService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await identityService.RegisterAsync(request, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    identityApi.MapPost("/websites/register", async (
        WebsiteIdentityRegistrationRequest request,
        IWebsiteIdentityService websiteIdentityService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await websiteIdentityService.RegisterAsync(request, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
        .RequireAuthorization(AdminPolicies.CanManageRules);

    identityApi.MapPost("/websites/verify", async (
        WebsiteVerificationRequest request,
        IWebsiteIdentityService websiteIdentityService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await websiteIdentityService.VerifyAsync(request, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
        .RequireAuthorization(AdminPolicies.CanManageRules);

    identityApi.MapGet("/websites/{domain}", async (
        string domain,
        IWebsiteIdentityService websiteIdentityService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return await websiteIdentityService.GetAsync(domain, cancellationToken) is { } website
                ? Results.Ok(website)
                : Results.NotFound();
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    identityApi.MapPost("/signature/verify", async (
        HipSignatureVerificationRequest request,
        IHipSignatureService signatureService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await signatureService.VerifyAsync(request, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    identityApi.MapPost("/domain-verification/start", async (
        DomainVerificationApiRequest request,
        IDomainVerificationService domainVerificationService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await domainVerificationService.StartAsync(request.Domain, request.Method, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    identityApi.MapPost("/domain-verification/verify", async (
        DomainVerificationApiRequest request,
        IDomainVerificationService domainVerificationService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await domainVerificationService.VerifyAsync(request.Domain, request.Method, request.Token ?? string.Empty, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    identityApi.MapPost("/sign", async (
        SignContentRequest request,
        IHipIdentityService identityService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await identityService.SignAsync(request, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    identityApi.MapPost("/verify", async (
        VerifySignatureRequest request,
        IHipIdentityService identityService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await identityService.VerifyAsync(request, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });
}

public sealed record AdminRuleSimulationRequest(
    TrustRule Rule,
    IReadOnlyCollection<RuleSimulationTestCase>? TestCases);

public sealed record AdminDecisionRequest(string ActorId, string Reason);

public sealed record AdminReviewDecisionRequest(string ActorId, ReviewStatus Status, string Reason);

public sealed record AdminAppealDecisionRequest(string ActorId, AppealStatus Status, string Reason);

public sealed record AdminAssignRequest(string ActorId, string AssignedTo);

public sealed record AuditQueryRequest(string? Action, TargetType? TargetType, string? TargetId, AuditSeverity? Severity, int? Limit);

public sealed record PrivacySafeReportListItem(
    string ReportId,
    string ReportType,
    string Source,
    string Platform,
    string Domain,
    string? UrlHash,
    string? SenderHash,
    string RiskLevel,
    string ReasonSummary,
    DateTimeOffset ReportedAtUtc,
    string Status)
{
    public static PrivacySafeReportListItem From(PrivacySafeReport report) =>
        new(
            report.ReportId,
            report.ReportType.ToString(),
            report.Source.ToString(),
            report.Platform.ToString(),
            report.Domain,
            report.UrlHash,
            report.SenderHash,
            report.RiskLevel.ToString(),
            report.ReasonSummary,
            report.ReportedAtUtc,
            report.Status.ToString());
}

public sealed record DomainVerificationApiRequest(string Domain, VerificationMethod Method, string? Token);

public sealed record PublicLookupRequest(string Domain);

public sealed record SafetyEvaluateRequest(string Url, string? Source);

public sealed record SafetyEvaluateResponse(
    string Url,
    string Domain,
    string? FinalDestinationUrl,
    string RiskLevel,
    int Score,
    int DomainScore,
    int? SenderScore,
    IReadOnlyCollection<string> Reasons,
    string ReasonSummary,
    string RecommendedAction,
    bool AllowContinue,
    bool ShouldRouteToSafetyPage)
{
    public static SafetyEvaluateResponse From(SafetyResult result)
    {
        var domain = Uri.TryCreate(result.OriginalUrl, UriKind.Absolute, out var uri)
            ? uri.Host.Replace("www.", string.Empty, StringComparison.OrdinalIgnoreCase).ToLowerInvariant()
            : string.Empty;

        return new SafetyEvaluateResponse(
            result.OriginalUrl,
            domain,
            result.FinalDestinationUrl,
            SafetyRoutingService.DisplayRiskLevel(result.RiskLevel),
            result.DomainScore,
            result.DomainScore,
            result.SenderScore,
            [result.Reason],
            result.Reason,
            result.RecommendedAction,
            result.AllowContinue,
            result.ShouldRouteToSafetyPage);
    }
}

public sealed record SafetyReportRequest(string Url, string? Source, string? Reason);

public sealed record SafetyReportResponse(
    bool Accepted,
    string Url,
    string? Source,
    string Message)
{
    public static SafetyReportResponse CreateAccepted(string url, string? source, string message) =>
        new(true, url, source, message);
}

public sealed record RuleEvaluationApiRequest(
    IReadOnlyCollection<TrustRule>? Rules,
    RuleScanContext Context);

public sealed record RuleSimulationApiRequest(
    string? RuleId,
    TrustRule? Rule,
    IReadOnlyCollection<RuleSimulationTestCase>? TestCases);

public sealed record RuleSimulationApiResponse(
    string SimulationId,
    string RuleId,
    bool Passed,
    decimal ConfidenceScore,
    decimal DetectionRate,
    decimal FalsePositiveRisk,
    decimal FalseNegativeRisk,
    string SpeedImpact,
    string PrivacyImpact,
    string RecommendedAction,
    string RecommendedMode,
    string ImpactClassification,
    IReadOnlyCollection<string> MatchedRules,
    IReadOnlyCollection<RuleSimulationCaseResult> FailedCases)
{
    public static RuleSimulationApiResponse From(RuleSimulationResult result) =>
        new(
            result.SimulationId,
            result.RuleId,
            result.Passed,
            result.ConfidenceScore,
            result.DetectionRate,
            result.FalsePositiveRisk,
            result.FalseNegativeRisk,
            result.SpeedImpact,
            result.PrivacyImpact,
            result.RecommendedAction,
            result.RecommendedMode,
            result.ImpactClassification,
            result.MatchedRules,
            result.FailedCases);
}

public sealed record RuleApiResponse(
    string RuleId,
    string Name,
    bool Enabled,
    string Mode,
    string Severity,
    IReadOnlyCollection<RuleCondition> Conditions,
    IReadOnlyCollection<RuleActionApiResponse> Actions,
    bool RequiresApproval,
    bool SimulationRequired)
{
    public static RuleApiResponse From(TrustRule rule) =>
        new(
            rule.RuleId,
            rule.Name,
            rule.Enabled,
            rule.Mode.ToString(),
            rule.Severity.ToString(),
            rule.Conditions,
            rule.Actions.Select(RuleActionApiResponse.From).ToArray(),
            rule.RequiresApproval,
            rule.SimulationRequired);
}

public sealed record RuleActionApiResponse(
    string Type,
    JsonElement Value)
{
    public static RuleActionApiResponse From(RuleAction action) =>
        new(action.Type.ToString(), action.Value);
}

public sealed record RuleEvaluationApiResponse(
    IReadOnlyCollection<string> MatchedRules,
    IReadOnlyCollection<RuleActionSummaryApiResponse> Actions,
    string RiskLevel,
    IReadOnlyCollection<string> Reasons,
    IReadOnlyCollection<RuleEvaluationItemApiResponse> WatchModeResults,
    IReadOnlyCollection<RuleEvaluationItemApiResponse> EnforcementResults,
    bool ShouldRouteToSafetyPage,
    bool ShouldBlock,
    bool RequiresReview)
{
    public static RuleEvaluationApiResponse From(RuleEvaluationResponse result) =>
        new(
            result.MatchedRules,
            result.Actions.Select(RuleActionSummaryApiResponse.From).ToArray(),
            result.RiskLevel.ToString(),
            result.Reasons,
            result.WatchModeResults.Select(RuleEvaluationItemApiResponse.From).ToArray(),
            result.EnforcementResults.Select(RuleEvaluationItemApiResponse.From).ToArray(),
            result.ShouldRouteToSafetyPage,
            result.ShouldBlock,
            result.RequiresReview);
}

public sealed record RuleEvaluationItemApiResponse(
    string RuleId,
    string Name,
    string Mode,
    bool Matched,
    IReadOnlyCollection<RuleActionSummaryApiResponse> Actions,
    IReadOnlyCollection<string> Reasons,
    bool Enforced)
{
    public static RuleEvaluationItemApiResponse From(RuleEvaluationItem item) =>
        new(
            item.RuleId,
            item.Name,
            item.Mode.ToString(),
            item.Matched,
            item.Actions.Select(RuleActionSummaryApiResponse.From).ToArray(),
            item.Reasons,
            item.Enforced);
}

public sealed record RuleActionSummaryApiResponse(
    string Type,
    string Value)
{
    public static RuleActionSummaryApiResponse From(RuleActionSummary action) =>
        new(action.Type.ToString(), action.Value);
}

public sealed record PublicBadgeApiResponse(
    string Domain,
    int Score,
    string Status,
    bool Verified,
    bool VerifiedDomain,
    DateTimeOffset LastCheckedUtc,
    string LookupUrl,
    string PublicLookupUrl,
    string BadgeText,
    string BadgeVariant,
    string IdentityVerificationStatus,
    bool? SignatureValid,
    string VerifiedMeaning,
    string? ResponseSignature)
{
    public static PublicBadgeApiResponse From(PublicBadgeResponse badge) =>
        new(
            badge.Domain,
            badge.Score,
            badge.Status.ToString(),
            badge.VerifiedDomain,
            badge.VerifiedDomain,
            badge.LastCheckedUtc,
            badge.LookupUrl,
            badge.PublicLookupUrl,
            badge.BadgeText,
            badge.BadgeVariant,
            badge.IdentityVerificationStatus,
            badge.SignatureValid,
            badge.VerifiedMeaning,
            badge.ResponseSignature);
}

public sealed record PublicLookupApiResponse(
    string Domain,
    int Score,
    int FinalHipScore,
    int DomainTrustScore,
    int PageTrustScore,
    int ContentRiskScore,
    string FinalHipScoreExplanation,
    string Status,
    string RiskLevel,
    string VerificationStatus,
    IReadOnlyCollection<string> KnownRisks,
    IReadOnlyCollection<string> Reasons,
    IReadOnlyCollection<string> Explanations,
    string RecommendedAction,
    DateTimeOffset LastCheckedUtc,
    string SignedIdentityStatus,
    string VerificationMethod,
    string? VerifiedOrganization,
    string SignatureStatus,
    string IdentityVerificationStatus,
    bool? SignatureValid,
    bool PublicBadgeEligible,
    string PublicLookupUrl,
    IReadOnlyCollection<ScoreBreakdownApiItem> ScoreBreakdown,
    int? LinksScanned,
    int? RiskyLinksFound,
    int? SuspiciousLinksFound,
    int? DangerousLinksFound,
    string DataSource,
    string Message)
{
    /// <summary>
    /// Converts the application lookup response into the API shape while preserving privacy-safe scan summary fields only.
    /// </summary>
    /// <param name="lookup">Application lookup response.</param>
    /// <returns>API lookup response.</returns>
    public static PublicLookupApiResponse From(PublicDomainLookupResponse lookup) =>
        new(
            lookup.Domain,
            lookup.Score,
            lookup.FinalHipScore,
            lookup.DomainTrustScore,
            lookup.PageTrustScore,
            lookup.ContentRiskScore,
            lookup.FinalHipScoreExplanation,
            lookup.Status.ToString(),
            lookup.RiskLevel,
            lookup.VerificationStatus,
            lookup.KnownRisks,
            lookup.Reasons,
            lookup.Explanations,
            lookup.RecommendedAction,
            lookup.LastCheckedUtc,
            lookup.SignedIdentityStatus,
            lookup.VerificationMethod,
            lookup.VerifiedOrganization,
            lookup.SignatureStatus,
            lookup.IdentityVerificationStatus,
            lookup.SignatureValid,
            lookup.PublicBadgeEligible,
            lookup.PublicLookupUrl,
            lookup.ScoreBreakdown.Select(ScoreBreakdownApiItem.From).ToArray(),
            lookup.LinksScanned,
            lookup.RiskyLinksFound,
            lookup.SuspiciousLinksFound,
            lookup.DangerousLinksFound,
            lookup.DataSource,
            lookup.Message);
}

public sealed record ScoreBreakdownApiItem(
    string Category,
    int Score,
    string Status,
    string Explanation,
    IReadOnlyCollection<string> Reasons)
{
    public static ScoreBreakdownApiItem From(ScoreBreakdownItem item) =>
        new(item.Category, item.Score, item.Status.ToString(), item.Explanation, item.Reasons);
}

public partial class Program
{
    public static void MapJsonRulesApis(RouteGroupBuilder rulesApi)
    {
        rulesApi.MapGet("/", async (
            IRuleRepository repository,
            CancellationToken cancellationToken) =>
        {
            var rules = await RulesOrSamplesAsync(repository, cancellationToken);
            return Results.Ok(rules.Select(RuleApiResponse.From).ToArray());
        });

        rulesApi.MapGet("/{id}", async (
            string id,
            IRuleRepository repository,
            CancellationToken cancellationToken) =>
        {
            var rule = await repository.GetByIdAsync(id, cancellationToken)
                ?? SampleRules().FirstOrDefault(sample => sample.RuleId.Equals(id, StringComparison.OrdinalIgnoreCase));

            return rule is null ? Results.NotFound() : Results.Ok(RuleApiResponse.From(rule));
        });

        rulesApi.MapPost("/evaluate", (
            RuleEvaluationApiRequest request,
            IRuleEvaluationService evaluationService) =>
        {
            var rules = request.Rules is { Count: > 0 } ? request.Rules : SampleRules();
            return Results.Ok(RuleEvaluationApiResponse.From(evaluationService.Evaluate(rules, request.Context)));
        });

        rulesApi.MapPost("/simulate", async (
            RuleSimulationApiRequest request,
            IRuleRepository ruleRepository,
            IRuleSimulationService simulationService,
            IRuleSimulationResultRepository simulationRepository,
            CancellationToken cancellationToken) =>
        {
            var rule = request.Rule;
            if (rule is null && !string.IsNullOrWhiteSpace(request.RuleId))
            {
                rule = await ruleRepository.GetByIdAsync(request.RuleId, cancellationToken)
                    ?? SampleRules().FirstOrDefault(sample => sample.RuleId.Equals(request.RuleId, StringComparison.OrdinalIgnoreCase));
            }

            if (rule is null)
            {
                return Results.BadRequest(new { error = "A rule or known ruleId is required." });
            }

            var result = simulationService.Simulate(rule, request.TestCases);
            await simulationRepository.SaveAsync(result.SimulationId, result, cancellationToken);
            return Results.Ok(RuleSimulationApiResponse.From(result));
        });

        rulesApi.MapGet("/simulations/{id}", async (
            string id,
            IRuleSimulationResultRepository simulationRepository,
            CancellationToken cancellationToken) =>
        {
            var result = await simulationRepository.GetAsync(id, cancellationToken);
            return result is null ? Results.NotFound() : Results.Ok(RuleSimulationApiResponse.From(result));
        });
    }

    private static async Task<IReadOnlyCollection<TrustRule>> RulesOrSamplesAsync(IRuleRepository repository, CancellationToken cancellationToken)
    {
        var rules = await repository.ListAsync(cancellationToken);
        return rules.Count == 0 ? SampleRules() : rules;
    }

    private static IReadOnlyCollection<TrustRule> SampleRules() =>
    [
        new TrustRule(
            "new-domain-shortener-high-risk",
            "New Domain With Shortened URL",
            "Flags shortened links that resolve to new domains.",
            true,
            RuleMode.Watch,
            RuleSeverity.High,
            [
                new RuleCondition("domain.ageDays", RuleOperator.LessThan, JsonSerializer.SerializeToElement(30)),
                new RuleCondition("url.usesShortener", RuleOperator.Equals, JsonSerializer.SerializeToElement(true))
            ],
            [
                new RuleAction(RuleActionType.SetRiskLevel, JsonSerializer.SerializeToElement("HighRisk")),
                new RuleAction(RuleActionType.AddReason, JsonSerializer.SerializeToElement("This link is risky because it uses a shortener and resolves to a new domain.")),
                new RuleAction(RuleActionType.RouteToSafetyPage, JsonSerializer.SerializeToElement(true))
            ],
            true,
            true,
            "system",
            "MVP sample JSON rule.",
            ApprovalStatus.Pending,
            0m,
            1)
    ];

    public static string BuildBadgeScript(string domain)
    {
        var domainLiteral = JsonSerializer.Serialize(domain);
        return $$"""
(function renderHipLiveTrustBadge() {
  const domain = {{domainLiteral}};
  const currentScript = document.currentScript;
  const apiBase = currentScript && currentScript.src ? new URL(currentScript.src).origin : window.location.origin;
  const selector = `[data-hip-badge="${domain}"], .hip-trust-badge[data-domain="${domain}"]`;
  let container = document.querySelector(selector);
  if (!container) {
    container = document.createElement("div");
    container.setAttribute("data-hip-badge", domain);
    if (currentScript && currentScript.parentNode) {
      currentScript.parentNode.insertBefore(container, currentScript);
    } else {
      document.body.appendChild(container);
    }
  }

  ensureStyles();
  fetch(`${apiBase}/api/v1/badge/${encodeURIComponent(domain)}`, { headers: { "Accept": "application/json" } })
    .then(response => {
      if (!response.ok) {
        throw new Error(`HIP badge failed with status ${response.status}`);
      }
      return response.json();
    })
    .then(render)
    .catch(() => {
      container.innerHTML = `<a class="hip-live-badge hip-live-badge-unknown" href="${apiBase}/lookup/${encodeURIComponent(domain)}" target="_blank" rel="noopener noreferrer"><strong>HIP Unavailable</strong><span>Score: unavailable</span><span>Status: Unknown</span></a>`;
    });

  function render(badge) {
    const variant = String(badge.badgeVariant || badge.status || "unknown").replace(/[^a-z0-9]/gi, "").toLowerCase();
    const checked = badge.lastCheckedUtc ? new Date(badge.lastCheckedUtc).toLocaleDateString() : "Unknown";
    const lookupUrl = new URL(badge.lookupUrl || badge.publicLookupUrl || `/lookup/${badge.domain}`, apiBase).toString();
    container.innerHTML = `<a class="hip-live-badge hip-live-badge-${variant}" href="${escapeAttribute(lookupUrl)}" target="_blank" rel="noopener noreferrer"><strong>${badge.verified ? "HIP Verified" : "HIP Warning"}</strong><span>Score: ${escapeHtml(badge.score)}/100</span><span>Status: ${escapeHtml(badge.status)}</span><span>Verified domain: ${badge.verifiedDomain ? "Yes" : "No"}</span><small>Last checked: ${escapeHtml(checked)}</small><small>Verified identity does not automatically mean safe.</small></a>`;
  }

  function ensureStyles() {
    if (document.getElementById("hip-live-badge-style")) {
      return;
    }
    const style = document.createElement("style");
    style.id = "hip-live-badge-style";
    style.textContent = ".hip-live-badge{display:inline-grid;gap:2px;min-width:168px;padding:10px 12px;border:1px solid #cbd5e1;border-left:5px solid #64748b;border-radius:8px;background:#fff;color:#111827;font:12px/1.3 system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;text-decoration:none;box-shadow:0 6px 16px rgba(15,23,42,.12)}.hip-live-badge strong{font-size:13px;text-transform:uppercase}.hip-live-badge span{font-size:12px}.hip-live-badge small{font-size:11px;color:#475569}.hip-live-badge-trusted{border-left-color:#047857}.hip-live-badge-probablysafe{border-left-color:#0f766e}.hip-live-badge-caution{border-left-color:#ca8a04}.hip-live-badge-highrisk{border-left-color:#ea580c}.hip-live-badge-dangerous,.hip-live-badge-critical{border-left-color:#b91c1c}.hip-live-badge-unknown{border-left-color:#64748b}";
    document.head.appendChild(style);
  }

  function escapeHtml(value) {
    return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll("\"", "&quot;").replaceAll("'", "&#039;");
  }

  function escapeAttribute(value) {
    return escapeHtml(value);
  }
})();
""";
    }
}

/// <summary>
/// Public-safe admin response for external evidence provider settings.
/// </summary>
/// <param name="ExternalProvidersEnabled">Whether any external provider can run.</param>
/// <param name="AllowFullUrlChecks">Whether full URL checks are globally allowed.</param>
/// <param name="ProviderTimeout">Provider timeout.</param>
/// <param name="DefaultCacheDuration">Default provider cache duration.</param>
/// <param name="SslLabs">SSL Labs/Qualys-style TLS settings.</param>
/// <param name="GoogleWebRisk">Google Web Risk/Safe Browsing-style settings.</param>
/// <param name="VirusTotal">VirusTotal-style settings.</param>
sealed record ExternalProviderSettingsResponse(
    bool ExternalProvidersEnabled,
    bool AllowFullUrlChecks,
    TimeSpan ProviderTimeout,
    TimeSpan DefaultCacheDuration,
    ExternalProviderSettings SslLabs,
    ExternalProviderSettings GoogleWebRisk,
    ExternalProviderSettings VirusTotal)
{
    /// <summary>
    /// Converts runtime options into an admin-safe response.
    /// </summary>
    /// <param name="options">Runtime external evidence options.</param>
    /// <returns>Admin-safe settings response.</returns>
    public static ExternalProviderSettingsResponse From(ExternalSiteEvidenceOptions options) =>
        new(
            options.ExternalProvidersEnabled,
            options.AllowFullUrlChecks,
            options.ProviderTimeout,
            options.DefaultCacheDuration,
            ExternalProviderSettings.From(options.SslLabs),
            ExternalProviderSettings.From(options.GoogleWebRisk),
            ExternalProviderSettings.From(options.VirusTotal));
}

/// <summary>
/// Admin request for updating external evidence provider settings at runtime.
/// </summary>
/// <param name="ExternalProvidersEnabled">Whether any external provider can run.</param>
/// <param name="AllowFullUrlChecks">Whether full URL checks are globally allowed.</param>
/// <param name="ProviderTimeout">Provider timeout.</param>
/// <param name="DefaultCacheDuration">Default provider cache duration.</param>
/// <param name="SslLabs">SSL Labs/Qualys-style TLS settings.</param>
/// <param name="GoogleWebRisk">Google Web Risk/Safe Browsing-style settings.</param>
/// <param name="VirusTotal">VirusTotal-style settings.</param>
sealed record ExternalProviderSettingsUpdateRequest(
    bool ExternalProvidersEnabled,
    bool AllowFullUrlChecks,
    TimeSpan? ProviderTimeout,
    TimeSpan? DefaultCacheDuration,
    ExternalProviderSettings SslLabs,
    ExternalProviderSettings GoogleWebRisk,
    ExternalProviderSettings VirusTotal);

/// <summary>
/// Provider-specific settings that avoid exposing raw scanner response data.
/// </summary>
/// <param name="Enabled">Whether this provider can run when global external providers are enabled.</param>
/// <param name="Endpoint">Optional provider endpoint.</param>
/// <param name="ApiKey">Optional API key placeholder. Production should move secrets to secret storage.</param>
/// <param name="AllowFullUrl">Whether this provider may receive full URLs.</param>
/// <param name="CacheDuration">Optional provider cache duration.</param>
sealed record ExternalProviderSettings(
    bool Enabled,
    string? Endpoint,
    string? ApiKey,
    bool AllowFullUrl,
    TimeSpan? CacheDuration)
{
    /// <summary>
    /// Converts runtime provider options into the UI/API shape.
    /// </summary>
    /// <param name="options">Runtime provider options.</param>
    /// <returns>Provider settings.</returns>
    public static ExternalProviderSettings From(ExternalProviderOptions options) =>
        new(options.Enabled, options.Endpoint, options.ApiKey, options.AllowFullUrl, options.CacheDuration);
}

/// <summary>
/// API-facing simulator request that accepts source type as text for simple browser and cURL testing.
/// </summary>
/// <param name="Sender">Sender label or hash.</param>
/// <param name="MessageText">Simulated message text.</param>
/// <param name="SourceType">Source type name such as GroupChat or PrivateIM.</param>
/// <param name="DetectedUrls">Optional detected URL list.</param>
/// <param name="ScanMode">HUD scan mode.</param>
/// <param name="PopupAlertsEnabled">Whether popup alerts are enabled.</param>
/// <param name="PrivateWarningsEnabled">Whether private warnings are enabled.</param>
/// <param name="SafetyPageRoutingEnabled">Whether safety routing is enabled.</param>
sealed record SecondLifeHudSimulationApiRequest(
    string? Sender,
    string? MessageText,
    string SourceType,
    IReadOnlyCollection<string>? DetectedUrls,
    string ScanMode,
    bool PopupAlertsEnabled,
    bool PrivateWarningsEnabled,
    bool SafetyPageRoutingEnabled)
{
    /// <summary>
    /// Converts the API request into the application request after validating the source type string.
    /// </summary>
    /// <returns>The application simulator request.</returns>
    public SecondLifeHudSimulationRequest ToApplicationRequest()
    {
        if (!Enum.TryParse<SecondLifeHudSimulationSourceType>(SourceType, ignoreCase: true, out var sourceType))
        {
            throw new ArgumentException("Invalid SL HUD source type.");
        }

        return new SecondLifeHudSimulationRequest(
            Sender,
            MessageText,
            sourceType,
            DetectedUrls,
            ScanMode,
            PopupAlertsEnabled,
            PrivateWarningsEnabled,
            SafetyPageRoutingEnabled);
    }
}

/// <summary>
/// API-facing simulator response that serializes HUD action as text without changing global enum behavior.
/// </summary>
/// <param name="DetectedUrls">Detected URLs.</param>
/// <param name="RiskLevel">Risk level.</param>
/// <param name="Score">HIP score.</param>
/// <param name="Reasons">Plain-English reasons.</param>
/// <param name="RecommendedHudAction">Recommended HUD action name.</param>
/// <param name="OwnerWarningWouldShow">Whether owner warning would show.</param>
/// <param name="PopupWouldShow">Whether popup would show.</param>
/// <param name="SafetyPageWouldBeUsed">Whether safety page would be used.</param>
/// <param name="SafetyPageUrl">Safety page URL preview.</param>
/// <param name="PrivacySafePayload">Privacy-safe payload preview.</param>
/// <param name="RawPrivateTextExcluded">Whether raw private text is excluded.</param>
/// <param name="OwnerWarningPreview">Owner warning preview.</param>
/// <param name="PopupPreview">Popup preview.</param>
sealed record SecondLifeHudSimulationApiResponse(
    IReadOnlyCollection<string> DetectedUrls,
    string RiskLevel,
    int Score,
    IReadOnlyCollection<string> Reasons,
    string RecommendedHudAction,
    bool OwnerWarningWouldShow,
    bool PopupWouldShow,
    bool SafetyPageWouldBeUsed,
    string? SafetyPageUrl,
    IReadOnlyDictionary<string, string> PrivacySafePayload,
    bool RawPrivateTextExcluded,
    string? OwnerWarningPreview,
    string? PopupPreview)
{
    /// <summary>
    /// Converts the application result to an API-safe response with string action values.
    /// </summary>
    /// <param name="result">Application simulator result.</param>
    /// <returns>API response.</returns>
    public static SecondLifeHudSimulationApiResponse From(SecondLifeHudSimulationResult result) =>
        new(
            result.DetectedUrls,
            result.RiskLevel,
            result.Score,
            result.Reasons,
            result.RecommendedHudAction.ToString(),
            result.OwnerWarningWouldShow,
            result.PopupWouldShow,
            result.SafetyPageWouldBeUsed,
            result.SafetyPageUrl,
            result.PrivacySafePayload,
            result.RawPrivateTextExcluded,
            result.OwnerWarningPreview,
            result.PopupPreview);
}
