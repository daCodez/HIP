using System.IO.Compression;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.RateLimiting;
using System.Globalization;
using System.Security.Claims;
using HIP.Application;
using HIP.Application.Ai;
using HIP.Application.Browser;
using HIP.Application.Consumer;
using HIP.Application.Dashboard;
using HIP.Application.Identity;
using HIP.Application.PublicLookup;
using HIP.Application.Performance;
using HIP.Application.Platforms;
using HIP.Application.Reporting;
using HIP.Application.Reputation;
using HIP.Application.Review;
using HIP.Application.Rules;
using HIP.Application.Safety;
using HIP.Application.Scans;
using HIP.Application.Security;
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
using Microsoft.AspNetCore.OutputCaching;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);
const string HipInstanceIdHeader = "X-HIP-Instance-Id";

builder.AddServiceDefaults();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(new DevelopmentHipCryptoProviderOptions(builder.Environment.IsDevelopment()));
builder.Services.AddHipApplication();
builder.Services.AddSingleton(BindExternalSiteEvidenceOptions(builder.Configuration));
builder.Services.AddHipInfrastructure(builder.Configuration, builder.Environment.IsDevelopment());
builder.Services.AddOptions<HipPerformanceOptions>()
    .Bind(builder.Configuration.GetSection(HipPerformanceOptions.SectionName))
    .Validate(ValidateHipPerformanceOptions, "HIP performance options must use positive cache durations and request limits.")
    .ValidateOnStart();
builder.Services.AddOptions<HipSecurityOptions>()
    .Bind(builder.Configuration.GetSection(HipSecurityOptions.SectionName))
    .ValidateOnStart();
if (ShouldUseRedisOutputCache(builder.Configuration))
{
    builder.AddRedisOutputCache("redis");
}
builder.Services.AddOutputCache(options => ConfigureOutputCachePolicies(options, builder.Configuration));
builder.Services.AddResponseCompression(options =>
{
    // Response compression lowers bandwidth for badge scripts, JSON APIs, and Blazor assets without changing HIP scoring data.
    options.EnableForHttps = true;
    options.MimeTypes = ResponseCompressionDefaults.MimeTypes.Concat(["application/javascript", "application/json"]);
});
builder.Services.Configure<BrotliCompressionProviderOptions>(options => options.Level = CompressionLevel.Fastest);
builder.Services.Configure<GzipCompressionProviderOptions>(options => options.Level = CompressionLevel.Fastest);
builder.Services.AddHipAdminAuthorization();
builder.Services.Configure<HipAdminLoginOptions>(builder.Configuration.GetSection(HipAdminLoginOptions.SectionName));
builder.Services.AddSingleton<IPasswordHasher<string>, PasswordHasher<string>>();
builder.Services.AddHipAdminAuthenticationProvider<LocalPasswordAdminAuthenticationProvider>();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddCors(options =>
{
    var security = BindHipSecurityOptions(builder.Configuration);
    options.AddPolicy(HipCorsPolicies.PublicRead, policy =>
        policy.AllowAnyOrigin()
            .WithMethods("GET")
            .AllowAnyHeader());
    options.AddPolicy(HipCorsPolicies.ClientWrite, policy =>
        policy.SetIsOriginAllowed(origin => IsAllowedClientWriteOrigin(origin, security))
            .WithMethods("POST")
            .AllowAnyHeader());
});
builder.Services.AddRateLimiter(options =>
{
    var performance = BindHipPerformanceOptions(builder.Configuration);
    // Baseline public limits reduce data poisoning and DoS risk until HIP client signatures and stronger trust controls exist.
    options.AddPolicy(RateLimitPolicies.PublicScanPolicy, httpContext =>
        CreateFixedWindowPartition(httpContext, "scan", performance.PublicScanRequestsPerMinute));
    options.AddPolicy(RateLimitPolicies.PublicFeedbackPolicy, httpContext =>
        CreateFixedWindowPartition(httpContext, "feedback", performance.PublicFeedbackRequestsPerMinute));
    options.AddPolicy(RateLimitPolicies.IdentityDevPolicy, httpContext =>
        CreateFixedWindowPartition(httpContext, "identity", performance.IdentityRequestsPerMinute));
    options.AddPolicy(RateLimitPolicies.AdminLoginPolicy, httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            $"admin-login:{httpContext.Connection.RemoteIpAddress}",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(10),
                QueueLimit = 0,
                AutoReplenishment = true
            }));
    options.OnRejected = async (context, cancellationToken) =>
    {
        if (context.HttpContext.Request.Path.Equals("/auth/login", StringComparison.OrdinalIgnoreCase))
        {
            context.HttpContext.Response.Redirect("/login?error=too-many");
            return;
        }

        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        await context.HttpContext.Response.WriteAsJsonAsync(new { error = "Too many HIP requests. Try again shortly." }, cancellationToken);
    };
});
// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

var app = builder.Build();

await HipDatabaseInitializer.EnsureCreatedAsync(app.Services, app.Environment.IsDevelopment());

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
if (ShouldUseHttpsRedirection(app))
{
    app.UseHttpsRedirection();
}
app.UseCors(HipCorsPolicies.PublicRead);
app.UseResponseCompression();
app.UseRateLimiter();
app.UseOutputCache();
app.UseAuthentication();
app.UseAuthorization();

app.UseAntiforgery();

app.MapHipDevelopmentLogin();

MapPublicApis(app.MapGroup(ApiRoutes.Public));
MapReportApis(app.MapGroup($"{ApiRoutes.V1}/reports"));
MapBadgeApis(app.MapGroup(ApiRoutes.Badge));
MapBrowserApis(app.MapGroup(ApiRoutes.Browser));
MapSafetyApis(app.MapGroup(ApiRoutes.Safety));
MapSiteSafetyApis(app.MapGroup(ApiRoutes.SiteSafety));
MapAdminSiteSafetyRuleApis(app.MapGroup($"{ApiRoutes.Admin}/site-safety-rules").RequireAuthorization(AdminPolicies.CanManageRules));
Program.MapJsonRulesApis(app.MapGroup(ApiRoutes.Rules));
MapAiApis(app.MapGroup(ApiRoutes.Ai).RequireAuthorization(AdminPolicies.CanManageRules));
MapSelfHealingPatternApis(app.MapGroup(ApiRoutes.SelfHealing).RequireAuthorization(AdminPolicies.CanManageRules));
MapSecondLifeHudApis(app.MapGroup(ApiRoutes.SecondLifeHud));
MapLicenseApis(app.MapGroup(ApiRoutes.Licenses).RequireAuthorization(AdminPolicies.CanManageLicenses));
MapRulesApis(app.MapGroup($"{ApiRoutes.Admin}/rules").RequireAuthorization(AdminPolicies.CanManageRules));
MapSelfHealingApis(app.MapGroup($"{ApiRoutes.Admin}/self-healing").RequireAuthorization(AdminPolicies.CanManageRules));
MapReviewApis(app.MapGroup($"{ApiRoutes.Admin}/review").RequireAuthorization(AdminPolicies.CanReviewReports));
MapAdminReviewQueueApis(app.MapGroup($"{ApiRoutes.Admin}/review-queue").RequireAuthorization(AdminPolicies.CanReviewReports));
MapAppealApis(app.MapGroup($"{ApiRoutes.Admin}/appeals").RequireAuthorization(AdminPolicies.CanReviewReports));
MapReputationOverrideApis(app.MapGroup($"{ApiRoutes.Admin}/reputation-overrides").RequireAuthorization(AdminPolicies.CanApproveOverrides));
MapReputationApis(app.MapGroup($"{ApiRoutes.Admin}/reputation").RequireAuthorization(AdminPolicies.CanViewAdminDashboard));
MapDashboardApis(app.MapGroup($"{ApiRoutes.Admin}/dashboard").RequireAuthorization(AdminPolicies.CanViewAdminDashboard));
MapAdminScanApis(app.MapGroup($"{ApiRoutes.Admin}/scans").RequireAuthorization(AdminPolicies.CanViewAdminDashboard));
MapPlatformConnectionApis(app.MapGroup($"{ApiRoutes.Admin}/platforms").RequireAuthorization(AdminPolicies.CanViewAdminDashboard));
MapConsumerApis(app.MapGroup(ApiRoutes.Consumer).RequireAuthorization(ConsumerPolicies.CanUseConsumerPortal));
MapIdentityApis(app.MapGroup(ApiRoutes.Identity).RequireRateLimiting(RateLimitPolicies.IdentityDevPolicy));
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
app.MapGet($"{ApiRoutes.Admin}/site-safety/external-providers", async (
    HttpContext httpContext,
    ExternalSiteEvidenceOptions defaultOptions,
    IExternalSiteEvidenceSettingsStore settingsStore,
    CancellationToken cancellationToken) =>
{
    var scopeKey = ResolveProviderSettingsScope(httpContext);
    var options = await settingsStore.GetAsync(scopeKey, cancellationToken) ?? defaultOptions.Clone();
    return Results.Ok(ExternalProviderSettingsResponse.From(options, scopeKey));
})
    .RequireAuthorization(AdminPolicies.CanViewAdminDashboard);
app.MapPost($"{ApiRoutes.Admin}/site-safety/external-providers", async (
    ExternalProviderSettingsUpdateRequest request,
    HttpContext httpContext,
    ExternalSiteEvidenceOptions defaultOptions,
    IExternalSiteEvidenceSettingsStore settingsStore,
    CancellationToken cancellationToken) =>
{
    var scopeKey = ResolveProviderSettingsScope(httpContext);
    var options = defaultOptions.Clone();
    ApplyExternalProviderSettings(options, request);
    var saved = await settingsStore.SaveAsync(scopeKey, options, cancellationToken);
    return Results.Ok(ExternalProviderSettingsResponse.From(saved, scopeKey));
})
    .RequireAuthorization(AdminPolicies.CanManageRules);

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.MapDefaultEndpoints();

app.Run();

/// <summary>
/// Determines whether HTTPS redirection should be enabled for this host.
/// </summary>
/// <param name="app">The built web application.</param>
/// <returns>True when HIP should redirect HTTP requests to HTTPS.</returns>
/// <remarks>
/// Local Aspire and browser-extension testing often run HIP.Web on HTTP-only localhost ports.
/// In that mode ASP.NET Core cannot infer the target HTTPS port and logs a noisy warning.
/// Production keeps redirection enabled so public deployments still enforce HTTPS at the app edge.
/// </remarks>
static bool ShouldUseHttpsRedirection(WebApplication app) =>
    !app.Environment.IsDevelopment();

/// <summary>
/// Determines whether Redis-backed output caching should be enabled for this host.
/// </summary>
/// <param name="configuration">Application configuration that may include an Aspire Redis connection string.</param>
/// <returns>True when Redis output caching is both configured and allowed by HIP performance options.</returns>
static bool ShouldUseRedisOutputCache(IConfiguration configuration)
{
    var options = BindHipPerformanceOptions(configuration);
    return options.UseRedisOutputCacheWhenAvailable && !string.IsNullOrWhiteSpace(configuration.GetConnectionString("redis"));
}

/// <summary>
/// Configures named output-cache policies for high-volume public HIP reads.
/// </summary>
/// <param name="options">ASP.NET Core output-cache options.</param>
/// <param name="configuration">Application configuration used to bind cache durations.</param>
static void ConfigureOutputCachePolicies(OutputCacheOptions options, IConfiguration configuration)
{
    var performance = BindHipPerformanceOptions(configuration);
    options.AddPolicy(HipOutputCachePolicies.PublicLookup, policy =>
        policy.Expire(TimeSpan.FromSeconds(performance.PublicLookupCacheSeconds)).Tag("hip-public-lookup"));
    options.AddPolicy(HipOutputCachePolicies.Badge, policy =>
        policy.Expire(TimeSpan.FromSeconds(performance.BadgeCacheSeconds)).Tag("hip-badge"));
    options.AddPolicy(HipOutputCachePolicies.Safety, policy =>
        policy.Expire(TimeSpan.FromSeconds(performance.SafetyCacheSeconds)).Tag("hip-safety"));
    options.AddPolicy(HipOutputCachePolicies.SiteSafety, policy =>
        policy.Expire(TimeSpan.FromSeconds(performance.SiteSafetyCacheSeconds)).Tag("hip-site-safety"));
}

/// <summary>
/// Binds HIP performance options with safe defaults for direct local runs.
/// </summary>
/// <param name="configuration">Application configuration.</param>
/// <returns>Bound performance options.</returns>
static HipPerformanceOptions BindHipPerformanceOptions(IConfiguration configuration)
{
    var options = new HipPerformanceOptions();
    configuration.GetSection(HipPerformanceOptions.SectionName).Bind(options);
    return options;
}

/// <summary>
/// Binds HIP security options with safe defaults for local browser-extension testing.
/// </summary>
/// <param name="configuration">Application configuration.</param>
/// <returns>Bound security options.</returns>
static HipSecurityOptions BindHipSecurityOptions(IConfiguration configuration)
{
    var options = new HipSecurityOptions();
    configuration.GetSection(HipSecurityOptions.SectionName).Bind(options);
    return options;
}

/// <summary>
/// Determines whether a browser origin may send privacy-safe public write requests to HIP.Web.
/// </summary>
/// <param name="origin">Origin header supplied by the browser.</param>
/// <param name="options">Host-level security options.</param>
/// <returns>True when the origin is an explicitly configured HIP client or allowed local dev origin.</returns>
static bool IsAllowedClientWriteOrigin(string? origin, HipSecurityOptions options)
{
    if (string.IsNullOrWhiteSpace(origin))
    {
        return false;
    }

    if (options.AllowedClientWriteOrigins.Any(allowed => string.Equals(allowed, origin, StringComparison.OrdinalIgnoreCase)))
    {
        return true;
    }

    if (options.AllowBrowserExtensionOrigins
        && (origin.StartsWith("chrome-extension://", StringComparison.OrdinalIgnoreCase)
            || origin.StartsWith("moz-extension://", StringComparison.OrdinalIgnoreCase)
            || origin.StartsWith("ms-browser-extension://", StringComparison.OrdinalIgnoreCase)))
    {
        return true;
    }

    return options.AllowLocalhostClientWriteOrigins
        && Uri.TryCreate(origin, UriKind.Absolute, out var uri)
        && (uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
            || uri.Host.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase)
            || uri.Host.Equals("[::1]", StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// Validates performance options before the host accepts traffic.
/// </summary>
/// <param name="options">Bound performance options.</param>
/// <returns>True when all durations and limits are positive.</returns>
static bool ValidateHipPerformanceOptions(HipPerformanceOptions options) =>
    options.PublicLookupCacheSeconds > 0
    && options.BadgeCacheSeconds > 0
    && options.SafetyCacheSeconds > 0
    && options.SiteSafetyCacheSeconds > 0
    && options.PublicScanRequestsPerMinute > 0
    && options.PublicFeedbackRequestsPerMinute > 0
    && options.IdentityRequestsPerMinute > 0;

/// <summary>
/// Creates a fixed-window limiter partitioned by the best available privacy-safe client identifier.
/// </summary>
/// <param name="httpContext">Current HTTP request context.</param>
/// <param name="policyPrefix">Policy prefix used to keep scan, feedback, and identity budgets separate.</param>
/// <param name="permitLimit">Requests allowed per minute for the partition.</param>
/// <returns>Partitioned fixed-window limiter for the request.</returns>
static RateLimitPartition<string> CreateFixedWindowPartition(HttpContext httpContext, string policyPrefix, int permitLimit) =>
    RateLimitPartition.GetFixedWindowLimiter(
        ResolveRateLimitPartitionKey(httpContext, policyPrefix),
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = permitLimit,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        });

/// <summary>
/// Resolves a bounded rate-limit partition from API key, HIP signer, browser instance, domain, or client IP.
/// </summary>
/// <param name="httpContext">Current HTTP request context.</param>
/// <param name="policyPrefix">Policy prefix used to isolate named budgets.</param>
/// <returns>Privacy-safe partition key.</returns>
static string ResolveRateLimitPartitionKey(HttpContext httpContext, string policyPrefix)
{
    var candidate =
        httpContext.Request.Headers["X-HIP-API-Key"].FirstOrDefault()
        ?? httpContext.Request.Headers["X-HIP-Signer"].FirstOrDefault()
        ?? httpContext.Request.Headers[HipInstanceIdHeader].FirstOrDefault()
        ?? httpContext.Request.RouteValues["domain"]?.ToString()
        ?? httpContext.Connection.RemoteIpAddress?.ToString()
        ?? "anonymous";

    return $"{policyPrefix}:{NormalizeSettingsScopeSegment(candidate)}";
}

/// <summary>
/// Resolves provider settings scope from authenticated admin identity plus optional browser instance id.
/// </summary>
/// <param name="httpContext">Current HTTP context.</param>
/// <returns>Stable scope key for provider settings.</returns>
static string ResolveProviderSettingsScope(HttpContext httpContext)
{
    var userName = NormalizeSettingsScopeSegment(httpContext.User.Identity?.Name);
    var instanceId = NormalizeSettingsScopeSegment(httpContext.Request.Headers[HipInstanceIdHeader].FirstOrDefault());
    return $"user:{userName}:instance:{instanceId}";
}

/// <summary>
/// Normalizes untrusted user or instance identifiers before they are used as in-memory setting keys.
/// </summary>
/// <param name="value">Raw identity or browser instance value.</param>
/// <returns>Bounded key segment containing only safe characters.</returns>
static string NormalizeSettingsScopeSegment(string? value)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return "default";
    }

    var chars = value.Trim()
        .Where(character => char.IsLetterOrDigit(character) || character is '-' or '_' or '.' or '@')
        .Take(96)
        .ToArray();

    return chars.Length == 0 ? "default" : new string(chars);
}

/// <summary>
/// Loads request-scoped external provider settings for browser-originated scans routed through HIP.Web.
/// </summary>
/// <param name="httpContext">Current HTTP context.</param>
/// <param name="settingsStore">Scoped provider settings store.</param>
/// <param name="cancellationToken">Token used to cancel the lookup.</param>
/// <returns>Scoped options or null when defaults should apply.</returns>
static Task<ExternalSiteEvidenceOptions?> LoadScopedExternalProviderOptionsAsync(
    HttpContext httpContext,
    IExternalSiteEvidenceSettingsStore settingsStore,
    CancellationToken cancellationToken) =>
    settingsStore.GetAsync(ResolveProviderSettingsScope(httpContext), cancellationToken);

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
/// Detects repeated public feedback submissions without storing raw feedback bodies as throttling keys.
/// </summary>
/// <param name="feedback">Submitted reputation feedback.</param>
/// <param name="duplicateGuard">In-memory duplicate guard that hashes fingerprint parts internally.</param>
/// <returns>True when the same feedback was already accepted recently.</returns>
static bool IsDuplicateFeedback(ReputationFeedbackRequest feedback, IDuplicateSubmissionGuard duplicateGuard) =>
    !duplicateGuard.TryAccept(
        "web-public-feedback",
        [
            feedback.TargetType.ToString(),
            feedback.TargetId,
            feedback.EventType.ToString(),
            feedback.Severity.ToString(),
            feedback.ReporterTrustLevel.ToString(),
            feedback.Platform,
            feedback.UrlHash,
            feedback.Reason
        ],
        TimeSpan.FromMinutes(5));

/// <summary>
/// Detects repeated privacy-safe report submissions before they enter the reporting service.
/// </summary>
/// <param name="report">Submitted report payload.</param>
/// <param name="duplicateGuard">In-memory duplicate guard that hashes fingerprint parts internally.</param>
/// <returns>True when an equivalent report was already accepted recently.</returns>
static bool IsDuplicatePrivacySafeReport(PrivacySafeReport report, IDuplicateSubmissionGuard duplicateGuard) =>
    !duplicateGuard.TryAccept(
        "web-privacy-safe-report",
        [
            report.ReportType.ToString(),
            report.Source.ToString(),
            report.Platform.ToString(),
            report.Domain,
            report.UrlHash ?? report.RiskyUrl,
            report.SenderHash,
            report.DeviceHash,
            report.RiskLevel.ToString(),
            report.ReasonSummary,
            report.PrivacySafeEvidence.EvidenceType,
            report.PrivacySafeEvidence.Summary
        ],
        TimeSpan.FromMinutes(5));

/// <summary>
/// Detects repeated risk finding submissions so public clients cannot spam the review queue with identical signals.
/// </summary>
/// <param name="report">Risk finding submitted by a HIP client.</param>
/// <param name="duplicateGuard">In-memory duplicate guard that hashes fingerprint parts internally.</param>
/// <returns>True when an equivalent finding was already accepted recently.</returns>
static bool IsDuplicateRiskFinding(RiskFindingReport report, IDuplicateSubmissionGuard duplicateGuard) =>
    !duplicateGuard.TryAccept(
        "web-risk-finding",
        [
            report.SourceClient.ToString(),
            report.Platform.ToString(),
            report.TargetType.ToString(),
            report.Domain,
            report.UrlHash ?? report.OriginalUrl,
            report.SenderHash,
            report.RiskLevel.ToString(),
            report.Reason,
            report.PrivacySafeEvidence.EvidenceType,
            report.PrivacySafeEvidence.Summary
        ],
        TimeSpan.FromMinutes(5));

/// <summary>
/// Detects replayed browser scan summaries while allowing fresh scans with new timestamps or URL hashes.
/// </summary>
/// <param name="request">Browser plugin scan result request.</param>
/// <param name="duplicateGuard">In-memory duplicate guard that hashes fingerprint parts internally.</param>
/// <returns>True when an equivalent scan result was already accepted recently.</returns>
static bool IsDuplicateBrowserScanResult(BrowserScanResultSaveRequest request, IDuplicateSubmissionGuard duplicateGuard) =>
    !duplicateGuard.TryAccept(
        "web-browser-scan-result",
        [
            request.Domain,
            request.PageUrlHash ?? request.PageUrl,
            request.Score.ToString(CultureInfo.InvariantCulture),
            request.Status,
            request.RiskLevel,
            request.LinksScanned.ToString(CultureInfo.InvariantCulture),
            request.RiskyLinksFound.ToString(CultureInfo.InvariantCulture),
            request.SuspiciousLinksFound.ToString(CultureInfo.InvariantCulture),
            request.DangerousLinksFound.ToString(CultureInfo.InvariantCulture),
            request.PluginVersion,
            request.ScannedAtUtc?.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            request.PrivacySafeMetadata is null ? null : string.Join(';', request.PrivacySafeMetadata.OrderBy(pair => pair.Key).Select(pair => $"{pair.Key}={pair.Value}"))
        ],
        TimeSpan.FromSeconds(30));

/// <summary>
/// Detects repeated Site Safety scan requests so public clients cannot rapidly replay the same signal payload.
/// </summary>
/// <param name="request">Site Safety scan request.</param>
/// <param name="duplicateGuard">In-memory duplicate guard that hashes fingerprint parts internally.</param>
/// <returns>True when an equivalent scan request was already accepted recently.</returns>
static bool IsDuplicateSiteSafetyScan(SiteSafetyScanRequest request, IDuplicateSubmissionGuard duplicateGuard) =>
    !duplicateGuard.TryAccept(
        "web-site-safety-scan",
        SiteSafetyFingerprintParts(request),
        TimeSpan.FromSeconds(20));

/// <summary>
/// Builds a privacy-safe fingerprint from structured scan fields rather than raw page content.
/// </summary>
/// <param name="request">Site Safety scan request.</param>
/// <returns>Stable fingerprint parts used only by the duplicate guard.</returns>
static IEnumerable<string?> SiteSafetyFingerprintParts(SiteSafetyScanRequest request)
{
    var signals = request.ObservedSignals;
    yield return request.Url;
    yield return request.PluginVersion;
    yield return signals?.InlineScriptCount.ToString(CultureInfo.InvariantCulture);
    yield return signals?.SuspiciousScriptPatternCount.ToString(CultureInfo.InvariantCulture);
    yield return signals?.HasLoginForm.ToString();
    yield return signals?.HasPasswordField.ToString();
    yield return signals?.HasPaymentField.ToString();
    yield return signals?.KnownAbuseReports.ToString(CultureInfo.InvariantCulture);
    yield return signals?.ShortenedLinkCount.ToString(CultureInfo.InvariantCulture);
    yield return signals?.ObfuscatedLinkCount.ToString(CultureInfo.InvariantCulture);
    yield return signals?.DomainReputationScore?.ToString(CultureInfo.InvariantCulture);
    yield return signals?.PageReputationScore?.ToString(CultureInfo.InvariantCulture);
    yield return signals?.RedirectChain is null ? null : string.Join('|', signals.RedirectChain);
    yield return signals?.ExternalScriptUrls is null ? null : string.Join('|', signals.ExternalScriptUrls);
    yield return signals?.DownloadLinks is null ? null : string.Join('|', signals.DownloadLinks);
    yield return signals?.MatchedRiskTerms is null ? null : string.Join('|', signals.MatchedRiskTerms);
}

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
/// Maps development-only browser login helpers for manually testing protected admin pages.
/// </summary>
/// <param name="app">Web application route builder.</param>
/// <summary>
/// Applies admin-managed external evidence provider settings to the runtime options object.
/// </summary>
/// <param name="options">Runtime options used by Site Safety providers.</param>
/// <param name="request">Requested settings from an authorized admin.</param>
static void ApplyExternalProviderSettings(ExternalSiteEvidenceOptions options, ExternalProviderSettingsUpdateRequest request)
{
    options.ExternalProvidersEnabled = request.ExternalProvidersEnabled;
    options.AllowFullUrlChecks = request.AllowFullUrlChecks;
    options.ProviderTimeout = request.ProviderTimeout is { Ticks: > 0 } ? request.ProviderTimeout.Value : TimeSpan.FromSeconds(10);
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
    })
        .CacheOutput(HipOutputCachePolicies.PublicLookup);

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
    })
        .CacheOutput(HipOutputCachePolicies.PublicLookup);

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
    })
        .RequireCors(HipCorsPolicies.ClientWrite);

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
        .CacheOutput(HipOutputCachePolicies.Badge);

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
    })
        .RequireCors(HipCorsPolicies.ClientWrite)
        .RequireRateLimiting(RateLimitPolicies.PublicFeedbackPolicy);

    publicApi.MapPost("/feedback", async (
        ReputationFeedbackRequest feedback,
        IDuplicateSubmissionGuard duplicateGuard,
        IReputationService reputationService,
        IWeightedFeedbackAggregationService weightedFeedbackService,
        IAdminReviewQueueService reviewQueueService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            if (IsDuplicateFeedback(feedback, duplicateGuard))
            {
                return Results.Conflict(new { error = "Duplicate feedback submission ignored." });
            }

            await StoreWeightedFeedbackIfDomainAsync(feedback, weightedFeedbackService, reviewQueueService, cancellationToken);
            return Results.Ok(await reputationService.SubmitFeedbackAsync(feedback, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
        .RequireCors(HipCorsPolicies.ClientWrite)
        .RequireRateLimiting(RateLimitPolicies.PublicFeedbackPolicy);

    publicApi.MapPost("/risk-findings", async (
        RiskFindingReport report,
        HttpContext httpContext,
        IDuplicateSubmissionGuard duplicateGuard,
        IRiskFindingIngestionService ingestionService,
        IPrivacyHashingService privacyHashingService,
        CancellationToken cancellationToken) =>
    {
        var consumerId = httpContext.User.FindFirst("hip_consumer_id")?.Value;
        var ownedReport = report with
        {
            ConsumerScopeHash = string.IsNullOrWhiteSpace(consumerId) ? null : privacyHashingService.Hash(consumerId)
        };

        if (IsDuplicateRiskFinding(ownedReport, duplicateGuard))
        {
            return Results.Conflict(new { error = "Duplicate risk finding ignored." });
        }

        var response = await ingestionService.IngestAsync(ownedReport, cancellationToken);
        return response.Accepted ? Results.Ok(response) : Results.BadRequest(response);
    })
        .RequireCors(HipCorsPolicies.ClientWrite)
        .RequireRateLimiting(RateLimitPolicies.PublicFeedbackPolicy);
}

static void MapReportApis(RouteGroupBuilder reportApi)
{
    reportApi.MapPost("/", async (
        PrivacySafeReport report,
        IDuplicateSubmissionGuard duplicateGuard,
        IPrivacySafeReportService reportService,
        CancellationToken cancellationToken) =>
    {
        if (IsDuplicatePrivacySafeReport(report, duplicateGuard))
        {
            return Results.Conflict(new PrivacySafeReportResponse(false, null, report.Status, null, report.UrlHash, "Duplicate report ignored."));
        }

        var result = await reportService.SubmitAsync(report, cancellationToken);
        return result.Accepted ? Results.Ok(result) : Results.BadRequest(result);
    })
        .RequireCors(HipCorsPolicies.ClientWrite)
        .RequireRateLimiting(RateLimitPolicies.PublicFeedbackPolicy);
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

/// <summary>
/// Maps protected admin scan detail endpoints that expose only privacy-safe scan explanations.
/// </summary>
/// <param name="scanApi">Versioned admin scan route group.</param>
static void MapAdminScanApis(RouteGroupBuilder scanApi)
{
    scanApi.MapGet("/{scanId}", async (
        string scanId,
        IAdminScanDetailService scanDetailService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            var detail = await scanDetailService.GetAsync(scanId, cancellationToken);
            return detail is null
                ? Results.NotFound(new { error = "Scan result was not found." })
                : Results.Ok(detail);
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });
}

/// <summary>
/// Maps admin platform connection endpoints. Mutations are restricted to Owner/Admin roles because platform connectors
/// control future ingestion paths and must not be writable by read-only dashboard users.
/// </summary>
/// <param name="platformApi">Versioned admin platform route group.</param>
static void MapPlatformConnectionApis(RouteGroupBuilder platformApi)
{
    platformApi.MapGet("/", async (
        IPlatformConnectionService platformService,
        CancellationToken cancellationToken) =>
    {
        var connections = await platformService.ListAsync(cancellationToken);
        return Results.Ok(connections);
    })
    .WithName("ListPlatformConnections")
    .WithSummary("List configured platform connections")
    .WithDescription("Returns privacy-safe admin metadata for configured platform connections. Raw platform tokens and webhook URLs are never returned.")
    .Produces<IReadOnlyCollection<PlatformConnectionResponse>>();

    platformApi.MapGet("/discord", async (
        IPlatformConnectionService platformService,
        CancellationToken cancellationToken) =>
    {
        var connection = await platformService.GetDiscordAsync(cancellationToken);
        return connection is null
            ? Results.NotFound(new { error = "Discord is not connected yet." })
            : Results.Ok(connection);
    })
    .WithName("GetDiscordPlatformConnection")
    .WithSummary("Get the Discord platform connection")
    .WithDescription("Returns the saved Discord bot/OAuth connection state without exposing raw bot tokens or optional outbound alert webhook URLs.")
    .Produces<PlatformConnectionResponse>();

    platformApi.MapPost("/discord/connect", async (
        ConnectDiscordPlatformRequest request,
        IPlatformConnectionService platformService,
        HttpContext httpContext,
        CancellationToken cancellationToken) =>
    {
        try
        {
            var connection = await platformService.ConnectDiscordAsync(request, ResolveAdminActor(httpContext), cancellationToken);
            return Results.Ok(connection);
        }
        catch (ArgumentException exception)
        {
            return Results.BadRequest(new { error = exception.Message });
        }
    })
    .RequireAuthorization(AdminPolicies.CanManagePlatforms)
    .WithName("ConnectDiscordPlatform")
    .WithSummary("Connect Discord as a HIP bot platform")
    .WithDescription("Saves Discord bot/OAuth metadata for privacy-safe server-channel ingestion. Optional webhook URLs are treated only as outbound alert destinations; HIP hashes them and records only whether bot credentials are configured.")
    .Produces<PlatformConnectionResponse>();

    platformApi.MapPost("/discord/disable", async (
        IPlatformConnectionService platformService,
        HttpContext httpContext,
        CancellationToken cancellationToken) =>
    {
        var connection = await platformService.DisableDiscordAsync(ResolveAdminActor(httpContext), cancellationToken);
        return connection is null
            ? Results.NotFound(new { error = "Discord is not connected yet." })
            : Results.Ok(connection);
    })
    .RequireAuthorization(AdminPolicies.CanManagePlatforms)
    .WithName("DisableDiscordPlatform")
    .WithSummary("Disable the Discord platform connection")
    .WithDescription("Disables Discord ingestion without deleting saved admin metadata, preserving history and avoiding accidental data loss.")
    .Produces<PlatformConnectionResponse>();
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
    })
        .CacheOutput(HipOutputCachePolicies.Badge);

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
    })
        .CacheOutput(HipOutputCachePolicies.Badge);
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
    })
        .RequireCors(HipCorsPolicies.ClientWrite)
        .RequireRateLimiting(RateLimitPolicies.PublicScanPolicy);

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
        .RequireCors(HipCorsPolicies.ClientWrite)
        .RequireRateLimiting(RateLimitPolicies.PublicScanPolicy);

    browserApi.MapPost("/scan-results", async (
        BrowserScanResultSaveRequest request,
        IDuplicateSubmissionGuard duplicateGuard,
        IBrowserScanResultService scanResultService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            if (IsDuplicateBrowserScanResult(request, duplicateGuard))
            {
                return Results.Conflict(new BrowserScanResultErrorResponse("Duplicate browser scan result ignored."));
            }

            return Results.Ok(await scanResultService.SaveAsync(request, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new BrowserScanResultErrorResponse(ex.Message));
        }
    })
        .RequireCors(HipCorsPolicies.ClientWrite)
        .RequireRateLimiting(RateLimitPolicies.PublicScanPolicy);

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
    })
        .RequireCors(HipCorsPolicies.ClientWrite)
        .RequireRateLimiting(RateLimitPolicies.PublicScanPolicy);

    safetyApi.MapPost("/report-safe", (SafetyReportRequest request) =>
        Results.Ok(SafetyReportResponse.CreateAccepted(SafetyUrlDisplay.StripQueryAndFragment(request.Url), request.Source, "Report as safe was accepted for MVP review.")))
        .RequireCors(HipCorsPolicies.ClientWrite)
        .RequireRateLimiting(RateLimitPolicies.PublicFeedbackPolicy);

    safetyApi.MapPost("/report-dangerous", (SafetyReportRequest request) =>
        Results.Ok(SafetyReportResponse.CreateAccepted(SafetyUrlDisplay.StripQueryAndFragment(request.Url), request.Source, "Report as dangerous was accepted for MVP review.")))
        .RequireCors(HipCorsPolicies.ClientWrite)
        .RequireRateLimiting(RateLimitPolicies.PublicFeedbackPolicy);
}

/// <summary>
/// Maps the versioned Site Safety Scan endpoint used by HIP clients and public tools.
/// </summary>
/// <param name="siteSafetyApi">Versioned site safety route group.</param>
static void MapSiteSafetyApis(RouteGroupBuilder siteSafetyApi)
{
    siteSafetyApi.MapPost("/scan", async (
        SiteSafetyScanRequest request,
        HttpContext httpContext,
        IDuplicateSubmissionGuard duplicateGuard,
        ExternalSiteEvidenceOptions defaultOptions,
        IExternalSiteEvidenceSettingsStore settingsStore,
        ISiteSafetyScanner scanner,
        ISiteSafetyScanResultStorageService scanResultStorageService,
        IAdminReviewQueueService reviewQueueService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            if (IsDuplicateSiteSafetyScan(request, duplicateGuard))
            {
                return Results.Conflict(new { error = "Duplicate site safety scan ignored." });
            }

            var scopedOptions = await LoadScopedExternalProviderOptionsAsync(httpContext, settingsStore, cancellationToken);
            using var _ = defaultOptions.UseScopedOverride(scopedOptions);
            var result = await scanner.ScanAsync(request, cancellationToken);
            await scanResultStorageService.SaveAsync(request, result, cancellationToken);
            await reviewQueueService.CreateSignalsFromScanAsync(result, cancellationToken);
            return Results.Ok(ToSiteSafetyScanResponse(result));
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
        .RequireCors(HipCorsPolicies.ClientWrite)
        .RequireRateLimiting(RateLimitPolicies.PublicScanPolicy);

    siteSafetyApi.MapPost("/external-evidence/check", async (
        SiteSafetyScanRequest request,
        HttpContext httpContext,
        ExternalSiteEvidenceOptions defaultOptions,
        IExternalSiteEvidenceSettingsStore settingsStore,
        IExternalSiteEvidenceCollector collector,
        CancellationToken cancellationToken) =>
    {
        try
        {
            var scopedOptions = await LoadScopedExternalProviderOptionsAsync(httpContext, settingsStore, cancellationToken);
            using var _ = defaultOptions.UseScopedOverride(scopedOptions);
            var evidence = await collector.CollectAsync(request, cancellationToken);
            var domain = evidence.FirstOrDefault()?.Domain ?? new Uri(request.Url, UriKind.Absolute).Host.Trim().TrimEnd('.').ToLowerInvariant();
            var checkedAtUtc = evidence.FirstOrDefault()?.CheckedAtUtc ?? DateTimeOffset.UtcNow;
            return Results.Ok(new
            {
                Domain = domain,
                CheckedAtUtc = checkedAtUtc,
                ProviderEvidence = ToSiteSafetyProviderEvidenceResponse(evidence)
            });
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException or UriFormatException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
        .RequireCors(HipCorsPolicies.ClientWrite)
        .RequireRateLimiting(RateLimitPolicies.PublicScanPolicy);
}

/// <summary>
/// Maps protected admin-managed Site Safety rule endpoints.
/// </summary>
/// <param name="adminRuleApi">Versioned admin Site Safety rule route group.</param>
static void MapAdminSiteSafetyRuleApis(RouteGroupBuilder adminRuleApi)
{
    adminRuleApi.MapGet("/", async (
        IAdminSiteSafetyRuleRepository repository,
        CancellationToken cancellationToken) =>
        Results.Ok(await repository.ListAsync(cancellationToken)));

    adminRuleApi.MapGet("/{ruleId}", async (
        string ruleId,
        IAdminSiteSafetyRuleRepository repository,
        CancellationToken cancellationToken) =>
    {
        var rule = await repository.GetByIdAsync(ruleId, cancellationToken);
        return rule is null ? Results.NotFound() : Results.Ok(rule);
    });

    adminRuleApi.MapPost("/", async (
        AdminSiteSafetyRule rule,
        AdminSiteSafetyRuleService service,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await service.CreateAsync(rule, cancellationToken));
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    adminRuleApi.MapPost("/{ruleId}/simulate", async (
        string ruleId,
        AdminSiteSafetyRuleSimulationInput input,
        IAdminSiteSafetyRuleRepository repository,
        AdminSiteSafetyRuleService service,
        CancellationToken cancellationToken) =>
    {
        try
        {
            var rule = await repository.GetByIdAsync(ruleId, cancellationToken);
            return rule is null ? Results.NotFound() : Results.Ok(service.Simulate(rule, input));
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    adminRuleApi.MapPost("/{ruleId}/approve", async (
        string ruleId,
        AdminSiteSafetyRuleActionRequest request,
        AdminSiteSafetyRuleService service,
        CancellationToken cancellationToken) =>
        await RunRuleActionAsync(() => service.ApproveAsync(ruleId, request.ActorId, cancellationToken)));

    adminRuleApi.MapPost("/{ruleId}/activate", async (
        string ruleId,
        AdminSiteSafetyRuleActionRequest request,
        AdminSiteSafetyRuleService service,
        CancellationToken cancellationToken) =>
        await RunRuleActionAsync(() => service.ActivateAsync(ruleId, request.ActorId, cancellationToken)));

    adminRuleApi.MapPost("/{ruleId}/disable", async (
        string ruleId,
        AdminSiteSafetyRuleActionRequest request,
        AdminSiteSafetyRuleService service,
        CancellationToken cancellationToken) =>
        await RunRuleActionAsync(() => service.DisableAsync(ruleId, request.ActorId, cancellationToken)));

    adminRuleApi.MapPost("/{ruleId}/rollback", async (
        string ruleId,
        AdminSiteSafetyRuleActionRequest request,
        AdminSiteSafetyRuleService service,
        CancellationToken cancellationToken) =>
        await RunRuleActionAsync(() => service.RollbackAsync(ruleId, request.ActorId, cancellationToken)));
}

/// <summary>
/// Converts admin rule action exceptions into safe API responses.
/// </summary>
/// <param name="action">Rule lifecycle action to run.</param>
/// <returns>HTTP result for the admin rule action.</returns>
static async Task<IResult> RunRuleActionAsync(Func<Task<AdminSiteSafetyRule>> action)
{
    try
    {
        return Results.Ok(await action());
    }
    catch (InvalidOperationException ex)
    {
        return ex.Message.Contains("not found", StringComparison.OrdinalIgnoreCase)
            ? Results.NotFound(new { error = ex.Message })
            : Results.BadRequest(new { error = ex.Message });
    }
    catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
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
    ProviderEvidence = ToSiteSafetyProviderEvidenceResponse(result.ProviderEvidence),
    result.ScoreImpact
};

/// <summary>
/// Converts provider evidence to the public-safe anonymous JSON shape used by HIP.Web local APIs.
/// </summary>
/// <param name="providerEvidence">Normalized evidence records from a scan or explicit external check.</param>
/// <returns>Public-safe provider evidence objects.</returns>
/// <remarks>
/// Updated 2026-06-21 10:57 UTC by HIP Development Team. Assisted by Codex.
/// Keeping this helper shared prevents the local Web API from showing different provider details than the
/// main ApiService route.
/// </remarks>
static object[] ToSiteSafetyProviderEvidenceResponse(IEnumerable<SiteSafetyEvidence> providerEvidence) =>
    providerEvidence.Select(evidence => new
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
    }).ToArray();

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

/// <summary>
/// Resolves the current admin actor label for audit-friendly metadata without exposing authentication internals.
/// </summary>
/// <param name="httpContext">Current HTTP request context.</param>
/// <returns>Admin actor label suitable for persistence in privacy-safe admin records.</returns>
static string ResolveAdminActor(HttpContext httpContext) =>
    httpContext.User.Identity?.Name
    ?? httpContext.User.FindFirst("name")?.Value
    ?? "local-admin";

static void MapSecondLifeHudApis(RouteGroupBuilder slHudApi)
{
    const string hudCredentialHeader = "X-HIP-HUD-Credential";

    slHudApi.MapPost("/activate", (
        SecondLifeHudActivationRequest request,
        ISecondLifeHudService hudService) =>
    {
        var response = hudService.Activate(request);
        return response.Activated ? Results.Ok(response) : Results.BadRequest(response);
    });

    slHudApi.MapPost("/scan", (
        SecondLifeHudScanRequest request,
        HttpContext httpContext,
        ISecondLifeHudService hudService,
        IHudDeviceCredentialService credentialService) =>
    {
        try
        {
            if (!credentialService.IsValid(request.DeviceId, httpContext.Request.Headers[hudCredentialHeader].FirstOrDefault()))
            {
                return Results.Unauthorized();
            }

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
        HttpContext httpContext,
        ISecondLifeHudService hudService,
        IHudDeviceCredentialService credentialService) =>
    {
        try
        {
            if (!credentialService.IsValid(deviceId, httpContext.Request.Headers[hudCredentialHeader].FirstOrDefault()))
            {
                return Results.Unauthorized();
            }

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
        HttpContext httpContext,
        ISecondLifeHudService hudService,
        IHudDeviceCredentialService credentialService) =>
    {
        try
        {
            if (!credentialService.IsValid(deviceId, httpContext.Request.Headers[hudCredentialHeader].FirstOrDefault()))
            {
                return Results.Unauthorized();
            }

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
        HttpContext httpContext,
        ISecondLifeHudService hudService,
        IHudDeviceCredentialService credentialService,
        CancellationToken cancellationToken) =>
    {
        if (!credentialService.IsValid(report.HudDeviceId, httpContext.Request.Headers[hudCredentialHeader].FirstOrDefault()))
        {
            return Results.Unauthorized();
        }

        var response = await hudService.ReportFindingAsync(report, cancellationToken);
        return response.Accepted ? Results.Ok(response) : Results.BadRequest(response);
    });

    slHudApi.MapPost("/report-finding", async (
        SecondLifeHudFindingReport report,
        HttpContext httpContext,
        ISecondLifeHudService hudService,
        IHudDeviceCredentialService credentialService,
        CancellationToken cancellationToken) =>
    {
        if (!credentialService.IsValid(report.HudDeviceId, httpContext.Request.Headers[hudCredentialHeader].FirstOrDefault()))
        {
            return Results.Unauthorized();
        }

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

/// <summary>
/// Maps privacy-safe admin review-signal endpoints used by Site Safety, feedback, and future self-healing flows.
/// </summary>
/// <param name="adminReviewQueueApi">Versioned admin review queue route group.</param>
static void MapAdminReviewQueueApis(RouteGroupBuilder adminReviewQueueApi)
{
    adminReviewQueueApi.MapGet("/", async (
        IAdminReviewQueueService adminReviewQueueService,
        CancellationToken cancellationToken) =>
        Results.Ok(await adminReviewQueueService.ListAsync(cancellationToken)));

    adminReviewQueueApi.MapGet("/{id}", async (
        string id,
        IAdminReviewQueueService adminReviewQueueService,
        CancellationToken cancellationToken) =>
    {
        var item = await adminReviewQueueService.GetAsync(id, cancellationToken);
        return item is null ? Results.NotFound() : Results.Ok(item);
    });

    adminReviewQueueApi.MapPost("/{id}/assign", async (
        string id,
        AdminReviewQueueAssignRequest request,
        IAdminReviewQueueService adminReviewQueueService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await adminReviewQueueService.AssignAsync(id, request.AssignedTo, request.ActorId, cancellationToken));
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    adminReviewQueueApi.MapPost("/{id}/decision", async (
        string id,
        HIP.Application.Review.AdminReviewDecisionRequest request,
        IAdminReviewQueueService adminReviewQueueService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await adminReviewQueueService.RecordDecisionAsync(id, request, cancellationToken));
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    adminReviewQueueApi.MapPost("/{id}/dismiss", async (
        string id,
        AdminReviewQueueDismissRequest request,
        IAdminReviewQueueService adminReviewQueueService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await adminReviewQueueService.DismissAsync(id, request.ActorId, request.Reason, cancellationToken));
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });
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
        HttpContext httpContext,
        IHipIdentityService identityService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            if (!LocalDevelopmentRequestGuard.IsLocalDevelopmentRequest(httpContext.Request, httpContext.RequestServices.GetRequiredService<IWebHostEnvironment>()))
            {
                return Results.NotFound();
            }

            return Results.Ok(await identityService.RegisterAsync(request, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
        .RequireRateLimiting(RateLimitPolicies.IdentityDevPolicy);

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
        .RequireAuthorization(AdminPolicies.CanManageDomainVerifications);

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
        .RequireAuthorization(AdminPolicies.CanManageDomainVerifications);

    identityApi.MapPost("/websites/{domain}/retry", async (
        string domain,
        HttpContext httpContext,
        IWebsiteIdentityService websiteIdentityService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await websiteIdentityService.RetryVerificationAsync(
                domain,
                httpContext.User.Identity?.Name ?? "unknown-admin",
                httpContext.User.FindFirstValue(ClaimTypes.Role) ?? "Unknown",
                cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            return Results.Conflict(new { error = ex.Message });
        }
    })
        .RequireAuthorization(AdminPolicies.CanManageDomainVerifications);

    identityApi.MapPost("/websites/{domain}/revoke", async (
        string domain,
        DomainVerificationRevokeRequest request,
        HttpContext httpContext,
        IWebsiteIdentityService websiteIdentityService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await websiteIdentityService.RevokeVerificationAsync(
                domain,
                request.Reason,
                httpContext.User.Identity?.Name ?? "unknown-owner",
                httpContext.User.FindFirstValue(ClaimTypes.Role) ?? "Unknown",
                cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
        .RequireAuthorization(AdminPolicies.CanRevokeDomainVerifications);

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
        HttpContext httpContext,
        IHipIdentityService identityService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            if (!LocalDevelopmentRequestGuard.IsLocalDevelopmentRequest(httpContext.Request, httpContext.RequestServices.GetRequiredService<IWebHostEnvironment>()))
            {
                return Results.NotFound();
            }

            return Results.Ok(await identityService.SignAsync(request, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
        .RequireRateLimiting(RateLimitPolicies.IdentityDevPolicy);

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

/// <summary>
/// Request used to assign a generated admin review signal to a reviewer without exposing private evidence.
/// </summary>
/// <param name="ActorId">Admin actor or service account performing the assignment.</param>
/// <param name="AssignedTo">Reviewer ID, alias, or hash that should handle the review.</param>
public sealed record AdminReviewQueueAssignRequest(string ActorId, string AssignedTo);

/// <summary>
/// Request used to dismiss a generated admin review signal while preserving its privacy-safe evidence summary.
/// </summary>
/// <param name="ActorId">Admin actor or service account dismissing the review.</param>
/// <param name="Reason">Privacy-safe dismissal reason. Raw page text, credentials, and private messages are rejected by validation.</param>
public sealed record AdminReviewQueueDismissRequest(string ActorId, string Reason);

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
            SafetyUrlDisplay.StripQueryAndFragment(result.OriginalUrl),
            domain,
            result.FinalDestinationUrl is null ? null : SafetyUrlDisplay.StripQueryAndFragment(result.FinalDestinationUrl),
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
/// <param name="SettingsScope">Scope key used for diagnostics when settings are isolated per admin or browser instance.</param>
/// <param name="ExternalProvidersEnabled">Whether any external provider can run.</param>
/// <param name="AllowFullUrlChecks">Whether full URL checks are globally allowed.</param>
/// <param name="ProviderTimeout">Provider timeout.</param>
/// <param name="DefaultCacheDuration">Default provider cache duration.</param>
/// <param name="SslLabs">SSL Labs/Qualys-style TLS settings.</param>
/// <param name="GoogleWebRisk">Google Web Risk/Safe Browsing-style settings.</param>
/// <param name="VirusTotal">VirusTotal-style settings.</param>
sealed record ExternalProviderSettingsResponse(
    string SettingsScope,
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
    /// <param name="settingsScope">Resolved settings scope.</param>
    /// <returns>Admin-safe settings response.</returns>
    public static ExternalProviderSettingsResponse From(ExternalSiteEvidenceOptions options, string settingsScope) =>
        new(
            settingsScope,
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
        new(options.Enabled, options.Endpoint, null, options.AllowFullUrl, options.CacheDuration);
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
