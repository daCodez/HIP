using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.RateLimiting;
using System.Globalization;
using System.Security.Claims;
using HIP.Application;
using HIP.Application.Administration;
using HIP.Application.Ai;
using HIP.Application.Browser;
using HIP.Application.Certificates;
using HIP.Application.Consumer;
using HIP.Application.Dashboard;
using HIP.Application.Devices;
using HIP.Application.Identity;
using HIP.Application.PublicLookup;
using HIP.Application.Performance;
using HIP.Application.Platforms;
using HIP.Application.Protocol;
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
using HIP.Domain.Protocol;
using HIP.Domain.Rules;
using HIP.Domain.Safety;
using HIP.Domain.SelfHealing;
using HIP.Infrastructure;
using HIP.Infrastructure.Persistence;
using HIP.Web;
using HIP.Web.Components;
using HIP.Web.Navigation;
using HIP.Web.Security;
using Microsoft.AspNetCore.OutputCaching;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

const string ConsumerHistoryBackfillOperation = "--maintenance=consumer-history-owner-index-backfill";
const string ConsumerHistoryBackfillConfirmation = "--confirm=APPLY-CONSUMER-HISTORY-OWNER-INDEX";
var consumerHistoryBackfillRequested = args.Contains(
    ConsumerHistoryBackfillOperation,
    StringComparer.Ordinal);
var consumerHistoryBackfillConfirmed = args.Contains(
    ConsumerHistoryBackfillConfirmation,
    StringComparer.Ordinal);

var builder = WebApplication.CreateBuilder(args);
const string HipInstanceIdHeader = "X-HIP-Instance-Id";
const string ConsumerDeviceMutationRateLimitPolicy = "ConsumerDeviceMutationPolicy";

builder.AddServiceDefaults();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddHipApplication(
    builder.Environment.IsDevelopment(),
    builder.Environment.IsDevelopment() ? "web" : null);
builder.Services.AddSingleton(BindExternalSiteEvidenceOptions(builder.Configuration));
builder.Services.AddHipInfrastructure(builder.Configuration, builder.Environment.IsDevelopment());
var managedSigningReadiness = builder.Configuration
    .GetSection(HipManagedSigningReadinessOptions.SectionName)
    .Get<HipManagedSigningReadinessOptions>() ?? new HipManagedSigningReadinessOptions();
builder.Services.AddSingleton(managedSigningReadiness);
builder.Services.AddHostedService<DomainVerificationRecheckWorker>();
builder.Services.AddHostedService<DomainCertificateMonitoringWorker>();
builder.Services.AddOptions<HipPerformanceOptions>()
    .Bind(builder.Configuration.GetSection(HipPerformanceOptions.SectionName))
    .Validate(ValidateHipPerformanceOptions, "HIP performance options must use positive cache durations and request limits.")
    .ValidateOnStart();
builder.Services.AddOptions<HipSecurityOptions>()
    .Bind(builder.Configuration.GetSection(HipSecurityOptions.SectionName))
    .ValidateOnStart();
builder.Services.AddOptions<HipPortalLinkOptions>()
    .Bind(builder.Configuration.GetSection(HipPortalLinkOptions.SectionName))
    .Validate(options => options.HasValidOrigins(), "HIP portal links must use bounded HTTPS origins.")
    .ValidateOnStart();
builder.Services.AddSingleton<HipPortalLinks>();
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
builder.Services.AddHipWebAuthentication(builder.Configuration, builder.Environment);
builder.Services.AddHipAdminAuthorization();
if (builder.Environment.IsDevelopment())
{
    builder.Services.Configure<HipAdminLoginOptions>(builder.Configuration.GetSection(HipAdminLoginOptions.SectionName));
    builder.Services.AddSingleton<IPasswordHasher<string>, PasswordHasher<string>>();
    builder.Services.AddHipAdminAuthenticationProvider<LocalPasswordAdminAuthenticationProvider>();
}
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddCors(options =>
{
    var security = BindHipSecurityOptions(builder.Configuration);
    options.AddPolicy(HipCorsPolicies.PublicRead, policy =>
        policy.AllowAnyOrigin()
            .WithMethods("GET")
            .AllowAnyHeader());
    options.AddPolicy(HipCorsPolicies.PublicBadgeVerification, policy =>
        policy.AllowAnyOrigin()
            .WithMethods("POST")
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
    options.AddPolicy(ConsumerDeviceMutationRateLimitPolicy, CreateConsumerDeviceMutationPartition);
    ServiceClientManagementEndpoints.AddMutationRateLimitPolicy(options);
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

var databaseInitializationMode = app.Environment.IsDevelopment()
    ? HipDatabaseInitializationMode.CreateDevelopmentSchema
    : HipDatabaseInitializationMode.ValidateMigrations;
await HipDatabaseInitializer.InitializeAsync(app.Services, databaseInitializationMode);
await HipManagedSigningReadiness.ValidateAsync(app.Services, managedSigningReadiness);

if (consumerHistoryBackfillRequested)
{
    if (!consumerHistoryBackfillConfirmed)
    {
        throw new InvalidOperationException(
            "Consumer-history owner-index maintenance requires the exact confirmation argument.");
    }

    ConsumerHistoryOwnerIndexBackfillSummary summary;
    using (var maintenanceScope = app.Services.CreateScope())
    {
        var backfillService = maintenanceScope.ServiceProvider
            .GetRequiredService<ConsumerHistoryOwnerIndexBackfillService>();
        summary = await backfillService.BackfillAllAsync(batchSize: 100, CancellationToken.None);
    }
    Console.WriteLine(
        "Consumer-history owner-index backfill completed: " +
        $"processed={summary.ProcessedGlobalRecords}, " +
        $"created={summary.CreatedOwnerRecords}, " +
        $"existing={summary.AlreadyIndexedRecords}, " +
        $"unowned={summary.SkippedWithoutOwner}, " +
        $"batches={summary.Batches}.");
    await app.DisposeAsync();
    return;
}

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
app.UseAuthentication();
app.UseRateLimiter();
app.UseOutputCache();
app.UseAuthorization();

app.UseAntiforgery();

app.MapHipDevelopmentLogin();
app.MapHipProductionLogin();

MapPublicApis(app.MapGroup(ApiRoutes.Public));
MapReportApis(app.MapGroup($"{ApiRoutes.V1}/reports"));
MapBadgeApis(app.MapGroup(ApiRoutes.Badge));
MapBrowserApis(app.MapGroup(ApiRoutes.Browser));
MapSafetyApis(app.MapGroup(ApiRoutes.Safety));
MapSiteSafetyApis(app.MapGroup(ApiRoutes.SiteSafety));
MapProtocolApis(app.MapGroup(ApiRoutes.Protocol));
MapAdminSiteSafetyRuleApis(app.MapGroup($"{ApiRoutes.Admin}/site-safety-rules").RequireAuthorization(AdminPolicies.CanManageRules));
Program.MapJsonRulesApis(app.MapGroup(ApiRoutes.Rules).RequireAuthorization(AdminPolicies.CanManageRules));
MapAiApis(app.MapGroup(ApiRoutes.Ai).RequireAuthorization(AdminPolicies.CanManageRules));
MapSelfHealingPatternApis(app.MapGroup(ApiRoutes.SelfHealing).RequireAuthorization(AdminPolicies.CanManageRules));
MapSecondLifeHudApis(app.MapGroup(ApiRoutes.SecondLifeHud));
MapLicenseApis(app.MapGroup(ApiRoutes.Licenses));
MapRulesApis(app.MapGroup($"{ApiRoutes.Admin}/rules").RequireAuthorization(AdminPolicies.CanManageRules));
MapSelfHealingApis(app.MapGroup($"{ApiRoutes.Admin}/self-healing").RequireAuthorization(AdminPolicies.CanManageRules));
MapReviewApis(app.MapGroup($"{ApiRoutes.Admin}/review"));
MapAdminReviewQueueApis(app.MapGroup($"{ApiRoutes.Admin}/review-queue"));
MapAppealApis(app.MapGroup($"{ApiRoutes.Admin}/appeals"));
MapReputationOverrideApis(app.MapGroup($"{ApiRoutes.Admin}/reputation-overrides").RequireAuthorization(AdminPolicies.CanApproveOverrides));
MapReputationApis(app.MapGroup($"{ApiRoutes.Admin}/reputation").RequireAuthorization(AdminPolicies.CanViewAdminDashboard));
MapDashboardApis(app.MapGroup($"{ApiRoutes.Admin}/dashboard").RequireAuthorization(AdminPolicies.CanViewAdminDashboard));
MapAdminScanApis(app.MapGroup($"{ApiRoutes.Admin}/scans").RequireAuthorization(AdminPolicies.CanViewAdminDashboard));
MapPlatformConnectionApis(app.MapGroup($"{ApiRoutes.Admin}/platforms").RequireAuthorization(AdminPolicies.CanViewAdminDashboard));
ServiceClientManagementEndpoints.Map(app.MapGroup($"{ApiRoutes.Admin}/service-clients"));
MapConsumerApis(app.MapGroup(ApiRoutes.Consumer).RequireAuthorization(ConsumerPolicies.CanUseConsumerPortal));
MapIdentityApis(app.MapGroup(ApiRoutes.Identity).RequireRateLimiting(RateLimitPolicies.IdentityDevPolicy));
app.MapGet($"{ApiRoutes.Admin}/audit-logs", (IAuditLogService auditLogService) => Results.Ok(auditLogService.List()))
    .RequireAuthorization(AdminPolicies.CanViewAuditLogs);
app.MapGet($"{ApiRoutes.Admin}/audit/export", async (
    HttpContext httpContext,
    IAuditExportService auditExportService,
    CancellationToken cancellationToken) =>
{
    var export = await auditExportService.ExportAsync(cancellationToken);
    httpContext.Response.Headers["Cache-Control"] = "no-store";
    httpContext.Response.Headers["X-HIP-Audit-Sha256"] = export.Sha256;
    httpContext.Response.Headers["X-HIP-Audit-Entry-Count"] =
        export.EntryCount.ToString(System.Globalization.CultureInfo.InvariantCulture);
    return Results.File(export.JsonLines, "application/x-ndjson", "hip-audit-export.jsonl");
})
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
app.MapGet($"{ApiRoutes.Admin}/access/me", async (
    HttpContext httpContext,
    IAdminAccessService accessService,
    CancellationToken cancellationToken) =>
{
    if (!HipAuthenticatedIdentity.TryResolveUniqueClaim(
            httpContext.User,
            HipAuthenticationClaimTypes.ActorId,
            out var actorId))
    {
        return Results.Unauthorized();
    }

    httpContext.Response.Headers.CacheControl = "no-store";
    var assignment = await accessService.GetCurrentAssignmentAsync(actorId, cancellationToken);
    return Results.Ok(new AdminSelfAccessResponse(actorId, assignment));
})
    .RequireAuthorization(AdminPolicies.CanViewOwnAdminAccess);app.MapGet($"{ApiRoutes.Admin}/users", async (
    HttpContext httpContext,
    IAdminAccessService accessService,
    CancellationToken cancellationToken) =>
{
    if (!AdminEndpointIdentity.TryResolve(httpContext.User, out var actorId, out var role))
    {
        return Results.Unauthorized();
    }

    return Results.Ok(await accessService.GetDirectoryAsync(actorId, role, cancellationToken));
})
    .RequireAuthorization(AdminPolicies.CanViewAdminUsers);
app.MapPut($"{ApiRoutes.Admin}/users", async (
    HttpContext httpContext,
    AdminAccessChangeRequest request,
    IAdminAccessService accessService,
    CancellationToken cancellationToken) =>
{
    if (!AdminEndpointIdentity.TryResolve(httpContext.User, out var actorId, out var role))
    {
        return Results.Unauthorized();
    }

    var result = await accessService.ChangeAsync(actorId, role, request, cancellationToken);
    return result.Status switch
    {
        AdminAccessChangeStatus.Saved => Results.Ok(result),
        AdminAccessChangeStatus.Conflict => Results.Conflict(result),
        AdminAccessChangeStatus.Forbidden => Results.Forbid(),
        _ => Results.BadRequest(result)
    };
})
    .RequireAuthorization(AdminPolicies.CanManageAdmins);
app.MapGet($"{ApiRoutes.Admin}/reports", async (
    IPrivacySafeReportService reportService,
    CancellationToken cancellationToken) =>
    Results.Ok((await reportService.ListAsync(cancellationToken)).Select(PrivacySafeReportListItem.From).ToArray()))
    .RequireAuthorization(AdminPolicies.CanViewReviews);
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
    IAuditLogService auditLogService,
    CancellationToken cancellationToken) =>
{
    var actor = ResolveAdminActor(httpContext);
    var scopeKey = ResolveProviderSettingsScope(httpContext);
    var options = await settingsStore.GetAsync(scopeKey, cancellationToken) ?? defaultOptions.Clone();
    var beforeSettings = ExternalProviderSettingsAuditMetadata(options);
    ApplyExternalProviderSettings(options, request);
    var saved = await settingsStore.SaveAsync(scopeKey, options, cancellationToken);
    auditLogService.Write(
        actor,
        "ExternalProviderSettings.Updated",
        TargetType.Rule,
        "site-safety-external-providers",
        "External site-safety provider settings were updated.",
        AuditSeverity.High,
        actorRole: httpContext.User.FindFirstValue(ClaimTypes.Role) ?? "Unknown",
        beforeMetadata: beforeSettings,
        afterMetadata: ExternalProviderSettingsAuditMetadata(saved),
        correlationId: httpContext.TraceIdentifier);
    return Results.Ok(ExternalProviderSettingsResponse.From(saved, scopeKey));
})
    .RequireAuthorization(AdminPolicies.CanManageRules)
    .RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);

app.MapStaticAssets()
    .WithMetadata(HipFrameworkGeneratedEndpointMetadata.StaticAssets);
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode()
    .WithMetadata(HipFrameworkGeneratedEndpointMetadata.RazorComponents);

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
/// Limits consumer-device mutations by the matched route and authenticated consumer scope.
/// </summary>
/// <remarks>
/// The route template is used instead of the caller-supplied opaque identifier so changing device or challenge IDs
/// cannot create unbounded limiter partitions. Authentication runs before rate limiting, so a caller cannot exhaust
/// another consumer's budget merely by sharing its network address. The owner claim is hashed before it becomes an
/// in-memory partition key; unauthenticated or ambiguous callers use a separate remote-address partition.
/// </remarks>
static RateLimitPartition<string> CreateConsumerDeviceMutationPartition(HttpContext httpContext)
{
    const int permitLimit = 10;
    var route = httpContext.GetEndpoint() is RouteEndpoint routeEndpoint
        ? routeEndpoint.RoutePattern.RawText
        : null;
    var routeKey = string.IsNullOrWhiteSpace(route) ? "unknown-route" : route;
    var callerKey = HipAuthenticatedIdentity.TryResolveUniqueClaim(
        httpContext.User,
        HipAuthenticationClaimTypes.ConsumerId,
        out var consumerId)
        ? $"owner:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(consumerId)))}"
        : $"unauthenticated:{httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown-address"}";
    var partitionKey = $"consumer-device:{httpContext.Request.Method}:{routeKey}:{callerKey}";

    return RateLimitPartition.GetFixedWindowLimiter(
        partitionKey,
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = permitLimit,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        });
}

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
/// <param name="duplicateGuard">Distributed duplicate guard that hashes fingerprint parts internally.</param>
/// <returns>True when the same feedback was already accepted recently.</returns>
static async ValueTask<bool> IsDuplicateFeedbackAsync(ReputationFeedbackRequest feedback, IDuplicateSubmissionGuard duplicateGuard, CancellationToken cancellationToken) =>
    !await duplicateGuard.TryAcceptAsync(
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
        TimeSpan.FromMinutes(5), cancellationToken);

/// <summary>
/// Detects repeated privacy-safe report submissions before they enter the reporting service.
/// </summary>
/// <param name="report">Submitted report payload.</param>
/// <param name="duplicateGuard">Distributed duplicate guard that hashes fingerprint parts internally.</param>
/// <returns>True when an equivalent report was already accepted recently.</returns>
static async ValueTask<bool> IsDuplicatePrivacySafeReportAsync(PrivacySafeReport report, IDuplicateSubmissionGuard duplicateGuard, CancellationToken cancellationToken) =>
    !await duplicateGuard.TryAcceptAsync(
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
        TimeSpan.FromMinutes(5), cancellationToken);

/// <summary>
/// Detects repeated risk finding submissions so public clients cannot spam the review queue with identical signals.
/// </summary>
/// <param name="report">Risk finding submitted by a HIP client.</param>
/// <param name="duplicateGuard">Distributed duplicate guard that hashes fingerprint parts internally.</param>
/// <returns>True when an equivalent finding was already accepted recently.</returns>
static async ValueTask<bool> IsDuplicateRiskFindingAsync(RiskFindingReport report, IDuplicateSubmissionGuard duplicateGuard, CancellationToken cancellationToken) =>
    !await duplicateGuard.TryAcceptAsync(
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
        TimeSpan.FromMinutes(5), cancellationToken);

/// <summary>
/// Detects replayed browser scan summaries while allowing fresh scans with new timestamps or URL hashes.
/// </summary>
/// <param name="request">Browser plugin scan result request.</param>
/// <param name="duplicateGuard">Distributed duplicate guard that hashes fingerprint parts internally.</param>
/// <returns>True when an equivalent scan result was already accepted recently.</returns>
static async ValueTask<bool> IsDuplicateBrowserScanResultAsync(BrowserScanResultSaveRequest request, IDuplicateSubmissionGuard duplicateGuard, CancellationToken cancellationToken) =>
    !await duplicateGuard.TryAcceptAsync(
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
        TimeSpan.FromSeconds(30), cancellationToken);

/// <summary>
/// Detects repeated Site Safety scan requests so public clients cannot rapidly replay the same signal payload.
/// </summary>
/// <param name="request">Site Safety scan request.</param>
/// <param name="duplicateGuard">Distributed duplicate guard that hashes fingerprint parts internally.</param>
/// <returns>True when an equivalent scan request was already accepted recently.</returns>
static async ValueTask<bool> IsDuplicateSiteSafetyScanAsync(SiteSafetyScanRequest request, IDuplicateSubmissionGuard duplicateGuard, CancellationToken cancellationToken) =>
    !await duplicateGuard.TryAcceptAsync(
        "web-site-safety-scan",
        SiteSafetyFingerprintParts(request),
        TimeSpan.FromSeconds(20), cancellationToken);

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
    if (!string.IsNullOrWhiteSpace(request.ApiKey))
    {
        options.ApiKey = request.ApiKey.Trim();
    }

    options.AllowFullUrl = request.AllowFullUrl;
    options.CacheDuration = request.CacheDuration is { Ticks: > 0 } ? request.CacheDuration : null;
}

/// <summary>
/// Creates an allowlisted audit projection that excludes provider endpoints and credentials.
/// </summary>
/// <param name="options">Provider settings to summarize.</param>
/// <returns>Privacy-safe state metadata for before/after audit evidence.</returns>
static IReadOnlyDictionary<string, string> ExternalProviderSettingsAuditMetadata(
    ExternalSiteEvidenceOptions options) =>
    new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["externalProvidersEnabled"] = options.ExternalProvidersEnabled.ToString(),
        ["allowFullUrlChecks"] = options.AllowFullUrlChecks.ToString(),
        ["sslLabsEnabled"] = options.SslLabs.Enabled.ToString(),
        ["googleWebRiskEnabled"] = options.GoogleWebRisk.Enabled.ToString(),
        ["virusTotalEnabled"] = options.VirusTotal.Enabled.ToString()
    };

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
        .AllowAnonymous()
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
        .AllowAnonymous()
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
        .AllowAnonymous()
        .RequireCors(HipCorsPolicies.ClientWrite);


    publicApi.MapGet("/certificates/{certificateId}", async (
        string certificateId,
        HttpContext httpContext,
        IPublicDomainCertificateService certificateService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            var result = await certificateService.GetByIdAsync(certificateId, cancellationToken);
            if (result.Status == PublicDomainCertificateLookupStatus.NotFound)
            {
                httpContext.Response.Headers.CacheControl = "no-store";
                return Results.NotFound();
            }
            if (result.Status == PublicDomainCertificateLookupStatus.Unavailable || result.Certificate is null)
            {
                httpContext.Response.Headers.CacheControl = "no-store";
                return Results.Problem("HIP could not verify this certificate right now.",
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            httpContext.Response.Headers.CacheControl = result.Certificate.IsActive
                ? "public, max-age=60"
                : "no-store";
            return Results.Ok(result.Certificate);
        }
        catch (ArgumentException ex)
        {
            httpContext.Response.Headers.CacheControl = "no-store";
            return Results.BadRequest(new { error = ex.Message });
        }
    })
        .AllowAnonymous()
        .RequireRateLimiting(RateLimitPolicies.PublicScanPolicy);

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
        .AllowAnonymous()
        .CacheOutput(HipOutputCachePolicies.Badge);

    publicApi.MapPost("/badge/verify", async (
        HipLiveBadgeDocument document,
        IHipLiveBadgeVerificationService verificationService,
        CancellationToken cancellationToken) =>
        Results.Ok(await verificationService.VerifyAsync(document, cancellationToken)))
        .AllowAnonymous()
        .RequireCors(HipCorsPolicies.PublicBadgeVerification)
        .WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(HipLiveBadgeDocument.MaximumDocumentBytes))
        .RequireRateLimiting(RateLimitPolicies.PublicScanPolicy);

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
        .AllowAnonymous()
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
            var anonymousFeedback = feedback with
            {
                ReporterTrustLevel = HIP.Domain.Reputation.ReporterTrustLevel.Anonymous
            };
            if (await IsDuplicateFeedbackAsync(anonymousFeedback, duplicateGuard, cancellationToken))
            {
                return Results.Conflict(new { error = "Duplicate feedback submission ignored." });
            }

            await StoreWeightedFeedbackIfDomainAsync(anonymousFeedback, weightedFeedbackService, reviewQueueService, cancellationToken);
            return Results.Ok(await reputationService.SubmitFeedbackAsync(anonymousFeedback, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
        .AllowAnonymous()
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
            ReportId = $"risk-report-{Guid.NewGuid():N}",
            SourceClient = SourceClient.Unknown,
            Platform = ReportPlatform.Unknown,
            DetectedAtUtc = DateTimeOffset.UtcNow,
            ReporterTrustLevel = HIP.Domain.SelfHealing.ReporterTrustLevel.Unknown,
            HipSignature = string.Empty,
            ConsumerScopeHash = string.IsNullOrWhiteSpace(consumerId) ? null : privacyHashingService.Hash(consumerId)
        };

        if (await IsDuplicateRiskFindingAsync(ownedReport, duplicateGuard, cancellationToken))
        {
            return Results.Conflict(new { error = "Duplicate risk finding ignored." });
        }

        var response = await ingestionService.IngestAsync(ownedReport, cancellationToken);
        return response.Accepted ? Results.Ok(response) : Results.BadRequest(response);
    })
        .AllowAnonymous()
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
        if (await IsDuplicatePrivacySafeReportAsync(report, duplicateGuard, cancellationToken))
        {
            return Results.Conflict(new PrivacySafeReportResponse(false, null, report.Status, null, report.UrlHash, "Duplicate report ignored."));
        }

        var result = await reportService.SubmitAsync(report, cancellationToken);
        return result.Accepted ? Results.Ok(result) : Results.BadRequest(result);
    })
        .AllowAnonymous()
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
    .RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication)
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
    .RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication)
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
        .AllowAnonymous()
        .CacheOutput(HipOutputCachePolicies.Badge);

    badgeApi.MapPost("/verify", async (
        HipLiveBadgeDocument document,
        IHipLiveBadgeVerificationService verificationService,
        CancellationToken cancellationToken) =>
        Results.Ok(await verificationService.VerifyAsync(document, cancellationToken)))
        .AllowAnonymous()
        .RequireCors(HipCorsPolicies.PublicBadgeVerification)
        .WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(HipLiveBadgeDocument.MaximumDocumentBytes))
        .RequireRateLimiting(RateLimitPolicies.PublicScanPolicy);

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
        .AllowAnonymous()
        .CacheOutput(HipOutputCachePolicies.Badge);
}

/// <summary>
/// Maps browser plugin endpoints for site scoring, link scanning, and privacy-safe scan result persistence.
/// </summary>
/// <param name="browserApi">Versioned browser plugin route group.</param>
static (bool Supplied, DeviceRequestProof? Proof) ReadDeviceRequestProof(HttpRequest request)
{
    string? Header(string name) => request.Headers[name].FirstOrDefault();
    var values = new[]
    {
        Header("X-HIP-Device-Id"),
        Header("X-HIP-Device-Timestamp"),
        Header("X-HIP-Device-Nonce"),
        Header("X-HIP-Device-Body-SHA256"),
        Header("X-HIP-Device-Signature")
    };
    if (values.All(string.IsNullOrWhiteSpace))
    {
        return (false, null);
    }

    return values.Any(string.IsNullOrWhiteSpace)
        ? (true, null)
        : (true, new DeviceRequestProof(values[0]!, values[1]!, values[2]!, values[3]!, values[4]!));
}

static IResult InvalidDeviceProofResult(DeviceRequestProofStatus status) => status switch
{
    DeviceRequestProofStatus.Replayed => Results.Conflict(
        new BrowserScanResultErrorResponse("Device request proof was already used.")),
    DeviceRequestProofStatus.StateUnavailable => Results.Json(
        new BrowserScanResultErrorResponse("Device request proof is temporarily unavailable."),
        statusCode: StatusCodes.Status503ServiceUnavailable),
    _ => Results.Json(
        new BrowserScanResultErrorResponse("Device request proof is invalid."),
        statusCode: StatusCodes.Status401Unauthorized)
};

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
        .AllowAnonymous()
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
        .AllowAnonymous()
        .RequireCors(HipCorsPolicies.ClientWrite)
        .RequireRateLimiting(RateLimitPolicies.PublicScanPolicy);

    browserApi.MapPost("/scan-results", async (
        BrowserScanResultSaveRequest request,
        HttpContext httpContext,
        IDuplicateSubmissionGuard duplicateGuard,
        IUntrustedBrowserScanResultSubmissionService scanResultSubmissionService,
        IRegisteredDeviceBrowserScanResultSubmissionService registeredSubmissionService,
        IDeviceRequestProofService deviceProofService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            var suppliedProof = ReadDeviceRequestProof(httpContext.Request);
            if (suppliedProof.Supplied)
            {
                if (suppliedProof.Proof is null)
                {
                    return InvalidDeviceProofResult(DeviceRequestProofStatus.Invalid);
                }
                var proofResult = await deviceProofService.ValidateAndReserveAsync(
                    suppliedProof.Proof,
                    httpContext.Request.Method,
                    httpContext.Request.Path.Value ?? "/api/v1/browser/scan-results",
                    request,
                    cancellationToken);
                if (!proofResult.IsAccepted)
                {
                    return InvalidDeviceProofResult(proofResult.Status);
                }
            }

            if (await IsDuplicateBrowserScanResultAsync(request, duplicateGuard, cancellationToken))
            {
                return Results.Conflict(new BrowserScanResultErrorResponse("Duplicate browser scan result ignored."));
            }

            return Results.Ok(suppliedProof.Supplied
                ? await registeredSubmissionService.SaveRegisteredDeviceAsync(request, cancellationToken)
                : await scanResultSubmissionService.SaveUntrustedAsync(request, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new BrowserScanResultErrorResponse(ex.Message));
        }
    })
        .AllowAnonymous()
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
    })
        .AllowAnonymous();
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
        .AllowAnonymous()
        .RequireCors(HipCorsPolicies.ClientWrite)
        .RequireRateLimiting(RateLimitPolicies.PublicScanPolicy);

    safetyApi.MapPost("/decisions", async (
        SafetyDecisionRequest request,
        ISafetyDecisionService decisionService,
        CancellationToken cancellationToken) =>
    {
        var result = await decisionService.RecordAsync(request, cancellationToken);
        return result.Status switch
        {
            SafetyDecisionStatus.Recorded => Results.Ok(SafetyDecisionApiResponse.From(result)),
            SafetyDecisionStatus.AdditionalConfirmationRequired => Results.Conflict(SafetyDecisionApiResponse.From(result)),
            SafetyDecisionStatus.BlockedByPolicy => Results.Json(
                SafetyDecisionApiResponse.From(result),
                statusCode: StatusCodes.Status403Forbidden),
            SafetyDecisionStatus.InvalidRequest => Results.BadRequest(SafetyDecisionApiResponse.From(result)),
            _ => Results.Json(
                SafetyDecisionApiResponse.From(result),
                statusCode: StatusCodes.Status503ServiceUnavailable)
        };
    })
        .AllowAnonymous()
        .RequireCors(HipCorsPolicies.ClientWrite)
        .WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(8_192))
        .RequireRateLimiting(RateLimitPolicies.PublicFeedbackPolicy);

    safetyApi.MapPost("/report-safe", async (
        SafetyReportRequest request,
        ISafetyDecisionService decisionService,
        CancellationToken cancellationToken) =>
    {
        var result = await decisionService.RecordAsync(
            new SafetyDecisionRequest(
                request.Url,
                request.Source,
                SafetyDecisionAction.ReportSafe,
                DangerAcknowledged: false),
            cancellationToken);
        return result.IsRecorded
            ? Results.Ok(SafetyReportResponse.CreateAccepted(
                SafetyUrlDisplay.StripQueryAndFragment(request.Url),
                request.Source,
                "Privacy-safe report as safe was recorded for review."))
            : Results.Json(new { error = "HIP could not record the report." }, statusCode: StatusCodes.Status503ServiceUnavailable);
    })
        .AllowAnonymous()
        .RequireCors(HipCorsPolicies.ClientWrite)
        .RequireRateLimiting(RateLimitPolicies.PublicFeedbackPolicy);

    safetyApi.MapPost("/report-dangerous", async (
        SafetyReportRequest request,
        ISafetyDecisionService decisionService,
        CancellationToken cancellationToken) =>
    {
        var result = await decisionService.RecordAsync(
            new SafetyDecisionRequest(
                request.Url,
                request.Source,
                SafetyDecisionAction.ReportDangerous,
                DangerAcknowledged: false),
            cancellationToken);
        return result.IsRecorded
            ? Results.Ok(SafetyReportResponse.CreateAccepted(
                SafetyUrlDisplay.StripQueryAndFragment(request.Url),
                request.Source,
                "Privacy-safe report as dangerous was recorded for review."))
            : Results.Json(new { error = "HIP could not record the report." }, statusCode: StatusCodes.Status503ServiceUnavailable);
    })
        .AllowAnonymous()
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
        IUntrustedSiteSafetyScanner scanner,
        ISiteSafetyScanResultStorageService scanResultStorageService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            if (await IsDuplicateSiteSafetyScanAsync(request, duplicateGuard, cancellationToken))
            {
                return Results.Conflict(new { error = "Duplicate site safety scan ignored." });
            }

            var scopedOptions = await LoadScopedExternalProviderOptionsAsync(httpContext, settingsStore, cancellationToken);
            using var _ = defaultOptions.UseScopedOverride(scopedOptions);
            var result = await scanner.ScanUntrustedAsync(request, cancellationToken);
            await scanResultStorageService.SaveAsync(request, result, cancellationToken);
            return Results.Ok(ToSiteSafetyScanResponse(result));
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
        .AllowAnonymous()
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
        .RequireAuthorization(AdminPolicies.CanManageRules)
        .RequireCors(HipCorsPolicies.ClientWrite)
        .RequireRateLimiting(RateLimitPolicies.PublicScanPolicy);

    siteSafetyApi.MapPost("/external-evidence/jobs", async (
        SiteSafetyScanRequest request,
        HttpContext httpContext,
        ExternalSiteEvidenceJobService jobService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            var scopeKey = ResolveProviderSettingsScope(httpContext);
            var job = await jobService.QueueAsync(request, scopeKey, scopeKey, cancellationToken);
            var location = $"/api/v1/site-safety/external-evidence/jobs/{Uri.EscapeDataString(job.JobId)}";
            return Results.Accepted(location, ToExternalSiteEvidenceJobResponse(job));
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException or UriFormatException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
        .RequireAuthorization(AdminPolicies.CanManageRules)
        .RequireCors(HipCorsPolicies.ClientWrite)
        .RequireRateLimiting(RateLimitPolicies.PublicScanPolicy);

    siteSafetyApi.MapGet("/external-evidence/jobs/{jobId}", async (
        string jobId,
        HttpContext httpContext,
        ExternalSiteEvidenceJobService jobService,
        CancellationToken cancellationToken) =>
    {
        var job = await jobService.GetForRequesterAsync(
            jobId,
            ResolveProviderSettingsScope(httpContext),
            cancellationToken);
        return job is null ? Results.NotFound() : Results.Ok(ToExternalSiteEvidenceJobResponse(job));
    })
        .RequireAuthorization(AdminPolicies.CanManageRules);
}

/// <summary>
/// Maps the public version-one HIP trust receipt issuance, lookup, and verification endpoints.
/// </summary>
/// <param name="protocolApi">Versioned HIP protocol route group.</param>
/// <remarks>
/// Receipt evaluation treats only the validated URL as caller input. Client observations, plugin metadata, and
/// client-scoped provider settings are ignored so only server-controlled providers and rules affect a signed receipt.
/// </remarks>
static void MapProtocolApis(RouteGroupBuilder protocolApi)
{
    protocolApi.MapPost("/issue-receipt", async (
        HipTrustReceiptIssueRequest request,
        HttpContext httpContext,
        IHipTrustReceiptAuthoritativeEvaluationService evaluationService,
        IHipTrustReceiptIssuanceService issuanceService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            var authoritativeEvaluation = await evaluationService.EvaluateAsync(request, cancellationToken);
            var result = await issuanceService.IssueAsync(authoritativeEvaluation, cancellationToken);
            return ToTrustReceiptIssueHttpResult(result, httpContext.Response);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or FluentValidation.ValidationException)
        {
            return Results.BadRequest(new ApiErrorResponse(
                "HIP could not evaluate the supplied site safety request."));
        }
        catch (Exception)
        {
            return Results.Json(
                new ApiErrorResponse("HIP site safety evaluation is unavailable."),
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }
    })
        .WithSummary("Issues a signed HIP trust receipt from a server-authoritative site safety evaluation.")
        .WithDescription("Validates only the requested URL and evaluates it with server-controlled providers and rules; client observations, plugin metadata, and client-scoped provider settings are ignored.")
        .Accepts<HipTrustReceiptIssueRequest>("application/json")
        .WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(
            HipTrustReceiptIssueRequest.MaximumRequestBodyBytes))
        .AllowAnonymous()
        .RequireCors(HipCorsPolicies.ClientWrite)
        .RequireRateLimiting(RateLimitPolicies.PublicScanPolicy);

    protocolApi.MapGet("/receipts/{receiptId}", async (
        string receiptId,
        IHipTrustReceiptRepository repository,
        CancellationToken cancellationToken) =>
    {
        if (!IsValidTrustReceiptId(receiptId))
        {
            return Results.BadRequest(new ApiErrorResponse("The trust receipt identifier is invalid."));
        }

        try
        {
            var stored = await repository.GetByIdAsync(receiptId, cancellationToken);
            return stored is null
                ? Results.NotFound(new ApiErrorResponse("HIP trust receipt was not found."))
                : Results.Text(stored.ReceiptJson, "application/json", Encoding.UTF8);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (ArgumentException)
        {
            return Results.BadRequest(new ApiErrorResponse("The trust receipt identifier is invalid."));
        }
        catch (Exception)
        {
            return Results.Json(
                new ApiErrorResponse("HIP trust receipt storage is unavailable."),
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }
    })
        .AllowAnonymous();

    protocolApi.MapPost("/receipts/verify", async (
        HttpRequest request,
        IHipTrustReceiptVerificationService verificationService,
        CancellationToken cancellationToken) =>
    {
        var body = await ReadBoundedTrustReceiptBodyAsync(request, cancellationToken);
        if (body.IsTooLarge)
        {
            return Results.Json(
                new ApiErrorResponse("HIP trust receipt request exceeds the maximum allowed size."),
                statusCode: StatusCodes.Status413PayloadTooLarge);
        }

        HipTrustReceiptVerificationResult verification;
        try
        {
            verification = await verificationService.VerifyAsync(body.Content, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            verification = new HipTrustReceiptVerificationResult(
                HipTrustReceiptVerificationStatus.VerificationStateUnavailable);
        }

        return Results.Json(
            HipTrustReceiptVerificationApiResponse.From(verification),
            statusCode: TrustReceiptVerificationStatusCode(verification.Status));
    })
        .AllowAnonymous()
        .RequireCors(HipCorsPolicies.ClientWrite)
        .RequireRateLimiting(RateLimitPolicies.PublicScanPolicy);
}

/// <summary>Maps a receipt issuance result without reserializing successful signed documents.</summary>
static IResult ToTrustReceiptIssueHttpResult(
    HipTrustReceiptIssueResult result,
    HttpResponse response)
{
    if (result.IsSuccess && result.Receipt is not null)
    {
        var statusCode = result.Status == HipTrustReceiptIssueStatus.Issued
            ? StatusCodes.Status201Created
            : StatusCodes.Status200OK;
        if (statusCode == StatusCodes.Status201Created)
        {
            response.Headers.Location =
                $"{ApiRoutes.Protocol}/receipts/{Uri.EscapeDataString(result.Receipt.ReceiptId)}";
        }

        return Results.Text(
            HipTrustReceiptJson.Serialize(result.Receipt),
            "application/json",
            Encoding.UTF8,
            statusCode);
    }

    var responseStatus = result.IsSuccess ? HipTrustReceiptIssueStatus.Unspecified : result.Status;
    var (httpStatus, error) = responseStatus switch
    {
        HipTrustReceiptIssueStatus.InvalidEvaluation => (
            StatusCodes.Status400BadRequest,
            "HIP could not issue a receipt from the authoritative site safety evaluation."),
        HipTrustReceiptIssueStatus.Conflict => (
            StatusCodes.Status409Conflict,
            "A different trust receipt already exists for this authoritative evaluation."),
        HipTrustReceiptIssueStatus.SignerUnavailable or
        HipTrustReceiptIssueStatus.SignerNotAuthorized => (
            StatusCodes.Status503ServiceUnavailable,
            "HIP trust receipt signing is unavailable."),
        HipTrustReceiptIssueStatus.VerificationFailed => (
            StatusCodes.Status503ServiceUnavailable,
            "HIP could not verify the newly signed trust receipt."),
        HipTrustReceiptIssueStatus.PersistenceUnavailable => (
            StatusCodes.Status503ServiceUnavailable,
            "HIP trust receipt storage is unavailable."),
        _ => (
            StatusCodes.Status503ServiceUnavailable,
            "HIP trust receipt issuance is unavailable.")
    };
    return Results.Json(
        new ApiErrorResponse(error),
        statusCode: httpStatus);
}

/// <summary>Reads an untrusted receipt request with the protocol's strict byte cap.</summary>
static async Task<BoundedTrustReceiptBody> ReadBoundedTrustReceiptBodyAsync(
    HttpRequest request,
    CancellationToken cancellationToken)
{
    if (request.ContentLength > HipTrustReceiptJson.MaximumReceiptBytes)
    {
        return BoundedTrustReceiptBody.TooLarge;
    }

    var buffer = new byte[HipTrustReceiptJson.MaximumReceiptBytes + 1];
    var totalBytesRead = 0;
    while (totalBytesRead < buffer.Length)
    {
        var bytesRead = await request.Body.ReadAsync(
            buffer.AsMemory(totalBytesRead, buffer.Length - totalBytesRead),
            cancellationToken);
        if (bytesRead == 0)
        {
            return new BoundedTrustReceiptBody(
                buffer.AsMemory(0, totalBytesRead),
                IsTooLarge: false);
        }

        totalBytesRead += bytesRead;
    }

    return BoundedTrustReceiptBody.TooLarge;
}

/// <summary>Maps typed verification outcomes to stable HTTP status codes.</summary>
static int TrustReceiptVerificationStatusCode(HipTrustReceiptVerificationStatus status) => status switch
{
    HipTrustReceiptVerificationStatus.Verified => StatusCodes.Status200OK,
    HipTrustReceiptVerificationStatus.MalformedReceipt or
    HipTrustReceiptVerificationStatus.UnsupportedVersion or
    HipTrustReceiptVerificationStatus.WrongDocumentType => StatusCodes.Status400BadRequest,
    HipTrustReceiptVerificationStatus.Expired or
    HipTrustReceiptVerificationStatus.TimestampOutsideTolerance or
    HipTrustReceiptVerificationStatus.ValidityWindowExceeded or
    HipTrustReceiptVerificationStatus.IssuerNotAuthorized or
    HipTrustReceiptVerificationStatus.IssuerNotFound or
    HipTrustReceiptVerificationStatus.IssuerNotVerified or
    HipTrustReceiptVerificationStatus.IssuerSuspended or
    HipTrustReceiptVerificationStatus.IssuerRevoked or
    HipTrustReceiptVerificationStatus.IssuerBindingMismatch or
    HipTrustReceiptVerificationStatus.KeyNotFound or
    HipTrustReceiptVerificationStatus.KeyNotValidAtIssuedTime or
    HipTrustReceiptVerificationStatus.KeyRevoked or
    HipTrustReceiptVerificationStatus.SignatureMetadataMismatch or
    HipTrustReceiptVerificationStatus.InvalidSignature => StatusCodes.Status422UnprocessableEntity,
    _ => StatusCodes.Status503ServiceUnavailable
};

/// <summary>Validates receipt identifiers before allowing a persistence query.</summary>
static bool IsValidTrustReceiptId(string? receiptId) =>
    !string.IsNullOrWhiteSpace(receiptId) &&
    receiptId.Length <= HipTrustReceipt.MaximumReceiptIdLength &&
    receiptId.All(character =>
        character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '_' or '.' or ':');

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
        HttpContext httpContext,
        AdminSiteSafetyRuleService service,
        CancellationToken cancellationToken) =>
    {
        try
        {
            var actor = ResolveAdminActor(httpContext);
            var actorBoundRule = rule with
            {
                CreatedBy = actor,
                CreatedAtUtc = default,
                ApprovedBy = null,
                ApprovedAtUtc = null,
                UpdatedBy = null,
                UpdatedAtUtc = null
            };
            return Results.Ok(await service.CreateAsync(actorBoundRule, cancellationToken));
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
        .RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);

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
        HttpContext httpContext,
        AdminSiteSafetyRuleService service,
        CancellationToken cancellationToken) =>
        await RunRuleActionAsync(() => service.ApproveAsync(ruleId, ResolveAdminActor(httpContext), cancellationToken)))
        .RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);

    adminRuleApi.MapPost("/{ruleId}/activate", async (
        string ruleId,
        AdminSiteSafetyRuleActionRequest request,
        HttpContext httpContext,
        AdminSiteSafetyRuleService service,
        CancellationToken cancellationToken) =>
        await RunRuleActionAsync(() => service.ActivateAsync(ruleId, ResolveAdminActor(httpContext), cancellationToken)))
        .RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);

    adminRuleApi.MapPost("/{ruleId}/disable", async (
        string ruleId,
        AdminSiteSafetyRuleActionRequest request,
        HttpContext httpContext,
        AdminSiteSafetyRuleService service,
        CancellationToken cancellationToken) =>
        await RunRuleActionAsync(() => service.DisableAsync(ruleId, ResolveAdminActor(httpContext), cancellationToken)))
        .RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);

    adminRuleApi.MapPost("/{ruleId}/rollback", async (
        string ruleId,
        AdminSiteSafetyRuleActionRequest request,
        HttpContext httpContext,
        AdminSiteSafetyRuleService service,
        CancellationToken cancellationToken) =>
        await RunRuleActionAsync(() => service.RollbackAsync(ruleId, ResolveAdminActor(httpContext), cancellationToken)))
        .RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);
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
    result.ScoreImpact,
    Scoring = result.Scoring is null
        ? null
        : new
        {
            result.Scoring.ModelVersion,
            result.Scoring.DomainTrustScore,
            result.Scoring.PageTrustScore,
            result.Scoring.ContentRiskScore,
            result.Scoring.FinalHipScore,
            FinalStatus = result.Scoring.FinalStatus.ToString(),
            PresentationStatus = result.Scoring.PresentationStatus.ToString(),
            Confidence = result.Scoring.Confidence.ToString(),
            EvidenceFreshness = result.Scoring.EvidenceFreshness.ToString(),
            TrustAssertionDisposition = result.Scoring.TrustAssertionDisposition.ToString(),
            result.Scoring.CanAssertPositiveTrust,
            result.Scoring.FinalScoreHigherMeansMoreTrust,
            result.Scoring.ContentRiskScoreHigherMeansMoreRisk,
            result.Scoring.Reasons,
            result.Scoring.Warnings,
            ReasonEntries = result.Scoring.ReasonEntries.Select(entry => new
            {
                entry.Code,
                entry.Explanation,
                entry.WarningCode,
                entry.Warning,
                Impact = new
                {
                    Kind = entry.Impact.Kind.ToString(),
                    entry.Impact.Value
                },
                entry.EvidenceSourceCode,
                entry.EvidenceObservedAtUtc,
                PrivacyClassification = entry.PrivacyClassification.ToString()
            }).ToArray()
        }
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
        ResultStatus = evidence.ResultStatus.ToString(),
        evidence.LatencyMilliseconds,
        Freshness = evidence.Freshness.ToString(),
        PrivacyClassification = evidence.PrivacyClassification.ToString(),
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

/// <summary>Projects durable provider job state without owner, settings, lease, hash, or observed-signal data.</summary>
static object ToExternalSiteEvidenceJobResponse(ExternalSiteEvidenceJob job) => new
{
    job.JobId,
    job.Domain,
    Status = job.Status.ToString(),
    job.AttemptCount,
    job.RequestedAtUtc,
    job.UpdatedAtUtc,
    job.NextAttemptAtUtc,
    job.CompletedAtUtc,
    job.LastError,
    ProviderEvidence = ToSiteSafetyProviderEvidenceResponse(job.ProviderEvidence)
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
        AiRuleDraftService draftService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            var draft = await draftService.CreateAsync(request, cancellationToken);
            return Results.Created(
                $"/api/v1/ai/rule-drafts/{Uri.EscapeDataString(draft.DraftId)}",
                AiRuleDraftApiResponse.From(draft));
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException or InvalidOperationException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    aiApi.MapGet("/rule-drafts", async (
        AiRuleDraftService draftService,
        CancellationToken cancellationToken) =>
        Results.Ok((await draftService.ListAsync(cancellationToken)).Select(AiRuleDraftApiResponse.From).ToArray()));

    aiApi.MapGet("/rule-drafts/{draftId}", async (
        string draftId,
        AiRuleDraftService draftService,
        CancellationToken cancellationToken) =>
    {
        var draft = await draftService.GetAsync(draftId, cancellationToken);
        return draft is null ? Results.NotFound() : Results.Ok(AiRuleDraftApiResponse.From(draft));
    });

    aiApi.MapPost("/rule-drafts/{draftId}/submit-for-approval", async (
        string draftId,
        HttpContext httpContext,
        AiRuleDraftService draftService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            var workflow = await draftService.SubmitForApprovalAsync(
                draftId,
                HipAuthenticatedIdentity.ResolveRequiredUniqueClaim(
                    httpContext.User,
                    HipAuthenticationClaimTypes.ActorId),
                cancellationToken);
            return Results.Ok(RuleApprovalWorkflowApiResponse.From(workflow));
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }).RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);
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

    consumerApi.MapPost("/appeals", async (
        HttpContext httpContext,
        ConsumerAppealSubmissionRequest request,
        IConsumerPortalService consumerPortalService,
        CancellationToken cancellationToken) =>
    {
        var result = await consumerPortalService.SubmitAppealAsync(
            ConsumerId(httpContext),
            request,
            cancellationToken);
        return result.Accepted ? Results.Ok(result) : Results.BadRequest(result);
    });

    consumerApi.MapGet("/settings", async (
        HttpContext httpContext,
        IConsumerPortalService consumerPortalService,
        CancellationToken cancellationToken) =>
        Results.Ok(await consumerPortalService.GetSettingsAsync(ConsumerId(httpContext), cancellationToken)));

    consumerApi.MapPost("/settings", async (
        HttpContext httpContext,
        ConsumerSettings settings,
        IConsumerPortalService consumerPortalService,
        CancellationToken cancellationToken) =>
    {
        var result = await consumerPortalService.SaveSettingsAsync(
            ConsumerId(httpContext),
            settings,
            cancellationToken);
        return result.Saved ? Results.Ok(result) : Results.BadRequest(result);
    });

    MapConsumerDeviceApis(consumerApi.MapGroup("/devices"));
}

/// <summary>Maps consumer-owned device registration, listing, and revocation endpoints.</summary>
static void MapConsumerDeviceApis(RouteGroupBuilder deviceApi)
{
    const long maximumDeviceMutationBodyBytes = 8 * 1024;

    deviceApi.MapPost("/registration-challenges", async (
        StartDeviceRegistrationRequest request,
        HttpContext httpContext,
        IAntiforgery antiforgery,
        IDeviceRegistrationService registrationService,
        CancellationToken cancellationToken) =>
    {
        var antiforgeryFailure = await ValidateConsumerDeviceAntiforgeryAsync(httpContext, antiforgery);
        if (antiforgeryFailure is not null)
        {
            return antiforgeryFailure;
        }

        try
        {
            var result = await registrationService.IssueChallengeAsync(
                ConsumerId(httpContext),
                request,
                cancellationToken);
            return result.Outcome == DeviceRegistrationOutcome.Succeeded && result.Challenge is { } challenge
                ? Results.Created(
                    $"{ApiRoutes.Consumer}/devices/registration-challenges/{Uri.EscapeDataString(challenge.ChallengeId)}",
                    challenge)
                : DeviceRegistrationFailure(result.Outcome);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return DeviceRegistrationUnavailable();
        }
    })
        .WithName("IssueConsumerDeviceRegistrationChallenge")
        .WithSummary("Issue a consumer-owned device registration challenge")
        .WithDescription("Validates bounded public device metadata, derives the owner only from the authenticated HIP consumer claim, and returns a short-lived signing input. Private keys and hardware fingerprints are never accepted.")
        .Accepts<StartDeviceRegistrationRequest>("application/json")
        .Produces<DeviceRegistrationChallengeResponse>(StatusCodes.Status201Created)
        .Produces<ApiErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status401Unauthorized)
        .Produces(StatusCodes.Status403Forbidden)
        .Produces<ApiErrorResponse>(StatusCodes.Status409Conflict)
        .Produces(StatusCodes.Status413PayloadTooLarge)
        .Produces<ApiErrorResponse>(StatusCodes.Status429TooManyRequests)
        .Produces<ApiErrorResponse>(StatusCodes.Status503ServiceUnavailable)
        .RequireRateLimiting(ConsumerDeviceMutationRateLimitPolicy)
        .WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(maximumDeviceMutationBodyBytes));

    deviceApi.MapPost("/registration-challenges/{challengeId}/responses", async (
        string challengeId,
        CompleteDeviceRegistrationRequest request,
        HttpContext httpContext,
        IAntiforgery antiforgery,
        IDeviceRegistrationService registrationService,
        CancellationToken cancellationToken) =>
    {
        var antiforgeryFailure = await ValidateConsumerDeviceAntiforgeryAsync(httpContext, antiforgery);
        if (antiforgeryFailure is not null)
        {
            return antiforgeryFailure;
        }

        try
        {
            var result = await registrationService.CompleteAsync(
                ConsumerId(httpContext),
                challengeId,
                request,
                cancellationToken);
            return result.Outcome == DeviceRegistrationOutcome.Succeeded && result.Device is { } device
                ? Results.Ok(device)
                : DeviceRegistrationFailure(result.Outcome);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return DeviceRegistrationUnavailable();
        }
    })
        .WithName("CompleteConsumerDeviceRegistration")
        .WithSummary("Complete a consumer-owned device registration")
        .WithDescription("Verifies the exact challenge signing input and a WebCrypto-compatible P-256 proof for the authenticated consumer, then atomically consumes the challenge.")
        .Accepts<CompleteDeviceRegistrationRequest>("application/json")
        .Produces<DeviceRegistrationDeviceResponse>(StatusCodes.Status200OK)
        .Produces<ApiErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status401Unauthorized)
        .Produces(StatusCodes.Status403Forbidden)
        .Produces<ApiErrorResponse>(StatusCodes.Status404NotFound)
        .Produces<ApiErrorResponse>(StatusCodes.Status409Conflict)
        .Produces<ApiErrorResponse>(StatusCodes.Status410Gone)
        .Produces(StatusCodes.Status413PayloadTooLarge)
        .Produces<ApiErrorResponse>(StatusCodes.Status422UnprocessableEntity)
        .Produces<ApiErrorResponse>(StatusCodes.Status429TooManyRequests)
        .Produces<ApiErrorResponse>(StatusCodes.Status503ServiceUnavailable)
        .RequireRateLimiting(ConsumerDeviceMutationRateLimitPolicy)
        .WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(maximumDeviceMutationBodyBytes));

    deviceApi.MapGet("/", async (
        HttpContext httpContext,
        IAntiforgery antiforgery,
        IDeviceRegistrationService registrationService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            AddConsumerDeviceAntiforgeryToken(httpContext, antiforgery);
            return Results.Ok(await registrationService.ListAsync(ConsumerId(httpContext), cancellationToken));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return DeviceRegistrationUnavailable();
        }
    })
        .WithName("ListConsumerDevices")
        .WithSummary("List the authenticated consumer's devices")
        .WithDescription("Returns only privacy-safe device summaries owned by the authenticated HIP consumer. Cookie-session callers also receive an antiforgery request token in the named response header for later mutations.")
        .Produces<IReadOnlyCollection<DeviceRegistrationDeviceResponse>>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status401Unauthorized)
        .Produces(StatusCodes.Status403Forbidden)
        .Produces<ApiErrorResponse>(StatusCodes.Status503ServiceUnavailable);

    deviceApi.MapPost("/{deviceId}/revoke", async (
        string deviceId,
        HttpContext httpContext,
        IAntiforgery antiforgery,
        IDeviceRegistrationService registrationService,
        CancellationToken cancellationToken) =>
    {
        var antiforgeryFailure = await ValidateConsumerDeviceAntiforgeryAsync(httpContext, antiforgery);
        if (antiforgeryFailure is not null)
        {
            return antiforgeryFailure;
        }

        try
        {
            var result = await registrationService.RevokeAsync(
                ConsumerId(httpContext),
                deviceId,
                cancellationToken);
            return result.Outcome == DeviceRegistrationOutcome.Succeeded && result.Device is { } device
                ? Results.Ok(device)
                : DeviceRegistrationFailure(result.Outcome);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return DeviceRegistrationUnavailable();
        }
    })
        .WithName("RevokeConsumerDevice")
        .WithSummary("Revoke a consumer-owned device")
        .WithDescription("Irreversibly revokes only a device owned by the authenticated HIP consumer. Unknown and wrong-owner device identifiers receive the same non-disclosing response.")
        .Produces<DeviceRegistrationDeviceResponse>(StatusCodes.Status200OK)
        .Produces<ApiErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status401Unauthorized)
        .Produces(StatusCodes.Status403Forbidden)
        .Produces<ApiErrorResponse>(StatusCodes.Status404NotFound)
        .Produces<ApiErrorResponse>(StatusCodes.Status409Conflict)
        .Produces(StatusCodes.Status413PayloadTooLarge)
        .Produces<ApiErrorResponse>(StatusCodes.Status429TooManyRequests)
        .Produces<ApiErrorResponse>(StatusCodes.Status503ServiceUnavailable)
        .RequireRateLimiting(ConsumerDeviceMutationRateLimitPolicy)
        .WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(maximumDeviceMutationBodyBytes));
}

/// <summary>Maps a typed device-registration failure to a stable, non-sensitive API result.</summary>
static IResult DeviceRegistrationFailure(DeviceRegistrationOutcome outcome) => outcome switch
{
    DeviceRegistrationOutcome.InvalidRequest => Results.BadRequest(
        new ApiErrorResponse(DeviceRegistrationMessages.InvalidRequest)),
    DeviceRegistrationOutcome.InvalidProof => Results.Json(
        new ApiErrorResponse(DeviceRegistrationMessages.InvalidProof),
        statusCode: StatusCodes.Status422UnprocessableEntity),
    DeviceRegistrationOutcome.Expired => Results.Json(
        new ApiErrorResponse(DeviceRegistrationMessages.Expired),
        statusCode: StatusCodes.Status410Gone),
    DeviceRegistrationOutcome.Conflict => Results.Conflict(
        new ApiErrorResponse(DeviceRegistrationMessages.Conflict)),
    DeviceRegistrationOutcome.NotFound => Results.NotFound(
        new ApiErrorResponse(DeviceRegistrationMessages.ResourceUnavailable)),
    _ => DeviceRegistrationUnavailable()
};

/// <summary>Returns HIP's generic device-registration availability boundary without exception details.</summary>
static IResult DeviceRegistrationUnavailable() => Results.Json(
    new ApiErrorResponse(DeviceRegistrationMessages.Unavailable),
    statusCode: StatusCodes.Status503ServiceUnavailable);

/// <summary>Requires an antiforgery token only when the current request was authenticated by HIP's browser cookie.</summary>
static async Task<IResult?> ValidateConsumerDeviceAntiforgeryAsync(
    HttpContext httpContext,
    IAntiforgery antiforgery)
{
    if (!IsHipSessionCookieAuthenticated(httpContext))
    {
        return null;
    }

    return await antiforgery.IsRequestValidAsync(httpContext)
        ? null
        : Results.BadRequest(new ApiErrorResponse("The antiforgery token is invalid."));
}

/// <summary>Adds a same-origin antiforgery request token to an authenticated device-list response.</summary>
static void AddConsumerDeviceAntiforgeryToken(HttpContext httpContext, IAntiforgery antiforgery)
{
    if (!IsHipSessionCookieAuthenticated(httpContext))
    {
        return;
    }

    var tokens = antiforgery.GetAndStoreTokens(httpContext);
    if (!string.IsNullOrWhiteSpace(tokens.HeaderName) && !string.IsNullOrWhiteSpace(tokens.RequestToken))
    {
        httpContext.Response.Headers[tokens.HeaderName] = tokens.RequestToken;
        httpContext.Response.Headers.CacheControl = "no-store";
        httpContext.Response.Headers.Pragma = "no-cache";
    }
}

static bool IsHipSessionCookieAuthenticated(HttpContext httpContext) =>
    string.Equals(
        httpContext.Features.Get<IAuthenticateResultFeature>()
            ?.AuthenticateResult
            ?.Ticket
            ?.AuthenticationScheme,
        HipAuthenticationSchemes.SessionCookie,
        StringComparison.Ordinal);

static string ConsumerId(HttpContext httpContext) =>
    HipAuthenticatedIdentity.ResolveRequiredUniqueClaim(
        httpContext.User,
        HipAuthenticationClaimTypes.ConsumerId);

/// <summary>
/// Resolves the current admin actor label for audit-friendly metadata without exposing authentication internals.
/// </summary>
/// <param name="httpContext">Current HTTP request context.</param>
/// <returns>Admin actor label suitable for persistence in privacy-safe admin records.</returns>
static string ResolveAdminActor(HttpContext httpContext) =>
    HipAuthenticatedIdentity.ResolveRequiredUniqueClaim(
        httpContext.User,
        HipAuthenticationClaimTypes.ActorId);

static void MapSecondLifeHudApis(RouteGroupBuilder slHudApi)
{
    const long maximumHudActivationBodyBytes = 16 * 1024;
    const long maximumHudSettingsBodyBytes = 16 * 1024;
    const long maximumHudSignalBodyBytes = 64 * 1024;

    slHudApi.MapPost("/activate", (
        SecondLifeHudActivationRequest request,
        ISecondLifeHudService hudService) =>
    {
        try
        {
            var response = hudService.Activate(request);
            return response.Activated ? Results.Ok(response) : Results.BadRequest(response);
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
        .AllowAnonymous()
        .RequireRateLimiting(RateLimitPolicies.PublicScanPolicy)
        .WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(maximumHudActivationBodyBytes));

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
    })
        .RequireAuthorization(HudPolicies.CanUseActiveDevice)
        .RequireRateLimiting(RateLimitPolicies.PublicScanPolicy)
        .WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(maximumHudSignalBodyBytes))
        .WithMetadata(new HudDeviceAuthorizationMetadata(HudDeviceIdentifierLocation.JsonBody, "deviceId"));

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
    })
        .RequireAuthorization(AdminPolicies.CanSupportLicenses)
        .WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(maximumHudSignalBodyBytes));

    slHudApi.MapGet("/settings/{deviceId}", (
        string deviceId,
        HttpContext httpContext,
        ISecondLifeHudService hudService) =>
    {
        try
        {
            return Results.Ok(hudService.GetSettings(
                HudDeviceAuthorizationContext.GetRequiredLicenseId(httpContext),
                deviceId));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
        .RequireAuthorization(HudPolicies.CanUseActiveDevice)
        .RequireRateLimiting(RateLimitPolicies.PublicScanPolicy)
        .WithMetadata(new HudDeviceAuthorizationMetadata(HudDeviceIdentifierLocation.Route, "deviceId"));

    slHudApi.MapPost("/settings/{deviceId}", (
        string deviceId,
        SecondLifeHudSettings settings,
        HttpContext httpContext,
        ISecondLifeHudService hudService) =>
    {
        try
        {
            var response = hudService.SaveSettings(
                HudDeviceAuthorizationContext.GetRequiredLicenseId(httpContext),
                deviceId,
                settings);
            return response.Saved ? Results.Ok(response) : Results.BadRequest(response);
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
        .RequireAuthorization(HudPolicies.CanUseActiveDevice)
        .RequireRateLimiting(RateLimitPolicies.PublicScanPolicy)
        .WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(maximumHudSettingsBodyBytes))
        .WithMetadata(new HudDeviceAuthorizationMetadata(HudDeviceIdentifierLocation.Route, "deviceId"));

    slHudApi.MapPost("/report", async (
        SecondLifeHudFindingReport report,
        ISecondLifeHudService hudService,
        CancellationToken cancellationToken) =>
    {
        var response = await hudService.ReportFindingAsync(report, cancellationToken);
        return response.Accepted ? Results.Ok(response) : Results.BadRequest(response);
    })
        .RequireAuthorization(HudPolicies.CanUseActiveDevice)
        .RequireRateLimiting(RateLimitPolicies.PublicFeedbackPolicy)
        .WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(maximumHudSignalBodyBytes))
        .WithMetadata(new HudDeviceAuthorizationMetadata(HudDeviceIdentifierLocation.JsonBody, "hudDeviceId"));

    slHudApi.MapPost("/report-finding", async (
        SecondLifeHudFindingReport report,
        ISecondLifeHudService hudService,
        CancellationToken cancellationToken) =>
    {
        var response = await hudService.ReportFindingAsync(report, cancellationToken);
        return response.Accepted ? Results.Ok(response) : Results.BadRequest(response);
    })
        .RequireAuthorization(HudPolicies.CanUseActiveDevice)
        .RequireRateLimiting(RateLimitPolicies.PublicFeedbackPolicy)
        .WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(maximumHudSignalBodyBytes))
        .WithMetadata(new HudDeviceAuthorizationMetadata(HudDeviceIdentifierLocation.JsonBody, "hudDeviceId"));
}

/// <summary>
/// Maps protected setup code and license support endpoints for the Second Life HUD marketplace flow.
/// </summary>
/// <param name="licenseApi">The protected license route group.</param>
static void MapLicenseApis(RouteGroupBuilder licenseApi)
{
    licenseApi.MapPost("/setup-codes", (
        CreateSetupCodeRequest request,
        HttpContext httpContext,
        ISetupCodeLicenseService licenseService) =>
        Results.Ok(licenseService.CreateSetupCode(request with
        {
            CreatedBy = ResolveAdminActor(httpContext)
        })))
        .RequireAuthorization(AdminPolicies.CanAdministerLicenses)
        .RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);

    licenseApi.MapGet("/", async (
        ISetupCodeLicenseService licenseService,
        CancellationToken cancellationToken) =>
        Results.Ok((await licenseService.ListLicensesAsync(cancellationToken))
            .Select(ToPrivacySafeLicenseSummary)
            .ToArray()))
        .RequireAuthorization(AdminPolicies.CanViewLicenses);

    licenseApi.MapGet("/{licenseId}", (
        string licenseId,
        ISetupCodeLicenseService licenseService) =>
        licenseService.GetLicense(licenseId) is { } license
            ? Results.Ok(ToPrivacySafeLicenseSummary(license))
            : Results.NotFound(new { error = "License was not found." }))
        .RequireAuthorization(AdminPolicies.CanViewLicenses);

    licenseApi.MapPost("/{licenseId}/reset", (
        string licenseId,
        ISetupCodeLicenseService licenseService) =>
        licenseService.ResetActivation(licenseId) is { } license
            ? Results.Ok(ToPrivacySafeLicenseSummary(license))
            : Results.NotFound(new { error = "License was not found." }))
        .RequireAuthorization(AdminPolicies.CanSupportLicenses);

    licenseApi.MapPost("/{licenseId}/revoke", (
        string licenseId,
        ISetupCodeLicenseService licenseService) =>
        licenseService.SetStatus(licenseId, LicenseStatus.Revoked) is { } license
            ? Results.Ok(ToPrivacySafeLicenseSummary(license))
            : Results.NotFound(new { error = "License was not found." }))
        .RequireAuthorization(AdminPolicies.CanAdministerLicenses)
        .RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);

    licenseApi.MapPost("/{licenseId}/suspend", (
        string licenseId,
        ISetupCodeLicenseService licenseService) =>
        licenseService.SetStatus(licenseId, LicenseStatus.Suspended) is { } license
            ? Results.Ok(ToPrivacySafeLicenseSummary(license))
            : Results.NotFound(new { error = "License was not found." }))
        .RequireAuthorization(AdminPolicies.CanAdministerLicenses)
        .RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);

    licenseApi.MapPost("/{licenseId}/reactivate", (
        string licenseId,
        ISetupCodeLicenseService licenseService) =>
        licenseService.SetStatus(licenseId, LicenseStatus.Active) is { } license
            ? Results.Ok(ToPrivacySafeLicenseSummary(license))
            : Results.NotFound(new { error = "License was not found." }))
        .RequireAuthorization(AdminPolicies.CanAdministerLicenses)
        .RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);
}

/// <summary>
/// Removes stable actor attribution and masks device identifiers before a license summary crosses the admin API boundary.
/// </summary>
static LicenseSummary ToPrivacySafeLicenseSummary(LicenseSummary license) =>
    license with
    {
        DeviceIds = license.DeviceIds.Select(MaskLicenseDeviceId).ToArray(),
        CreatedBy = null
    };

/// <summary>
/// Produces the same shortened device reference used by the admin license UI.
/// </summary>
static string MaskLicenseDeviceId(string deviceId) =>
    deviceId.Length <= 8 ? "••••" : $"{deviceId[..6]}••••{deviceId[^4..]}";

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
    reviewApi.MapGet("/", (IReviewQueueService reviewQueueService) => Results.Ok(reviewQueueService.List()))
        .RequireAuthorization(AdminPolicies.CanViewReviews);

    reviewApi.MapGet("/{id}", (string id, IReviewQueueService reviewQueueService) =>
        reviewQueueService.Get(id) is { } item ? Results.Ok(item) : Results.NotFound())
        .RequireAuthorization(AdminPolicies.CanViewReviews);

    reviewApi.MapPost("/", (
        ReviewItem item,
        HttpContext httpContext,
        IReviewQueueService reviewQueueService) =>
    {
        try
        {
            var actorBoundItem = item with
            {
                ReviewItemId = string.Empty,
                Status = ReviewStatus.Submitted,
                CreatedAtUtc = default,
                UpdatedAtUtc = default,
                CreatedBy = ResolveAdminActor(httpContext),
                AssignedTo = null,
                Decision = null,
                DecisionReason = null
            };
            return Results.Ok(reviewQueueService.Create(actorBoundItem));
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
        .RequireAuthorization(AdminPolicies.CanDecideReviews);

    reviewApi.MapPost("/{id}/approve", (
        string id,
        AdminDecisionRequest request,
        HttpContext httpContext,
        IReviewQueueService reviewQueueService) =>
        Results.Ok(reviewQueueService.Approve(id, ResolveAdminActor(httpContext), request.Reason)))
        .RequireAuthorization(AdminPolicies.CanDecideReviews);

    reviewApi.MapPost("/{id}/reject", (
        string id,
        AdminDecisionRequest request,
        HttpContext httpContext,
        IReviewQueueService reviewQueueService) =>
        Results.Ok(reviewQueueService.Reject(id, ResolveAdminActor(httpContext), request.Reason)))
        .RequireAuthorization(AdminPolicies.CanDecideReviews);

    reviewApi.MapPost("/{id}/needs-more-info", (
        string id,
        AdminDecisionRequest request,
        HttpContext httpContext,
        IReviewQueueService reviewQueueService) =>
        Results.Ok(reviewQueueService.RequestMoreInfo(id, ResolveAdminActor(httpContext), request.Reason)))
        .RequireAuthorization(AdminPolicies.CanDecideReviews);

    reviewApi.MapPost("/{id}/decision", (
        string id,
        AdminReviewDecisionRequest request,
        HttpContext httpContext,
        IReviewQueueService reviewQueueService) =>
        ReviewDecision(id, request, ResolveAdminActor(httpContext), reviewQueueService))
        .RequireAuthorization(AdminPolicies.CanDecideReviews);

    reviewApi.MapPost("/{id}/assign", (
        string id,
        AdminAssignRequest request,
        HttpContext httpContext,
        IReviewQueueService reviewQueueService) =>
        Results.Ok(reviewQueueService.Assign(id, request.AssignedTo, ResolveAdminActor(httpContext))))
        .RequireAuthorization(AdminPolicies.CanDecideReviews);
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
        Results.Ok(await adminReviewQueueService.ListAsync(cancellationToken)))
        .RequireAuthorization(AdminPolicies.CanViewReviews);

    adminReviewQueueApi.MapGet("/{id}", async (
        string id,
        IAdminReviewQueueService adminReviewQueueService,
        CancellationToken cancellationToken) =>
    {
        var item = await adminReviewQueueService.GetAsync(id, cancellationToken);
        return item is null ? Results.NotFound() : Results.Ok(item);
    })
        .RequireAuthorization(AdminPolicies.CanViewReviews);

    adminReviewQueueApi.MapPost("/{id}/assign", async (
        string id,
        AdminReviewQueueAssignRequest request,
        HttpContext httpContext,
        IAdminReviewQueueService adminReviewQueueService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await adminReviewQueueService.AssignAsync(
                id,
                request.AssignedTo,
                ResolveAdminActor(httpContext),
                cancellationToken));
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
        .RequireAuthorization(AdminPolicies.CanDecideReviews);

    adminReviewQueueApi.MapPost("/{id}/decision", async (
        string id,
        HIP.Application.Review.AdminReviewDecisionRequest request,
        HttpContext httpContext,
        IAdminReviewQueueService adminReviewQueueService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            var actorBoundRequest = request with { ReviewedBy = ResolveAdminActor(httpContext) };
            return Results.Ok(await adminReviewQueueService.RecordDecisionAsync(
                id,
                actorBoundRequest,
                cancellationToken));
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
        .RequireAuthorization(AdminPolicies.CanDecideReviews);

    adminReviewQueueApi.MapPost("/{id}/dismiss", async (
        string id,
        AdminReviewQueueDismissRequest request,
        HttpContext httpContext,
        IAdminReviewQueueService adminReviewQueueService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await adminReviewQueueService.DismissAsync(
                id,
                ResolveAdminActor(httpContext),
                request.Reason,
                cancellationToken));
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
        .RequireAuthorization(AdminPolicies.CanDecideReviews);
}

static void MapAppealApis(RouteGroupBuilder appealApi)
{
    appealApi.MapGet("/", (IAppealService appealService) => Results.Ok(appealService.List()))
        .RequireAuthorization(AdminPolicies.CanViewAppeals);
    appealApi.MapGet("/{id}", (string id, IAppealService appealService) =>
        appealService.Get(id) is { } appeal ? Results.Ok(appeal) : Results.NotFound())
        .RequireAuthorization(AdminPolicies.CanViewAppeals);
    appealApi.MapPost("/{id}/approve", (
        string id,
        AdminDecisionRequest request,
        HttpContext httpContext,
        IAppealService appealService) =>
        Results.Ok(appealService.Approve(id, ResolveAdminActor(httpContext), request.Reason)))
        .RequireAuthorization(AdminPolicies.CanDecideAppeals);
    appealApi.MapPost("/{id}/reject", (
        string id,
        AdminDecisionRequest request,
        HttpContext httpContext,
        IAppealService appealService) =>
        Results.Ok(appealService.Reject(id, ResolveAdminActor(httpContext), request.Reason)))
        .RequireAuthorization(AdminPolicies.CanDecideAppeals);
    appealApi.MapPost("/{id}/needs-more-info", (
        string id,
        AdminDecisionRequest request,
        HttpContext httpContext,
        IAppealService appealService) =>
        Results.Ok(appealService.RequestMoreInfo(id, ResolveAdminActor(httpContext), request.Reason)))
        .RequireAuthorization(AdminPolicies.CanDecideAppeals);
    appealApi.MapPost("/{id}/decision", (
        string id,
        AdminAppealDecisionRequest request,
        HttpContext httpContext,
        IAppealService appealService) =>
        AppealDecision(id, request, ResolveAdminActor(httpContext), appealService))
        .RequireAuthorization(AdminPolicies.CanDecideAppeals);
}

static IResult ReviewDecision(
    string id,
    AdminReviewDecisionRequest request,
    string actorId,
    IReviewQueueService reviewQueueService) =>
    request.Status switch
    {
        ReviewStatus.Confirmed or ReviewStatus.Approved => Results.Ok(reviewQueueService.Approve(id, actorId, request.Reason)),
        ReviewStatus.Rejected => Results.Ok(reviewQueueService.Reject(id, actorId, request.Reason)),
        ReviewStatus.NeedsMoreInfo => Results.Ok(reviewQueueService.RequestMoreInfo(id, actorId, request.Reason)),
        ReviewStatus.Closed => Results.Ok(reviewQueueService.Close(id, actorId, request.Reason)),
        ReviewStatus.InReview => Results.Ok(reviewQueueService.UpdateStatus(id, ReviewStatus.InReview, actorId, request.Reason)),
        _ => Results.BadRequest(new { error = "Decision status must be InReview, Confirmed, Rejected, NeedsMoreInfo, or Closed." })
    };

static IResult AppealDecision(
    string id,
    AdminAppealDecisionRequest request,
    string actorId,
    IAppealService appealService) =>
    request.Status switch
    {
        AppealStatus.Approved => Results.Ok(appealService.Approve(id, actorId, request.Reason)),
        AppealStatus.Rejected => Results.Ok(appealService.Reject(id, actorId, request.Reason)),
        AppealStatus.NeedsMoreInfo => Results.Ok(appealService.RequestMoreInfo(id, actorId, request.Reason)),
        _ => Results.BadRequest(new { error = "Decision status must be Approved, Rejected, or NeedsMoreInfo." })
    };

static void MapReputationOverrideApis(RouteGroupBuilder overrideApi)
{
    overrideApi.MapGet("/", (IReputationOverrideService reputationOverrideService) => Results.Ok(reputationOverrideService.List()));
    overrideApi.MapPost("/", (
        ReputationOverrideRequest request,
        HttpContext httpContext,
        IReputationOverrideService reputationOverrideService) =>
    {
        try
        {
            var actorBoundRequest = request with
            {
                RequestedBy = ResolveAdminActor(httpContext),
                Approvals = [],
                CreatedAtUtc = default,
                UpdatedAtUtc = default
            };
            return Results.Ok(reputationOverrideService.Request(actorBoundRequest));
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
        .RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);
    overrideApi.MapPost("/{id}/approve", (
        string id,
        AdminDecisionRequest request,
        HttpContext httpContext,
        IReputationOverrideService reputationOverrideService) =>
        RunReputationOverrideAction(() => reputationOverrideService.Approve(
            id,
            ResolveAdminActor(httpContext),
            request.Reason)))
        .RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);
    overrideApi.MapPost("/{id}/reject", (
        string id,
        AdminDecisionRequest request,
        HttpContext httpContext,
        IReputationOverrideService reputationOverrideService) =>
        RunReputationOverrideAction(() => reputationOverrideService.Reject(
            id,
            ResolveAdminActor(httpContext),
            request.Reason)))
        .RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);
}

static IResult RunReputationOverrideAction(Func<ReputationOverrideRequest> action)
{
    try
    {
        return Results.Ok(action());
    }
    catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
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
    })
        .RequireAuthorization(AdminPolicies.CanManageReputation)
        .RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);

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
    })
        .RequireAuthorization(AdminPolicies.CanManageReputation)
        .RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);
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
        .RequireAuthorization(AdminPolicies.CanManageDomainVerifications)
        .RequireRateLimiting(RateLimitPolicies.IdentityDevPolicy);

    identityApi.MapPost("/websites/register", async (
        WebsiteIdentityRegistrationRequest request,
        HttpContext httpContext,
        IWebsiteIdentityService websiteIdentityService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await websiteIdentityService.RegisterAsync(
                request,
                ResolveAdminActor(httpContext),
                httpContext.User.FindFirstValue(ClaimTypes.Role) ?? "Unknown",
                cancellationToken));
        }
        catch (WebsiteIdentityRegistrationConflictException ex)
        {
            return Results.Conflict(new { error = ex.Message });
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    })
        .RequireAuthorization(AdminPolicies.CanManageDomainVerifications);

    identityApi.MapPost("/websites/verify", async (
        WebsiteVerificationRequest request,
        HttpContext httpContext,
        IWebsiteIdentityService websiteIdentityService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await websiteIdentityService.VerifyAsync(
                request,
                ResolveAdminActor(httpContext),
                httpContext.User.FindFirstValue(ClaimTypes.Role) ?? "Unknown",
                cancellationToken));
        }
        catch (WebsiteIdentityRegistrationConflictException ex)
        {
            return Results.Conflict(new { error = ex.Message });
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
                ResolveAdminActor(httpContext),
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
                ResolveAdminActor(httpContext),
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
        .RequireAuthorization(AdminPolicies.CanRevokeDomainVerifications)
        .RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);

    identityApi.MapGet("/websites/{domain}/well-known-template", async (
        string domain,
        HttpContext httpContext,
        IWebsiteIdentityService websiteIdentityService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await websiteIdentityService.BuildWellKnownDocumentAsync(
                domain,
                ResolveAdminActor(httpContext),
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

    identityApi.MapGet("/websites/{domain}", async (
        string domain,
        HttpContext httpContext,
        IWebsiteIdentityService websiteIdentityService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return await websiteIdentityService.GetAsync(
                domain,
                ResolveAdminActor(httpContext),
                httpContext.User.FindFirstValue(ClaimTypes.Role) ?? "Unknown",
                cancellationToken) is { } website
                ? Results.Ok(website)
                : Results.NotFound();
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
        .AllowAnonymous();

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
    })
        .AllowAnonymous();

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
        catch (InvalidOperationException ex)
        {
            return Results.Conflict(new { error = ex.Message });
        }
    })
        .RequireAuthorization(AdminPolicies.CanManageDomainVerifications);

    identityApi.MapPost("/websites/{domain}/renew", async (
        string domain,
        HttpContext httpContext,
        IWebsiteIdentityService websiteIdentityService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await websiteIdentityService.RenewExpiredVerificationAsync(
                domain,
                ResolveAdminActor(httpContext),
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
        catch (InvalidOperationException ex)
        {
            return Results.Conflict(new { error = ex.Message });
        }
    })
        .RequireAuthorization(AdminPolicies.CanManageDomainVerifications);

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
        .RequireAuthorization(AdminPolicies.CanManageDomainVerifications)
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
    })
        .AllowAnonymous();
}

public sealed record AdminRuleSimulationRequest(
    TrustRule Rule,
    IReadOnlyCollection<RuleSimulationTestCase>? TestCases);

/// <summary>
/// Carries an administrative decision reason. <paramref name="ActorId"/> is retained for wire compatibility and ignored;
/// HIP binds attribution to the unique authenticated actor claim.
/// </summary>
public sealed record AdminDecisionRequest(string ActorId, string Reason);

/// <summary>
/// Carries a review status decision. <paramref name="ActorId"/> is compatibility-only and never trusted for attribution.
/// </summary>
public sealed record AdminReviewDecisionRequest(string ActorId, ReviewStatus Status, string Reason);

/// <summary>
/// Carries an appeal status decision. <paramref name="ActorId"/> is compatibility-only and never trusted for attribution.
/// </summary>
public sealed record AdminAppealDecisionRequest(string ActorId, AppealStatus Status, string Reason);

/// <summary>
/// Carries an assignee selection. <paramref name="ActorId"/> is compatibility-only and never trusted for attribution.
/// </summary>
public sealed record AdminAssignRequest(string ActorId, string AssignedTo);

/// <summary>
/// Request used to assign a generated admin review signal to a reviewer without exposing private evidence.
/// </summary>
/// <param name="ActorId">Compatibility-only actor field; HIP ignores it and uses the authenticated actor claim.</param>
/// <param name="AssignedTo">Reviewer ID, alias, or hash that should handle the review.</param>
public sealed record AdminReviewQueueAssignRequest(string ActorId, string AssignedTo);

/// <summary>
/// Request used to dismiss a generated admin review signal while preserving its privacy-safe evidence summary.
/// </summary>
/// <param name="ActorId">Compatibility-only actor field; HIP ignores it and uses the authenticated actor claim.</param>
/// <param name="Reason">Privacy-safe dismissal reason. Raw page text, credentials, and private messages are rejected by validation.</param>
public sealed record AdminReviewQueueDismissRequest(string ActorId, string Reason);

internal static class AdminEndpointIdentity
{
    public static bool TryResolve(ClaimsPrincipal principal, out string actorId, out string role)
    {
        actorId = string.Empty;
        role = string.Empty;
        if (!HipAuthenticatedIdentity.TryResolveUniqueClaim(
                principal,
                HipAuthenticationClaimTypes.ActorId,
                out actorId))
        {
            return false;
        }

        var roles = principal.FindAll(ClaimTypes.Role)
            .Select(claim => claim.Value)
            .Where(AdminRoles.All.Contains)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (roles.Length != 1)
        {
            actorId = string.Empty;
            return false;
        }

        role = roles[0];
        return true;
    }
}
public sealed record AdminSelfAccessResponse(string ActorId, AdminAccessAssignment? Assignment);

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
    bool ShouldRouteToSafetyPage,
    int PageTrustScore,
    int ContentRiskScore,
    int FinalHipScore,
    string ContinuationRequirement,
    bool ContentRiskScoreHigherMeansMoreRisk)
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
            result.ShouldRouteToSafetyPage,
            result.PageTrustScore,
            result.ContentRiskScore,
            result.FinalHipScore,
            result.ContinuationRequirement.ToString(),
            result.ContentRiskScoreHigherMeansMoreRisk);
    }
}

public sealed record SafetyDecisionApiResponse(
    string Status,
    string? DecisionId,
    string? Action,
    string? RiskLevel,
    DateTimeOffset? RecordedAtUtc)
{
    public static SafetyDecisionApiResponse From(SafetyDecisionResult result) => new(
        result.Status.ToString(),
        result.DecisionId,
        result.Action?.ToString(),
        result.RiskLevel?.ToString(),
        result.RecordedAtUtc);
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

public sealed record RuleApprovalWorkflowRequest(string SimulationId);

public sealed record RuleTransitionReasonRequest(string Reason);

public sealed record RuleDeploymentTransitionRequest(long ExpectedVersion, string Reason);

/// <summary>Privacy-safe approval progress; actor identities remain in protected audit evidence.</summary>
public sealed record RuleApprovalWorkflowApiResponse(
    string WorkflowId,
    string RuleId,
    int RuleVersion,
    string SimulationId,
    string ImpactLevel,
    int RequiredApprovalCount,
    int ApprovalCount,
    bool ManualDeploymentRequired,
    bool RollbackTestRequired,
    bool RollbackTestCompleted,
    bool ManualDeploymentAuthorized,
    string Status,
    bool CanActivate,
    DateTimeOffset RequestedAtUtc,
    DateTimeOffset UpdatedAtUtc)
{
    public static RuleApprovalWorkflowApiResponse From(RuleApprovalWorkflowState state) => new(
        state.WorkflowId,
        state.RuleId,
        state.RuleVersion,
        state.SimulationId,
        state.ImpactLevel.ToString(),
        state.RequiredApprovalCount,
        state.Approvals.Count,
        state.ManualDeploymentRequired,
        state.RollbackTestRequired,
        state.RollbackTestCompleted,
        state.ManualDeploymentAuthorized,
        state.Status.ToString(),
        RuleApprovalWorkflowService.CanActivate(state),
        state.RequestedAtUtc,
        state.UpdatedAtUtc);
}

/// <summary>Privacy-safe deployment projection; actor identities and reason text remain encrypted.</summary>
public sealed record RuleDeploymentApiResponse(
    string RuleId,
    int? ActiveVersion,
    string Status,
    int? RollbackVersion,
    bool UseDisabledRollback,
    bool RollbackAvailable,
    string WorkflowId,
    string LastTransitionId,
    string LastTransitionType,
    DateTimeOffset UpdatedAtUtc,
    long Version)
{
    public static RuleDeploymentApiResponse From(RuleDeploymentState state) => new(
        state.RuleId,
        state.ActiveRule?.Version,
        state.Status.ToString(),
        state.RollbackRule?.Version,
        state.UseDisabledRollback,
        state.RollbackAvailable,
        state.WorkflowId,
        state.LastTransitionId,
        state.LastTransitionType,
        state.UpdatedAtUtc,
        state.Version);
}

public sealed record AiRuleDraftApiResponse(
    string DraftId,
    RuleApiResponse ProposedRule,
    IReadOnlyCollection<string> EvidenceSummary,
    string ExpectedBenefit,
    IReadOnlyCollection<string> Risks,
    int Confidence,
    string ProviderName,
    bool IsPlaceholder,
    string SimulationId,
    bool SimulationPassed,
    string FixtureSetId,
    int PassedTestCount,
    int FailedTestCount,
    string RollbackPlan,
    DateTimeOffset CreatedAtUtc)
{
    public static AiRuleDraftApiResponse From(AiRuleDraft draft) => new(
        draft.DraftId,
        RuleApiResponse.From(draft.ProposedRule),
        draft.EvidenceSummary,
        draft.ExpectedBenefit,
        draft.Risks,
        draft.Confidence,
        draft.ProviderName,
        draft.IsPlaceholder,
        draft.SimulationId,
        draft.SimulationPassed,
        draft.FixtureSetId,
        draft.PassedTestCount,
        draft.FailedTestCount,
        draft.RollbackPlan,
        draft.CreatedAtUtc);
}

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
    IReadOnlyCollection<RuleSimulationCaseResult> FailedCases,
    int RuleVersion,
    string FixtureSetId,
    int TotalTestCases,
    int PassedCount,
    int FailedCount,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset CompletedAtUtc,
    RuleSimulationRollbackPlan RollbackPlan)
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
            result.FailedCases,
            result.RuleVersion,
            result.FixtureSetId,
            result.TotalTestCases,
            result.PassedCount,
            result.FailedCount,
            result.StartedAtUtc,
            result.CompletedAtUtc,
            result.RollbackPlan);
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
    string? ResponseSignature,
    HipLiveBadgeDocument? SignedBadge,
    string SignatureStatus,
    bool IsAvailable,
    HipLiveBadgeCertificateState? Certificate,
    int? DisplayScore,
    string ScorePresentation,
    string EvidenceCoverage,
    string EvidenceConfidence,
    string IdentityStatus)
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
            badge.ResponseSignature,
            badge.SignedBadge,
            badge.SignatureStatus,
            badge.IsAvailable,
            badge.Certificate,
            badge.DisplayScore,
            badge.ScorePresentation,
            badge.EvidenceCoverage,
            badge.EvidenceConfidence,
            badge.IdentityStatus);
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
    string Message,
    string IdentityStatus,
    int? DisplayScore,
    string ScorePresentation,
    string EvidenceCoverage,
    string EvidenceConfidence,
    string CertificateApplicationStatus,
    string CertificateProgressStatus,
    string MonitoringStatus)
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
            lookup.Message,
            lookup.IdentityStatus,
            lookup.DisplayScore,
            lookup.ScorePresentation,
            lookup.EvidenceCoverage,
            lookup.EvidenceConfidence,
            lookup.CertificateApplicationStatus,
            lookup.CertificateProgressStatus,
            lookup.MonitoringStatus);
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

        rulesApi.MapPost("/evaluate", async (
            RuleEvaluationApiRequest request,
            IRuleEvaluationService evaluationService,
            IRuleDeploymentRepository deployments,
            CancellationToken cancellationToken) =>
        {
            IReadOnlyCollection<TrustRule> rules;
            if (request.Rules is { Count: > 0 })
            {
                rules = request.Rules;
            }
            else
            {
                var deploymentStates = await deployments.ListAsync(cancellationToken);
                rules = deploymentStates.Count == 0
                    ? SampleRules()
                    : deploymentStates
                        .Where(state => state.ActiveRule is not null)
                        .Select(state => state.ActiveRule!)
                        .ToArray();
            }
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

        rulesApi.MapPost("/{ruleId}/approval-workflows", async (
            string ruleId,
            RuleApprovalWorkflowRequest request,
            IRuleRepository ruleRepository,
            RuleApprovalWorkflowService workflowService,
            CancellationToken cancellationToken) =>
        {
            var rule = await ruleRepository.GetByIdAsync(ruleId, cancellationToken) ??
                       SampleRules().FirstOrDefault(sample => sample.RuleId.Equals(ruleId, StringComparison.OrdinalIgnoreCase));
            if (rule is null) return Results.NotFound();
            try
            {
                var workflow = await workflowService.RequestAsync(rule, request.SimulationId, cancellationToken);
                return Results.Created(
                    $"/api/v1/rules/approval-workflows/{Uri.EscapeDataString(workflow.WorkflowId)}",
                    RuleApprovalWorkflowApiResponse.From(workflow));
            }
            catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
            {
                return Results.BadRequest(new { error = exception.Message });
            }
        });

        rulesApi.MapGet("/approval-workflows/{workflowId}", async (
            string workflowId,
            IRuleApprovalWorkflowRepository repository,
            CancellationToken cancellationToken) =>
        {
            var workflow = await repository.GetAsync(workflowId, cancellationToken);
            return workflow is null
                ? Results.NotFound()
                : Results.Ok(RuleApprovalWorkflowApiResponse.From(workflow));
        });

        rulesApi.MapPost("/approval-workflows/{workflowId}/approvals", async (
            string workflowId,
            HttpContext httpContext,
            RuleApprovalWorkflowService workflowService,
            CancellationToken cancellationToken) =>
        {
            try
            {
                var workflow = await workflowService.ApproveAsync(
                    workflowId,
                    HipAuthenticatedIdentity.ResolveRequiredUniqueClaim(
                        httpContext.User,
                        HipAuthenticationClaimTypes.ActorId),
                    cancellationToken);
                return Results.Ok(RuleApprovalWorkflowApiResponse.From(workflow));
            }
            catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
            {
                return Results.BadRequest(new { error = exception.Message });
            }
        }).RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);

        rulesApi.MapPost("/approval-workflows/{workflowId}/rollback-test", async (
            string workflowId,
            RuleTransitionReasonRequest request,
            HttpContext httpContext,
            RuleApprovalWorkflowService workflowService,
            CancellationToken cancellationToken) =>
        {
            try
            {
                var workflow = await workflowService.CompleteRollbackTestAsync(
                    workflowId,
                    HipAuthenticatedIdentity.ResolveRequiredUniqueClaim(
                        httpContext.User,
                        HipAuthenticationClaimTypes.ActorId),
                    request.Reason,
                    cancellationToken);
                return Results.Ok(RuleApprovalWorkflowApiResponse.From(workflow));
            }
            catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
            {
                return Results.BadRequest(new { error = exception.Message });
            }
        }).RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);

        rulesApi.MapPost("/approval-workflows/{workflowId}/manual-deployment", async (
            string workflowId,
            RuleTransitionReasonRequest request,
            HttpContext httpContext,
            RuleApprovalWorkflowService workflowService,
            CancellationToken cancellationToken) =>
        {
            try
            {
                var workflow = await workflowService.AuthorizeManualDeploymentAsync(
                    workflowId,
                    HipAuthenticatedIdentity.ResolveRequiredUniqueClaim(
                        httpContext.User,
                        HipAuthenticationClaimTypes.ActorId),
                    request.Reason,
                    cancellationToken);
                return Results.Ok(RuleApprovalWorkflowApiResponse.From(workflow));
            }
            catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
            {
                return Results.BadRequest(new { error = exception.Message });
            }
        }).RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);

        rulesApi.MapPost("/approval-workflows/{workflowId}/activate", async (
            string workflowId,
            RuleTransitionReasonRequest request,
            HttpContext httpContext,
            RuleDeploymentService deploymentService,
            CancellationToken cancellationToken) =>
        {
            try
            {
                var deployment = await deploymentService.ActivateAsync(
                    workflowId,
                    HipAuthenticatedIdentity.ResolveRequiredUniqueClaim(
                        httpContext.User,
                        HipAuthenticationClaimTypes.ActorId),
                    request.Reason,
                    cancellationToken);
                return Results.Ok(RuleDeploymentApiResponse.From(deployment));
            }
            catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
            {
                return Results.BadRequest(new { error = exception.Message });
            }
        }).RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);

        rulesApi.MapGet("/deployments/{ruleId}", async (
            string ruleId,
            RuleDeploymentService deploymentService,
            CancellationToken cancellationToken) =>
        {
            var deployment = await deploymentService.GetAsync(ruleId, cancellationToken);
            return deployment is null ? Results.NotFound() : Results.Ok(RuleDeploymentApiResponse.From(deployment));
        });

        rulesApi.MapPost("/deployments/{ruleId}/rollback", async (
            string ruleId,
            RuleDeploymentTransitionRequest request,
            HttpContext httpContext,
            RuleDeploymentService deploymentService,
            CancellationToken cancellationToken) =>
        {
            try
            {
                var deployment = await deploymentService.RollbackAsync(
                    ruleId,
                    request.ExpectedVersion,
                    HipAuthenticatedIdentity.ResolveRequiredUniqueClaim(
                        httpContext.User,
                        HipAuthenticationClaimTypes.ActorId),
                    request.Reason,
                    cancellationToken);
                return Results.Ok(RuleDeploymentApiResponse.From(deployment));
            }
            catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
            {
                return Results.BadRequest(new { error = exception.Message });
            }
        }).RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);

        rulesApi.MapPost("/deployments/{ruleId}/promote", async (
            string ruleId,
            RuleDeploymentTransitionRequest request,
            HttpContext httpContext,
            RuleDeploymentService deploymentService,
            CancellationToken cancellationToken) =>
        {
            try
            {
                var deployment = await deploymentService.PromoteAsync(
                    ruleId,
                    request.ExpectedVersion,
                    HipAuthenticatedIdentity.ResolveRequiredUniqueClaim(
                        httpContext.User,
                        HipAuthenticationClaimTypes.ActorId),
                    request.Reason,
                    cancellationToken);
                return Results.Ok(RuleDeploymentApiResponse.From(deployment));
            }
            catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
            {
                return Results.BadRequest(new { error = exception.Message });
            }
        }).RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication);
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

  container.classList.add("hip-live-badge-host");
  ensureStyles();
  if (normalizeDomain(window.location.hostname) !== domain) {
    container.innerHTML = `<a class="hip-live-badge hip-live-badge-mismatch" href="${apiBase}/lookup/${encodeURIComponent(domain)}" target="_blank" rel="noopener noreferrer"><strong>HIP Badge Domain Mismatch</strong><span>Certificate unavailable for this hostname</span></a>`;
    return;
  }
  fetch(`${apiBase}/api/v1/badge/${encodeURIComponent(domain)}`, { headers: { "Accept": "application/json" } })
    .then(response => {
      if (!response.ok) {
        throw new Error(`HIP badge failed with status ${response.status}`);
      }
      return response.json();
    })
    .then(verify)
    .then(render)
    .catch(() => {
      container.innerHTML = `<a class="hip-live-badge hip-live-badge-unknown" href="${apiBase}/lookup/${encodeURIComponent(domain)}" target="_blank" rel="noopener noreferrer"><strong>HIP Unavailable</strong><span>Score: unavailable</span><span>Status: Unknown</span></a>`;
    });

  function render(badge) {
    const certificate = badge.certificate;
    const active = certificate && certificate.isActive === true && certificate.domain === domain;
    const variant = certificate ? String(active ? certificate.level : certificate.status).toLowerCase() : "unknown";
    const checked = badge.lastCheckedUtc ? new Date(badge.lastCheckedUtc).toLocaleDateString() : "Unknown";
    const lookupUrl = new URL(certificate?.publicCertificateUrl || badge.lookupUrl || badge.publicLookupUrl || `/lookup/${badge.domain}`, apiBase).toString();
    const identityStatus = badge.identityVerificationStatus === "Verified" ? "Verified" : badge.identityVerificationStatus === "Pending" ? "Pending" : "Unverified";
    const label = active && identityStatus === "Verified" ? "HIP Identity Verified" : active ? "HIP Identity Pending" : certificate ? `HIP ${certificate.status}` : "HIP Identity Unverified";
    const safetyAssessment = badge.scorePresentation === "Available" && badge.displayScore !== null && badge.displayScore !== undefined && Number.isFinite(Number(badge.displayScore))
      ? `<span class="hip-badge-fact"><b>Safety score</b>${escapeHtml(badge.displayScore)}/100 (${escapeHtml(badge.status)})</span>`
      : '<span class="hip-badge-fact"><b>Safety assessment</b>Not enough evidence yet</span>';
    const panelId = `hip-live-badge-panel-${domain.replace(/[^a-z0-9]/g, "-")}`;

    container.classList.add(`hip-badge-${variant}`);
    container.innerHTML = `
      <div class="hip-badge-widget" data-hip-state="expanded">
        <button type="button" class="hip-badge-shield" data-hip-action="toggle" aria-label="Minimize HIP trust details" aria-expanded="true" aria-controls="${escapeAttribute(panelId)}">
          ${shieldMarkup(new URL("/hip-logo.svg?v=87b1fcee", apiBase).toString())}
        </button>
        <section id="${escapeAttribute(panelId)}" class="hip-badge-panel" aria-label="${escapeAttribute(label)} for ${escapeAttribute(domain)}">
          <div class="hip-badge-toolbar">
            <strong class="hip-badge-label">${escapeHtml(label)}</strong>
            <span class="hip-badge-controls">
              <button type="button" data-hip-action="minimize" aria-label="Minimize HIP badge" title="Minimize">−</button>
              <button type="button" data-hip-action="close" aria-label="Close HIP badge" title="Close">×</button>
            </span>
          </div>
          <span class="hip-badge-fact"><b>Certificate</b>${escapeHtml(certificate?.status || "Not issued")} · ${escapeHtml(certificate?.level || "None")}</span>
          <span class="hip-badge-fact"><b>Identity</b>${escapeHtml(identityStatus)}</span>
          <span class="hip-badge-fact"><b>Evidence</b>${escapeHtml(badge.evidenceCoverage || "Insufficient")} · ${escapeHtml(badge.evidenceConfidence || "None")} confidence</span>
          ${safetyAssessment}
          <small>Last checked: ${escapeHtml(checked)}</small>
          <small>Identity verification does not automatically mean safe.</small>
          <a class="hip-badge-details" href="${escapeAttribute(lookupUrl)}" target="_blank" rel="noopener noreferrer">View HIP details</a>
        </section>
        <button type="button" class="hip-badge-show" data-hip-action="show" aria-controls="${escapeAttribute(panelId)}" hidden>Show HIP</button>
      </div>`;
    initializeWidget();
  }

  /**
   * Wires accessible expanded, minimized, and closed states without storing visitor data.
   */
  function initializeWidget() {
    const widget = container.querySelector(".hip-badge-widget");
    const panel = widget?.querySelector(".hip-badge-panel");
    const shield = widget?.querySelector(".hip-badge-shield");
    const show = widget?.querySelector(".hip-badge-show");
    const minimize = widget?.querySelector('[data-hip-action="minimize"]');
    const close = widget?.querySelector('[data-hip-action="close"]');
    if (!widget || !panel || !shield || !show || !minimize || !close) {
      throw new Error("HIP badge controls are unavailable.");
    }

    const setState = (state, focusTarget) => {
      widget.dataset.hipState = state;
      const expanded = state === "expanded";
      panel.hidden = !expanded;
      show.hidden = expanded;
      shield.hidden = state === "closed";
      shield.setAttribute("aria-expanded", String(expanded));
      shield.setAttribute("aria-label", expanded ? "Minimize HIP trust details" : "Show HIP trust details");
      if (focusTarget) {
        focusTarget.focus();
      }
    };

    shield.addEventListener("click", () =>
      setState(widget.dataset.hipState === "expanded" ? "minimized" : "expanded"));
    minimize.addEventListener("click", () => setState("minimized", show));
    close.addEventListener("click", () => setState("closed", show));
    show.addEventListener("click", () => setState("expanded", minimize));
  }

  /**
   * Returns the transparent HIP protocol shield used by the floating badge.
   */
  function shieldMarkup(logoUrl) {
    return `<img class="hip-badge-shield-logo" src="${escapeAttribute(logoUrl)}" alt="" aria-hidden="true">`;
  }
  function verify(badge) {
    const signed = badge && badge.signedBadge;
    const payload = signed && signed.payload;
    const expiresAt = payload && Date.parse(payload.expiresAtUtc);
    const certificate = badge && badge.certificate;
    const signedCertificate = payload && payload.certificate;
    const certificateMatches = (!certificate && !signedCertificate) ||
      (certificate && signedCertificate &&
       certificate.certificateId === signedCertificate.certificateId &&
       certificate.domain === signedCertificate.domain &&
       certificate.level === signedCertificate.level &&
       certificate.status === signedCertificate.status &&
       certificate.signatureStatus === signedCertificate.signatureStatus &&
       certificate.expiresAtUtc === signedCertificate.expiresAtUtc &&
       certificate.publicCertificateUrl === signedCertificate.publicCertificateUrl &&
       certificate.isActive === signedCertificate.isActive);
    if (!badge || badge.isAvailable !== true || badge.signatureStatus !== "Verified" ||
        !signed || !payload || !signed.signature ||
        payload.documentType !== "hip-live-badge" || payload.version !== "1.0" ||
        payload.domain !== domain || badge.domain !== domain ||
        payload.score !== badge.score || payload.status !== badge.status ||
        payload.displayScore !== badge.displayScore ||
        payload.scorePresentation !== badge.scorePresentation ||
        payload.evidenceCoverage !== badge.evidenceCoverage ||
        payload.evidenceConfidence !== badge.evidenceConfidence ||
        payload.verifiedDomain !== badge.verifiedDomain ||
        payload.identityVerificationStatus !== badge.identityVerificationStatus ||
        payload.verifiedMeaning !== badge.verifiedMeaning || !certificateMatches ||
        (certificate && certificate.domain !== domain) ||
        (certificate?.isActive === true && (certificate.status !== "Active" || certificate.signatureStatus !== "Verified")) ||
        !Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
      throw new Error("HIP badge signature state is unavailable or inconsistent.");
    }

    return fetch(`${apiBase}/api/v1/badge/verify`, {
      method: "POST",
      headers: { "Accept": "application/json", "Content-Type": "application/json" },
      body: JSON.stringify(signed)
    }).then(response => {
      if (!response.ok) {
        throw new Error(`HIP badge verification failed with status ${response.status}`);
      }
      return response.json();
    }).then(result => {
      if (!result || result.isVerified !== true || result.status !== "Verified") {
        throw new Error("HIP badge signature did not verify.");
      }
      return badge;
    });
  }

  function ensureStyles() {
    if (document.getElementById("hip-live-badge-style")) {
      return;
    }
    const style = document.createElement("style");
    style.id = "hip-live-badge-style";
    style.textContent = `
      .hip-live-badge-host {
        --hip-accent: #5ad7bb;
        position: fixed !important;
        right: max(1rem, env(safe-area-inset-right)) !important;
        bottom: max(1rem, env(safe-area-inset-bottom)) !important;
        z-index: 2147483000 !important;
        display: block !important;
        width: auto !important;
        max-width: calc(100vw - 2rem) !important;
        margin: 0 !important;
        padding: 0 !important;
        background: transparent !important;
        border: 0 !important;
        color: #f8fafc !important;
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif !important;
      }
      .hip-live-badge-host .hip-badge-widget { display: grid; justify-items: end; gap: .5rem; background: transparent; }
      .hip-live-badge-host .hip-badge-panel[hidden],
      .hip-live-badge-host .hip-badge-shield[hidden],
      .hip-live-badge-host .hip-badge-show[hidden] { display: none !important; }
      .hip-live-badge-host .hip-badge-shield {
        all: unset;
        box-sizing: border-box;
        width: 4.25rem;
        height: 4.25rem;
        cursor: pointer;
        filter: drop-shadow(0 .4rem .65rem rgba(2, 8, 23, .38));
        transition: transform .16s ease, filter .16s ease;
      }
      .hip-live-badge-host .hip-badge-shield:hover { transform: translateY(-.125rem); }
      .hip-live-badge-host .hip-badge-shield-logo { display: block; width: 100%; height: 100%; }
      .hip-live-badge-host .hip-badge-panel {
        box-sizing: border-box;
        display: grid;
        gap: .5rem;
        width: min(22rem, calc(100vw - 2rem));
        max-height: calc(100vh - 7rem);
        overflow: auto;
        padding: .875rem;
        color: #f8fafc;
        border: 1px solid rgba(148, 163, 184, .42);
        border-left: .25rem solid var(--hip-accent);
        border-radius: .75rem;
        background: rgba(7, 18, 34, .82);
        box-shadow: 0 .75rem 2rem rgba(2, 8, 23, .28);
        backdrop-filter: blur(1rem) saturate(130%);
        -webkit-backdrop-filter: blur(1rem) saturate(130%);
        line-height: 1.35;
      }
      .hip-live-badge-host .hip-badge-toolbar { display: flex; align-items: center; justify-content: space-between; gap: .75rem; }
      .hip-live-badge-host .hip-badge-label { font-size: .8125rem; font-weight: 800; letter-spacing: .02em; text-transform: uppercase; }
      .hip-live-badge-host .hip-badge-controls { display: inline-flex; gap: .25rem; }
      .hip-live-badge-host .hip-badge-controls button,
      .hip-live-badge-host .hip-badge-show {
        all: unset;
        box-sizing: border-box;
        cursor: pointer;
        color: #f8fafc;
        border: 1px solid rgba(148, 163, 184, .55);
        background: rgba(15, 23, 42, .4);
      }
      .hip-live-badge-host .hip-badge-controls button {
        display: inline-grid;
        place-items: center;
        width: 2rem;
        height: 2rem;
        border-radius: .375rem;
        font-size: 1.125rem;
        line-height: 1;
      }
      .hip-live-badge-host .hip-badge-show {
        padding: .5rem .75rem;
        border-radius: 999px;
        font: 700 .75rem/1 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        backdrop-filter: blur(.75rem);
      }
      .hip-live-badge-host .hip-badge-controls button:hover,
      .hip-live-badge-host .hip-badge-show:hover { background: rgba(30, 41, 59, .72); }
      .hip-live-badge-host button:focus-visible,
      .hip-live-badge-host a:focus-visible { outline: .1875rem solid #67e8f9; outline-offset: .1875rem; }
      .hip-live-badge-host .hip-badge-fact { display: grid; grid-template-columns: 7rem minmax(0, 1fr); gap: .5rem; font-size: .8125rem; }
      .hip-live-badge-host .hip-badge-fact b { color: #a7f3d0; font-weight: 700; }
      .hip-live-badge-host small { color: #cbd5e1; font-size: .75rem; }
      .hip-live-badge-host .hip-badge-details { justify-self: start; color: #67e8f9; font-size: .8125rem; font-weight: 700; text-underline-offset: .1875rem; }
      .hip-live-badge-host .hip-live-badge {
        display: grid;
        gap: .25rem;
        padding: .75rem;
        color: #f8fafc;
        border: 1px solid rgba(148, 163, 184, .42);
        border-radius: .75rem;
        background: rgba(7, 18, 34, .82);
        text-decoration: none;
        backdrop-filter: blur(1rem);
      }
      .hip-live-badge-host.hip-badge-dangerous,
      .hip-live-badge-host.hip-badge-critical,
      .hip-live-badge-host:has(.hip-live-badge-mismatch) { --hip-accent: #fb7185; }
      .hip-live-badge-host.hip-badge-highrisk { --hip-accent: #fb923c; }
      .hip-live-badge-host.hip-badge-caution { --hip-accent: #fbbf24; }
      @media (max-width: 30rem) {
        .hip-live-badge-host .hip-badge-panel { width: calc(100vw - 2rem); max-height: calc(100vh - 6rem); }
        .hip-live-badge-host .hip-badge-fact { grid-template-columns: 1fr; gap: .125rem; }
      }
      @media (prefers-reduced-motion: reduce) {
        .hip-live-badge-host, .hip-live-badge-host * { transition: none !important; animation: none !important; }
      }
    `;
    document.head.appendChild(style);
  }
  function normalizeDomain(value) {
    return String(value || "").trim().replace(/\.$/, "").toLowerCase();
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

/// <summary>Public error body that does not expose internal protocol, signer, or persistence details.</summary>
/// <param name="Error">Safe public error message.</param>
sealed record ApiErrorResponse(string Error);

/// <summary>Public verification result that intentionally excludes internal trust state and evidence.</summary>
/// <param name="Status">Typed verification outcome.</param>
/// <param name="IsVerified">Whether origin and integrity verification succeeded.</param>
/// <param name="EstablishesSafetyOrReputationBySignatureAlone">Always false because a signature is not a safety verdict.</param>
/// <param name="VerifiedIssuerId">Verified issuer identifier when successful.</param>
/// <param name="VerifiedKeyId">Verified signing key identifier when successful.</param>
sealed record HipTrustReceiptVerificationApiResponse(
    string Status,
    bool IsVerified,
    bool EstablishesSafetyOrReputationBySignatureAlone,
    string? VerifiedIssuerId,
    string? VerifiedKeyId)
{
    /// <summary>Creates the privacy-safe API projection for an application verification result.</summary>
    public static HipTrustReceiptVerificationApiResponse From(HipTrustReceiptVerificationResult result) => new(
        result.Status.ToString(),
        result.IsVerified,
        result.EstablishesSafetyOrReputationBySignatureAlone,
        result.VerifiedIssuerId,
        result.VerifiedKeyId);

}

/// <summary>Result of reading a request body through the trust receipt byte limit.</summary>
/// <param name="Content">Receipt bytes when the request was within the limit.</param>
/// <param name="IsTooLarge">Whether the request exceeded the receipt byte limit.</param>
readonly record struct BoundedTrustReceiptBody(ReadOnlyMemory<byte> Content, bool IsTooLarge)
{
    public static BoundedTrustReceiptBody TooLarge { get; } = new(ReadOnlyMemory<byte>.Empty, true);
}
