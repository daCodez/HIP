using System.IO.Compression;
using System.Globalization;
using System.Text;
using System.Threading.RateLimiting;
using HIP.ApiService.Security;
using HIP.Application;
using HIP.Application.Browser;
using HIP.Application.Certificates;
using HIP.Application.Devices;
using HIP.Application.Dns;
using HIP.Application.Identity;
using HIP.Application.Performance;
using HIP.Application.Protocol;
using HIP.Application.PublicLookup;
using HIP.Application.Reputation;
using HIP.Application.Review;
using HIP.Application.Security;
using HIP.Application.SiteSafety;
using HIP.Domain.Protocol;
using HIP.Domain.Reputation;
using HIP.Domain.Scoring;
using HIP.Infrastructure;
using HIP.Infrastructure.Persistence;
using Microsoft.AspNetCore.OutputCaching;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi;

var builder = WebApplication.CreateBuilder(args);
const string PublicScanPolicy = "PublicScanPolicy";
const string PublicDnsPolicy = "PublicDnsPolicy";
const string PublicFeedbackPolicy = "PublicFeedbackPolicy";
const string HipInstanceIdHeader = "X-HIP-Instance-Id";

builder.AddServiceDefaults();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddHipApiServiceAuthorization();
builder.Services.AddHipApplication(
    builder.Environment.IsDevelopment(),
    builder.Environment.IsDevelopment() ? "api" : null);
builder.Services.AddSingleton(BindExternalSiteEvidenceOptions(builder.Configuration));
builder.Services.AddHipInfrastructure(builder.Configuration, builder.Environment.IsDevelopment());
var managedSigningReadiness = builder.Configuration
    .GetSection(HipManagedSigningReadinessOptions.SectionName)
    .Get<HipManagedSigningReadinessOptions>() ?? new HipManagedSigningReadinessOptions();
builder.Services.AddSingleton(managedSigningReadiness);
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
    // Compress public JSON responses while keeping payload contents privacy-safe and unchanged.
    options.EnableForHttps = true;
    options.MimeTypes = ResponseCompressionDefaults.MimeTypes.Concat(["application/json", "application/javascript"]);
});
builder.Services.Configure<BrotliCompressionProviderOptions>(options => options.Level = CompressionLevel.Fastest);
builder.Services.Configure<GzipCompressionProviderOptions>(options => options.Level = CompressionLevel.Fastest);
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
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    // Baseline public limits reduce unauthenticated scan/report abuse until HIP client signatures are introduced.
    options.AddPolicy(PublicScanPolicy, httpContext =>
        CreateFixedWindowPartition(httpContext, "scan", performance.PublicScanRequestsPerMinute));
    options.AddPolicy(PublicDnsPolicy, httpContext =>
        CreateClientIpFixedWindowPartition(httpContext, "dns", performance.PublicDnsRequestsPerMinute));
    options.AddPolicy(PublicFeedbackPolicy, httpContext =>
        CreateFixedWindowPartition(httpContext, "feedback", performance.PublicFeedbackRequestsPerMinute));
});
// Swagger is registered for local API discoverability; the interactive UI is only exposed in Development below.
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "HIP API",
        Version = "v1",
        Description = """
        Human Identity Protocol API for website trust scoring, browser plugin scan ingestion, public lookup, live badges, site safety checks, provider preferences, and feedback.

        HIP sits above TCP and TLS: TCP connects, TLS encrypts, and HIP evaluates origin, reputation, page behavior, and content risk.

        Security model:
        - A valid signature or verified domain proves origin and integrity; it does not automatically mean safe.
        - Domain trust, page trust, content risk, and final HIP score are separate concepts.
        - External scanners provide evidence only. HIP scoring makes the final decision.

        Privacy baseline:
        - HIP endpoints must not receive page text, form values, passwords, tokens, cookies, private messages, or unrelated browsing history.
        - Browser endpoints accept only the current domain, current URL when allowed by policy, URL hashes, observed page signals, link counts, risk summaries, provider names, and rule IDs.
        - Public endpoints return domain-level summaries only.

        MVP note:
        This API is still a local/dev foundation. Scores and provider evidence are useful for development and testing, but they are not production threat intelligence until connected to hardened identity, reputation, provider, queue, and persistence infrastructure.
        """
    });
});
builder.Services.AddOpenApi();

var app = builder.Build();

// Generate the unknown-client verifier at startup so every canonical unknown identifier performs
// the same deliberately slow verification work without deriving a verifier on the request path.
_ = app.Services.GetRequiredService<ApiServiceClientDummyVerifier>();

var databaseInitializationMode = app.Environment.IsDevelopment()
    ? HipDatabaseInitializationMode.CreateDevelopmentSchema
    : HipDatabaseInitializationMode.ValidateMigrations;
await HipDatabaseInitializer.InitializeAsync(app.Services, databaseInitializationMode);
await HipManagedSigningReadiness.ValidateAsync(app.Services, managedSigningReadiness);

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi().AllowAnonymous();
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        // Keep Swagger on a predictable local URL so the API port can be inspected directly during development.
        options.RoutePrefix = "swagger";
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "HIP API v1");
    });
}

if (ShouldUseHttpsRedirection(app))
{
    app.UseHttpsRedirection();
}
app.UseCors(HipCorsPolicies.PublicRead);
app.UseResponseCompression();
app.UseAuthentication();
app.UseRateLimiter();
app.UseAuthorization();
app.UseOutputCache();
app.MapDefaultEndpoints();

app.MapGet("/", () => Results.Ok(new ApiServiceInfoResponse(
    "HIP API",
    "Running",
    "0.1.0-dev",
    "/alive",
    app.Environment.IsDevelopment() ? "/openapi/v1.json" : null,
    app.Environment.IsDevelopment() ? "/swagger" : null)))
.WithName("ApiServiceInfo")
.WithSummary("Returns local HIP API service information.")
.WithDescription("Provides a safe, non-sensitive API root response for local development and service discovery.")
.Produces<ApiServiceInfoResponse>()
.AllowAnonymous();

var publicApi = app.MapGroup("/api/v1/public").WithTags("Public Lookup and Feedback");
var browserApi = app.MapGroup("/api/v1/browser").WithTags("Browser Plugin");
var siteSafetyApi = app.MapGroup("/api/v1/site-safety").WithTags("Site Safety");
var domainVerificationApi = app.MapGroup("/api/v1/domain-verification").WithTags("Domain Verification");
var protocolApi = app.MapGroup("/api/v1/protocol").WithTags("HIP Protocol");

app.MapGet("/dns-query", async (
    HttpContext httpContext,
    string? name,
    string? type,
    string? dns,
    IHipAwareDnsLookupService dnsLookupService,
    CancellationToken cancellationToken) =>
{
    try
    {
        if (!string.IsNullOrWhiteSpace(dns))
        {
            var wireQuery = DnsWireMessageCodec.ParseQuery(DecodeDnsBase64Url(dns), allowUnsupportedRecordType: true);
            return await ResolveDnsWireQueryAsync(
                httpContext,
                wireQuery,
                dnsLookupService,
                isPost: false,
                cancellationToken);
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("A DNS name or RFC 8484 dns parameter is required.", nameof(name));
        }
        var recordType = ParseDnsLookupRecordType(type);
        var response = await dnsLookupService.LookupAsync(name, recordType, cancellationToken);
        return Results.Json(response, contentType: "application/dns-json");
    }
    catch (ArgumentException exception)
    {
        return Results.BadRequest(new ApiErrorResponse(exception.Message));
    }
})
.WithName("HipAwareDnsQuery")
.WithTags("HIP-aware DNS")
.WithSummary("Resolves a public A or AAAA record and attaches HIP trust evidence.")
.WithDescription("""
Provides the bounded JSON form of HIP-aware DNS. The DNS answer comes from the configured recursive provider,
while the hip property contains the same public-safe trust evidence used by HIP public lookup. The trust extension
is not authoritative DNS data, does not prove that a site is safe, and never includes verification tokens or private
scan content. JSON clients may use name and type. RFC 8484 clients use an unpadded base64url dns parameter and
receive application/dns-message. DNSSEC validation evidence is reported from the configured recursive resolver.
A and AAAA are supported. Production DNS-over-HTTPS is available at https://dns.guardwithhip.com/dns-query,
and DNS-over-TLS is available at dns.guardwithhip.com:853. UDP/TCP port 53 remains deferred.
""")
.Produces<HipAwareDnsLookupResponse>(StatusCodes.Status200OK, "application/dns-json")
.Produces(StatusCodes.Status200OK, contentType: "application/dns-message")
.Produces<ApiErrorResponse>(StatusCodes.Status400BadRequest)
.Produces(StatusCodes.Status429TooManyRequests)
.AllowAnonymous()
.RequireRateLimiting(PublicDnsPolicy);

app.MapPost("/dns-query", async (
    HttpContext httpContext,
    IHipAwareDnsLookupService dnsLookupService,
    CancellationToken cancellationToken) =>
{
    if (!string.Equals(
        httpContext.Request.ContentType?.Split(';', 2)[0].Trim(),
        "application/dns-message",
        StringComparison.OrdinalIgnoreCase))
    {
        return Results.StatusCode(StatusCodes.Status415UnsupportedMediaType);
    }

    if (httpContext.Request.ContentLength > DnsWireMessageCodec.MaximumQueryBytes)
    {
        return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
    }

    try
    {
        var body = await ReadBoundedDnsWireBodyAsync(httpContext.Request, cancellationToken);
        var wireQuery = DnsWireMessageCodec.ParseQuery(body, allowUnsupportedRecordType: true);
        return await ResolveDnsWireQueryAsync(
            httpContext,
            wireQuery,
            dnsLookupService,
            isPost: true,
            cancellationToken);
    }
    catch (InvalidDataException)
    {
        return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
    }
    catch (ArgumentException exception)
    {
        return Results.BadRequest(new ApiErrorResponse(exception.Message));
    }
})
.WithName("HipAwareDnsQueryPost")
.WithTags("HIP-aware DNS")
.WithSummary("Resolves an RFC 8484 DNS wire-format request.")
.Accepts<byte[]>("application/dns-message")
.Produces(StatusCodes.Status200OK, contentType: "application/dns-message")
.Produces<ApiErrorResponse>(StatusCodes.Status400BadRequest)
.Produces(StatusCodes.Status413PayloadTooLarge)
.Produces(StatusCodes.Status415UnsupportedMediaType)
.Produces(StatusCodes.Status429TooManyRequests)
.AllowAnonymous()
.RequireRateLimiting(PublicDnsPolicy);

domainVerificationApi.MapPost("/check", async (
    DomainVerificationCheckApiRequest request,
    HttpContext httpContext,
    IDomainVerificationService domainVerificationService,
    CancellationToken cancellationToken) =>
{
    try
    {
        var normalizedDomain = DomainInputValidator.ValidateAndNormalize(request.Domain);
        if (ApiServiceServiceClientPrincipal.HasServiceIdentity(httpContext.User) &&
            !ApiServiceServiceClientPrincipal.HasExactDomainGrant(httpContext.User, normalizedDomain))
        {
            return Results.Forbid();
        }

        var result = await domainVerificationService.CheckDnsTxtAsync(
            normalizedDomain,
            request.ExpectedToken,
            cancellationToken);
        return Results.Ok(DomainVerificationCheckApiResponse.FromResult(result));
    }
    catch (ArgumentException ex)
    {
        return Results.BadRequest(new ApiErrorResponse(ex.Message));
    }
})
.WithName("CheckDomainDnsVerification")
.WithSummary("Checks a HIP DNS TXT verification record for a domain.")
.WithDescription("""
Checks _hip.{domain} for a TXT record in the format hip-site-verification={token}.
This endpoint proves domain-control evidence only; it does not mark a website safe or trusted.
The expected token is accepted only for this verification check and is never returned in the response.
Callers may use the existing privileged administrator policy or a HIP-Service credential with the exact
domain-verification:check scope and an exact normalized domain grant. Parent and child domains are not implied.
""")
.Produces<DomainVerificationCheckApiResponse>()
.Produces<ApiErrorResponse>(StatusCodes.Status400BadRequest)
.Produces(StatusCodes.Status401Unauthorized)
.Produces(StatusCodes.Status403Forbidden)
.RequireAuthorization(ApiServiceAdminPolicies.CanCheckDomainVerification)
.RequireCors(HipCorsPolicies.ClientWrite)
.RequireRateLimiting(PublicScanPolicy);

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
        return Results.BadRequest(new ApiErrorResponse(ex.Message));
    }
})
.WithName("PublicDomainLookup")
.WithSummary("Looks up the public HIP trust summary for a domain.")
.WithDescription(GetPublicDomainLookupDescription())
.Produces<PublicDomainLookupResponse>()
.Produces<ApiErrorResponse>(StatusCodes.Status400BadRequest)
.AllowAnonymous()
.CacheOutput(HipOutputCachePolicies.PublicLookup);


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
        return Results.BadRequest(new ApiErrorResponse(ex.Message));
    }
})
.WithName("PublicDomainCertificate")
.WithSummary("Returns and verifies a signed HIP Domain Trust Certificate.")
.Produces<PublicDomainCertificateResponse>()
.Produces(StatusCodes.Status404NotFound)
.Produces(StatusCodes.Status503ServiceUnavailable)
.Produces<ApiErrorResponse>(StatusCodes.Status400BadRequest)
.AllowAnonymous()
.RequireRateLimiting(PublicScanPolicy);
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
        return Results.BadRequest(new ApiErrorResponse(ex.Message));
    }
})
.WithName("PublicDomainBadge")
.WithSummary("Returns live HIP badge data for a domain.")
.WithDescription(GetPublicDomainBadgeDescription())
.Produces<PublicBadgeResponse>()
.Produces<ApiErrorResponse>(StatusCodes.Status400BadRequest)
.AllowAnonymous()
.CacheOutput(HipOutputCachePolicies.Badge);

publicApi.MapPost("/badge/verify", async (
    HipLiveBadgeDocument document,
    IHipLiveBadgeVerificationService verificationService,
    CancellationToken cancellationToken) =>
    Results.Ok(await verificationService.VerifyAsync(document, cancellationToken)))
.WithName("VerifyPublicDomainBadge")
.WithSummary("Verifies a signed HIP live badge against current issuer and key state.")
.Produces<HipLiveBadgeVerificationResult>()
.AllowAnonymous()
.RequireCors(HipCorsPolicies.ClientWrite)
.WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(HipLiveBadgeDocument.MaximumDocumentBytes))
.RequireRateLimiting(PublicScanPolicy);

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
                // Duplicate suppression is an abuse-control decision, not a user-facing failure.
                // Returning OK keeps the browser plugin UX stable when a user double-clicks or retries a submitted signal.
                return Results.Ok(new { accepted = true, duplicateSuppressed = true, message = "Duplicate feedback submission already accepted recently." });
            }

            await StoreWeightedFeedbackIfDomainAsync(anonymousFeedback, weightedFeedbackService, reviewQueueService, cancellationToken);
            return Results.Ok(await reputationService.SubmitFeedbackAsync(anonymousFeedback, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new ApiErrorResponse(ex.Message));
        }
    })
.WithName("PublicFeedback")
.WithSummary("Submits weighted trust feedback for a domain.")
.WithDescription(GetPublicFeedbackDescription())
.Produces<ReputationProfile>()
.Produces<ApiErrorResponse>(StatusCodes.Status400BadRequest)
.AllowAnonymous()
.RequireCors(HipCorsPolicies.ClientWrite)
.RequireRateLimiting(PublicFeedbackPolicy);

MapBrowserApis(browserApi);
MapSiteSafetyApis(siteSafetyApi);
MapHipProtocolApis(protocolApi);

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
/// Determines whether Redis-backed output caching should be enabled for the API service.
/// </summary>
/// <param name="configuration">Application configuration that may include an Aspire Redis connection string.</param>
/// <returns>True when Redis output caching is both configured and allowed by HIP performance options.</returns>
static bool ShouldUseRedisOutputCache(IConfiguration configuration)
{
    var options = BindHipPerformanceOptions(configuration);
    return options.UseRedisOutputCacheWhenAvailable && !string.IsNullOrWhiteSpace(configuration.GetConnectionString("redis"));
}

/// <summary>
/// Configures named output-cache policies for public API reads.
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
/// Binds HIP performance options with safe defaults for local API runs.
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
/// Determines whether a browser origin may send privacy-safe public write requests.
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
/// Validates performance options before the API accepts traffic.
/// </summary>
/// <param name="options">Bound performance options.</param>
/// <returns>True when all durations and request limits are positive.</returns>
static bool ValidateHipPerformanceOptions(HipPerformanceOptions options) =>
    options.PublicLookupCacheSeconds > 0
    && options.BadgeCacheSeconds > 0
    && options.SafetyCacheSeconds > 0
    && options.SiteSafetyCacheSeconds > 0
    && options.PublicScanRequestsPerMinute > 0
    && options.PublicDnsRequestsPerMinute > 0
    && options.PublicFeedbackRequestsPerMinute > 0
    && options.IdentityRequestsPerMinute > 0;

/// <summary>
/// Creates a fixed-window rate-limit partition from privacy-safe client identifiers.
/// </summary>
/// <param name="httpContext">Current HTTP request context.</param>
/// <param name="policyPrefix">Policy prefix used to keep budgets separate.</param>
/// <param name="permitLimit">Requests allowed per minute for this partition.</param>
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
/// Creates a DNS request limiter partitioned only by the proxy-resolved client IP.
/// </summary>
/// <remarks>
/// Public DoH callers must not be able to rotate HIP identity headers to bypass the resolver budget.
/// The API container is private and receives its remote address through the trusted Caddy boundary.
/// </remarks>
static RateLimitPartition<string> CreateClientIpFixedWindowPartition(
    HttpContext httpContext,
    string policyPrefix,
    int permitLimit) =>
    RateLimitPartition.GetFixedWindowLimiter(
        $"{policyPrefix}:{NormalizeSettingsScopeSegment(httpContext.Connection.RemoteIpAddress?.ToString())}",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = permitLimit,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        });

/// <summary>
/// Resolves a bounded rate-limit key from API key, signer, browser instance, domain, or client IP.
/// </summary>
/// <param name="httpContext">Current HTTP request context.</param>
/// <param name="policyPrefix">Policy prefix used to isolate named limits.</param>
/// <returns>Privacy-safe rate-limit partition key.</returns>
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
/// Resolves the provider settings scope from a privacy-safe browser instance id.
/// </summary>
/// <param name="httpContext">Current HTTP context.</param>
/// <returns>Stable scope key used to isolate provider preferences.</returns>
static string ResolveProviderSettingsScope(HttpContext httpContext)
{
    var instanceId = NormalizeSettingsScopeSegment(httpContext.Request.Headers[HipInstanceIdHeader].FirstOrDefault());
    return $"instance:{instanceId}";
}

/// <summary>Resolves a stable requester scope for owner-isolated durable provider jobs.</summary>
static string ResolveExternalEvidenceJobRequesterScope(HttpContext httpContext)
{
    if (ApiServiceServiceClientPrincipal.HasServiceIdentity(httpContext.User))
    {
        var clientId = httpContext.User.FindFirst(ApiServiceClientClaimTypes.ClientId)?.Value
            ?? throw new InvalidOperationException("Authenticated service client is missing its canonical identifier.");
        return $"service-client:{clientId}";
    }

    return $"admin:{NormalizeSettingsScopeSegment(httpContext.User.Identity?.Name)}:{ResolveProviderSettingsScope(httpContext)}";
}

/// <summary>
/// Normalizes a user or instance settings scope so untrusted header values cannot affect storage keys.
/// </summary>
/// <param name="value">Raw user or browser instance identifier.</param>
/// <returns>Safe bounded scope segment.</returns>
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
/// Loads provider settings for the browser instance that initiated the request.
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
        "api-public-feedback",
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
/// Detects replayed browser scan summaries while allowing fresh scans with new timestamps or URL hashes.
/// </summary>
/// <param name="request">Browser plugin scan result request.</param>
/// <param name="duplicateGuard">Distributed duplicate guard that hashes fingerprint parts internally.</param>
/// <returns>True when an equivalent scan result was already accepted recently.</returns>
static async ValueTask<bool> IsDuplicateBrowserScanResultAsync(BrowserScanResultSaveRequest request, IDuplicateSubmissionGuard duplicateGuard, CancellationToken cancellationToken) =>
    !await duplicateGuard.TryAcceptAsync(
        "api-browser-scan-result",
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
        "api-site-safety-scan",
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
            return Results.BadRequest(new ApiErrorResponse(ex.Message));
        }
    })
    .WithName("BrowserScoreSite")
    .WithSummary("Scores the current browser tab domain.")
    .WithDescription(GetBrowserScoreSiteDescription())
    .Produces<BrowserScoreSiteResponse>()
    .Produces<ApiErrorResponse>(StatusCodes.Status400BadRequest)
    .AllowAnonymous()
    .RequireCors(HipCorsPolicies.ClientWrite)
    .RequireRateLimiting(PublicScanPolicy);

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
            return Results.BadRequest(new ApiErrorResponse(ex.Message));
        }
    })
    .WithName("BrowserScanLinks")
    .WithSummary("Scans links discovered on the current page.")
    .WithDescription(GetBrowserScanLinksDescription())
    .Produces<BrowserScanLinksResponse>()
    .Produces<ApiErrorResponse>(StatusCodes.Status400BadRequest)
    .AllowAnonymous()
    .RequireCors(HipCorsPolicies.ClientWrite)
    .RequireRateLimiting(PublicScanPolicy);

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
    .WithName("BrowserSaveScanResult")
    .WithSummary("Stores a privacy-safe browser scan summary.")
    .WithDescription(GetBrowserSaveScanResultDescription())
    .Produces<BrowserScanResultSaveResponse>()
    .Produces<BrowserScanResultErrorResponse>(StatusCodes.Status400BadRequest)
    .Produces<BrowserScanResultErrorResponse>(StatusCodes.Status409Conflict)
    .AllowAnonymous()
    .RequireCors(HipCorsPolicies.ClientWrite)
    .RequireRateLimiting(PublicScanPolicy);

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
    .WithName("BrowserGetScanResult")
    .WithSummary("Gets the latest stored browser scan summary for a domain.")
    .WithDescription(GetBrowserGetScanResultDescription())
    .Produces<BrowserScanResultResponse>()
    .Produces(StatusCodes.Status404NotFound)
    .Produces<BrowserScanResultErrorResponse>(StatusCodes.Status400BadRequest)
    .AllowAnonymous();
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
    siteSafetyApi.MapGet("/external-providers", async (
        HttpContext httpContext,
        ExternalSiteEvidenceOptions defaultOptions,
        IExternalSiteEvidenceSettingsStore settingsStore,
        CancellationToken cancellationToken) =>
    {
        var scopeKey = ResolveProviderSettingsScope(httpContext);
        var options = await settingsStore.GetAsync(scopeKey, cancellationToken) ?? defaultOptions.Clone();
        return Results.Ok(ExternalProviderSettingsResponse.From(options, scopeKey));
    })
    .WithName("ApiServiceGetExternalProviderPreferences")
    .WithSummary("Gets external provider preferences for the current HIP client scope.")
    .WithDescription(GetExternalProviderPreferencesDescription())
    .Produces<ExternalProviderSettingsResponse>()
    .RequireAuthorization(ApiServiceAdminPolicies.CanViewAdminDashboard);

    siteSafetyApi.MapPost("/external-providers", async (
        ExternalProviderSettingsUpdateRequest request,
        HttpContext httpContext,
        IOptions<HipSecurityOptions> securityOptions,
        ExternalSiteEvidenceOptions defaultOptions,
        IExternalSiteEvidenceSettingsStore settingsStore,
        CancellationToken cancellationToken) =>
    {
        if (!securityOptions.Value.AllowClientProviderPreferenceWrites)
        {
            return Results.Json(new ApiErrorResponse("Client provider preference writes are disabled for this HIP host."), statusCode: StatusCodes.Status403Forbidden);
        }

        var scopeKey = ResolveProviderSettingsScope(httpContext);
        var options = defaultOptions.Clone();
        ApplyClientExternalProviderSettings(options, request);
        var saved = await settingsStore.SaveAsync(scopeKey, options, cancellationToken);
        return Results.Ok(ExternalProviderSettingsResponse.From(saved, scopeKey));
    })
    .WithName("ApiServiceUpdateExternalProviderPreferences")
    .WithSummary("Updates external provider switches for the current HIP client scope.")
    .WithDescription(GetUpdateExternalProviderPreferencesDescription())
    .Produces<ExternalProviderSettingsResponse>()
    .Produces<ApiErrorResponse>(StatusCodes.Status403Forbidden)
    .RequireAuthorization(ApiServiceAdminPolicies.CanManageRules)
    .RequireAuthorization(ApiServiceAdminPolicies.RecentPrivilegedAuthentication)
    .RequireCors(HipCorsPolicies.ClientWrite)
    .RequireRateLimiting(PublicScanPolicy);

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
                return Results.Conflict(new ApiErrorResponse("Duplicate site safety scan ignored."));
            }

            var scopedOptions = await LoadScopedExternalProviderOptionsAsync(httpContext, settingsStore, cancellationToken);
            using var _ = defaultOptions.UseScopedOverride(scopedOptions);
            var result = await scanner.ScanUntrustedAsync(request, cancellationToken);
            await scanResultStorageService.SaveAsync(request, result, cancellationToken);
            return Results.Ok(ToSiteSafetyScanResponse(result));
        }
        catch (OperationCanceledException)
        {
            return Results.Empty;
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
        {
            return Results.BadRequest(new ApiErrorResponse(ex.Message));
        }
    })
    .WithName("ApiServiceSiteSafetyScan")
    .WithSummary("Runs a privacy-safe site safety scan from browser-observed signals.")
    .WithDescription(GetSiteSafetyScanDescription())
    .Produces<SiteSafetyScanApiResponse>()
    .Produces<ApiErrorResponse>(StatusCodes.Status400BadRequest)
    .Produces<ApiErrorResponse>(StatusCodes.Status409Conflict)
    .AllowAnonymous()
    .RequireCors(HipCorsPolicies.ClientWrite)
    .RequireRateLimiting(PublicScanPolicy);

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
            var targetUri = new Uri(request.Url, UriKind.Absolute);
            if (!string.Equals(targetUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(targetUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("Site safety checks require an absolute HTTP or HTTPS URL.", nameof(request));
            }

            var normalizedDomain = DomainInputValidator.ValidateAndNormalize(targetUri.Host);
            if (ApiServiceServiceClientPrincipal.HasServiceIdentity(httpContext.User) &&
                !ApiServiceServiceClientPrincipal.HasExactDomainGrant(httpContext.User, normalizedDomain))
            {
                return Results.Forbid();
            }

            var scopedOptions = ApiServiceServiceClientPrincipal.HasServiceIdentity(httpContext.User)
                ? null
                : await LoadScopedExternalProviderOptionsAsync(httpContext, settingsStore, cancellationToken);
            using var _ = defaultOptions.UseScopedOverride(scopedOptions);
            var evidence = await collector.CollectAsync(request, cancellationToken);
            var domain = evidence.FirstOrDefault()?.Domain ?? normalizedDomain;
            var checkedAtUtc = evidence.FirstOrDefault()?.CheckedAtUtc ?? DateTimeOffset.UtcNow;
            return Results.Ok(new ExternalSiteEvidenceCheckResponse(domain, checkedAtUtc, ToSiteSafetyProviderEvidenceResponses(evidence)));
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException or UriFormatException)
        {
            return Results.BadRequest(new ApiErrorResponse(ex.Message));
        }
    })
    .WithName("ApiServiceCheckExternalSiteEvidence")
    .WithSummary("Runs explicitly requested external site evidence providers.")
    .WithDescription(GetExternalSiteEvidenceCheckDescription())
    .Produces<ExternalSiteEvidenceCheckResponse>()
    .Produces<ApiErrorResponse>(StatusCodes.Status400BadRequest)
    .Produces(StatusCodes.Status401Unauthorized)
    .Produces(StatusCodes.Status403Forbidden)
    .RequireAuthorization(ApiServiceAdminPolicies.CanCheckExternalSiteEvidence)
    .RequireCors(HipCorsPolicies.ClientWrite)
    .RequireRateLimiting(PublicScanPolicy);

    siteSafetyApi.MapPost("/external-evidence/jobs", async (
        SiteSafetyScanRequest request,
        HttpContext httpContext,
        ExternalSiteEvidenceJobService jobService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            var targetUri = new Uri(request.Url, UriKind.Absolute);
            var normalizedDomain = DomainInputValidator.ValidateAndNormalize(targetUri.Host);
            var serviceClient = ApiServiceServiceClientPrincipal.HasServiceIdentity(httpContext.User);
            if (serviceClient && !ApiServiceServiceClientPrincipal.HasExactDomainGrant(httpContext.User, normalizedDomain))
            {
                return Results.Forbid();
            }

            var job = await jobService.QueueAsync(
                request,
                ResolveExternalEvidenceJobRequesterScope(httpContext),
                serviceClient ? null : ResolveProviderSettingsScope(httpContext),
                cancellationToken);
            var location = $"/api/v1/site-safety/external-evidence/jobs/{Uri.EscapeDataString(job.JobId)}";
            return Results.Accepted(location, ToExternalSiteEvidenceJobApiResponse(job));
        }
        catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException or UriFormatException)
        {
            return Results.BadRequest(new ApiErrorResponse(ex.Message));
        }
    })
    .WithName("ApiServiceQueueExternalSiteEvidence")
    .WithSummary("Queues external site evidence work outside the request path.")
    .Produces<ExternalSiteEvidenceJobApiResponse>(StatusCodes.Status202Accepted)
    .Produces<ApiErrorResponse>(StatusCodes.Status400BadRequest)
    .Produces(StatusCodes.Status401Unauthorized)
    .Produces(StatusCodes.Status403Forbidden)
    .RequireAuthorization(ApiServiceAdminPolicies.CanCheckExternalSiteEvidence)
    .RequireCors(HipCorsPolicies.ClientWrite)
    .RequireRateLimiting(PublicScanPolicy);

    siteSafetyApi.MapGet("/external-evidence/jobs/{jobId}", async (
        string jobId,
        HttpContext httpContext,
        ExternalSiteEvidenceJobService jobService,
        CancellationToken cancellationToken) =>
    {
        var job = await jobService.GetForRequesterAsync(
            jobId,
            ResolveExternalEvidenceJobRequesterScope(httpContext),
            cancellationToken);
        if (job is null ||
            ApiServiceServiceClientPrincipal.HasServiceIdentity(httpContext.User) &&
            !ApiServiceServiceClientPrincipal.HasExactDomainGrant(httpContext.User, job.Domain))
        {
            return Results.NotFound();
        }

        return Results.Ok(ToExternalSiteEvidenceJobApiResponse(job));
    })
    .WithName("ApiServiceGetExternalSiteEvidenceJob")
    .WithSummary("Gets owner-scoped external site evidence job status and normalized results.")
    .Produces<ExternalSiteEvidenceJobApiResponse>()
    .Produces(StatusCodes.Status401Unauthorized)
    .Produces(StatusCodes.Status404NotFound)
    .RequireAuthorization(ApiServiceAdminPolicies.CanCheckExternalSiteEvidence);
}

/// <summary>
/// Maps the version-one trust-receipt issuance, retrieval, and verification surface.
/// </summary>
/// <param name="protocolApi">The versioned HIP protocol route group.</param>
/// <remarks>
/// Receipt issuance accepts only the requested URL as authoritative input. Client observations, plugin settings,
/// provider settings, scores, evidence digests, issuer metadata, and signatures cannot influence the server-controlled
/// evaluation boundary. A valid signature proves origin and integrity; it does not establish safety or reputation by itself.
/// </remarks>
static void MapHipProtocolApis(RouteGroupBuilder protocolApi)
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
            var issueResult = await issuanceService.IssueAsync(authoritativeEvaluation, cancellationToken);
            return ToHipTrustReceiptIssueApiResult(issueResult, httpContext.Response);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is ArgumentException or FluentValidation.ValidationException)
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
    .WithName("ApiServiceIssueHipTrustReceipt")
    .WithSummary("Issues a signed HIP trust receipt from a server-authoritative site safety evaluation.")
    .WithDescription("""
Validates the target URL, ignores client observations, plugin metadata, and client-scoped provider settings, then
runs HIP's Site Safety evaluator with server-controlled providers and rules and stores an immutable signed version-one
trust receipt. Callers cannot supply evidence, scores, issuer metadata, signing keys, or signatures. Receipt signatures
prove issuer origin and document integrity; the bounded evidence and scores carry the separate trust result.
""")
    .Accepts<HipTrustReceiptIssueRequest>("application/json")
    .Produces<HipTrustReceipt>(StatusCodes.Status201Created, "application/json")
    .Produces<HipTrustReceipt>(StatusCodes.Status200OK, "application/json")
    .Produces<ApiErrorResponse>(StatusCodes.Status400BadRequest)
    .Produces<ApiErrorResponse>(StatusCodes.Status409Conflict)
    .Produces<ApiErrorResponse>(StatusCodes.Status503ServiceUnavailable)
    .WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(
        HipTrustReceiptIssueRequest.MaximumRequestBodyBytes))
    .AllowAnonymous()
    .RequireCors(HipCorsPolicies.ClientWrite)
    .RequireRateLimiting(PublicScanPolicy);

    protocolApi.MapGet("/receipts/{receiptId}", async (
        string receiptId,
        IHipTrustReceiptRepository receiptRepository,
        CancellationToken cancellationToken) =>
    {
        string validatedReceiptId;
        try
        {
            validatedReceiptId = ValidateHipTrustReceiptId(receiptId);
        }
        catch (ArgumentException)
        {
            return Results.BadRequest(new ApiErrorResponse("The trust receipt identifier is invalid."));
        }

        try
        {
            var stored = await receiptRepository.GetByIdAsync(validatedReceiptId, cancellationToken);
            return stored is null
                ? Results.NotFound(new ApiErrorResponse("HIP trust receipt was not found."))
                : Results.Text(
                    stored.ReceiptJson,
                    contentType: "application/json",
                    contentEncoding: Encoding.UTF8,
                    statusCode: StatusCodes.Status200OK);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Results.Json(
                new ApiErrorResponse("HIP trust receipt storage is unavailable."),
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }
    })
    .WithName("ApiServiceGetHipTrustReceipt")
    .WithSummary("Returns one immutable signed HIP trust receipt.")
    .WithDescription("Returns the exact stored version-one receipt JSON so signatures and canonical wire evidence remain unchanged.")
    .Produces<HipTrustReceipt>(StatusCodes.Status200OK, "application/json")
    .Produces<ApiErrorResponse>(StatusCodes.Status400BadRequest)
    .Produces<ApiErrorResponse>(StatusCodes.Status404NotFound)
    .Produces<ApiErrorResponse>(StatusCodes.Status503ServiceUnavailable)
    .AllowAnonymous();

    protocolApi.MapPost("/receipts/verify", async (
        HttpRequest request,
        IHipTrustReceiptVerificationService verificationService,
        CancellationToken cancellationToken) =>
    {
        var requestBody = await ReadHipTrustReceiptRequestAsync(request, cancellationToken);
        if (requestBody.IsTooLarge)
        {
            return Results.Json(
                new ApiErrorResponse("HIP trust receipt request exceeds the maximum allowed size."),
                statusCode: StatusCodes.Status413PayloadTooLarge);
        }

        HipTrustReceiptVerificationResult verification;
        try
        {
            verification = await verificationService.VerifyAsync(requestBody.Utf8Receipt, cancellationToken);
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
            HipTrustReceiptVerificationApiResponse.FromResult(verification),
            statusCode: HipTrustReceiptVerificationHttpStatus(verification.Status));
    })
    .WithName("ApiServiceVerifyHipTrustReceipt")
    .WithSummary("Verifies the signature and current issuer/key state of a HIP trust receipt.")
    .WithDescription("""
Strictly parses and verifies a version-one trust receipt without consuming replay state. A Verified result proves the
named issuer signed the unchanged receipt with a valid key at issuance time; it does not independently prove safety or reputation.
""")
    .Accepts<HipTrustReceipt>("application/json")
    .Produces<HipTrustReceiptVerificationApiResponse>(StatusCodes.Status200OK)
    .Produces<HipTrustReceiptVerificationApiResponse>(StatusCodes.Status400BadRequest)
    .Produces<HipTrustReceiptVerificationApiResponse>(StatusCodes.Status422UnprocessableEntity)
    .Produces<HipTrustReceiptVerificationApiResponse>(StatusCodes.Status503ServiceUnavailable)
    .Produces<ApiErrorResponse>(StatusCodes.Status413PayloadTooLarge)
    .AllowAnonymous()
    .RequireCors(HipCorsPolicies.ClientWrite)
    .RequireRateLimiting(PublicScanPolicy);
}

/// <summary>
/// Converts a typed receipt-issuance outcome to a stable HTTP response without reserializing successful receipts
/// through the host's general-purpose JSON settings.
/// </summary>
/// <param name="issueResult">Application-layer issuance outcome.</param>
/// <param name="response">Current response used to add the created-resource location.</param>
/// <returns>Exact receipt JSON on success, or a safe typed error response.</returns>
static IResult ToHipTrustReceiptIssueApiResult(
    HipTrustReceiptIssueResult issueResult,
    HttpResponse response)
{
    if (issueResult.Status is HipTrustReceiptIssueStatus.Issued or HipTrustReceiptIssueStatus.Existing)
    {
        if (issueResult.Receipt is null)
        {
            return Results.Json(
                new ApiErrorResponse("HIP trust receipt issuance is unavailable."),
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        string receiptJson;
        try
        {
            receiptJson = HipTrustReceiptJson.Serialize(issueResult.Receipt);
        }
        catch (Exception exception) when (exception is ArgumentException or System.Text.Json.JsonException)
        {
            return Results.Json(
                new ApiErrorResponse("HIP trust receipt issuance is unavailable."),
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        var statusCode = issueResult.Status == HipTrustReceiptIssueStatus.Issued
            ? StatusCodes.Status201Created
            : StatusCodes.Status200OK;
        if (statusCode == StatusCodes.Status201Created)
        {
            response.Headers.Location =
                $"/api/v1/protocol/receipts/{Uri.EscapeDataString(issueResult.Receipt.ReceiptId)}";
        }

        return Results.Text(
            receiptJson,
            contentType: "application/json",
            contentEncoding: Encoding.UTF8,
            statusCode: statusCode);
    }

    return issueResult.Status switch
    {
        HipTrustReceiptIssueStatus.InvalidEvaluation => Results.BadRequest(
            new ApiErrorResponse("HIP could not issue a receipt from the authoritative site safety evaluation.")),
        HipTrustReceiptIssueStatus.Conflict => Results.Conflict(
            new ApiErrorResponse("A different trust receipt already exists for this authoritative evaluation.")),
        HipTrustReceiptIssueStatus.SignerUnavailable or
        HipTrustReceiptIssueStatus.SignerNotAuthorized => Results.Json(
            new ApiErrorResponse("HIP trust receipt signing is unavailable."),
            statusCode: StatusCodes.Status503ServiceUnavailable),
        HipTrustReceiptIssueStatus.VerificationFailed => Results.Json(
            new ApiErrorResponse("HIP could not verify the newly signed trust receipt."),
            statusCode: StatusCodes.Status503ServiceUnavailable),
        HipTrustReceiptIssueStatus.PersistenceUnavailable => Results.Json(
            new ApiErrorResponse("HIP trust receipt storage is unavailable."),
            statusCode: StatusCodes.Status503ServiceUnavailable),
        _ => Results.Json(
            new ApiErrorResponse("HIP trust receipt issuance is unavailable."),
            statusCode: StatusCodes.Status503ServiceUnavailable)
    };
}

/// <summary>
/// Reads at most one bounded receipt document so chunked requests cannot force unbounded buffering before verification.
/// </summary>
/// <param name="request">HTTP request containing raw receipt JSON.</param>
/// <param name="cancellationToken">Token used to cancel request-body reads.</param>
/// <returns>The exact submitted bytes or an oversized marker.</returns>
static async Task<HipTrustReceiptRequestBody> ReadHipTrustReceiptRequestAsync(
    HttpRequest request,
    CancellationToken cancellationToken)
{
    if (request.ContentLength > HipTrustReceiptJson.MaximumReceiptBytes)
    {
        return new HipTrustReceiptRequestBody(ReadOnlyMemory<byte>.Empty, IsTooLarge: true);
    }

    var buffer = new byte[HipTrustReceiptJson.MaximumReceiptBytes + 1];
    var bytesRead = 0;
    while (bytesRead < buffer.Length)
    {
        var read = await request.Body.ReadAsync(buffer.AsMemory(bytesRead), cancellationToken);
        if (read == 0)
        {
            break;
        }

        bytesRead += read;
    }

    return bytesRead > HipTrustReceiptJson.MaximumReceiptBytes
        ? new HipTrustReceiptRequestBody(ReadOnlyMemory<byte>.Empty, IsTooLarge: true)
        : new HipTrustReceiptRequestBody(buffer.AsMemory(0, bytesRead).ToArray(), IsTooLarge: false);
}

/// <summary>
/// Validates an untrusted receipt path segment before it reaches persistence.
/// </summary>
/// <param name="receiptId">Receipt identifier supplied in the route.</param>
/// <returns>The validated identifier.</returns>
static string ValidateHipTrustReceiptId(string? receiptId)
{
    if (string.IsNullOrWhiteSpace(receiptId) ||
        receiptId.Length > HipTrustReceipt.MaximumReceiptIdLength ||
        !receiptId.All(character =>
            character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '_' or '.' or ':'))
    {
        throw new ArgumentException("The trust receipt identifier is invalid.", nameof(receiptId));
    }

    return receiptId;
}

/// <summary>
/// Maps verification outcomes to HTTP semantics without treating document verification as request authentication.
/// </summary>
/// <param name="status">Typed trust receipt verification outcome.</param>
/// <returns>HTTP status representing success, invalid input/evidence, or unavailable verification state.</returns>
static int HipTrustReceiptVerificationHttpStatus(HipTrustReceiptVerificationStatus status) => status switch
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

/// <summary>
/// Applies browser-instance provider preferences without accepting endpoints, API keys, or full-URL permission.
/// </summary>
/// <param name="options">Detached options cloned from server defaults.</param>
/// <param name="request">Client preferences from the extension options page.</param>
static void ApplyClientExternalProviderSettings(ExternalSiteEvidenceOptions options, ExternalProviderSettingsUpdateRequest request)
{
    options.ExternalProvidersEnabled = request.ExternalProvidersEnabled;
    options.AllowFullUrlChecks = false;
    options.ProviderTimeout = request.ProviderTimeout is { Ticks: > 0 } ? request.ProviderTimeout.Value : TimeSpan.FromSeconds(10);
    options.DefaultCacheDuration = request.DefaultCacheDuration is { Ticks: > 0 } ? request.DefaultCacheDuration.Value : TimeSpan.FromHours(6);
    options.SslLabs.Enabled = request.SslLabs.Enabled;
    options.GoogleWebRisk.Enabled = request.GoogleWebRisk.Enabled;
    options.VirusTotal.Enabled = request.VirusTotal.Enabled;
}

/// <summary>
/// Converts application site safety results to public-safe JSON with enum values rendered as readable strings.
/// </summary>
/// <param name="result">The application-layer scan result.</param>
/// <returns>A privacy-safe response for browser clients and public tools.</returns>
static SiteSafetyScanApiResponse ToSiteSafetyScanResponse(SiteSafetyScanResult result) =>
    new(
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
        result.Status.ToString(),
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
        ToSiteSafetyProviderEvidenceResponses(result.ProviderEvidence),
        result.ScoreImpact,
        ToHipScoringResponse(result.Scoring));

/// <summary>Projects the typed formal score without exposing implementation-only stage objects.</summary>
static HipScoringApiResponse? ToHipScoringResponse(HipScoringResult? result) => result is null
    ? null
    : new HipScoringApiResponse(
        result.ModelVersion,
        result.DomainTrustScore,
        result.PageTrustScore,
        result.ContentRiskScore,
        result.FinalHipScore,
        result.FinalStatus.ToString(),
        result.PresentationStatus.ToString(),
        result.Confidence.ToString(),
        result.EvidenceFreshness.ToString(),
        result.TrustAssertionDisposition.ToString(),
        result.CanAssertPositiveTrust,
        result.FinalScoreHigherMeansMoreTrust,
        result.ContentRiskScoreHigherMeansMoreRisk,
        result.Reasons,
        result.Warnings,
        result.ReasonEntries.Select(entry => new HipScoringReasonApiResponse(
            entry.Code,
            entry.Explanation,
            entry.WarningCode,
            entry.Warning,
            new HipScoreImpactApiResponse(entry.Impact.Kind.ToString(), entry.Impact.Value),
            entry.EvidenceSourceCode,
            entry.EvidenceObservedAtUtc,
            entry.PrivacyClassification.ToString())).ToArray());

/// <summary>
/// Converts normalized provider evidence to public-safe API DTOs.
/// </summary>
/// <param name="providerEvidence">Provider evidence returned by the scanner or external collector.</param>
/// <returns>Public-safe provider evidence responses.</returns>
/// <remarks>
/// Updated 2026-06-21 10:47 UTC by HIP Development Team. Assisted by Codex.
/// This keeps the scan and external-evidence endpoints using one response shape, so provider results are
/// easier to compare and less likely to drift.
/// </remarks>
static IReadOnlyList<SiteSafetyProviderEvidenceApiResponse> ToSiteSafetyProviderEvidenceResponses(IEnumerable<SiteSafetyEvidence> providerEvidence) =>
    providerEvidence.Select(evidence => new SiteSafetyProviderEvidenceApiResponse(
            evidence.ProviderName,
            evidence.ProviderType.ToString(),
            evidence.TargetType.ToString(),
            evidence.Domain,
            evidence.UrlHash,
            evidence.Confidence,
            evidence.CheckedAtUtc,
            evidence.ExpiresAtUtc,
            evidence.Errors,
            evidence.IsAuthoritativeForRisk,
            evidence.IsAuthoritativeForTrust,
            evidence.ResultStatus.ToString(),
            evidence.LatencyMilliseconds,
            evidence.Freshness.ToString(),
            evidence.PrivacyClassification.ToString(),
            evidence.EvidenceItems.Select(item => new SiteSafetyProviderEvidenceItemApiResponse(
                item.Category,
                item.Value,
                item.Status.ToString(),
                item.RiskImpact,
                item.TrustImpact,
                item.Summary)).ToArray())).ToArray();

/// <summary>Projects a durable provider job without owner, settings, lease, hash, or observed-signal data.</summary>
static ExternalSiteEvidenceJobApiResponse ToExternalSiteEvidenceJobApiResponse(ExternalSiteEvidenceJob job) => new(
    job.JobId,
    job.Domain,
    job.Status.ToString(),
    job.AttemptCount,
    job.RequestedAtUtc,
    job.UpdatedAtUtc,
    job.NextAttemptAtUtc,
    job.CompletedAtUtc,
    job.LastError,
    ToSiteSafetyProviderEvidenceResponses(job.ProviderEvidence));

/// <summary>
/// Provides detailed Swagger text for explicitly requested external evidence checks.
/// </summary>
/// <returns>Markdown description shown in Swagger UI.</returns>
static string GetExternalSiteEvidenceCheckDescription() => """
    Runs configured external site-safety evidence providers for a URL.

    Use this endpoint when:
    - An admin or local test wants to verify SSL Labs / Qualys-style TLS evidence.
    - A future slow-path worker wants to refresh provider evidence outside the browser request path.
    - You need normalized external provider results without changing the live score directly.

    Important behavior:
    - Callers may use the existing privileged administrator policy or a HIP-Service credential with the exact
      site-safety:external-evidence:check scope and an exact normalized domain grant.
    - Domain grants do not imply parent domains, child domains, or wildcard access.
    - This endpoint returns evidence only. HIP scoring still decides final trust and risk labels.
    - Provider failures return safe evidence errors instead of crashing the API.
    - Clean provider results do not automatically make an unknown domain trusted.
    - Threat-intel hits may later influence scoring when the evidence is used by the scanner or projections.

    Privacy:
    - The scan request may include the current URL and privacy-safe observed counts.
    - HIP strips query strings and fragments before hashing or returning evidence.
    - Do not send page text, form values, passwords, tokens, cookies, private messages, or browsing history.
    - Providers should prefer domain-only checks. Full URL submission remains disabled unless policy explicitly allows it.
    """;

/// <summary>
/// Provides detailed Swagger text for the public lookup endpoint.
/// </summary>
/// <returns>Markdown description shown in Swagger UI.</returns>
static string GetPublicDomainLookupDescription() => """
    Public lookup returns the latest public-safe HIP trust summary for a domain.

    Use this endpoint when:
    - A user types a domain into the public HIP lookup page.
    - A badge or client needs a domain-level public summary.
    - You need to confirm whether HIP has stored browser scan evidence for a domain.

    Input:
    - `domain` must be a domain name such as `example.com`.
    - Do not include a path, query string, fragment, username, password, or full page URL.

    Response meaning:
    - `score` and `status` describe the current public-facing HIP trust result.
    - `dataSource` identifies whether the result came from stored browser scan data or a no-data fallback.
    - `reasons` are written for humans and should explain whether the domain has real scan history or limited data.

    Privacy:
    - This endpoint must not expose full page URLs, page text, user identity, browsing history, form values, raw reports, or private scan payloads.
    - Public lookup is domain-level only.

    Example:
    `GET /api/v1/public/lookup/domain/example.com`
""";

static DnsLookupRecordType ParseDnsLookupRecordType(string? value) => value?.Trim().ToUpperInvariant() switch
{
    null or "" or "A" or "1" => DnsLookupRecordType.A,
    "AAAA" or "28" => DnsLookupRecordType.Aaaa,
    _ => throw new ArgumentException("HIP DNS currently supports A and AAAA queries only.", nameof(value))
};

static byte[] DecodeDnsBase64Url(string value)
{
    var encoded = value.Trim();
    if (encoded.Length == 0 || encoded.Length > ((DnsWireMessageCodec.MaximumQueryBytes + 2) / 3 * 4))
    {
        throw new ArgumentException("RFC 8484 dns parameter length is invalid.", nameof(value));
    }

    var normalized = encoded.Replace('-', '+').Replace('_', '/');
    normalized = normalized.PadRight(normalized.Length + ((4 - normalized.Length % 4) % 4), '=');
    try
    {
        return Convert.FromBase64String(normalized);
    }
    catch (FormatException exception)
    {
        throw new ArgumentException("RFC 8484 dns parameter is not valid base64url.", nameof(value), exception);
    }
}

static async Task<byte[]> ReadBoundedDnsWireBodyAsync(HttpRequest request, CancellationToken cancellationToken)
{
    await using var buffer = new MemoryStream();
    var chunk = new byte[1024];
    while (true)
    {
        var read = await request.Body.ReadAsync(chunk, cancellationToken);
        if (read == 0)
        {
            break;
        }
        if (buffer.Length + read > DnsWireMessageCodec.MaximumQueryBytes)
        {
            throw new InvalidDataException("DNS wire request exceeds the configured limit.");
        }
        await buffer.WriteAsync(chunk.AsMemory(0, read), cancellationToken);
    }
    return buffer.ToArray();
}

static async Task<IResult> ResolveDnsWireQueryAsync(
    HttpContext httpContext,
    DnsWireQuery wireQuery,
    IHipAwareDnsLookupService dnsLookupService,
    bool isPost,
    CancellationToken cancellationToken)
{
    if (wireQuery.RecordType is not DnsLookupRecordType.A and not DnsLookupRecordType.Aaaa)
    {
        httpContext.Response.Headers.CacheControl = "no-store";
        return Results.Bytes(
            DnsWireMessageCodec.EncodeErrorResponse(wireQuery, dnsResponseCode: 4),
            "application/dns-message");
    }

    var lookup = await dnsLookupService.LookupAsync(wireQuery.Domain, wireQuery.RecordType, cancellationToken);
    var response = DnsWireMessageCodec.EncodeResponse(wireQuery, lookup);
    ApplyHipDnsResponseHeaders(httpContext.Response, lookup, isPost);
    return Results.Bytes(response, "application/dns-message");
}

static void ApplyHipDnsResponseHeaders(
    HttpResponse response,
    HipAwareDnsLookupResponse lookup,
    bool isPost)
{
    response.Headers["X-HIP-Status"] = lookup.Hip.Status;
    response.Headers["X-HIP-Evidence-Coverage"] = lookup.Hip.EvidenceCoverage;
    response.Headers["X-HIP-Authoritative"] = "false";
    response.Headers["X-HIP-DNSSEC-Status"] = lookup.Dnssec.Status;
    if (lookup.Hip.DisplayScore is int score)
    {
        response.Headers["X-HIP-Score"] = score.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    var minimumTtl = lookup.Answer.Count == 0
        ? 0
        : lookup.Answer.Min(answer => Math.Max(0, answer.TtlSeconds));
    response.Headers.CacheControl = isPost ? "no-store" : $"public, max-age={minimumTtl}";
    response.Headers.Vary = "Accept";
}

/// <summary>
/// Provides detailed Swagger text for the public live badge endpoint.
/// </summary>
/// <returns>Markdown description shown in Swagger UI.</returns>
static string GetPublicDomainBadgeDescription() => """
    Returns the live HIP badge state for a domain.

    Use this endpoint when:
    - Rendering a HIP badge on a website.
    - Verifying that a badge shows both identity/verification state and current trust state.
    - Linking visitors back to the public HIP lookup page.

    Badge rules:
    - The badge must always show a score or status.
    - `verified` means HIP has domain or identity verification evidence; it does not mean the website is safe.
    - Low scores must still be visible. A site must not be able to display only "Verified by HIP".

    Response meaning:
    - `lookupUrl` points to the public lookup route for independent verification.
    - `lastCheckedUtc` tells users how fresh the badge data is.

    Privacy:
    - Badge data is public-safe and domain-level.
    - No page text, private reports, user identity, or browsing history is returned.
    """;

/// <summary>
/// Provides detailed Swagger text for public feedback submission.
/// </summary>
/// <returns>Markdown description shown in Swagger UI.</returns>
static string GetPublicFeedbackDescription() => """
    Submits a privacy-safe trust feedback signal.

    HIP treats feedback as weighted evidence, not popularity voting.

    Expected use:
    - Browser plugin banner buttons such as "Looks Safe" and "Looks Suspicious".
    - Safety page reports such as "Report Safe" or "Report Dangerous".
    - Public lookup feedback when a user believes a result is wrong.

    Security and abuse behavior:
    - Duplicate submissions are suppressed so double-clicks and retries do not spam reputation data.
    - Anonymous or untrusted feedback should carry low weight.
    - Future production clients should use stronger identity, signer, or instance authentication.

    Privacy:
    - Allowed fields are domain, feedback type, source, reason summary, timestamp, and safe reporter trust metadata when available.
    - Do not send page text, chat logs, private messages, form values, passwords, cookies, tokens, or unrelated browsing history.

    Example feedback:
    - LooksSafe from BrowserPluginBanner.
    - LooksSuspicious from BrowserPluginBanner.
    - ReportAsDangerous from SafetyPage.
    """;

/// <summary>
/// Provides detailed Swagger text for browser site scoring.
/// </summary>
/// <returns>Markdown description shown in Swagger UI.</returns>
static string GetBrowserScoreSiteDescription() => """
    Scores the current browser tab domain for the browser plugin.

    Expected caller:
    - HIP browser extension popup.
    - HIP browser content script when it needs a fast current-site summary.

    Request:
    - `url` is the current tab URL when policy allows it.
    - `domain` is the normalized current domain.
    - The request must be generated from the active tab only.

    Response:
    - Includes HIP score, status, verification status, signed identity placeholder/status, reasons, and recommended action.
    - This is a fast user-facing score. Deeper provider checks should be cached or handled by the site-safety scan path.

    Privacy:
    - Do not send DOM text, page body text, selected text, form values, password fields, cookies, tokens, email contents, chat contents, or browsing history.

    Failure behavior:
    - Invalid domains or malformed URLs return `400`.
    - The plugin should show a safe unavailable state instead of crashing.
    """;

/// <summary>
/// Provides detailed Swagger text for browser link scanning.
/// </summary>
/// <returns>Markdown description shown in Swagger UI.</returns>
static string GetBrowserScanLinksDescription() => """
    Scans links discovered on the current page and returns per-link routing decisions.

    Expected caller:
    - HIP browser content script.

    Request:
    - Include only discovered link URLs.
    - Do not include link surrounding text, visible page text, form data, or private content.

    Response:
    - Safe links should not require icons and should not be modified.
    - Suspicious and dangerous links may include safety-page routing.
    - Critical links should route through the safety page and avoid continue-by-default behavior where supported.

    Recommended client behavior:
    - Add icons/labels only to risky links.
    - Intercept clicks only for risky links.
    - Encode target URLs when routing through `/safety?url={encodedUrl}&source=browser`.

    Privacy:
    - HIP receives link URLs for risk checking, not page text or form values.
    """;

/// <summary>
/// Provides detailed Swagger text for browser scan result storage.
/// </summary>
/// <returns>Markdown description shown in Swagger UI.</returns>
static string GetBrowserSaveScanResultDescription() => """
    Stores a privacy-safe browser scan summary for later lookup and dashboard views.

    Expected caller:
    - HIP browser extension after it finishes scanning a page.

    Stored fields:
    - Domain.
    - URL hash and raw URL only when policy allows it.
    - Layered scores such as domain trust, page trust, content risk, and final HIP score when available.
    - Status, confidence, reasons, warnings, link counts, risky counts, provider names, matched rule IDs, plugin version, and scan timestamp.

    Not stored:
    - Page body text.
    - Form values.
    - Passwords, tokens, cookies, or secrets.
    - Private messages, chat logs, email bodies, or unrelated browsing history.

    Duplicate behavior:
    - Repeated submissions with the same domain, URL hash, and signal fingerprint may return `409` to prevent dashboard spam and storage waste.

    Downstream use:
    - Public lookup can show domain-level scan summaries.
    - Admin dashboard can show recent scan rows and aggregates.
    - Review queue can receive important risky or uncertain cases.
    """;

/// <summary>
/// Provides detailed Swagger text for browser scan result retrieval.
/// </summary>
/// <returns>Markdown description shown in Swagger UI.</returns>
static string GetBrowserGetScanResultDescription() => """
    Returns the latest stored browser scan summary for a domain.

    Use this endpoint when:
    - Debugging whether browser plugin scans are being persisted.
    - Confirming what public lookup or dashboard projections can read.
    - Showing the latest known scan state for a domain in local development.

    Response:
    - `200` returns the latest privacy-safe scan summary.
    - `404` means HIP has no stored browser scan result for the domain yet.
    - `400` means the domain was invalid.

    Privacy:
    - Response data must remain domain-level or hashed.
    - Do not expose raw page text, form contents, user identity, private reports, or browsing history.
    """;

/// <summary>
/// Provides detailed Swagger text for provider preference reads.
/// </summary>
/// <returns>Markdown description shown in Swagger UI.</returns>
static string GetExternalProviderPreferencesDescription() => """
    Returns external evidence provider switches for the current browser/HIP instance scope.

    Providers represented:
    - SSL Labs / Qualys-style TLS evidence.
    - Google Web Risk / Safe Browsing-style threat evidence.
    - VirusTotal-style URL/domain reputation evidence.

    Important:
    - Providers return evidence only; HIP scoring decides final trust and risk.
    - A clean provider result does not make an unknown site Trusted.
    - Provider errors should lower confidence or add warnings, not automatically create trust or danger.

    Privacy:
    - API keys and provider endpoints are never returned to browser clients.
    - Browser-scoped settings cannot enable full raw URL submission.
    """;

/// <summary>
/// Provides detailed Swagger text for provider preference updates.
/// </summary>
/// <returns>Markdown description shown in Swagger UI.</returns>
static string GetUpdateExternalProviderPreferencesDescription() => """
    Updates provider enablement switches for the current browser/HIP instance scope.

    Local development behavior:
    - Allows a tester to enable or disable provider categories from the extension/settings UI when the host permits client preference writes.
    - Server-side configuration still controls endpoints, API keys, privacy policy, and provider behavior.

    Rejected client control:
    - Provider API keys.
    - Provider base URLs.
    - Full raw URL submission permission.

    Security:
    - This endpoint is rate limited and CORS-restricted to configured client origins.
    - Production should move provider control behind authenticated admin or signed-instance policy.

    Privacy:
    - Domain-only or hashed checks remain preferred.
    - Browser clients cannot force HIP to send page text, form values, passwords, cookies, tokens, private messages, or unrelated browsing history to providers.
    """;

/// <summary>
/// Provides detailed Swagger text for site safety scans.
/// </summary>
/// <returns>Markdown description shown in Swagger UI.</returns>
static string GetSiteSafetyScanDescription() => """
    Runs a privacy-safe site safety scan from browser-observed signals.

    This is the detailed scan path used by the browser plugin and future HIP clients.

    Expected flow:
    1. Browser plugin observes the current page locally.
    2. Plugin sends only privacy-safe signals to HIP.
    3. HIP evaluates configured evidence providers and built-in/admin-managed rules.
    4. HIP calculates malware, phishing, redirect, script, download, form, reputation, domain trust, page trust, content risk, and final HIP score.
    5. HIP returns the immediate result to the requesting client.
    6. HIP stores the summary as untrusted client telemetry. It does not publish anonymous observations to authoritative lookup, dashboard, admin-review, sandbox, or outbox workflows.

    Request may include:
    - Current URL and normalized domain.
    - HTTPS status.
    - Login/password/payment flags.
    - Download counts and file-type indicators.
    - Redirect count, shortener count, obfuscation count, external script count, and matched risk-term categories.
    - Provider preference scope from headers.

    Request must not include:
    - Page body text.
    - Form values.
    - Passwords, tokens, cookies, or private keys.
    - Email bodies, chat logs, private messages, or unrelated browsing history.

    Response:
    - Returns separate risk scores and trust scores. Final HIP score must not hide domain, page, and content scoring.
    - Includes provider evidence so testers can see whether SSL Labs/Qualys-style TLS checks or other providers contributed evidence.
    - Includes reasons, warnings, positive signals, negative signals, confidence, and score impact.

    Status guidance:
    - Unknown clean sites should remain Unknown or LimitedTrustData.
    - Trusted domains can still have risky pages or content.
    - Downloads must not inherit full trust from the parent domain.

    Failure behavior:
    - Duplicate scans can return `409`.
    - Invalid URLs or private-field validation failures return `400`.
    - Provider failures should not crash scoring.
    """;

/// <summary>
/// Detailed Swagger response for site safety scans.
/// </summary>
/// <param name="ScanId">Unique scan identifier.</param>
/// <param name="Url">Current scanned URL when storage policy allows returning it to the local caller.</param>
/// <param name="Domain">Normalized domain that was scored.</param>
/// <param name="ScannedAtUtc">UTC time when HIP evaluated the scan.</param>
/// <param name="MalwareRiskScore">Malware risk component score.</param>
/// <param name="PhishingRiskScore">Phishing risk component score.</param>
/// <param name="RedirectRiskScore">Redirect risk component score.</param>
/// <param name="ScriptRiskScore">Script risk component score.</param>
/// <param name="DownloadRiskScore">Download risk component score.</param>
/// <param name="FormRiskScore">Form and credential collection risk component score.</param>
/// <param name="ReputationRiskScore">Reputation risk component score.</param>
/// <param name="OverallSafetyRiskScore">Combined safety risk score before trust-layer conversion.</param>
/// <param name="Status">Final readable HIP status label.</param>
/// <param name="Summary">Plain-English scan summary.</param>
/// <param name="Reasons">Plain-English reasons supporting the score.</param>
/// <param name="Warnings">User-visible warnings generated by rules or evidence providers.</param>
/// <param name="PositiveSignals">Positive trust or safety signals observed during the scan.</param>
/// <param name="NegativeSignals">Negative risk signals observed during the scan.</param>
/// <param name="ConfidenceLevel">Confidence level assigned to the result.</param>
/// <param name="DomainTrustScore">Trust score for the root domain overall.</param>
/// <param name="PageTrustScore">Trust score for this exact page or URL.</param>
/// <param name="ContentRiskScore">Risk score for observed page content and behavior.</param>
/// <param name="FinalHipScore">Final user-facing HIP score.</param>
/// <param name="ProviderEvidence">Normalized provider evidence used by the scan.</param>
/// <param name="ScoreImpact">Rule and evidence score impact details.</param>
/// <param name="Scoring">Versioned direction-explicit formal HIP score.</param>
sealed record SiteSafetyScanApiResponse(
    string ScanId,
    string Url,
    string Domain,
    DateTimeOffset ScannedAtUtc,
    int MalwareRiskScore,
    int PhishingRiskScore,
    int RedirectRiskScore,
    int ScriptRiskScore,
    int DownloadRiskScore,
    int FormRiskScore,
    int ReputationRiskScore,
    int OverallSafetyRiskScore,
    string Status,
    string Summary,
    IReadOnlyCollection<string> Reasons,
    IReadOnlyCollection<string> Warnings,
    IReadOnlyCollection<string> PositiveSignals,
    IReadOnlyCollection<string> NegativeSignals,
    string ConfidenceLevel,
    int DomainTrustScore,
    int PageTrustScore,
    int ContentRiskScore,
    int FinalHipScore,
    IReadOnlyList<SiteSafetyProviderEvidenceApiResponse> ProviderEvidence,
    object? ScoreImpact,
    HipScoringApiResponse? Scoring);

/// <summary>Public-safe projection of the formal HIP-0301 score pipeline.</summary>
sealed record HipScoringApiResponse(
    string ModelVersion,
    int DomainTrustScore,
    int? PageTrustScore,
    int ContentRiskScore,
    int FinalHipScore,
    string FinalStatus,
    string PresentationStatus,
    string Confidence,
    string EvidenceFreshness,
    string TrustAssertionDisposition,
    bool CanAssertPositiveTrust,
    bool FinalScoreHigherMeansMoreTrust,
    bool ContentRiskScoreHigherMeansMoreRisk,
    IReadOnlyCollection<string> Reasons,
    IReadOnlyCollection<string> Warnings,
    IReadOnlyCollection<HipScoringReasonApiResponse> ReasonEntries);

/// <summary>Public-safe stable code, explanation, warning, impact, and evidence metadata for one scoring reason.</summary>
sealed record HipScoringReasonApiResponse(
    string Code,
    string Explanation,
    string? WarningCode,
    string? Warning,
    HipScoreImpactApiResponse Impact,
    string EvidenceSourceCode,
    DateTimeOffset? EvidenceObservedAtUtc,
    string PrivacyClassification);

/// <summary>Public-safe typed score impact associated with a stable scoring reason.</summary>
sealed record HipScoreImpactApiResponse(
    string Kind,
    int? Value);

/// <summary>
/// Response returned when HIP explicitly checks external site safety evidence providers.
/// </summary>
/// <param name="Domain">Normalized public domain that was checked.</param>
/// <param name="CheckedAtUtc">UTC time associated with the first provider response.</param>
/// <param name="ProviderEvidence">Normalized provider evidence records.</param>
/// <remarks>
/// New 2026-06-21 10:47 UTC by HIP Development Team. Assisted by Codex.
/// This response intentionally contains provider evidence only, not a final score, because external scanners
/// provide facts and HIP scoring decides the final label.
/// </remarks>
sealed record ExternalSiteEvidenceCheckResponse(
    string Domain,
    DateTimeOffset CheckedAtUtc,
    IReadOnlyList<SiteSafetyProviderEvidenceApiResponse> ProviderEvidence);

/// <summary>Owner-scoped status and normalized result projection for one durable provider job.</summary>
sealed record ExternalSiteEvidenceJobApiResponse(
    string JobId,
    string Domain,
    string Status,
    int AttemptCount,
    DateTimeOffset RequestedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    DateTimeOffset? NextAttemptAtUtc,
    DateTimeOffset? CompletedAtUtc,
    string? LastError,
    IReadOnlyList<SiteSafetyProviderEvidenceApiResponse> ProviderEvidence);

/// <summary>
/// Detailed Swagger response for one normalized evidence provider result.
/// </summary>
/// <param name="ProviderName">Provider display name, such as BrowserObservedSignalProvider or SSL Labs / Qualys TLS.</param>
/// <param name="ProviderType">Normalized provider category.</param>
/// <param name="TargetType">Whether the evidence applies to the domain, URL, content, or another target type.</param>
/// <param name="Domain">Domain evaluated by the provider.</param>
/// <param name="UrlHash">Hashed URL when URL-level evidence is used.</param>
/// <param name="Confidence">Provider confidence score.</param>
/// <param name="CheckedAtUtc">UTC time the provider evidence was checked.</param>
/// <param name="ExpiresAtUtc">UTC time when cached provider evidence expires.</param>
/// <param name="Errors">Safe provider errors or timeout notes.</param>
/// <param name="IsAuthoritativeForRisk">Whether this provider can force high-risk outcomes for known-bad evidence.</param>
/// <param name="IsAuthoritativeForTrust">Whether this provider can contribute positive trust evidence.</param>
/// <param name="ResultStatus">Normalized provider completion status.</param>
/// <param name="LatencyMilliseconds">Bounded provider collection latency in milliseconds.</param>
/// <param name="Freshness">Normalized fresh, stale, or expired classification.</param>
/// <param name="PrivacyClassification">Most sensitive privacy-safe metadata class retained by the result.</param>
/// <param name="EvidenceItems">Normalized evidence items returned by the provider.</param>
sealed record SiteSafetyProviderEvidenceApiResponse(
    string ProviderName,
    string ProviderType,
    string TargetType,
    string Domain,
    string? UrlHash,
    int Confidence,
    DateTimeOffset CheckedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    IReadOnlyCollection<string> Errors,
    bool IsAuthoritativeForRisk,
    bool IsAuthoritativeForTrust,
    string ResultStatus,
    long LatencyMilliseconds,
    string Freshness,
    string PrivacyClassification,
    IReadOnlyList<SiteSafetyProviderEvidenceItemApiResponse> EvidenceItems);

/// <summary>
/// Detailed Swagger response for one normalized evidence item.
/// </summary>
/// <param name="Category">Evidence category, such as TLS grade, phishing hit, script signal, or observed browser signal.</param>
/// <param name="Value">Safe evidence value or label.</param>
/// <param name="Status">Normalized evidence status.</param>
/// <param name="RiskImpact">Risk impact contributed by this evidence item.</param>
/// <param name="TrustImpact">Trust impact contributed by this evidence item.</param>
/// <param name="Summary">Plain-English provider explanation.</param>
sealed record SiteSafetyProviderEvidenceItemApiResponse(
    string Category,
    string Value,
    string Status,
    int RiskImpact,
    int TrustImpact,
    string Summary);

/// <summary>
/// Client-safe provider settings response scoped to one browser instance.
/// </summary>
/// <param name="SettingsScope">Server-side scope key used for diagnostics only.</param>
/// <param name="ExternalProvidersEnabled">Whether external evidence may run for this scope.</param>
/// <param name="AllowFullUrlChecks">Always false for browser-scoped preferences because full URLs remain private by default.</param>
/// <param name="ProviderTimeout">Provider timeout.</param>
/// <param name="DefaultCacheDuration">Default provider cache duration.</param>
/// <param name="SslLabs">SSL Labs/Qualys-style TLS provider preferences.</param>
/// <param name="GoogleWebRisk">Google Web Risk/Safe Browsing-style provider preferences.</param>
/// <param name="VirusTotal">VirusTotal-style provider preferences.</param>
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
    /// Converts runtime options into a client-safe response without returning stored secrets.
    /// </summary>
    /// <param name="options">Runtime external evidence options.</param>
    /// <param name="settingsScope">Settings scope used for the response.</param>
    /// <returns>Safe provider settings response.</returns>
    public static ExternalProviderSettingsResponse From(ExternalSiteEvidenceOptions options, string settingsScope) =>
        new(
            settingsScope,
            options.ExternalProvidersEnabled,
            false,
            options.ProviderTimeout,
            options.DefaultCacheDuration,
            ExternalProviderSettings.From(options.SslLabs),
            ExternalProviderSettings.From(options.GoogleWebRisk),
            ExternalProviderSettings.From(options.VirusTotal));
}

/// <summary>
/// Browser-instance request for changing provider preferences.
/// </summary>
/// <param name="ExternalProvidersEnabled">Whether external evidence may run for this instance.</param>
/// <param name="AllowFullUrlChecks">Ignored for browser-instance settings to preserve privacy.</param>
/// <param name="ProviderTimeout">Provider timeout.</param>
/// <param name="DefaultCacheDuration">Default provider cache duration.</param>
/// <param name="SslLabs">SSL Labs/Qualys-style provider switch.</param>
/// <param name="GoogleWebRisk">Google Web Risk/Safe Browsing-style provider switch.</param>
/// <param name="VirusTotal">VirusTotal-style provider switch.</param>
sealed record ExternalProviderSettingsUpdateRequest(
    bool ExternalProvidersEnabled,
    bool AllowFullUrlChecks,
    TimeSpan? ProviderTimeout,
    TimeSpan? DefaultCacheDuration,
    ExternalProviderSettings SslLabs,
    ExternalProviderSettings GoogleWebRisk,
    ExternalProviderSettings VirusTotal);

/// <summary>
/// Provider-specific preference shape accepted from the extension options page.
/// </summary>
/// <param name="Enabled">Whether this provider can run when external providers are enabled.</param>
/// <param name="Endpoint">Ignored for browser-instance settings to avoid client-controlled scanner endpoints.</param>
/// <param name="ApiKey">Ignored for browser-instance settings to avoid storing secrets from the extension.</param>
/// <param name="AllowFullUrl">Ignored for browser-instance settings to avoid client-enabling full URL disclosure.</param>
/// <param name="CacheDuration">Ignored for browser-instance settings; server defaults remain authoritative.</param>
sealed record ExternalProviderSettings(
    bool Enabled,
    string? Endpoint,
    string? ApiKey,
    bool AllowFullUrl,
    TimeSpan? CacheDuration)
{
    /// <summary>
    /// Converts runtime provider options into a safe response that strips API keys and endpoints from public clients.
    /// </summary>
    /// <param name="options">Provider options.</param>
    /// <returns>Client-safe provider settings.</returns>
    public static ExternalProviderSettings From(ExternalProviderOptions options) =>
        new(options.Enabled, null, null, false, options.CacheDuration);
}

/// <summary>
/// Request used to check whether a domain has published the expected HIP DNS TXT verification record.
/// </summary>
/// <param name="Domain">Domain to verify, such as example.com.</param>
/// <param name="ExpectedToken">Raw HIP verification token expected at _hip.{domain}; this value is never returned.</param>
sealed record DomainVerificationCheckApiRequest(string Domain, string ExpectedToken);

/// <summary>
/// Public-safe response for a HIP DNS TXT verification check.
/// </summary>
/// <param name="Domain">Normalized domain that was checked.</param>
/// <param name="RecordName">DNS record name queried by HIP.</param>
/// <param name="Status">Verification status: NotConfigured, PendingVerification, Verified, or Invalid.</param>
/// <param name="CheckedAtUtc">UTC time when HIP performed the check.</param>
/// <param name="Message">Plain-English explanation that does not expose the expected token.</param>
sealed record DomainVerificationCheckApiResponse(
    string Domain,
    string RecordName,
    string Status,
    DateTimeOffset CheckedAtUtc,
    string Message)
{
    /// <summary>
    /// Converts the application-layer verification result into an API response that omits secrets.
    /// </summary>
    /// <param name="result">Domain verification result returned by the application service.</param>
    /// <returns>Public-safe API response.</returns>
    public static DomainVerificationCheckApiResponse FromResult(DomainVerificationCheckResult result) =>
        new(result.Domain, result.RecordName, result.Status.ToString(), result.CheckedAtUtc, result.Message);
}

/// <summary>
/// Bounded raw request body supplied to strict trust receipt verification.
/// </summary>
/// <param name="Utf8Receipt">Exact submitted UTF-8 bytes when the body is within the protocol limit.</param>
/// <param name="IsTooLarge">Whether the body exceeded the protocol's maximum receipt size.</param>
readonly record struct HipTrustReceiptRequestBody(
    ReadOnlyMemory<byte> Utf8Receipt,
    bool IsTooLarge);

/// <summary>
/// Public-safe verification result for a signed HIP trust receipt.
/// </summary>
/// <param name="Status">Typed verification status.</param>
/// <param name="IsVerified">Whether origin and integrity verification succeeded.</param>
/// <param name="EstablishesSafetyOrReputationBySignatureAlone">Always false because a signature does not itself prove safety.</param>
/// <param name="VerifiedIssuerId">Verified issuer identifier on success.</param>
/// <param name="VerifiedKeyId">Verified signing key identifier on success.</param>
sealed record HipTrustReceiptVerificationApiResponse(
    string Status,
    bool IsVerified,
    bool EstablishesSafetyOrReputationBySignatureAlone,
    string? VerifiedIssuerId,
    string? VerifiedKeyId)
{
    /// <summary>
    /// Converts the application result without exposing receipt contents or internal verification details.
    /// </summary>
    /// <param name="result">Application-layer verification result.</param>
    /// <returns>Stable API response.</returns>
    public static HipTrustReceiptVerificationApiResponse FromResult(
        HipTrustReceiptVerificationResult result) => new(
        result.Status.ToString(),
        result.IsVerified,
        result.EstablishesSafetyOrReputationBySignatureAlone,
        result.VerifiedIssuerId,
        result.VerifiedKeyId);
}

/// <summary>
/// Safe API root response shown in Swagger and returned from the local service root.
/// </summary>
/// <param name="Service">Service name.</param>
/// <param name="Status">Current service status.</param>
/// <param name="Version">Local API version string.</param>
/// <param name="Health">Health endpoint path.</param>
/// <param name="OpenApi">OpenAPI document path when exposed in Development.</param>
/// <param name="Swagger">Swagger UI path when exposed in Development.</param>
sealed record ApiServiceInfoResponse(
    string Service,
    string Status,
    string Version,
    string Health,
    string? OpenApi,
    string? Swagger);

/// <summary>
/// Consistent error response used by documented HIP API endpoints.
/// </summary>
/// <param name="Error">Public-safe error message suitable for local development and client diagnostics.</param>
sealed record ApiErrorResponse(string Error);

/// <summary>
/// Marker type used by integration tests to boot the standalone HIP API service.
/// </summary>
public partial class ApiServiceProgram;
