using FluentValidation;
using System.Diagnostics;
using HIP.ApiService.Application.Abstractions;
using HIP.Audit.Abstractions;
using HIP.Audit.Models;
using HIP.ApiService.Application.Behaviors;
using HIP.ApiService.Infrastructure.Identity;
using HIP.ApiService.Infrastructure.Reputation;
using HIP.ApiService.Infrastructure.Audit;
using HIP.ApiService.Infrastructure.Persistence;
using HIP.ApiService.Infrastructure.Security;
using HIP.ApiService.Infrastructure.Plugins;
using HIP.ApiService.Infrastructure.Connectors;
using HIP.Plugins.Abstractions.Contracts;
using HIP.Plugins.Sample;
using HIP.ApiService.Features.Status;
using HIP.ApiService.Features.Identity;
using HIP.ApiService.Features.Reputation;
using HIP.ApiService.Features.Admin;
using HIP.ApiService.Features.Messages;
using HIP.ApiService.Features.Jarvis;
using HIP.ApiService.Observability;
using HIP.ApiService.Swagger;
using HIP.ServiceDefaults;
using MediatR;
using HIP.ApiService;
using HIP.ApiService.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = 512 * 1024; // global safety net: 512 KB
});
builder.AddServiceDefaults();

builder.Services.Configure<CryptoProviderOptions>(builder.Configuration.GetSection(CryptoProviderOptions.SectionName)); // validation/security awareness: options bind from env/config only
builder.Services.Configure<AuditRetentionOptions>(builder.Configuration.GetSection(AuditRetentionOptions.SectionName));
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders =
        ForwardedHeaders.XForwardedFor |
        ForwardedHeaders.XForwardedProto;

    // Trust forwarded headers only from local reverse-proxy hops.
    options.KnownProxies.Clear();
    options.KnownProxies.Add(IPAddress.Loopback);
    options.KnownProxies.Add(IPAddress.IPv6Loopback);
    options.ForwardLimit = 1;
});

var cryptoOptions = builder.Configuration
    .GetSection(CryptoProviderOptions.SectionName)
    .Get<CryptoProviderOptions>() ?? new CryptoProviderOptions();

var policyOptions = builder.Configuration
    .GetSection(PolicyPackOptions.SectionName)
    .Get<PolicyPackOptions>() ?? new PolicyPackOptions();

var adminApiAuthOptions = builder.Configuration
    .GetSection(AdminApiAuthOptions.SectionName)
    .Get<AdminApiAuthOptions>() ?? new AdminApiAuthOptions();

if (string.Equals(cryptoOptions.Provider, "ECDsa", StringComparison.OrdinalIgnoreCase))
{
    if (string.IsNullOrWhiteSpace(cryptoOptions.PrivateKeyStorePath) ||
        !Directory.Exists(cryptoOptions.PrivateKeyStorePath))
    {
        throw new InvalidOperationException(
            $"HIP:Crypto:PrivateKeyStorePath is missing or does not exist: '{cryptoOptions.PrivateKeyStorePath ?? "<null>"}'.");
    }

    if (string.IsNullOrWhiteSpace(cryptoOptions.PublicKeyStorePath) ||
        !Directory.Exists(cryptoOptions.PublicKeyStorePath))
    {
        throw new InvalidOperationException(
            $"HIP:Crypto:PublicKeyStorePath is missing or does not exist: '{cryptoOptions.PublicKeyStorePath ?? "<null>"}'.");
    }
}

if (string.IsNullOrWhiteSpace(policyOptions.Version))
{
    throw new InvalidOperationException("HIP:Policy:Version must not be empty.");
}

if (policyOptions.LowRiskRequiredScore is < 0 or > 100 ||
    policyOptions.MediumRiskRequiredScore is < 0 or > 100 ||
    policyOptions.HighRiskRequiredScore is < 0 or > 100)
{
    throw new InvalidOperationException("HIP:Policy risk score thresholds must be within [0,100].");
}

if (policyOptions.LowRiskRequiredScore > policyOptions.MediumRiskRequiredScore ||
    policyOptions.MediumRiskRequiredScore > policyOptions.HighRiskRequiredScore)
{
    throw new InvalidOperationException("HIP:Policy thresholds must satisfy low <= medium <= high.");
}

builder.Services.AddLogging(); // performance awareness: central logging pipeline
builder.Services.AddHttpContextAccessor();
builder.Services.Configure<AdminApiAuthOptions>(builder.Configuration.GetSection(AdminApiAuthOptions.SectionName));

if (adminApiAuthOptions.EnableOidcJwt)
{
    builder.Services
        .AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.Authority = adminApiAuthOptions.Authority;
            options.Audience = adminApiAuthOptions.Audience;
            options.RequireHttpsMetadata = true;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = !string.IsNullOrWhiteSpace(adminApiAuthOptions.Audience),
                ValidateLifetime = true,
                NameClaimType = "sub",
                RoleClaimType = "app:role"
            };
        });

    builder.Services.AddTransient<IClaimsTransformation, AdminApiClaimsTransformation>();

    builder.Services.AddAuthorization(options =>
    {
        options.AddPolicy("AdminOnly", policy => policy.RequireClaim("app:role", "Admin"));
        options.AddPolicy("SupportOrAdmin", policy => policy.RequireClaim("app:role", "Admin", "Support"));
    });
}

builder.Services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(typeof(Program).Assembly));
builder.Services.AddValidatorsFromAssembly(typeof(Program).Assembly);
builder.Services.AddTransient(typeof(IPipelineBehavior<,>), typeof(ValidationBehavior<,>));

var connectionString = builder.Configuration.GetConnectionString("Hip")
    ?? "Data Source=hip.db";

builder.Services.AddDbContext<HipDbContext>(options =>
    options.UseSqlite(connectionString));

builder.Services.AddScoped<IIdentityService, DatabaseIdentityService>();
builder.Services.AddScoped<IReputationService, DatabaseReputationService>();
builder.Services.AddSingleton<PolicyRuleStore>();
builder.Services.AddSingleton<DeviceRegistrationStore>();
builder.Services.AddSingleton<AgentEnrollmentStore>();
builder.Services.AddSingleton<PolicyVersionStore>();
builder.Services.AddSingleton<AuthzPolicyStore>();
builder.Services.AddSingleton<ISecurityEventCounter, InMemorySecurityEventCounter>();
builder.Services.AddSingleton<ISecurityRejectLog, InMemorySecurityRejectLog>();
builder.Services.AddScoped<IReplayProtectionService, InMemoryReplayProtectionService>();
builder.Services.AddScoped<IHipEnvelopeVerifier, HipEnvelopeVerifier>();
builder.Services.AddSingleton<IReplayAssessmentService, InMemoryReplayAssessmentService>();
builder.Services.AddSingleton<IKeyRotationPolicy, InMemoryKeyRotationPolicy>();
builder.Services.AddScoped<IJarvisTokenService, InMemoryJarvisTokenService>();
builder.Services.AddScoped<IMessageSignatureService, EcdsaMessageSignatureService>();
builder.Services.AddHttpClient();
builder.Services.AddSingleton(GmailConnectorOptions.FromEnvironment());
builder.Services.AddSingleton<GmailTokenStore>();
builder.Services.AddScoped<GmailConnectorService>();
builder.Services.AddHostedService<GmailConnectorPoller>();

builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler(_ => { });

var pluginRegistry = new HipPluginRegistry();
builder.Services.AddSingleton<IHipPluginRegistry>(pluginRegistry);

// Core plugins: always provide default audit + policy implementations.
pluginRegistry.Register(new AuditDatabasePlugin());
pluginRegistry.Register(new PolicyDefaultPlugin());
pluginRegistry.Register(new RichardWidgetPlugin());

var enabledPlugins = (builder.Configuration.GetSection("HIP:Plugins:Enabled").Get<string[]>() ?? [])
    .Select(x => x?.Trim())
    .Where(x => !string.IsNullOrWhiteSpace(x))
    .Cast<string>()
    .ToHashSet(StringComparer.OrdinalIgnoreCase);

var autoDiscover = builder.Configuration.GetValue<bool>("HIP:Plugins:AutoDiscover");
var pluginDirectory = builder.Configuration["HIP:Plugins:Directory"];
var pluginAllowlist = (builder.Configuration.GetSection("HIP:Plugins:Allowlist").Get<string[]>() ?? [])
    .Select(x => x?.Trim())
    .Where(x => !string.IsNullOrWhiteSpace(x))
    .Cast<string>()
    .ToHashSet(StringComparer.OrdinalIgnoreCase);

if (enabledPlugins.Contains("sample"))
{
    pluginRegistry.Register(new SamplePlugin());
}

if (enabledPlugins.Contains("core.policy.strict"))
{
    pluginRegistry.Register(new PolicyStrictPlugin());
}

if (enabledPlugins.Contains("core.reputation.feedback"))
{
    pluginRegistry.Register(new ReputationFeedbackPlugin());
}

if (enabledPlugins.Contains("core.identity.oidc"))
{
    pluginRegistry.Register(new IdentityOidcPlugin());
}

if (enabledPlugins.Contains("core.metrics.system"))
{
    pluginRegistry.Register(new SystemMetricsPlugin());
}

if (enabledPlugins.Contains("core.identity.insights"))
{
    pluginRegistry.Register(new IdentityInsightsPlugin());
}

if (enabledPlugins.Contains("core.chat.insights"))
{
    pluginRegistry.Register(new ChatInsightsPlugin());
}

if (autoDiscover)
{
    var discovered = HipPluginDiscovery.Discover(pluginDirectory);
    foreach (var plugin in discovered)
    {
        if (enabledPlugins.Count > 0 && !enabledPlugins.Contains(plugin.Manifest.Id))
        {
            continue;
        }

        if (pluginAllowlist.Count > 0 && !pluginAllowlist.Contains(plugin.Manifest.Id))
        {
            continue;
        }

        if (string.IsNullOrWhiteSpace(plugin.Manifest.Id) || string.IsNullOrWhiteSpace(plugin.Manifest.Version) || plugin.Manifest.Capabilities.Count == 0)
        {
            continue;
        }

        try
        {
            pluginRegistry.Register(plugin);
        }
        catch
        {
            // Ignore duplicate/invalid plugin registrations to keep startup resilient.
        }
    }
}

pluginRegistry.ConfigureServices(builder.Services, builder.Configuration, builder.Environment);

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = async (context, cancellationToken) =>
    {
        var retryAfter = context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfterValue)
            ? retryAfterValue.TotalSeconds
            : (double?)null;

        if (retryAfter is not null)
        {
            context.HttpContext.Response.Headers.RetryAfter = Math.Ceiling(retryAfter.Value).ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        var request = context.HttpContext.Request;
        var identityId = context.HttpContext.Request.Headers.TryGetValue("x-hip-identity", out var hdr)
            ? hdr.ToString()
            : "anonymous";

        var auditTrail = context.HttpContext.RequestServices.GetService<IAuditTrail>();
        if (auditTrail is not null)
        {
            await auditTrail.AppendAsync(new AuditEvent(
                Id: Guid.NewGuid().ToString("n"),
                CreatedAtUtc: DateTimeOffset.UtcNow,
                EventType: "api.rate_limit.rejected",
                Subject: string.IsNullOrWhiteSpace(identityId) ? "anonymous" : identityId,
                Source: "api",
                Detail: "rateLimit.exceeded",
                Category: "security",
                Outcome: "throttled",
                ReasonCode: "rateLimit.exceeded",
                Route: request.Path,
                CorrelationId: Activity.Current?.TraceId.ToString()),
                cancellationToken);
        }

        await context.HttpContext.Response.WriteAsJsonAsync(new
        {
            code = "rateLimit.exceeded",
            reason = "too many requests",
            retryAfterSeconds = retryAfter
        }, cancellationToken);
    };

    options.AddPolicy("read-api", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 120,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst
            }));

    // tighter per-endpoint limits to reduce enumeration/abuse risk on identity/reputation reads
    options.AddPolicy("identity-read", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 20,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst
            }));

    options.AddPolicy("reputation-read", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 20,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst
            }));
});
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = System.IO.Path.Combine(System.AppContext.BaseDirectory, xmlFile);
    if (System.IO.File.Exists(xmlPath))
    {
        options.IncludeXmlComments(xmlPath);
    }

    options.DocumentFilter<ApiVersionDocumentFilter>();
});

var app = builder.Build();

await HipDbInitializer.InitializeAsync(app.Services, CancellationToken.None);

var insecureTransportAllowed = string.Equals(
    Environment.GetEnvironmentVariable("ASPIRE_ALLOW_UNSECURED_TRANSPORT"),
    "true",
    StringComparison.OrdinalIgnoreCase);

if (!app.Environment.IsDevelopment() && insecureTransportAllowed)
{
    throw new InvalidOperationException("ASPIRE_ALLOW_UNSECURED_TRANSPORT must be disabled outside Development.");
}

app.UseExceptionHandler(); // security awareness: prevent leaking internals
app.UseForwardedHeaders(); // honor reverse-proxy X-Forwarded-* headers for scheme/client metadata

// API versioning bridge: keep unversioned routes during migration and mark them deprecated.
app.Use(async (httpContext, next) =>
{
    var originalPath = httpContext.Request.Path.Value ?? string.Empty;

    // Set compatibility/version headers before response starts.
    if (originalPath.StartsWith("/api/v1/", StringComparison.OrdinalIgnoreCase))
    {
        httpContext.Response.Headers["X-API-Version"] = "v1";
    }

    // Temporary compatibility notice for unversioned API calls.
    if (originalPath.StartsWith("/api/", StringComparison.OrdinalIgnoreCase) && !originalPath.StartsWith("/api/v", StringComparison.OrdinalIgnoreCase))
    {
        httpContext.Response.Headers["Deprecation"] = "true";
        httpContext.Response.Headers["Sunset"] = "Tue, 30 Jun 2026 00:00:00 GMT";
        httpContext.Response.Headers["Link"] = "</api/v1>; rel=\"successor-version\"";
    }

    await next();
});

app.Use(async (httpContext, next) =>
{
    const long globalMaxBytes = 512 * 1024;

    var endpointLimitMetadata = httpContext.GetEndpoint()?
        .Metadata
        .GetMetadata<Microsoft.AspNetCore.Http.Metadata.IRequestSizeLimitMetadata>();

    long? endpointLimit = endpointLimitMetadata is null ? null : endpointLimitMetadata.MaxRequestBodySize;
    var effectiveLimit = endpointLimit ?? globalMaxBytes;
    var contentLength = httpContext.Request.ContentLength;

    if (contentLength is not null && contentLength.Value > effectiveLimit)
    {
        var routePattern = (httpContext.GetEndpoint() as Microsoft.AspNetCore.Routing.RouteEndpoint)
            ?.RoutePattern
            .RawText ?? "unknown";

        HipTelemetry.RecordHttpRequestSize(contentLength.Value, routePattern, httpContext.Request.Method, "4xx");

        httpContext.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
        await httpContext.Response.WriteAsJsonAsync(new
        {
            code = "payload.tooLarge",
            reason = "request payload exceeds configured endpoint limit"
        });
        return;
    }

    await next();
});

app.Use(async (httpContext, next) =>
{
    const int samplePercent = 20; // keep telemetry cost/noise low
    var shouldSample = Random.Shared.Next(100) < samplePercent;

    await next();

    if (!shouldSample)
    {
        return;
    }

    var routePattern = (httpContext.GetEndpoint() as Microsoft.AspNetCore.Routing.RouteEndpoint)
        ?.RoutePattern
        .RawText ?? "unknown";

    var method = httpContext.Request.Method;
    var statusClass = $"{httpContext.Response.StatusCode / 100}xx";
    var contentLength = httpContext.Request.ContentLength ?? 0;

    HipTelemetry.RecordHttpRequestSize(contentLength, routePattern, method, statusClass);
});

app.UseRateLimiter(); // security awareness: basic abuse throttling on public reads

if (adminApiAuthOptions.EnableOidcJwt)
{
    app.UseAuthentication();
    app.UseAuthorization();
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.MapGet("/", () => Results.Redirect("/swagger/index.html", permanent: false));
    app.MapGet("/api/admin/crypto-config", async (HttpContext httpContext, string? keyId, IConfiguration configuration, IHipEnvelopeVerifier envelopeVerifier, IIdentityService identityService, IReputationService reputationService, CancellationToken cancellationToken) =>
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null)
            {
                return gate;
            }

            var opts = configuration.GetSection(CryptoProviderOptions.SectionName).Get<CryptoProviderOptions>() ?? new CryptoProviderOptions();
            var resolvedKeyId = string.IsNullOrWhiteSpace(keyId) ? "hip-system" : keyId.Trim();

            var privateKeyPath = string.IsNullOrWhiteSpace(opts.PrivateKeyStorePath)
                ? null
                : Path.Combine(opts.PrivateKeyStorePath, $"{resolvedKeyId}.key");
            var publicKeyPath = string.IsNullOrWhiteSpace(opts.PublicKeyStorePath)
                ? null
                : Path.Combine(opts.PublicKeyStorePath, $"{resolvedKeyId}.pub");

            return Results.Ok(new
            {
                opts.Provider,
                opts.PrivateKeyStorePath,
                opts.PublicKeyStorePath,
                KeyId = resolvedKeyId,
                PrivateKeyPath = privateKeyPath,
                PublicKeyPath = publicKeyPath,
                PrivateKeyExists = privateKeyPath is not null && File.Exists(privateKeyPath),
                PublicKeyExists = publicKeyPath is not null && File.Exists(publicKeyPath)
            });
        })
        .RequireRateLimiting("read-api")
        .WithName("GetCryptoConfig")
        .WithTags("Admin")
        .Produces(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status429TooManyRequests);
}
else
{
    app.UseHsts();
    app.UseHttpsRedirection();
}

var exposeInternalApisSetting = builder.Configuration["HIP:ExposeInternalApis"];
var exposeInternalApis = bool.TryParse(exposeInternalApisSetting, out var parsedExposeInternal)
    ? parsedExposeInternal
    : app.Environment.IsDevelopment();

app.MapStatusEndpoints();
app.MapIdentityEndpoints();
app.MapReputationEndpoints();
app.MapMessageEndpoints();

if (exposeInternalApis)
{
    app.MapJarvisEndpoints();
    app.MapAuditEndpoints();
    app.MapSecurityEndpoints();
    app.MapPolicyEndpoints();
    app.MapAuthzPolicyEndpoints();
    app.MapGmailConnectorEndpoints();
}

var runtimePluginRegistry = app.Services.GetRequiredService<IHipPluginRegistry>();
app.MapGet("/api/plugins", () => Results.Ok(runtimePluginRegistry.Manifests))
    .RequireRateLimiting("read-api")
    .WithName("GetPlugins")
    .WithTags("Plugins")
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status429TooManyRequests);

app.MapGet("/api/plugins/nav", () =>
    {
        var nav = runtimePluginRegistry.Manifests
            .SelectMany(x => x.NavItems ?? Array.Empty<HipPluginNavItem>())
            .Where(x => string.Equals(x.Display, "page", StringComparison.OrdinalIgnoreCase))
            .OrderBy(x => x.Order)
            .ToArray();
        return Results.Ok(nav);
    })
    .RequireRateLimiting("read-api")
    .WithName("GetPluginNav")
    .WithTags("Plugins")
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status429TooManyRequests);

app.MapGet("/api/plugins/widgets", () =>
    {
        var widgets = runtimePluginRegistry.Manifests
            .SelectMany(x => x.NavItems ?? Array.Empty<HipPluginNavItem>())
            .Where(x => string.Equals(x.Display, "widget", StringComparison.OrdinalIgnoreCase))
            .OrderBy(x => x.Order)
            .ToArray();
        return Results.Ok(widgets);
    })
    .RequireRateLimiting("read-api")
    .WithName("GetPluginWidgets")
    .WithTags("Plugins")
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status429TooManyRequests);

runtimePluginRegistry.MapEndpoints(app, app.Configuration, app.Environment);

app.MapDefaultEndpoints();

app.Run();

/// <summary>
/// Partial Program marker used by integration tests to bootstrap the API host.
/// </summary>
public partial class Program { }
