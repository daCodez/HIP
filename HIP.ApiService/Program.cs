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
using HIP.Plugins.Abstractions.Contracts;
using HIP.Plugins.Sample;
using HIP.ApiService.Features.Status;
using HIP.ApiService.Features.Identity;
using HIP.ApiService.Features.Reputation;
using HIP.ApiService.Features.Admin;
using HIP.ApiService.Features.Messages;
using HIP.ApiService.Features.Jarvis;
using HIP.ApiService.Observability;
using HIP.ServiceDefaults;
using MediatR;
using HIP.ApiService;
using Microsoft.EntityFrameworkCore;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = 512 * 1024; // global safety net: 512 KB
});
builder.AddServiceDefaults();

builder.Services.Configure<CryptoProviderOptions>(builder.Configuration.GetSection(CryptoProviderOptions.SectionName)); // validation/security awareness: options bind from env/config only

var cryptoOptions = builder.Configuration
    .GetSection(CryptoProviderOptions.SectionName)
    .Get<CryptoProviderOptions>() ?? new CryptoProviderOptions();

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

builder.Services.AddLogging(); // performance awareness: central logging pipeline
builder.Services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(typeof(Program).Assembly));
builder.Services.AddValidatorsFromAssembly(typeof(Program).Assembly);
builder.Services.AddTransient(typeof(IPipelineBehavior<,>), typeof(ValidationBehavior<,>));

var connectionString = builder.Configuration.GetConnectionString("Hip")
    ?? "Data Source=hip.db";

builder.Services.AddDbContext<HipDbContext>(options =>
    options.UseSqlite(connectionString));

builder.Services.AddScoped<IIdentityService, InMemoryIdentityService>();
builder.Services.AddScoped<IReputationService, DatabaseReputationService>();
builder.Services.AddSingleton<ISecurityEventCounter, InMemorySecurityEventCounter>();
builder.Services.AddSingleton<ISecurityRejectLog, InMemorySecurityRejectLog>();
builder.Services.AddScoped<IReplayProtectionService, InMemoryReplayProtectionService>();
builder.Services.AddScoped<IHipEnvelopeVerifier, HipEnvelopeVerifier>();
builder.Services.AddSingleton<IReplayAssessmentService, InMemoryReplayAssessmentService>();
builder.Services.AddSingleton<IKeyRotationPolicy, InMemoryKeyRotationPolicy>();
builder.Services.AddScoped<IJarvisTokenService, InMemoryJarvisTokenService>();
builder.Services.AddScoped<IMessageSignatureService, EcdsaMessageSignatureService>();

builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler(_ => { });

var pluginRegistry = new HipPluginRegistry();
builder.Services.AddSingleton<IHipPluginRegistry>(pluginRegistry);

// Core plugin: always provide the durable default audit sink.
pluginRegistry.Register(new AuditDatabasePlugin());

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
builder.Services.AddSwaggerGen();

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

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
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
}

var runtimePluginRegistry = app.Services.GetRequiredService<IHipPluginRegistry>();
app.MapGet("/api/plugins", () => Results.Ok(runtimePluginRegistry.Manifests))
    .WithName("GetPlugins")
    .WithTags("Plugins")
    .Produces(StatusCodes.Status200OK);

app.MapGet("/api/plugins/nav", () =>
    {
        var nav = runtimePluginRegistry.Manifests
            .SelectMany(x => x.NavItems ?? Array.Empty<HipPluginNavItem>())
            .OrderBy(x => x.Order)
            .ToArray();
        return Results.Ok(nav);
    })
    .WithName("GetPluginNav")
    .WithTags("Plugins")
    .Produces(StatusCodes.Status200OK);

runtimePluginRegistry.MapEndpoints(app, app.Configuration, app.Environment);

app.MapDefaultEndpoints();

app.Run();

/// <summary>
/// Partial Program marker used by integration tests to bootstrap the API host.
/// </summary>
public partial class Program { }
