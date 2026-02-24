using FluentValidation;
using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Application.Behaviors;
using HIP.ApiService.Infrastructure.Identity;
using HIP.ApiService.Infrastructure.Reputation;
using HIP.ApiService.Infrastructure.Audit;
using HIP.ApiService.Infrastructure.Persistence;
using HIP.ApiService.Infrastructure.Security;
using HIP.ApiService.Features.Status;
using HIP.ApiService.Features.Identity;
using HIP.ApiService.Features.Reputation;
using HIP.ApiService.Features.Admin;
using HIP.ApiService.Features.Messages;
using HIP.ApiService.Features.Jarvis;
using HIP.ServiceDefaults;
using MediatR;
using HIP.ApiService;
using Microsoft.EntityFrameworkCore;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);
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
builder.Services.AddSingleton<IAuditTrail, InMemoryAuditTrail>();
builder.Services.AddSingleton<ISecurityEventCounter, InMemorySecurityEventCounter>();
builder.Services.AddSingleton<IReplayProtectionService, InMemoryReplayProtectionService>();
builder.Services.AddSingleton<IMessageSignatureService, EcdsaMessageSignatureService>();

builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler(_ => { });
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
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
app.UseRateLimiter(); // security awareness: basic abuse throttling on public reads

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.MapGet("/api/admin/crypto-config", (string? keyId, IConfiguration configuration) =>
        {
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

app.MapStatusEndpoints();
app.MapIdentityEndpoints();
app.MapReputationEndpoints();
app.MapMessageEndpoints();
app.MapJarvisEndpoints();
app.MapAuditEndpoints();
app.MapSecurityEndpoints();
app.MapDefaultEndpoints();

app.Run();

public partial class Program { }
