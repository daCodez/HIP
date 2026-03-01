using System.Security.Cryptography;
using System.Text;
using HIP.Audit.Abstractions;
using HIP.Audit.Models;
using HIP.ApiService.Infrastructure.Persistence;
using HIP.Plugins.Abstractions.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace HIP.ApiService.Infrastructure.Plugins;

/// <summary>
/// OIDC identity adapter plugin that maps external issuer/subject pairs to HIP identities.
/// </summary>
public sealed class IdentityOidcPlugin : IHipPlugin
{
    /// <inheritdoc />
    public HipPluginManifest Manifest { get; } = new(
        Id: "core.identity.oidc",
        Version: "1.0.0",
        Capabilities: ["identity.oidc.resolve", "identity.oidc.sync"],
        Description: "Maps OIDC issuer/subject claims to HIP identity records.",
        NavItems:
        [
            new HipPluginNavItem("OIDC Identity", "/api/plugins/identity/oidc/info", "fa-id-badge", 96, "identity.oidc.resolve")
        ]);

    /// <inheritdoc />
    public void ConfigureServices(IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
    }

    /// <inheritdoc />
    public void MapEndpoints(IEndpointRouteBuilder endpoints, IConfiguration configuration, IHostEnvironment environment)
    {
        endpoints.MapGet("/api/plugins/identity/oidc/info", () => Results.Ok(new
            {
                pluginId = Manifest.Id,
                version = Manifest.Version,
                supported = new[] { "resolve", "sync" }
            }))
            .WithName("GetOidcIdentityPluginInfo")
            .WithTags("Plugins")
            .Produces(StatusCodes.Status200OK);

        endpoints.MapPost("/api/plugins/identity/oidc/resolve", HandleResolveAsync)
            .RequireRateLimiting("read-api")
            .WithName("ResolveOidcIdentity")
            .WithTags("Plugins")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest);

        endpoints.MapPost("/api/plugins/identity/oidc/sync", HandleSyncAsync)
            .RequireRateLimiting("read-api")
            .WithName("SyncOidcIdentity")
            .WithTags("Plugins")
            .Produces(StatusCodes.Status202Accepted)
            .Produces(StatusCodes.Status400BadRequest);
    }

    private static async Task<IResult> HandleResolveAsync(
        OidcIdentityRequest request,
        HipDbContext db,
        IAuditTrail auditTrail,
        CancellationToken cancellationToken)
    {
        var issuer = request.Issuer?.Trim();
        var subject = request.Subject?.Trim();

        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(subject))
        {
            return Results.BadRequest(new { code = "identity.oidc.invalid", reason = "issuer and subject are required" });
        }

        var identityId = BuildIdentityId(issuer, subject);
        var exists = await db.Identities.AsNoTracking().AnyAsync(x => x.Id == identityId, cancellationToken);

        await auditTrail.AppendAsync(new AuditEvent(
            Id: Guid.NewGuid().ToString("n"),
            CreatedAtUtc: DateTimeOffset.UtcNow,
            EventType: "identity.oidc.resolve",
            Subject: identityId,
            Source: "api",
            Detail: exists ? "resolved_existing" : "resolved_missing",
            Category: "identity",
            Outcome: exists ? "found" : "not_found",
            ReasonCode: exists ? "oidc.mapped" : "oidc.notMapped"), cancellationToken);

        return Results.Ok(new
        {
            identityId,
            issuer,
            subject,
            exists,
            assurance = request.EmailVerified == true ? "high" : "medium"
        });
    }

    private static async Task<IResult> HandleSyncAsync(
        OidcIdentityRequest request,
        HipDbContext db,
        IAuditTrail auditTrail,
        CancellationToken cancellationToken)
    {
        var issuer = request.Issuer?.Trim();
        var subject = request.Subject?.Trim();

        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(subject))
        {
            return Results.BadRequest(new { code = "identity.oidc.invalid", reason = "issuer and subject are required" });
        }

        var identityId = BuildIdentityId(issuer, subject);
        var now = DateTimeOffset.UtcNow;

        var identity = await db.Identities.FirstOrDefaultAsync(x => x.Id == identityId, cancellationToken);
        if (identity is null)
        {
            identity = new IdentityRecord
            {
                Id = identityId,
                PublicKeyRef = $"oidc:{issuer}",
                CreatedAtUtc = now
            };
            db.Identities.Add(identity);
        }
        else
        {
            identity.PublicKeyRef = $"oidc:{issuer}";
        }

        await db.SaveChangesAsync(cancellationToken);

        await auditTrail.AppendAsync(new AuditEvent(
            Id: Guid.NewGuid().ToString("n"),
            CreatedAtUtc: now,
            EventType: "identity.oidc.sync",
            Subject: identityId,
            Source: "api",
            Detail: "synced",
            Category: "identity",
            Outcome: "success",
            ReasonCode: "oidc.synced"), cancellationToken);

        return Results.Accepted(value: new { synced = true, identityId, issuer, subject });
    }

    private static string BuildIdentityId(string issuer, string subject)
    {
        var data = Encoding.UTF8.GetBytes($"{issuer}|{subject}");
        var hash = SHA256.HashData(data);
        var shortId = Convert.ToHexString(hash)[..16].ToLowerInvariant();
        return $"oidc-{shortId}";
    }

    /// <summary>
    /// OIDC identity request payload.
    /// </summary>
    public sealed record OidcIdentityRequest(string Issuer, string Subject, string? Email = null, bool? EmailVerified = null);
}
