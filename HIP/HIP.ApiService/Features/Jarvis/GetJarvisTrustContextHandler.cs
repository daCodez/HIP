using HIP.ApiService.Application.Abstractions;
using HIP.Audit.Abstractions;
using HIP.Audit.Models;
using HIP.ApiService.Application.Contracts;
using HIP.ApiService.Observability;
using MediatR;
using System.Diagnostics;

namespace HIP.ApiService.Features.Jarvis;

/// <summary>
/// Executes the operation for this public API member.
/// </summary>
/// <returns>The operation result.</returns>
public sealed class GetJarvisTrustContextHandler(
    IIdentityService identityService,
    IReputationService reputationService,
    IAuditTrail auditTrail,
    ILogger<GetJarvisTrustContextHandler> logger) : IRequestHandler<GetJarvisTrustContextQuery, JarvisTrustContextDto>
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="request">The request value used by this operation.</param>
    /// <param name="cancellationToken">The cancellationToken value used by this operation.</param>
    /// <returns>The operation result.</returns>
    public async Task<JarvisTrustContextDto> Handle(GetJarvisTrustContextQuery request, CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        var identity = await identityService.GetByIdAsync(request.IdentityId, cancellationToken);
        var score = await reputationService.GetScoreAsync(request.IdentityId, cancellationToken);

        var trustLevel = score >= 80 ? "high" : score >= 50 ? "medium" : "low";
        var canUseSensitiveTools = identity is not null && score >= 70;
        var memoryRoute = trustLevel == "high" ? "trusted" : "constrained";

        var dto = new JarvisTrustContextDto(
            request.IdentityId,
            identity is not null,
            score,
            trustLevel,
            canUseSensitiveTools,
            memoryRoute);

        await auditTrail.AppendAsync(new AuditEvent(
            Id: Guid.NewGuid().ToString("n"),
            CreatedAtUtc: DateTimeOffset.UtcNow,
            EventType: "jarvis.context.read",
            Subject: request.IdentityId,
            Source: "api",
            Detail: trustLevel), cancellationToken);

        sw.Stop();
        HipTelemetry.Record("jarvis.context.read", trustLevel, sw.Elapsed.TotalMilliseconds);
        logger.LogInformation("Jarvis trust context evaluated for {IdentityId}: trust={TrustLevel}, score={Score}", request.IdentityId, trustLevel, score);

        return dto;
    }
}