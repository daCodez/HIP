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
public sealed class EvaluateJarvisToolAccessHandler(
    IIdentityService identityService,
    IReputationService reputationService,
    IAuditTrail auditTrail,
    ILogger<EvaluateJarvisToolAccessHandler> logger) : IRequestHandler<EvaluateJarvisToolAccessCommand, JarvisToolAccessResultDto>
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="request">The request value used by this operation.</param>
    /// <param name="cancellationToken">The cancellationToken value used by this operation.</param>
    /// <returns>The operation result.</returns>
    public async Task<JarvisToolAccessResultDto> Handle(EvaluateJarvisToolAccessCommand request, CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        var identity = await identityService.GetByIdAsync(request.Request.IdentityId, cancellationToken);
        var score = await reputationService.GetScoreAsync(request.Request.IdentityId, cancellationToken);

        var requiredScore = request.Request.RiskLevel switch
        {
            "low" => 20,
            "medium" => 50,
            "high" => 80,
            _ => 101
        };

        var allowed = identity is not null && score >= requiredScore;
        var reason = identity is null
            ? "identity_not_found"
            : allowed ? "allowed" : "insufficient_reputation";

        await auditTrail.AppendAsync(new AuditEvent(
            Id: Guid.NewGuid().ToString("n"),
            CreatedAtUtc: DateTimeOffset.UtcNow,
            EventType: "jarvis.tool-access.check",
            Subject: request.Request.IdentityId,
            Source: "api",
            Detail: $"{request.Request.ToolName}:{reason}"), cancellationToken);

        sw.Stop();
        HipTelemetry.Record("jarvis.tool-access.check", reason, sw.Elapsed.TotalMilliseconds);
        logger.LogInformation("Jarvis tool access check for {IdentityId} tool {ToolName} risk {RiskLevel}: {Reason}",
            request.Request.IdentityId, request.Request.ToolName, request.Request.RiskLevel, reason);

        return new JarvisToolAccessResultDto(
            allowed,
            reason,
            score,
            requiredScore,
            request.Request.RiskLevel);
    }
}