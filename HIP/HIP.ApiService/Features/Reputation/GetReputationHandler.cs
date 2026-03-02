using HIP.ApiService.Application.Abstractions;
using HIP.Audit.Abstractions;
using HIP.Audit.Models;
using System.Diagnostics;
using HIP.ApiService.Application.Contracts;
using HIP.ApiService.Observability;
using MediatR;

namespace HIP.ApiService.Features.Reputation;

/// <summary>
/// Executes the operation for this public API member.
/// </summary>
/// <param name="reputationService">The reputationService value used by this operation.</param>
/// <param name="auditTrail">The auditTrail value used by this operation.</param>
/// <param name="httpContextAccessor">The httpContextAccessor value used by this operation.</param>
/// <param name="logger">The logger value used by this operation.</param>
/// <returns>The operation result.</returns>
public sealed class GetReputationHandler(
    IReputationService reputationService,
    IAuditTrail auditTrail,
    IHttpContextAccessor httpContextAccessor,
    ILogger<GetReputationHandler> logger)
    : IRequestHandler<GetReputationQuery, ReputationDto>
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="request">The request value used by this operation.</param>
    /// <param name="cancellationToken">The cancellationToken value used by this operation.</param>
    /// <returns>The operation result.</returns>
    public async Task<ReputationDto> Handle(GetReputationQuery request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request); // validation

        using var _ = logger.BeginScope(new Dictionary<string, object>
        {
            ["eventType"] = "reputation.read",
            ["identityId"] = request.IdentityId
        });

        var stopwatch = Stopwatch.StartNew();
        logger.LogInformation("Handling reputation query for {IdentityId}", request.IdentityId); // logging

        var score = await reputationService.GetScoreAsync(request.IdentityId, cancellationToken); // performance awareness
        var result = new ReputationDto(request.IdentityId, score, DateTimeOffset.UtcNow); // security awareness: no secrets
        var route = httpContextAccessor.HttpContext?.Request.Path.Value;

        await auditTrail.AppendAsync(
            new AuditEvent(
                Id: Guid.NewGuid().ToString("n"),
                CreatedAtUtc: DateTimeOffset.UtcNow,
                EventType: "reputation.read",
                Subject: request.IdentityId,
                Source: "api",
                Detail: "ok",
                Category: "api",
                Outcome: "success",
                ReasonCode: "ok",
                Route: route,
                CorrelationId: Activity.Current?.TraceId.ToString(),
                LatencyMs: stopwatch.Elapsed.TotalMilliseconds),
            cancellationToken);

        stopwatch.Stop();
        HipTelemetry.Record("reputation.read", "ok", stopwatch.Elapsed.TotalMilliseconds);
        return result;
    }
}
