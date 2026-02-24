using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Application.Audit;
using System.Diagnostics;
using HIP.ApiService.Application.Contracts;
using HIP.ApiService.Observability;
using MediatR;

namespace HIP.ApiService.Features.Reputation;

public sealed class GetReputationHandler(IReputationService reputationService, IAuditTrail auditTrail, ILogger<GetReputationHandler> logger)
    : IRequestHandler<GetReputationQuery, ReputationDto>
{
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

        await auditTrail.AppendAsync(
            new AuditEvent(
                Id: Guid.NewGuid().ToString("n"),
                CreatedAtUtc: DateTimeOffset.UtcNow,
                EventType: "reputation.read",
                Subject: request.IdentityId,
                Source: "api",
                Detail: "ok"),
            cancellationToken);

        stopwatch.Stop();
        HipTelemetry.Record("reputation.read", "ok", stopwatch.Elapsed.TotalMilliseconds);
        return result;
    }
}
