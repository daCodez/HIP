using HIP.ApiService.Application.Abstractions;
using HIP.Audit.Abstractions;
using HIP.Audit.Models;
using System.Diagnostics;
using HIP.ApiService.Application.Contracts;
using HIP.ApiService.Observability;
using MediatR;

namespace HIP.ApiService.Features.Identity;

/// <summary>
/// Executes the operation for this public API member.
/// </summary>
/// <param name="identityService">The identityService value used by this operation.</param>
/// <param name="auditTrail">The auditTrail value used by this operation.</param>
/// <param name="logger">The logger value used by this operation.</param>
/// <returns>The operation result.</returns>
public sealed class GetIdentityHandler(IIdentityService identityService, IAuditTrail auditTrail, ILogger<GetIdentityHandler> logger)
    : IRequestHandler<GetIdentityQuery, IdentityDto?>
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="request">The request value used by this operation.</param>
    /// <param name="cancellationToken">The cancellationToken value used by this operation.</param>
    /// <returns>The operation result.</returns>
    public async Task<IdentityDto?> Handle(GetIdentityQuery request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request); // validation

        using var _ = logger.BeginScope(new Dictionary<string, object>
        {
            ["eventType"] = "identity.read",
            ["identityId"] = request.Id
        });

        var stopwatch = Stopwatch.StartNew();
        logger.LogInformation("Handling identity query for {IdentityId}", request.Id); // logging without secrets

        var result = await identityService.GetByIdAsync(request.Id, cancellationToken); // performance awareness: async + cancellation
        var auditResult = result is null ? "not-found" : "ok";

        await auditTrail.AppendAsync(
            new AuditEvent(
                Id: Guid.NewGuid().ToString("n"),
                CreatedAtUtc: DateTimeOffset.UtcNow,
                EventType: "identity.read",
                Subject: request.Id,
                Source: "api",
                Detail: auditResult,
                Category: "api",
                Outcome: result is null ? "not_found" : "success",
                ReasonCode: auditResult,
                CorrelationId: Activity.Current?.TraceId.ToString(),
                LatencyMs: stopwatch.Elapsed.TotalMilliseconds),
            cancellationToken);

        stopwatch.Stop();
        HipTelemetry.Record("identity.read", auditResult, stopwatch.Elapsed.TotalMilliseconds);
        return result;
    }
}
