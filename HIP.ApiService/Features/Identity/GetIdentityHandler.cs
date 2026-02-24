using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Application.Audit;
using System.Diagnostics;
using HIP.ApiService.Application.Contracts;
using HIP.ApiService.Observability;
using MediatR;

namespace HIP.ApiService.Features.Identity;

public sealed class GetIdentityHandler(IIdentityService identityService, IAuditTrail auditTrail, ILogger<GetIdentityHandler> logger)
    : IRequestHandler<GetIdentityQuery, IdentityDto?>
{
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
                Detail: auditResult),
            cancellationToken);

        stopwatch.Stop();
        HipTelemetry.Record("identity.read", auditResult, stopwatch.Elapsed.TotalMilliseconds);
        return result;
    }
}
