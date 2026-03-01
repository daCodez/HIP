using HIP.ApiService.Application.Abstractions;
using HIP.Audit.Abstractions;
using HIP.Audit.Models;

namespace HIP.ApiService.Features.Admin;

/// <summary>
/// Admin endpoints for querying HIP audit trail data.
/// </summary>
public static class AuditEndpoints
{
    /// <summary>
    /// Maps audit-trail admin endpoints.
    /// </summary>
    public static IEndpointRouteBuilder MapAuditEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(
                "/api/admin/audit",
                async (
                    HttpContext httpContext,
                    int? take,
                    string? eventType,
                    string? identityId,
                    string? outcome,
                    string? reasonCode,
                    DateTimeOffset? fromUtc,
                    DateTimeOffset? toUtc,
                    IAuditTrail auditTrail,
                    IHipEnvelopeVerifier envelopeVerifier,
                    IIdentityService identityService,
                    IReputationService reputationService,
                    CancellationToken cancellationToken) =>
                {
                    var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
                    if (gate is not null)
                    {
                        return gate;
                    }

                    var query = new AuditQuery(
                        Take: Math.Clamp(take ?? 50, 1, 200),
                        EventType: eventType,
                        IdentityId: identityId,
                        Outcome: outcome,
                        ReasonCode: reasonCode,
                        FromUtc: fromUtc,
                        ToUtc: toUtc);

                    var items = await auditTrail.QueryAsync(query, cancellationToken);
                    return Results.Ok(items);
                })
            .RequireRateLimiting("read-api")
            .WithName("GetAuditEvents")
            .WithTags("Admin")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        return endpoints;
    }
}
