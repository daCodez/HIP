using HIP.ApiService.Application.Abstractions;

namespace HIP.ApiService.Features.Admin;

/// <summary>
/// Represents a publicly visible API member.
/// </summary>
public static class SecurityEndpoints
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="endpoints">The endpoints value used by this operation.</param>
    /// <returns>The operation result.</returns>
    public static IEndpointRouteBuilder MapSecurityEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/admin/security-status", async (HttpContext httpContext, ISecurityEventCounter counter, IHipEnvelopeVerifier envelopeVerifier, IIdentityService identityService, IReputationService reputationService, CancellationToken cancellationToken) =>
            {
                var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
                if (gate is not null)
                {
                    return gate;
                }

                return Results.Ok(counter.Snapshot());
            })
            .RequireRateLimiting("read-api")
            .WithName("GetSecurityStatus")
            .WithTags("Admin")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/admin/security-events", async (HttpContext httpContext, int? take, ISecurityRejectLog rejectLog, IHipEnvelopeVerifier envelopeVerifier, IIdentityService identityService, IReputationService reputationService, CancellationToken cancellationToken) =>
            {
                var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
                if (gate is not null)
                {
                    return gate;
                }

                var count = Math.Clamp(take ?? 10, 1, 100);
                return Results.Ok(rejectLog.Recent(count));
            })
            .RequireRateLimiting("read-api")
            .WithName("GetSecurityEvents")
            .WithTags("Admin")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        return endpoints;
    }
}
