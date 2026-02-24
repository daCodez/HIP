using HIP.ApiService.Application.Abstractions;

namespace HIP.ApiService.Features.Admin;

public static class AuditEndpoints
{
    public static IEndpointRouteBuilder MapAuditEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/admin/audit", async (HttpContext httpContext, int? take, IAuditTrail auditTrail, IIdentityService identityService, IReputationService reputationService, CancellationToken cancellationToken) =>
            {
                var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, identityService, reputationService, cancellationToken);
                if (gate is not null)
                {
                    return gate;
                }

                var count = Math.Clamp(take ?? 50, 1, 200); // validation + performance awareness: bounded reads
                var items = await auditTrail.RecentAsync(count, cancellationToken);
                return Results.Ok(items); // security awareness: event metadata only, no sensitive payloads
            })
            .RequireRateLimiting("read-api")
            .WithName("GetAuditEvents")
            .WithTags("Admin")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        return endpoints;
    }
}
