using HIP.ApiService.Application.Abstractions;

namespace HIP.ApiService.Features.Admin;

public static class SecurityEndpoints
{
    public static IEndpointRouteBuilder MapSecurityEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/admin/security-status", (ISecurityEventCounter counter) =>
            {
                return Results.Ok(counter.Snapshot());
            })
            .RequireRateLimiting("read-api")
            .WithName("GetSecurityStatus")
            .WithTags("Admin")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        return endpoints;
    }
}
