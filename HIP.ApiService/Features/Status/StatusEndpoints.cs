using MediatR;

namespace HIP.ApiService.Features.Status;

/// <summary>
/// Endpoint registration for service status/health metadata routes.
/// </summary>
public static class StatusEndpoints
{
    /// <summary>
    /// Maps the status endpoint used by internal checks and SDK callers.
    /// </summary>
    /// <param name="endpoints">Endpoint route builder from the host pipeline.</param>
    /// <returns>The same route builder for fluent mapping composition.</returns>
    public static IEndpointRouteBuilder MapStatusEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints); // validation

        endpoints.MapGet("/api/status", async (ISender sender, CancellationToken cancellationToken) =>
            {
                // Use MediatR query path so status behavior stays testable and composable.
                var response = await sender.Send(new GetStatusQuery(), cancellationToken); // performance awareness: cancellation supported
                return Results.Ok(response); // security awareness: fixed payload only, no user secrets
            })
            .RequireRateLimiting("read-api")
            .WithName("GetStatus")
            .WithTags("Status")
            .Produces<StatusResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        return endpoints;
    }
}
