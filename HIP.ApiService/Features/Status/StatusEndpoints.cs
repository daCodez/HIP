using MediatR;

namespace HIP.ApiService.Features.Status;

public static class StatusEndpoints
{
    public static IEndpointRouteBuilder MapStatusEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints); // validation

        endpoints.MapGet("/api/status", async (ISender sender, CancellationToken cancellationToken) =>
            {
                var response = await sender.Send(new GetStatusQuery(), cancellationToken); // performance awareness: cancellation supported
                return Results.Ok(response); // security awareness: fixed payload only, no user secrets
            })
            .WithName("GetStatus")
            .WithTags("Status")
            .Produces<StatusResponse>(StatusCodes.Status200OK);

        return endpoints;
    }
}
