using System.Text.RegularExpressions;
using HIP.ApiService.Application.Abstractions;
using MediatR;

namespace HIP.ApiService.Features.Identity;

public static partial class IdentityEndpoints
{
    [GeneratedRegex("^[a-zA-Z0-9_-]{1,64}$", RegexOptions.Compiled)]
    private static partial Regex IdentityIdPattern();

    public static IEndpointRouteBuilder MapIdentityEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/identity/{id}", async (HttpContext httpContext, string id, IHipEnvelopeVerifier envelopeVerifier, ISender sender, CancellationToken cancellationToken) =>
            {
                var verification = await envelopeVerifier.VerifyIfRequiredAsync(httpContext, cancellationToken);
                if (!verification.IsValid) return Results.Json(new { code = verification.Code, reason = verification.Reason }, statusCode: verification.StatusCode);

                if (string.IsNullOrWhiteSpace(id) || !IdentityIdPattern().IsMatch(id)) return Results.BadRequest(); // validation + endpoint guard

                var identity = await sender.Send(new GetIdentityQuery(id), cancellationToken); // CQRS + performance awareness
                return identity is null
                    ? Results.NotFound()
                    : Results.Ok(identity); // security awareness: placeholder data only
            })
            .RequireRateLimiting("read-api")
            .WithName("GetIdentity")
            .WithTags("Identity")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status429TooManyRequests);

        return endpoints;
    }
}
