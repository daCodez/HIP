using System.Text.RegularExpressions;
using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Application.Contracts;
using MediatR;

namespace HIP.ApiService.Features.Reputation;

public static partial class ReputationEndpoints
{
    [GeneratedRegex("^[a-zA-Z0-9_-]{1,64}$", RegexOptions.Compiled)]
    private static partial Regex IdentityIdPattern();

    public static IEndpointRouteBuilder MapReputationEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/reputation/{identityId}", async (HttpContext httpContext, string identityId, IHipEnvelopeVerifier envelopeVerifier, ISender sender, CancellationToken cancellationToken) =>
            {
                var verification = await envelopeVerifier.VerifyIfRequiredAsync(httpContext, cancellationToken);
                if (!verification.IsValid) return Results.Json(new { code = verification.Code, reason = verification.Reason }, statusCode: verification.StatusCode);

                if (string.IsNullOrWhiteSpace(identityId) || !IdentityIdPattern().IsMatch(identityId)) return Results.BadRequest(); // validation + endpoint guard

                var result = await sender.Send(new GetReputationQuery(identityId), cancellationToken); // CQRS + performance awareness
                return Results.Ok(result); // security awareness: no secrets
            })
            .RequireRateLimiting("read-api")
            .WithName("GetReputation")
            .WithTags("Reputation")
            .Produces<ReputationDto>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status429TooManyRequests);

        return endpoints;
    }
}
