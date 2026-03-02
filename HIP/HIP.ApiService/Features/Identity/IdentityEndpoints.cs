using System.Text.RegularExpressions;
using HIP.ApiService.Application.Abstractions;
using MediatR;

namespace HIP.ApiService.Features.Identity;

/// <summary>
/// Endpoint registration for identity lookup routes.
/// </summary>
public static partial class IdentityEndpoints
{
    // Restrict route id shape to reduce malformed input and basic enumeration noise.
    [GeneratedRegex("^[a-zA-Z0-9_-]{1,64}$", RegexOptions.Compiled)]
    private static partial Regex IdentityIdPattern();

    /// <summary>
    /// Maps identity read endpoints.
    /// </summary>
    /// <param name="endpoints">Endpoint route builder from the host pipeline.</param>
    /// <returns>The same route builder for fluent mapping composition.</returns>
    public static IEndpointRouteBuilder MapIdentityEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/identity/{id}", async (HttpContext httpContext, string id, IHipEnvelopeVerifier envelopeVerifier, ISender sender, CancellationToken cancellationToken) =>
            {
                // Enforce signed-envelope verification when policy requires it.
                var verification = await envelopeVerifier.VerifyIfRequiredAsync(httpContext, cancellationToken);
                if (!verification.IsValid) return Results.Json(new { code = verification.Code, reason = verification.Reason }, statusCode: verification.StatusCode);

                if (string.IsNullOrWhiteSpace(id) || !IdentityIdPattern().IsMatch(id)) return Results.BadRequest(); // validation + endpoint guard

                var identity = await sender.Send(new GetIdentityQuery(id), cancellationToken); // CQRS + performance awareness
                return identity is null
                    ? Results.NotFound()
                    : Results.Ok(identity); // security awareness: placeholder data only
            })
            .RequireRateLimiting("identity-read")
            .WithName("GetIdentity")
            .WithTags("Identity")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status429TooManyRequests);

        return endpoints;
    }
}
