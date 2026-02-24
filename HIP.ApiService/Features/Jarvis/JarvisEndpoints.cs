using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Application.Contracts;
using MediatR;

namespace HIP.ApiService.Features.Jarvis;

public static class JarvisEndpoints
{
    public static IEndpointRouteBuilder MapJarvisEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/jarvis/context/{identityId}", async (string identityId, ISender sender, CancellationToken cancellationToken) =>
            {
                var result = await sender.Send(new GetJarvisTrustContextQuery(identityId), cancellationToken);
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithName("GetJarvisTrustContext")
            .WithTags("Jarvis")
            .Produces<JarvisTrustContextDto>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/jarvis/tool-access", async (JarvisToolAccessRequestDto request, ISender sender, CancellationToken cancellationToken) =>
            {
                var result = await sender.Send(new EvaluateJarvisToolAccessCommand(request), cancellationToken);
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithName("EvaluateJarvisToolAccess")
            .WithTags("Jarvis")
            .Produces<JarvisToolAccessResultDto>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/jarvis/policy/evaluate", async (JarvisPolicyEvaluationRequestDto request, ISender sender, CancellationToken cancellationToken) =>
            {
                var result = await sender.Send(new EvaluateJarvisPolicyCommand(request), cancellationToken);
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithName("EvaluateJarvisPolicy")
            .WithTags("Jarvis")
            .Produces<JarvisPolicyEvaluationResultDto>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/jarvis/token/issue", (JarvisTokenIssueRequestDto request, IJarvisTokenService tokenService) =>
            {
                var tokenSet = tokenService.Issue(request.IdentityId);
                return Results.Ok(tokenSet);
            })
            .RequireRateLimiting("read-api")
            .WithName("IssueJarvisToken")
            .WithTags("Jarvis");

        endpoints.MapPost("/api/jarvis/token/validate", (JarvisTokenValidateRequestDto request, IJarvisTokenService tokenService) =>
            {
                var result = tokenService.Validate(request.AccessToken);
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithName("ValidateJarvisToken")
            .WithTags("Jarvis");

        endpoints.MapPost("/api/jarvis/token/refresh", (JarvisTokenRefreshRequestDto request, IJarvisTokenService tokenService) =>
            {
                var result = tokenService.Refresh(request.RefreshToken);
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithName("RefreshJarvisToken")
            .WithTags("Jarvis");

        return endpoints;
    }
}
