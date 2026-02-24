using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Application.Contracts;
using HIP.ApiService.Observability;
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

        endpoints.MapPost("/api/jarvis/token/issue", async (JarvisTokenIssueRequestDto request, IJarvisTokenService tokenService, CancellationToken cancellationToken) =>
            {
                var tokenSet = await tokenService.IssueAsync(new TokenIssueRequest(request.IdentityId, request.Audience, request.DeviceId), cancellationToken);
                HipTelemetry.Record("jarvis.token.issue", "ok", 0);
                return Results.Ok(tokenSet);
            })
            .RequireRateLimiting("read-api")
            .WithName("IssueJarvisToken")
            .WithTags("Jarvis");

        endpoints.MapPost("/api/jarvis/token/validate", async (JarvisTokenValidateRequestDto request, IJarvisTokenService tokenService, CancellationToken cancellationToken) =>
            {
                var result = await tokenService.ValidateAsync(new TokenValidationRequest(request.AccessToken, request.Audience, request.DeviceId), cancellationToken);
                HipTelemetry.Record("jarvis.token.validate", result.Reason, 0);
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithName("ValidateJarvisToken")
            .WithTags("Jarvis");

        endpoints.MapPost("/api/jarvis/token/refresh", async (JarvisTokenRefreshRequestDto request, IJarvisTokenService tokenService, CancellationToken cancellationToken) =>
            {
                var result = await tokenService.RefreshAsync(new TokenRefreshRequest(request.RefreshToken), cancellationToken);
                HipTelemetry.Record("jarvis.token.refresh", result.Reason, 0);
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithName("RefreshJarvisToken")
            .WithTags("Jarvis");

        endpoints.MapPost("/api/jarvis/token/revoke", async (JarvisTokenRevokeRequestDto request, IJarvisTokenService tokenService, CancellationToken cancellationToken) =>
            {
                var result = await tokenService.RevokeAsync(new TokenRevokeRequest(request.AccessToken, request.RefreshToken, request.IdentityId), cancellationToken);
                HipTelemetry.Record("jarvis.token.revoke", result.Reason, 0);
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithName("RevokeJarvisToken")
            .WithTags("Jarvis");

        endpoints.MapPost("/api/jarvis/proof/issue", async (JarvisProofTokenIssueRequestDto request, IJarvisTokenService tokenService, CancellationToken cancellationToken) =>
            {
                var ttl = request.TtlSeconds is > 0 ? TimeSpan.FromSeconds(request.TtlSeconds.Value) : (TimeSpan?)null;
                var result = await tokenService.IssueProofTokenAsync(new ProofTokenIssueRequest(request.IdentityId, request.Audience, request.DeviceId, request.Action, ttl), cancellationToken);
                HipTelemetry.Record("jarvis.proof.issue", result.Reason, 0);
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithName("IssueJarvisProofToken")
            .WithTags("Jarvis");

        endpoints.MapPost("/api/jarvis/proof/consume", async (JarvisProofTokenConsumeRequestDto request, IJarvisTokenService tokenService, CancellationToken cancellationToken) =>
            {
                var result = await tokenService.ConsumeProofTokenAsync(new ProofTokenConsumeRequest(request.ProofToken, request.ExpectedAction, request.Audience, request.DeviceId), cancellationToken);
                HipTelemetry.Record("jarvis.proof.consume", result.Reason, 0);
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithName("ConsumeJarvisProofToken")
            .WithTags("Jarvis");

        return endpoints;
    }
}
