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

        endpoints.MapPost("/api/jarvis/token/issue", (JarvisTokenIssueRequestDto request, IJarvisTokenService tokenService) =>
            {
                var tokenSet = tokenService.Issue(new TokenIssueRequest(request.IdentityId, request.Audience, request.DeviceId));
                HipTelemetry.Record("jarvis.token.issue", "ok", 0);
                return Results.Ok(tokenSet);
            })
            .RequireRateLimiting("read-api")
            .WithName("IssueJarvisToken")
            .WithTags("Jarvis");

        endpoints.MapPost("/api/jarvis/token/validate", (JarvisTokenValidateRequestDto request, IJarvisTokenService tokenService) =>
            {
                var result = tokenService.Validate(new TokenValidationRequest(request.AccessToken, request.Audience, request.DeviceId));
                HipTelemetry.Record("jarvis.token.validate", result.Reason, 0);
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithName("ValidateJarvisToken")
            .WithTags("Jarvis");

        endpoints.MapPost("/api/jarvis/token/refresh", (JarvisTokenRefreshRequestDto request, IJarvisTokenService tokenService) =>
            {
                var result = tokenService.Refresh(new TokenRefreshRequest(request.RefreshToken));
                HipTelemetry.Record("jarvis.token.refresh", result.Reason, 0);
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithName("RefreshJarvisToken")
            .WithTags("Jarvis");

        endpoints.MapPost("/api/jarvis/token/revoke", (JarvisTokenRevokeRequestDto request, IJarvisTokenService tokenService) =>
            {
                var result = tokenService.Revoke(new TokenRevokeRequest(request.AccessToken, request.RefreshToken, request.IdentityId));
                HipTelemetry.Record("jarvis.token.revoke", result.Reason, 0);
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithName("RevokeJarvisToken")
            .WithTags("Jarvis");

        endpoints.MapPost("/api/jarvis/proof/issue", (JarvisProofTokenIssueRequestDto request, IJarvisTokenService tokenService) =>
            {
                var ttl = request.TtlSeconds is > 0 ? TimeSpan.FromSeconds(request.TtlSeconds.Value) : (TimeSpan?)null;
                var result = tokenService.IssueProofToken(new ProofTokenIssueRequest(request.IdentityId, request.Audience, request.DeviceId, request.Action, ttl));
                HipTelemetry.Record("jarvis.proof.issue", result.Reason, 0);
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithName("IssueJarvisProofToken")
            .WithTags("Jarvis");

        endpoints.MapPost("/api/jarvis/proof/consume", (JarvisProofTokenConsumeRequestDto request, IJarvisTokenService tokenService) =>
            {
                var result = tokenService.ConsumeProofToken(new ProofTokenConsumeRequest(request.ProofToken, request.ExpectedAction, request.Audience, request.DeviceId));
                HipTelemetry.Record("jarvis.proof.consume", result.Reason, 0);
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithName("ConsumeJarvisProofToken")
            .WithTags("Jarvis");

        return endpoints;
    }
}
