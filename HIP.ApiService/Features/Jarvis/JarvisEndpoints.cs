using System.Diagnostics;
using HIP.ApiService.Application.Abstractions;
using HIP.Audit.Abstractions;
using HIP.Audit.Models;
using HIP.ApiService.Application.Contracts;
using HIP.ApiService.Observability;
using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace HIP.ApiService.Features.Jarvis;

/// <summary>
/// Represents a publicly visible API member.
/// </summary>
public static class JarvisEndpoints
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="endpoints">The endpoints value used by this operation.</param>
    /// <returns>The operation result.</returns>
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
            .WithMetadata(new RequestSizeLimitAttribute(128 * 1024))
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
            .WithMetadata(new RequestSizeLimitAttribute(256 * 1024))
            .WithName("EvaluateJarvisPolicy")
            .WithTags("Jarvis")
            .Produces<JarvisPolicyEvaluationResultDto>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/jarvis/token/issue", async (HttpContext httpContext, JarvisTokenIssueRequestDto request, IJarvisTokenService tokenService, IAuditTrail auditTrail, CancellationToken cancellationToken) =>
            {
                var tokenSet = await tokenService.IssueAsync(new TokenIssueRequest(request.IdentityId, request.Audience, request.DeviceId), cancellationToken);
                HipTelemetry.Record("jarvis.token.issue", "ok", 0);
                await AppendAuditAsync(httpContext, auditTrail, "jarvis.token.issue", request.IdentityId, "success", "ok", cancellationToken);
                return Results.Ok(tokenSet);
            })
            .RequireRateLimiting("read-api")
            .WithMetadata(new RequestSizeLimitAttribute(128 * 1024))
            .WithName("IssueJarvisToken")
            .WithTags("Jarvis");

        endpoints.MapPost("/api/jarvis/token/validate", async (HttpContext httpContext, JarvisTokenValidateRequestDto request, IJarvisTokenService tokenService, IAuditTrail auditTrail, CancellationToken cancellationToken) =>
            {
                var result = await tokenService.ValidateAsync(new TokenValidationRequest(request.AccessToken, request.Audience, request.DeviceId), cancellationToken);
                HipTelemetry.Record("jarvis.token.validate", result.Reason, 0);
                await AppendAuditAsync(httpContext, auditTrail, "jarvis.token.validate", result.IdentityId ?? "unknown", result.IsValid ? "success" : "fail", result.Reason, cancellationToken);
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithMetadata(new RequestSizeLimitAttribute(256 * 1024))
            .WithName("ValidateJarvisToken")
            .WithTags("Jarvis");

        endpoints.MapPost("/api/jarvis/token/refresh", async (HttpContext httpContext, JarvisTokenRefreshRequestDto request, IJarvisTokenService tokenService, IAuditTrail auditTrail, CancellationToken cancellationToken) =>
            {
                var result = await tokenService.RefreshAsync(new TokenRefreshRequest(request.RefreshToken), cancellationToken);
                HipTelemetry.Record("jarvis.token.refresh", result.Reason, 0);
                await AppendAuditAsync(httpContext, auditTrail, "jarvis.token.refresh", "unknown", result.Success ? "success" : "fail", result.Reason, cancellationToken);
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithMetadata(new RequestSizeLimitAttribute(128 * 1024))
            .WithName("RefreshJarvisToken")
            .WithTags("Jarvis");

        endpoints.MapPost("/api/jarvis/token/revoke", async (HttpContext httpContext, JarvisTokenRevokeRequestDto request, IJarvisTokenService tokenService, IAuditTrail auditTrail, CancellationToken cancellationToken) =>
            {
                var result = await tokenService.RevokeAsync(new TokenRevokeRequest(request.AccessToken, request.RefreshToken, request.IdentityId), cancellationToken);
                HipTelemetry.Record("jarvis.token.revoke", result.Reason, 0);
                await AppendAuditAsync(httpContext, auditTrail, "jarvis.token.revoke", request.IdentityId ?? "unknown", result.Success ? "success" : "fail", result.Reason, cancellationToken);
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithMetadata(new RequestSizeLimitAttribute(128 * 1024))
            .WithName("RevokeJarvisToken")
            .WithTags("Jarvis");

        endpoints.MapPost("/api/jarvis/proof/issue", async (HttpContext httpContext, JarvisProofTokenIssueRequestDto request, IJarvisTokenService tokenService, IAuditTrail auditTrail, CancellationToken cancellationToken) =>
            {
                var ttl = request.TtlSeconds is > 0 ? TimeSpan.FromSeconds(request.TtlSeconds.Value) : (TimeSpan?)null;
                var result = await tokenService.IssueProofTokenAsync(new ProofTokenIssueRequest(request.IdentityId, request.Audience, request.DeviceId, request.Action, ttl), cancellationToken);
                HipTelemetry.Record("jarvis.proof.issue", result.Reason, 0);
                await AppendAuditAsync(httpContext, auditTrail, "jarvis.proof.issue", request.IdentityId, result.Success ? "success" : "fail", result.Reason, cancellationToken);
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithMetadata(new RequestSizeLimitAttribute(128 * 1024))
            .WithName("IssueJarvisProofToken")
            .WithTags("Jarvis");

        endpoints.MapPost("/api/jarvis/proof/consume", async (HttpContext httpContext, JarvisProofTokenConsumeRequestDto request, IJarvisTokenService tokenService, IAuditTrail auditTrail, CancellationToken cancellationToken) =>
            {
                var result = await tokenService.ConsumeProofTokenAsync(new ProofTokenConsumeRequest(request.ProofToken, request.ExpectedAction, request.Audience, request.DeviceId), cancellationToken);
                HipTelemetry.Record("jarvis.proof.consume", result.Reason, 0);
                await AppendAuditAsync(httpContext, auditTrail, "jarvis.proof.consume", result.IdentityId ?? "unknown", result.Success ? "success" : "fail", result.Reason, cancellationToken);
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithMetadata(new RequestSizeLimitAttribute(128 * 1024))
            .WithName("ConsumeJarvisProofToken")
            .WithTags("Jarvis");

        return endpoints;
    }

    private static Task AppendAuditAsync(HttpContext httpContext, IAuditTrail auditTrail, string eventType, string subject, string outcome, string reasonCode, CancellationToken cancellationToken)
        => auditTrail.AppendAsync(
            new AuditEvent(
                Id: Guid.NewGuid().ToString("n"),
                CreatedAtUtc: DateTimeOffset.UtcNow,
                EventType: eventType,
                Subject: string.IsNullOrWhiteSpace(subject) ? "unknown" : subject,
                Source: "api",
                Detail: reasonCode,
                Category: "token",
                Outcome: outcome,
                ReasonCode: reasonCode,
                Route: httpContext.Request.Path,
                CorrelationId: Activity.Current?.TraceId.ToString()),
            cancellationToken);
}
