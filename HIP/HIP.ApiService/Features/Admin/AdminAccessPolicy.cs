using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Options;
using Microsoft.Extensions.Options;

namespace HIP.ApiService.Features.Admin;

/// <summary>
/// Represents a publicly visible API member.
/// </summary>
public static class AdminAccessPolicy
{
    /// <summary>
    /// Executes read-level admin authorization (Support/Admin).
    /// </summary>
    /// <returns>The operation result.</returns>
    public static async Task<IResult?> AuthorizeReadAsync(
        HttpContext httpContext,
        IHipEnvelopeVerifier envelopeVerifier,
        IIdentityService identityService,
        IReputationService reputationService,
        CancellationToken cancellationToken)
    {
        var authOptions = httpContext.RequestServices.GetRequiredService<IOptions<AdminApiAuthOptions>>().Value;

        // OIDC/JWT mode: rely on normalized app:role claims and authorization policies.
        if (authOptions.EnableOidcJwt)
        {
            if (httpContext.User.Identity?.IsAuthenticated != true)
            {
                return Results.Json(new { code = "policy.unauthenticated", reason = "authentication required" }, statusCode: StatusCodes.Status401Unauthorized);
            }

            var roles = httpContext.User.FindAll("app:role").Select(c => c.Value).ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (!roles.Contains("Admin") && !roles.Contains("Support"))
            {
                return Results.Json(new { code = "policy.adminDenied", reason = "requires Admin or Support role" }, statusCode: StatusCodes.Status403Forbidden);
            }

            return null;
        }

        // Legacy mode: keep envelope + identity/reputation checks for existing clients.
        var verification = await envelopeVerifier.VerifyIfRequiredAsync(httpContext, cancellationToken);
        if (!verification.IsValid)
        {
            return Results.Json(new { code = verification.Code, reason = verification.Reason }, statusCode: verification.StatusCode);
        }

        var identityId = ResolveIdentityId(httpContext);
        if (string.IsNullOrWhiteSpace(identityId))
        {
            return Results.Json(new { code = "policy.identityMissing", reason = "identity is required" }, statusCode: StatusCodes.Status400BadRequest);
        }

        var identity = await identityService.GetByIdAsync(identityId, cancellationToken);
        if (identity is null)
        {
            return Results.Json(new { code = "policy.adminDenied", reason = "identity_not_found" }, statusCode: StatusCodes.Status403Forbidden);
        }

        if (string.Equals(identityId, "hip-system", StringComparison.OrdinalIgnoreCase))
        {
            return null; // bootstrap/admin identity always allowed for console operations
        }

        var score = await reputationService.GetScoreAsync(identityId, cancellationToken);
        if (score < 40)
        {
            return Results.Json(new { code = "policy.lowReputation", reason = "admin read requires score >= 40", score }, statusCode: StatusCodes.Status403Forbidden);
        }

        return null;
    }

    /// <summary>
    /// Executes write-level admin authorization (Admin only).
    /// </summary>
    /// <returns>The operation result.</returns>
    public static async Task<IResult?> AuthorizeWriteAsync(
        HttpContext httpContext,
        IHipEnvelopeVerifier envelopeVerifier,
        IIdentityService identityService,
        IReputationService reputationService,
        CancellationToken cancellationToken)
    {
        var authOptions = httpContext.RequestServices.GetRequiredService<IOptions<AdminApiAuthOptions>>().Value;

        if (authOptions.EnableOidcJwt)
        {
            if (httpContext.User.Identity?.IsAuthenticated != true)
            {
                return Results.Json(new { code = "policy.unauthenticated", reason = "authentication required" }, statusCode: StatusCodes.Status401Unauthorized);
            }

            var roles = httpContext.User.FindAll("app:role").Select(c => c.Value).ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (!roles.Contains("Admin"))
            {
                return Results.Json(new { code = "policy.adminDenied", reason = "requires Admin role" }, statusCode: StatusCodes.Status403Forbidden);
            }

            return null;
        }

        // Legacy mode write safety: only allow bootstrap admin identity for mutating actions.
        var readGate = await AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
        if (readGate is not null)
        {
            return readGate;
        }

        var identityId = ResolveIdentityId(httpContext);
        if (!string.Equals(identityId, "hip-system", StringComparison.OrdinalIgnoreCase))
        {
            return Results.Json(new { code = "policy.adminDenied", reason = "legacy write access requires hip-system identity" }, statusCode: StatusCodes.Status403Forbidden);
        }

        return null;
    }

    private static string? ResolveIdentityId(HttpContext httpContext)
    {
        if (httpContext.Request.Headers.TryGetValue("x-hip-identity", out var header) && !string.IsNullOrWhiteSpace(header))
        {
            return header.ToString();
        }

        if (httpContext.Request.Query.TryGetValue("identityId", out var query) && !string.IsNullOrWhiteSpace(query))
        {
            return query.ToString();
        }

        return "hip-system";
    }
}
