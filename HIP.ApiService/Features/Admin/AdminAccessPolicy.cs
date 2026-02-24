using HIP.ApiService.Application.Abstractions;

namespace HIP.ApiService.Features.Admin;

public static class AdminAccessPolicy
{
    public static async Task<IResult?> AuthorizeReadAsync(
        HttpContext httpContext,
        IIdentityService identityService,
        IReputationService reputationService,
        CancellationToken cancellationToken)
    {
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

        var score = await reputationService.GetScoreAsync(identityId, cancellationToken);
        if (score < 40)
        {
            return Results.Json(new { code = "policy.lowReputation", reason = "admin read requires score >= 40", score }, statusCode: StatusCodes.Status403Forbidden);
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
