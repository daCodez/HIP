using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Infrastructure.Connectors;

namespace HIP.ApiService.Features.Admin;

/// <summary>
/// Admin endpoints for Gmail personal connector OAuth and status.
/// </summary>
public static class GmailConnectorEndpoints
{
    /// <summary>
    /// Maps Gmail connector endpoints under /api/admin/connectors/gmail/*.
    /// </summary>
    public static IEndpointRouteBuilder MapGmailConnectorEndpoints(this IEndpointRouteBuilder endpoints)
    {
        async Task<IResult> statusHandler(
            HttpContext httpContext,
            GmailConnectorService connector,
            IHipEnvelopeVerifier envelopeVerifier,
            IIdentityService identityService,
            IReputationService reputationService,
            CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null)
            {
                return gate;
            }

            var status = await connector.GetStatusAsync(cancellationToken);
            return Results.Ok(status);
        }

        async Task<IResult> startHandler(
            HttpContext httpContext,
            GmailConnectorService connector,
            IHipEnvelopeVerifier envelopeVerifier,
            IIdentityService identityService,
            IReputationService reputationService,
            CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeWriteAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null)
            {
                return gate;
            }

            try
            {
                var url = connector.BuildAuthorizeUrl();
                return Results.Redirect(url);
            }
            catch (InvalidOperationException ex)
            {
                return Results.BadRequest(new { code = "gmail.connector.config.missing", reason = ex.Message });
            }
        }

        async Task<IResult> callbackHandler(
            string? code,
            string? state,
            string? error,
            GmailConnectorService connector,
            CancellationToken cancellationToken)
        {
            if (!string.IsNullOrWhiteSpace(error))
            {
                return Results.BadRequest(new { code = "gmail.connector.oauth.error", reason = error });
            }

            var result = await connector.CompleteOAuthAsync(code, state, cancellationToken);
            if (!result.Success)
            {
                return Results.BadRequest(new { code = "gmail.connector.oauth.failed", reason = result.Message });
            }

            return Results.Ok(new { code = "gmail.connector.oauth.connected", message = result.Message });
        }

        endpoints.MapGet("/api/admin/connectors/gmail/status", statusHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetGmailConnectorStatus")
            .WithSummary("Get Gmail connector status")
            .WithTags("Admin", "Connectors")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/admin/connectors/gmail/oauth/start", startHandler)
            .RequireRateLimiting("read-api")
            .WithName("StartGmailConnectorOAuth")
            .WithSummary("Start Gmail OAuth consent flow")
            .WithTags("Admin", "Connectors")
            .Produces(StatusCodes.Status302Found)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/admin/connectors/gmail/oauth/callback", callbackHandler)
            .RequireRateLimiting("read-api")
            .WithName("CompleteGmailConnectorOAuth")
            .WithSummary("OAuth callback endpoint for Gmail connector")
            .WithTags("Admin", "Connectors")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status429TooManyRequests);

        return endpoints;
    }
}
