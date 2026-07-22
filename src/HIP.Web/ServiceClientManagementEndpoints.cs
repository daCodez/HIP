using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using HIP.Application.ServiceClients;
using HIP.Web.Security;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.RateLimiting;

namespace HIP.Web;

/// <summary>Maps the privileged, owner-bound service-client management HTTP surface.</summary>
internal static class ServiceClientManagementEndpoints
{
    public const string MutationRateLimitPolicy = "ServiceClientMutationPolicy";
    private const int MutationPermitLimit = 10;
    private const int DefaultPageSize = 25;
    private const long MaximumCreateBodyBytes = 8 * 1024;
    private const long MaximumTransitionBodyBytes = 1024;

    /// <summary>Adds the bounded actor-partitioned limiter used by service-client lifecycle mutations.</summary>
    public static void AddMutationRateLimitPolicy(RateLimiterOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.AddPolicy(MutationRateLimitPolicy, CreateMutationPartition);
    }

    /// <summary>Maps list, create, credential-rotation, and terminal-revocation endpoints.</summary>
    public static void Map(RouteGroupBuilder serviceClients)
    {
        ArgumentNullException.ThrowIfNull(serviceClients);

        serviceClients.MapGet("/", ListAsync)
            .WithName("ListAdminServiceClients")
            .WithSummary("List owner-bound service clients")
            .WithDescription(
                $"Returns a bounded page containing only public client metadata and exact domain resource grants for the principal-derived owner. " +
                $"The supported exact scopes are '{ServiceClientScopeValues.DomainVerificationCheck}' and " +
                $"'{ServiceClientScopeValues.SiteSafetyExternalEvidenceCheck}'. Authorization grants only the named operation and does not prove safety.")
            .Produces<ServiceClientManagementPageResponse>(StatusCodes.Status200OK)
            .Produces<ServiceClientManagementErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces<ServiceClientManagementErrorResponse>(StatusCodes.Status503ServiceUnavailable)
            .RequireAuthorization(AdminPolicies.CanViewServiceClients);

        serviceClients.MapPost("/", CreateAsync)
            .WithName("CreateAdminServiceClient")
            .WithSummary("Create a least-privilege service client")
            .WithDescription(
                $"Creates one owner-bound client with exactly one of '{ServiceClientScopeValues.DomainVerificationCheck}' or " +
                $"'{ServiceClientScopeValues.SiteSafetyExternalEvidenceCheck}' and one to sixteen exact domain resource grants. " +
                "The full credential is returned in a no-store one-time response only. Authorization does not prove safety or trustworthiness.")
            .Accepts<CreateServiceClientRequest>("application/json")
            .Produces<ServiceClientOneTimeCredentialResponse>(StatusCodes.Status201Created)
            .Produces<ServiceClientManagementErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces<ServiceClientManagementErrorResponse>(StatusCodes.Status409Conflict)
            .Produces(StatusCodes.Status413PayloadTooLarge)
            .Produces<ServiceClientManagementErrorResponse>(StatusCodes.Status429TooManyRequests)
            .Produces<ServiceClientManagementErrorResponse>(StatusCodes.Status503ServiceUnavailable)
            .RequireAuthorization(AdminPolicies.CanManageServiceClients)
            .RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication)
            .RequireRateLimiting(MutationRateLimitPolicy)
            .WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(MaximumCreateBodyBytes));

        serviceClients.MapPost("/{clientId}/credentials/rotate", RotateAsync)
            .WithName("RotateAdminServiceClientCredential")
            .WithSummary("Rotate a service-client credential")
            .WithDescription(
                "Atomically replaces the credential at the expected aggregate version while preserving its exact scope, exact domain grants, and expiry. " +
                "The replacement full credential is returned in a no-store one-time response only; the old credential stops authenticating. Authorization does not prove safety.")
            .Accepts<ServiceClientExpectedVersionRequest>("application/json")
            .Produces<ServiceClientOneTimeCredentialResponse>(StatusCodes.Status200OK)
            .Produces<ServiceClientManagementErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces<ServiceClientManagementErrorResponse>(StatusCodes.Status404NotFound)
            .Produces<ServiceClientManagementErrorResponse>(StatusCodes.Status409Conflict)
            .Produces<ServiceClientManagementErrorResponse>(StatusCodes.Status410Gone)
            .Produces(StatusCodes.Status413PayloadTooLarge)
            .Produces<ServiceClientManagementErrorResponse>(StatusCodes.Status429TooManyRequests)
            .Produces<ServiceClientManagementErrorResponse>(StatusCodes.Status503ServiceUnavailable)
            .RequireAuthorization(AdminPolicies.CanManageServiceClients)
            .RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication)
            .RequireRateLimiting(MutationRateLimitPolicy)
            .WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(MaximumTransitionBodyBytes));

        serviceClients.MapPost("/{clientId}/revoke", RevokeAsync)
            .WithName("RevokeAdminServiceClient")
            .WithSummary("Terminally revoke a service client")
            .WithDescription(
                "Terminally revokes only the principal-derived owner's matching client at the expected aggregate version. Unknown and cross-owner identifiers are non-disclosing. " +
                "Exact scope and domain grants remain audit facts; authorization does not prove safety.")
            .Accepts<ServiceClientExpectedVersionRequest>("application/json")
            .Produces<ServiceClientResponse>(StatusCodes.Status200OK)
            .Produces<ServiceClientManagementErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces<ServiceClientManagementErrorResponse>(StatusCodes.Status404NotFound)
            .Produces<ServiceClientManagementErrorResponse>(StatusCodes.Status409Conflict)
            .Produces(StatusCodes.Status413PayloadTooLarge)
            .Produces<ServiceClientManagementErrorResponse>(StatusCodes.Status429TooManyRequests)
            .Produces<ServiceClientManagementErrorResponse>(StatusCodes.Status503ServiceUnavailable)
            .RequireAuthorization(AdminPolicies.CanManageServiceClients)
            .RequireAuthorization(AdminPolicies.RecentPrivilegedAuthentication)
            .RequireRateLimiting(MutationRateLimitPolicy)
            .WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(MaximumTransitionBodyBytes));
    }

    private static async Task<IResult> ListAsync(
        string? cursor,
        int? limit,
        HttpContext httpContext,
        IAntiforgery antiforgery,
        IServiceClientLifecycleService lifecycle,
        CancellationToken cancellationToken)
    {
        SetNoStore(httpContext.Response);
        try
        {
            AddCookieAntiforgeryToken(httpContext, antiforgery);
            var owner = ResolveActor(httpContext);
            var result = await lifecycle.ListAsync(
                    owner,
                    cursor,
                    limit ?? DefaultPageSize,
                    cancellationToken)
                .ConfigureAwait(false);
            return result.Outcome == ServiceClientLifecycleOutcome.Succeeded
                ? Results.Ok(new ServiceClientManagementPageResponse(result.Items, result.NextCursor))
                : Failure(result.Outcome);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Unavailable();
        }
    }

    private static async Task<IResult> CreateAsync(
        CreateServiceClientRequest request,
        HttpContext httpContext,
        IAntiforgery antiforgery,
        IServiceClientLifecycleService lifecycle,
        CancellationToken cancellationToken)
    {
        SetNoStore(httpContext.Response);
        try
        {
            var antiforgeryFailure = await ValidateCookieAntiforgeryAsync(httpContext, antiforgery)
                .ConfigureAwait(false);
            if (antiforgeryFailure is not null)
            {
                return antiforgeryFailure;
            }

            var actor = ResolveActor(httpContext);
            var result = await lifecycle.CreateAsync(actor, actor, request, cancellationToken)
                .ConfigureAwait(false);
            if (result.Outcome != ServiceClientLifecycleOutcome.Succeeded || result.Registration is null)
            {
                return Failure(result.Outcome);
            }

            var response = OneTimeCredential(result.Registration);
            return Results.Json(response, statusCode: StatusCodes.Status201Created);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Unavailable();
        }
    }

    private static async Task<IResult> RotateAsync(
        string clientId,
        ServiceClientExpectedVersionRequest request,
        HttpContext httpContext,
        IAntiforgery antiforgery,
        IServiceClientLifecycleService lifecycle,
        CancellationToken cancellationToken)
    {
        SetNoStore(httpContext.Response);
        try
        {
            var antiforgeryFailure = await ValidateCookieAntiforgeryAsync(httpContext, antiforgery)
                .ConfigureAwait(false);
            if (antiforgeryFailure is not null)
            {
                return antiforgeryFailure;
            }

            var actor = ResolveActor(httpContext);
            var result = await lifecycle.RotateCredentialAsync(
                    actor,
                    actor,
                    clientId,
                    request.ExpectedAggregateVersion,
                    cancellationToken)
                .ConfigureAwait(false);
            return result.Outcome == ServiceClientLifecycleOutcome.Succeeded && result.Registration is not null
                ? Results.Ok(OneTimeCredential(result.Registration))
                : Failure(result.Outcome);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Unavailable();
        }
    }

    private static async Task<IResult> RevokeAsync(
        string clientId,
        ServiceClientExpectedVersionRequest request,
        HttpContext httpContext,
        IAntiforgery antiforgery,
        IServiceClientLifecycleService lifecycle,
        CancellationToken cancellationToken)
    {
        SetNoStore(httpContext.Response);
        try
        {
            var antiforgeryFailure = await ValidateCookieAntiforgeryAsync(httpContext, antiforgery)
                .ConfigureAwait(false);
            if (antiforgeryFailure is not null)
            {
                return antiforgeryFailure;
            }

            var actor = ResolveActor(httpContext);
            var result = await lifecycle.RevokeAsync(
                    actor,
                    actor,
                    clientId,
                    request.ExpectedAggregateVersion,
                    cancellationToken)
                .ConfigureAwait(false);
            return result.Outcome == ServiceClientLifecycleOutcome.Succeeded && result.Client is not null
                ? Results.Ok(result.Client)
                : Failure(result.Outcome);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Unavailable();
        }
    }

    private static ServiceClientOneTimeCredentialResponse OneTimeCredential(
        ServiceClientRegistrationResult registration) =>
        new(
            registration.Client,
            string.Concat(
                registration.Client.ClientId,
                ".",
                registration.OneTimeSecret.Reveal()));

    private static IResult Failure(ServiceClientLifecycleOutcome outcome) => outcome switch
    {
        ServiceClientLifecycleOutcome.InvalidRequest => Results.BadRequest(
            new ServiceClientManagementErrorResponse(ServiceClientLifecycleMessages.InvalidRequest)),
        ServiceClientLifecycleOutcome.NotFound => Results.NotFound(
            new ServiceClientManagementErrorResponse(ServiceClientLifecycleMessages.ResourceUnavailable)),
        ServiceClientLifecycleOutcome.Conflict => Results.Conflict(
            new ServiceClientManagementErrorResponse(ServiceClientLifecycleMessages.Conflict)),
        ServiceClientLifecycleOutcome.Expired => Results.Json(
            new ServiceClientManagementErrorResponse(ServiceClientLifecycleMessages.Expired),
            statusCode: StatusCodes.Status410Gone),
        ServiceClientLifecycleOutcome.Revoked => Results.Conflict(
            new ServiceClientManagementErrorResponse(ServiceClientLifecycleMessages.Revoked)),
        ServiceClientLifecycleOutcome.Throttled => Results.Json(
            new ServiceClientManagementErrorResponse(ServiceClientLifecycleMessages.Throttled),
            statusCode: StatusCodes.Status429TooManyRequests),
        _ => Unavailable()
    };

    private static IResult Unavailable() => Results.Json(
        new ServiceClientManagementErrorResponse(ServiceClientLifecycleMessages.Unavailable),
        statusCode: StatusCodes.Status503ServiceUnavailable);

    private static string ResolveActor(HttpContext httpContext) =>
        HipAuthenticatedIdentity.ResolveRequiredUniqueClaim(
            httpContext.User,
            HipAuthenticationClaimTypes.ActorId);

    private static async Task<IResult?> ValidateCookieAntiforgeryAsync(
        HttpContext httpContext,
        IAntiforgery antiforgery)
    {
        if (!IsSessionCookieAuthenticated(httpContext))
        {
            return null;
        }

        return await antiforgery.IsRequestValidAsync(httpContext).ConfigureAwait(false)
            ? null
            : Results.BadRequest(new ServiceClientManagementErrorResponse(
                "The antiforgery token is invalid."));
    }

    private static void AddCookieAntiforgeryToken(HttpContext httpContext, IAntiforgery antiforgery)
    {
        if (!IsSessionCookieAuthenticated(httpContext))
        {
            return;
        }

        var tokens = antiforgery.GetAndStoreTokens(httpContext);
        if (!string.IsNullOrWhiteSpace(tokens.HeaderName) && !string.IsNullOrWhiteSpace(tokens.RequestToken))
        {
            httpContext.Response.Headers[tokens.HeaderName] = tokens.RequestToken;
        }
    }

    private static bool IsSessionCookieAuthenticated(HttpContext httpContext) =>
        string.Equals(
            httpContext.Features.Get<IAuthenticateResultFeature>()
                ?.AuthenticateResult
                ?.Ticket
                ?.AuthenticationScheme,
            HipAuthenticationSchemes.SessionCookie,
            StringComparison.Ordinal);

    private static void SetNoStore(HttpResponse response)
    {
        response.Headers.CacheControl = "no-store, no-cache";
        response.Headers.Pragma = "no-cache";
    }

    private static RateLimitPartition<string> CreateMutationPartition(HttpContext httpContext)
    {
        var route = httpContext.GetEndpoint() is RouteEndpoint routeEndpoint
            ? routeEndpoint.RoutePattern.RawText
            : null;
        var routeKey = string.IsNullOrWhiteSpace(route) ? "unknown-route" : route;
        var actorKey = $"unauthenticated:{httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown-address"}";
        if (HipAuthenticatedIdentity.TryResolveUniqueClaim(
                httpContext.User,
                HipAuthenticationClaimTypes.ActorId,
                out var actor) &&
            Encoding.UTF8.GetByteCount(actor) <= 512)
        {
            actorKey = $"actor:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(actor)))}";
        }

        return RateLimitPartition.GetFixedWindowLimiter(
            $"service-client:{httpContext.Request.Method}:{routeKey}:{actorKey}",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = MutationPermitLimit,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true
            });
    }
}

/// <summary>Bounded owner-scoped list response with an opaque continuation cursor.</summary>
public sealed record ServiceClientManagementPageResponse(
    IReadOnlyList<ServiceClientResponse> Items,
    string? NextCursor);

/// <summary>One-time full credential response; this shape is never used by list operations.</summary>
public sealed record ServiceClientOneTimeCredentialResponse(
    ServiceClientResponse Client,
    string Credential)
{
    /// <inheritdoc />
    public override string ToString() => "ServiceClientOneTimeCredentialResponse { Credential = [REDACTED] }";
}

/// <summary>Untrusted optimistic-concurrency input for rotation and revocation.</summary>
public sealed record ServiceClientExpectedVersionRequest(long ExpectedAggregateVersion);

/// <summary>Stable non-sensitive management failure body.</summary>
public sealed record ServiceClientManagementErrorResponse(string Error);
