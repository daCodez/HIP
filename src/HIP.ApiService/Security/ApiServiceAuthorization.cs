using System.Globalization;
using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using HIP.Application.ServiceClients;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace HIP.ApiService.Security;

/// <summary>
/// Keeps the standalone API host's policy names aligned with the equivalent HIP.Web administrator policies.
/// </summary>
internal static class ApiServiceAdminPolicies
{
    public const string CanManageRules = nameof(CanManageRules);
    public const string CanViewAdminDashboard = nameof(CanViewAdminDashboard);
    public const string CanManageDomainVerifications = nameof(CanManageDomainVerifications);
    public const string CanCheckDomainVerification = nameof(CanCheckDomainVerification);
    public const string CanCheckExternalSiteEvidence = nameof(CanCheckExternalSiteEvidence);
    public const string RecentPrivilegedAuthentication = nameof(RecentPrivilegedAuthentication);
}

/// <summary>
/// Registers the standalone administrator and HIP-0205 service-client authentication boundaries.
/// </summary>
internal static class ApiServiceAuthorizationExtensions
{
    public static IServiceCollection AddHipApiServiceAuthorization(this IServiceCollection services)
    {
        services.AddAuthentication(options =>
        {
            options.DefaultScheme = ApiServiceAuthenticationSchemes.Router;
            options.DefaultAuthenticateScheme = ApiServiceAuthenticationSchemes.Router;
            options.DefaultChallengeScheme = ApiServiceAuthenticationSchemes.ServiceClient;
            options.DefaultForbidScheme = ApiServiceAuthenticationSchemes.Router;
        })
        .AddPolicyScheme(
            ApiServiceAuthenticationSchemes.Router,
            ApiServiceAuthenticationSchemes.Router,
            options => options.ForwardDefaultSelector = context =>
                context.Request.Headers.ContainsKey("Authorization")
                    ? ApiServiceAuthenticationSchemes.ServiceClient
                    : ApiServiceDevelopmentAuthenticationHandler.SchemeName)
        .AddScheme<AuthenticationSchemeOptions, ApiServiceClientAuthenticationHandler>(
            ApiServiceAuthenticationSchemes.ServiceClient,
            _ => { })
        .AddScheme<AuthenticationSchemeOptions, ApiServiceDevelopmentAuthenticationHandler>(
            ApiServiceDevelopmentAuthenticationHandler.SchemeName,
            _ => { });

        services.TryAddSingleton<IServiceClientCredentialGenerator, CryptographicServiceClientCredentialGenerator>();
        services.TryAddSingleton<IServiceClientSecretProtector, Pbkdf2ServiceClientSecretProtector>();
        services.TryAddSingleton<ApiServiceClientDummyVerifier>();
        services.AddSingleton<IAuthorizationHandler, ApiServicePrivilegedMfaRequirementHandler>();
        services.AddSingleton<IAuthorizationHandler, ApiServiceRecentAuthenticationRequirementHandler>();
        services.AddSingleton<IAuthorizationHandler, ApiServiceUniqueActorRequirementHandler>();
        services.AddSingleton<IAuthorizationHandler, ApiServiceScopedOperationRequirementHandler>();
        services.AddAuthorization(options =>
        {
            AddAdminPolicy(
                options,
                ApiServiceAdminPolicies.CanManageRules,
                [ApiServiceAdminRoles.Owner, ApiServiceAdminRoles.Admin]);
            AddAdminPolicy(
                options,
                ApiServiceAdminPolicies.CanViewAdminDashboard,
                [
                    ApiServiceAdminRoles.Owner,
                    ApiServiceAdminRoles.Admin,
                    ApiServiceAdminRoles.Moderator,
                    ApiServiceAdminRoles.Support,
                    ApiServiceAdminRoles.ReadOnly
                ]);
            AddAdminPolicy(
                options,
                ApiServiceAdminPolicies.CanManageDomainVerifications,
                [ApiServiceAdminRoles.Owner, ApiServiceAdminRoles.Admin]);
            AddScopedOperationPolicy(
                options,
                ApiServiceAdminPolicies.CanCheckDomainVerification,
                ServiceClientScopeValues.DomainVerificationCheck);
            AddScopedOperationPolicy(
                options,
                ApiServiceAdminPolicies.CanCheckExternalSiteEvidence,
                ServiceClientScopeValues.SiteSafetyExternalEvidenceCheck);
            AddAdminPolicy(
                options,
                ApiServiceAdminPolicies.RecentPrivilegedAuthentication,
                [ApiServiceAdminRoles.Owner, ApiServiceAdminRoles.Admin],
                new ApiServiceRecentAuthenticationRequirement());
        });

        return services;
    }

    private static void AddAdminPolicy(
        AuthorizationOptions options,
        string policyName,
        IReadOnlyCollection<string> roles,
        params IAuthorizationRequirement[] additionalRequirements)
    {
        options.AddPolicy(policyName, policy =>
        {
            policy.RequireAuthenticatedUser();
            policy.RequireRole(roles);
            policy.AddRequirements(new ApiServicePrivilegedMfaRequirement());
            policy.AddRequirements(new ApiServiceUniqueActorRequirement());
            policy.AddRequirements(additionalRequirements);
        });
    }

    private static void AddScopedOperationPolicy(
        AuthorizationOptions options,
        string policyName,
        string serviceScope)
    {
        options.AddPolicy(policyName, policy =>
        {
            policy.RequireAuthenticatedUser();
            policy.AddRequirements(new ApiServiceScopedOperationRequirement(serviceScope));
        });
    }
}

internal static class ApiServiceAdminRoles
{
    public const string Owner = nameof(Owner);
    public const string Admin = nameof(Admin);
    public const string Moderator = nameof(Moderator);
    public const string Support = nameof(Support);
    public const string ReadOnly = nameof(ReadOnly);

    public static readonly IReadOnlyDictionary<string, string> Canonical =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [Owner] = Owner,
            [Admin] = Admin,
            [Moderator] = Moderator,
            [Support] = Support,
            [ReadOnly] = ReadOnly
        };
}

internal static class ApiServiceAuthenticationClaimTypes
{
    public const string ActorId = "hip_actor_id";
    public const string MultiFactorAuthenticated = "hip_mfa";
    public const string AuthenticationTime = "hip_auth_time";
}

/// <summary>
/// Accepts the existing HIP development admin headers only for direct loopback Development requests.
/// </summary>
/// <remarks>
/// Outside Development this scheme always returns no identity. The independent HIP-Service scheme owns service
/// credentials, and this Development scheme must never treat Web cookies or arbitrary Authorization input as credentials.
/// </remarks>
internal sealed class ApiServiceDevelopmentAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IWebHostEnvironment environment)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "HipApiServiceDevelopment";
    private const string RoleHeaderName = "X-HIP-Admin-Role";
    private const string UserHeaderName = "X-HIP-Admin-User";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!environment.IsDevelopment())
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        if (!ApiServiceLocalDevelopmentRequestGuard.IsLocalDevelopmentRequest(Request, environment))
        {
            return Request.Headers.ContainsKey(RoleHeaderName)
                ? Task.FromResult(AuthenticateResult.Fail("HIP API development authentication is local-only."))
                : Task.FromResult(AuthenticateResult.NoResult());
        }

        if (!Request.Headers.TryGetValue(RoleHeaderName, out var roleValues))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var suppliedRole = roleValues.ToString().Trim();
        if (!ApiServiceAdminRoles.Canonical.TryGetValue(suppliedRole, out var role))
        {
            return Task.FromResult(AuthenticateResult.Fail("Unsupported HIP administrator role."));
        }

        var actor = Request.Headers.TryGetValue(UserHeaderName, out var userValues)
            ? userValues.ToString().Trim()
            : "hip-api-dev-admin";
        if (string.IsNullOrWhiteSpace(actor) || actor.Length > 256)
        {
            return Task.FromResult(AuthenticateResult.Fail("HIP administrator identity is invalid."));
        }

        var identity = new ClaimsIdentity(
        [
            new Claim(ClaimTypes.Name, actor),
            new Claim(ClaimTypes.Role, role),
            new Claim(ApiServiceAuthenticationClaimTypes.ActorId, actor)
        ],
        SchemeName);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    }
}

internal static class ApiServiceLocalDevelopmentRequestGuard
{
    private static readonly string[] ForwardingHeaderNames =
    [
        "Forwarded",
        "X-Forwarded-For",
        "X-Real-IP"
    ];

    public static bool IsLocalDevelopmentRequest(HttpRequest request, IWebHostEnvironment environment)
    {
        if (!environment.IsDevelopment() ||
            !IsLocalHost(request.Host.Host) ||
            ForwardingHeaderNames.Any(request.Headers.ContainsKey))
        {
            return false;
        }

        return request.HttpContext.Connection.RemoteIpAddress is { } remoteAddress &&
               IPAddress.IsLoopback(remoteAddress);
    }

    private static bool IsLocalHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return false;
        }

        var normalized = host.Trim().Trim('[', ']');
        return normalized.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
               IPAddress.TryParse(normalized, out var address) && IPAddress.IsLoopback(address);
    }
}

internal sealed class ApiServicePrivilegedMfaRequirement : IAuthorizationRequirement;

internal sealed class ApiServiceRecentAuthenticationRequirement : IAuthorizationRequirement;

internal sealed class ApiServiceUniqueActorRequirement : IAuthorizationRequirement;

internal sealed record ApiServiceScopedOperationRequirement(string ServiceScope)
    : IAuthorizationRequirement;

/// <summary>Implements the exact service-scope OR current privileged-administrator operation boundary.</summary>
internal sealed class ApiServiceScopedOperationRequirementHandler(IHostEnvironment environment)
    : AuthorizationHandler<ApiServiceScopedOperationRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        ApiServiceScopedOperationRequirement requirement)
    {
        if (ApiServiceServiceClientPrincipal.HasRequiredScope(context.User, requirement.ServiceScope) ||
            !ApiServiceServiceClientPrincipal.HasServiceIdentity(context.User) &&
            ApiServiceAdminPrincipalAuthorization.CanManagePrivilegedOperations(context.User, environment))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

internal static class ApiServiceServiceClientPrincipal
{
    public static bool HasServiceIdentity(ClaimsPrincipal principal) =>
        principal.Identities.Any(IsServiceIdentity);

    public static bool HasRequiredScope(ClaimsPrincipal principal, string requiredScope) =>
        TryGetTrustedIdentity(principal, out var identity) &&
        HasSingleClaim(identity, ApiServiceClientClaimTypes.Scope, requiredScope);

    public static bool HasExactDomainGrant(ClaimsPrincipal principal, string normalizedDomain) =>
        TryGetTrustedIdentity(principal, out var identity) &&
        identity.FindAll(ApiServiceClientClaimTypes.DomainGrant)
            .Select(claim => claim.Value)
            .Contains(normalizedDomain, StringComparer.Ordinal);

    private static bool TryGetTrustedIdentity(
        ClaimsPrincipal principal,
        out ClaimsIdentity identity)
    {
        var identities = principal.Identities
            .Where(IsServiceIdentity)
            .Take(2)
            .ToArray();
        identity = identities.FirstOrDefault()!;
        return identities.Length == 1 &&
               HasSingleClaim(
                   identity,
                   ApiServiceClientClaimTypes.TrustedServiceClient,
                   "true",
                   ClaimValueTypes.Boolean) &&
               identity.FindAll(ApiServiceClientClaimTypes.ClientId).Take(2).ToArray() is { Length: 1 } clientIds &&
               ServiceClientCredentialFormat.IsCanonicalClientId(clientIds[0].Value);
    }

    private static bool IsServiceIdentity(ClaimsIdentity identity) =>
        identity.IsAuthenticated &&
        string.Equals(
            identity.AuthenticationType,
            ApiServiceAuthenticationSchemes.ServiceClient,
            StringComparison.Ordinal);

    private static bool HasSingleClaim(
        ClaimsIdentity identity,
        string claimType,
        string expectedValue,
        string? expectedValueType = null)
    {
        var claims = identity.FindAll(claimType).Take(2).ToArray();
        return claims.Length == 1 &&
               string.Equals(claims[0].Value, expectedValue, StringComparison.Ordinal) &&
               (expectedValueType is null ||
                string.Equals(claims[0].ValueType, expectedValueType, StringComparison.Ordinal));
    }
}

internal static class ApiServiceAdminPrincipalAuthorization
{
    public static bool CanManagePrivilegedOperations(
        ClaimsPrincipal principal,
        IHostEnvironment environment) =>
        principal.Identity?.IsAuthenticated == true &&
        (principal.IsInRole(ApiServiceAdminRoles.Owner) || principal.IsInRole(ApiServiceAdminRoles.Admin)) &&
        (environment.IsDevelopment() ||
         ApiServicePrivilegedMfaRequirementHandler.HasCanonicalMfa(principal)) &&
        ApiServiceUniqueActorRequirementHandler.HasUniqueActor(principal);
}

internal sealed class ApiServicePrivilegedMfaRequirementHandler(IHostEnvironment environment)
    : AuthorizationHandler<ApiServicePrivilegedMfaRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        ApiServicePrivilegedMfaRequirement requirement)
    {
        if (environment.IsDevelopment() ||
            !IsPrivileged(context.User) ||
            HasCanonicalMfa(context.User))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }

    private static bool IsPrivileged(ClaimsPrincipal principal) =>
        principal.IsInRole(ApiServiceAdminRoles.Owner) || principal.IsInRole(ApiServiceAdminRoles.Admin);

    internal static bool HasCanonicalMfa(ClaimsPrincipal principal)
    {
        var claims = principal.FindAll(ApiServiceAuthenticationClaimTypes.MultiFactorAuthenticated).Take(2).ToArray();
        return claims.Length == 1 &&
               string.Equals(claims[0].Value, "true", StringComparison.Ordinal) &&
               string.Equals(claims[0].ValueType, ClaimValueTypes.Boolean, StringComparison.Ordinal);
    }
}

internal sealed class ApiServiceRecentAuthenticationRequirementHandler(
    IHostEnvironment environment,
    TimeProvider timeProvider)
    : AuthorizationHandler<ApiServiceRecentAuthenticationRequirement>
{
    private static readonly TimeSpan RecentAuthenticationLifetime = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan MaximumClockSkew = TimeSpan.FromMinutes(1);

    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        ApiServiceRecentAuthenticationRequirement requirement)
    {
        if (environment.IsDevelopment())
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        if (!ApiServicePrivilegedMfaRequirementHandler.HasCanonicalMfa(context.User))
        {
            return Task.CompletedTask;
        }

        var claims = context.User.FindAll(ApiServiceAuthenticationClaimTypes.AuthenticationTime).Take(2).ToArray();
        if (claims.Length != 1 ||
            !string.Equals(claims[0].ValueType, ClaimValueTypes.Integer64, StringComparison.Ordinal) ||
            !long.TryParse(claims[0].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var unixSeconds) ||
            !string.Equals(claims[0].Value, unixSeconds.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal))
        {
            return Task.CompletedTask;
        }

        try
        {
            var authenticatedAt = DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
            var now = timeProvider.GetUtcNow();
            if (authenticatedAt <= now + MaximumClockSkew &&
                authenticatedAt >= now - RecentAuthenticationLifetime)
            {
                context.Succeed(requirement);
            }
        }
        catch (ArgumentOutOfRangeException)
        {
            // Invalid external authentication evidence fails closed.
        }

        return Task.CompletedTask;
    }
}

internal sealed class ApiServiceUniqueActorRequirementHandler
    : AuthorizationHandler<ApiServiceUniqueActorRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        ApiServiceUniqueActorRequirement requirement)
    {
        if (HasUniqueActor(context.User))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }

    internal static bool HasUniqueActor(ClaimsPrincipal principal)
    {
        var actors = principal.Identities
            .Where(identity => identity.IsAuthenticated)
            .SelectMany(identity => identity.FindAll(ApiServiceAuthenticationClaimTypes.ActorId))
            .Take(2)
            .ToArray();
        return actors.Length == 1 && !string.IsNullOrWhiteSpace(actors[0].Value);
    }
}
