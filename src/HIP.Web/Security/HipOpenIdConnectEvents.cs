using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;

namespace HIP.Web.Security;

/// <summary>Reduces validated OIDC tickets to HIP-owned claims and bounded session properties.</summary>
public sealed class HipOpenIdConnectEvents(
    HipExternalClaimsMapper claimsMapper,
    HipExternalAuthenticationAssuranceEvaluator assuranceEvaluator,
    IOptions<HipProductionAuthenticationOptions> configuredOptions,
    TimeProvider timeProvider) : OpenIdConnectEvents
{
    private const string GenericMappingFailure = "External identity could not be accepted by HIP.";
    private readonly HipExternalClaimsMapper claimsMapper =
        claimsMapper ?? throw new ArgumentNullException(nameof(claimsMapper));
    private readonly HipExternalAuthenticationAssuranceEvaluator assuranceEvaluator =
        assuranceEvaluator ?? throw new ArgumentNullException(nameof(assuranceEvaluator));
    private readonly HipProductionAuthenticationOptions options =
        configuredOptions?.Value ?? throw new ArgumentNullException(nameof(configuredOptions));
    private readonly TimeProvider timeProvider =
        timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    /// <inheritdoc />
    public override Task TokenValidated(TokenValidatedContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var properties = context.Properties ?? new AuthenticationProperties();
        context.Properties = properties;
        IReadOnlyCollection<Claim> identityClaims;
        IReadOnlyCollection<Claim> assuranceClaims;
        try
        {
            var externalPrincipal = context.Principal ?? new ClaimsPrincipal();
            identityClaims = claimsMapper.Map(externalPrincipal);
            assuranceClaims = assuranceEvaluator.Evaluate(externalPrincipal);
        }
        catch (InvalidOperationException)
        {
            return Fail(context, properties);
        }

        var now = timeProvider.GetUtcNow();
        var absoluteExpiry = now.Add(options.AbsoluteSessionLifetime);
        var isStepUp = HipStepUpAuthenticationProperties.IsStepUp(properties);
        var hasMfa = assuranceClaims.Any(claim =>
            string.Equals(
                claim.Type,
                HipAuthenticationClaimTypes.MultiFactorAuthenticated,
                StringComparison.Ordinal) &&
            string.Equals(claim.Value, "true", StringComparison.Ordinal) &&
            string.Equals(claim.ValueType, ClaimValueTypes.Boolean, StringComparison.Ordinal));
        var isPrivileged = identityClaims.Any(claim =>
            string.Equals(claim.Type, ClaimTypes.Role, StringComparison.Ordinal) &&
            (string.Equals(claim.Value, AdminRoles.Owner, StringComparison.Ordinal) ||
             string.Equals(claim.Value, AdminRoles.Admin, StringComparison.Ordinal)));
        var hasAuthenticationTime = TryGetAuthenticationTime(
            assuranceClaims,
            out var authenticationTime);
        if (isPrivileged &&
            (!hasMfa ||
             !hasAuthenticationTime ||
             authenticationTime < now.Subtract(options.AbsoluteSessionLifetime)))
        {
            return Fail(context, properties);
        }

        if (isStepUp)
        {
            if (!hasMfa ||
                !hasAuthenticationTime ||
                authenticationTime < now.Subtract(options.RecentAuthenticationLifetime) ||
                !HipStepUpAuthenticationProperties.TryGetExpectedActorId(properties, out var expectedActorId) ||
                !HipStepUpAuthenticationProperties.TryGetOriginalAbsoluteExpiry(
                    properties,
                    out var originalAbsoluteExpiry) ||
                originalAbsoluteExpiry <= now)
            {
                return Fail(context, properties);
            }

            var returnedActorIds = identityClaims
                .Where(claim => string.Equals(
                    claim.Type,
                    HipAuthenticationClaimTypes.ActorId,
                    StringComparison.Ordinal))
                .Select(claim => claim.Value)
                .ToArray();
            if (returnedActorIds.Length != 1 ||
                !string.Equals(returnedActorIds[0], expectedActorId, StringComparison.Ordinal))
            {
                return Fail(context, properties);
            }

            if (originalAbsoluteExpiry < absoluteExpiry)
            {
                absoluteExpiry = originalAbsoluteExpiry;
            }
        }

        var idleExpiry = now.Add(options.IdleSessionLifetime);
        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(
            identityClaims.Concat(assuranceClaims),
            HipAuthenticationSchemes.OpenIdConnect,
            ClaimTypes.NameIdentifier,
            ClaimTypes.Role));
        HipStepUpAuthenticationProperties.Clear(properties);
        properties.IssuedUtc = now;
        properties.ExpiresUtc = idleExpiry < absoluteExpiry ? idleExpiry : absoluteExpiry;
        properties.AllowRefresh = true;
        HipSessionAuthenticationProperties.SetAbsoluteExpiry(properties, absoluteExpiry);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public override Task RedirectToIdentityProvider(RedirectContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var safeReturnUrl = HipDevelopmentLoginEndpoints.SafeLocalReturnUrl(context.Properties.RedirectUri);
        if (!HipStepUpAuthenticationProperties.IsStepUp(context.Properties) &&
            safeReturnUrl.StartsWith("/admin", StringComparison.OrdinalIgnoreCase))
        {
            context.ProtocolMessage.Prompt = "login";
            context.ProtocolMessage.MaxAge = "0";
        }

        if (options.TrustedMfaAcrValues.Count > 0)
        {
            context.ProtocolMessage.AcrValues = string.Join(" ", options.TrustedMfaAcrValues);
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public override Task RemoteFailure(RemoteFailureContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var safeReturnUrl = context.Properties is null
            ? "/admin"
            : HipDevelopmentLoginEndpoints.SafeLocalReturnUrl(context.Properties.RedirectUri);
        var isStepUp = context.Properties is not null &&
                       HipStepUpAuthenticationProperties.IsStepUp(context.Properties);
        if (context.Properties is not null)
        {
            HipStepUpAuthenticationProperties.Clear(context.Properties);
        }

        context.HandleResponse();
        context.Response.Redirect(
            isStepUp
                ? $"/step-up?error=unsatisfied&returnUrl={Uri.EscapeDataString(safeReturnUrl)}"
                : $"{HipDevelopmentLoginEndpoints.LoginPathFor(safeReturnUrl)}?error=external-authentication");
        return Task.CompletedTask;
    }

    private static Task Fail(
        TokenValidatedContext context,
        AuthenticationProperties properties)
    {
        context.Principal = null;
        context.Fail(GenericMappingFailure);
        return Task.CompletedTask;
    }

    private static bool TryGetAuthenticationTime(
        IEnumerable<Claim> assuranceClaims,
        out DateTimeOffset authenticationTime)
    {
        var matches = assuranceClaims
            .Where(claim => string.Equals(
                claim.Type,
                HipAuthenticationClaimTypes.AuthenticationTime,
                StringComparison.Ordinal))
            .ToArray();
        if (matches.Length == 1 &&
            long.TryParse(
                matches[0].Value,
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out var unixSeconds))
        {
            try
            {
                authenticationTime = DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
                return true;
            }
            catch (ArgumentOutOfRangeException)
            {
                // The evaluator normally excludes this; fail closed if an invalid internal claim is ever supplied.
            }
        }

        authenticationTime = default;
        return false;
    }

}
