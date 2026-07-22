using System.Globalization;
using System.Security.Claims;
using Microsoft.Extensions.Options;

namespace HIP.Web.Security;

/// <summary>
/// Reduces assurance evidence from a validated OIDC identity token to bounded HIP-owned claims.
/// </summary>
/// <remarks>
/// Signature, issuer, audience, nonce, and lifetime validation remain the OIDC handler's responsibility. Call this
/// evaluator only from the validated-token event; never use claims copied from a request or an existing session.
/// </remarks>
public sealed class HipExternalAuthenticationAssuranceEvaluator
{
    private const string AuthenticationMethodReferenceClaimType = "amr";
    private const string AuthenticationContextReferenceClaimType = "acr";
    private const string AuthenticationTimeClaimType = "auth_time";
    private const string StandardMfaAuthenticationMethod = "mfa";
    private const string HipMfaClaimValue = "true";
    private readonly bool acceptStandardMfaAmr;
    private readonly IReadOnlySet<string> trustedMfaAcrValues;
    private readonly TimeProvider timeProvider;

    /// <summary>Gets the shared tolerance for small provider/server clock differences.</summary>
    public static TimeSpan MaximumAuthenticationClockSkew { get; } = TimeSpan.FromMinutes(1);

    /// <summary>Gets the maximum number of bounded authentication-method references accepted from one token.</summary>
    public const int MaximumAuthenticationMethodReferences = 16;

    /// <summary>Gets the maximum length of one authentication-method reference.</summary>
    public const int MaximumAuthenticationMethodReferenceLength = 64;

    /// <summary>Creates an evaluator from validated production assurance configuration.</summary>
    public HipExternalAuthenticationAssuranceEvaluator(
        IOptions<HipProductionAuthenticationOptions> configuredOptions,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(configuredOptions);
        this.timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        var options = configuredOptions.Value;
        var validation = new HipProductionAuthenticationOptionsValidator().Validate(Options.DefaultName, options);
        if (validation.Failed)
        {
            throw new OptionsValidationException(
                Options.DefaultName,
                typeof(HipProductionAuthenticationOptions),
                validation.Failures);
        }

        acceptStandardMfaAmr = options.AcceptStandardMfaAmr;
        trustedMfaAcrValues = options.TrustedMfaAcrValues.ToHashSet(StringComparer.Ordinal);
    }

    /// <summary>Projects accepted MFA and authentication-time evidence without retaining external claims.</summary>
    /// <exception cref="InvalidOperationException">Thrown when present assurance evidence is malformed or ambiguous.</exception>
    public IReadOnlyCollection<Claim> Evaluate(ClaimsPrincipal externalPrincipal)
    {
        ArgumentNullException.ThrowIfNull(externalPrincipal);
        var claims = new List<Claim>(2);
        if (HasAcceptedMfa(externalPrincipal))
        {
            claims.Add(new Claim(
                HipAuthenticationClaimTypes.MultiFactorAuthenticated,
                HipMfaClaimValue,
                ClaimValueTypes.Boolean));
        }

        if (TryGetAuthenticationTime(externalPrincipal, out var authenticationTime))
        {
            claims.Add(new Claim(
                HipAuthenticationClaimTypes.AuthenticationTime,
                authenticationTime.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
                ClaimValueTypes.Integer64));
        }

        return claims.ToArray();
    }

    private bool HasAcceptedMfa(ClaimsPrincipal principal)
    {
        var authenticationMethods = principal.Claims
            .Where(claim => string.Equals(
                claim.Type,
                AuthenticationMethodReferenceClaimType,
                StringComparison.Ordinal))
            .Select(claim => claim.Value)
            .ToArray();
        if (authenticationMethods.Length > MaximumAuthenticationMethodReferences ||
            authenticationMethods.Distinct(StringComparer.Ordinal).Count() != authenticationMethods.Length ||
            authenticationMethods.Any(value => !IsBoundedProtocolValue(
                value,
                MaximumAuthenticationMethodReferenceLength)))
        {
            throw InvalidMfaEvidence();
        }

        var accepted = acceptStandardMfaAmr &&
                       authenticationMethods.Contains(StandardMfaAuthenticationMethod, StringComparer.Ordinal);

        var acr = OptionalUniqueClaim(principal, AuthenticationContextReferenceClaimType);
        if (acr is not null)
        {
            if (!IsBoundedProtocolValue(
                    acr.Value,
                    HipProductionAuthenticationOptions.MaxTrustedMfaAcrValueLength))
            {
                throw InvalidMfaEvidence();
            }

            accepted |= trustedMfaAcrValues.Contains(acr.Value);
        }

        return accepted;
    }

    private bool TryGetAuthenticationTime(
        ClaimsPrincipal principal,
        out DateTimeOffset authenticationTime)
    {
        var claim = OptionalUniqueClaim(principal, AuthenticationTimeClaimType);
        if (claim is null)
        {
            authenticationTime = default;
            return false;
        }

        if (!long.TryParse(
                claim.Value,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var unixSeconds) ||
            unixSeconds < 0 ||
            !string.Equals(
                claim.Value,
                unixSeconds.ToString(CultureInfo.InvariantCulture),
                StringComparison.Ordinal))
        {
            throw InvalidAuthenticationTime();
        }

        try
        {
            authenticationTime = DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
        }
        catch (ArgumentOutOfRangeException)
        {
            throw InvalidAuthenticationTime();
        }

        if (authenticationTime > timeProvider.GetUtcNow().Add(MaximumAuthenticationClockSkew))
        {
            throw InvalidAuthenticationTime();
        }

        return true;
    }

    private static Claim? OptionalUniqueClaim(ClaimsPrincipal principal, string claimType)
    {
        var claims = principal.Claims
            .Where(claim => string.Equals(claim.Type, claimType, StringComparison.Ordinal))
            .Take(2)
            .ToArray();
        if (claims.Length > 1)
        {
            throw new InvalidOperationException("Validated external identity contains ambiguous assurance evidence.");
        }

        return claims.SingleOrDefault();
    }

    private static bool IsBoundedProtocolValue(string? value, int maximumLength) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= maximumLength &&
        value.All(character => !char.IsWhiteSpace(character) && !char.IsControl(character));

    private static InvalidOperationException InvalidMfaEvidence() =>
        new("Validated external identity contains invalid MFA assurance evidence.");

    private static InvalidOperationException InvalidAuthenticationTime() =>
        new("Validated external identity contains invalid authentication-time evidence.");
}
