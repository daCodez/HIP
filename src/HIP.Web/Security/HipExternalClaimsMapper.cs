using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace HIP.Web.Security;

/// <summary>
/// Stable claim names emitted by HIP after an external identity has passed OIDC validation.
/// </summary>
public static class HipAuthenticationClaimTypes
{
    /// <summary>Gets the raw OIDC issuer claim name consumed by the mapper.</summary>
    public const string Issuer = "iss";

    /// <summary>Gets the raw OIDC subject claim name consumed by the mapper.</summary>
    public const string Subject = "sub";

    /// <summary>Gets HIP's privacy-safe stable actor identifier claim name.</summary>
    public const string ActorId = "hip_actor_id";

    /// <summary>Gets the compatibility claim used by the existing consumer portal.</summary>
    public const string ConsumerId = "hip_consumer_id";

    /// <summary>Gets HIP's bounded, display-only user label claim name.</summary>
    public const string DisplayName = "hip_display_name";

    /// <summary>Gets HIP's boolean marker that the external provider verified an account contact.</summary>
    public const string AccountContactVerified = "hip_account_contact_verified";

    /// <summary>Gets HIP's boolean claim proving accepted multi-factor evidence was present.</summary>
    public const string MultiFactorAuthenticated = "hip_mfa";

    /// <summary>Gets HIP's normalized Unix-time claim for the provider-authenticated instant.</summary>
    public const string AuthenticationTime = "hip_auth_time";
}

/// <summary>
/// Reduces validated external identity claims to HIP-owned identifiers and explicitly allowlisted roles.
/// </summary>
/// <remarks>
/// The OIDC handler remains responsible for validating tokens, issuer, audience, nonce, and signature. This mapper
/// deliberately ignores email claims. A bounded display name may be retained for presentation only; it is never used
/// as an identity key, authorization input, or audit identifier.
/// </remarks>
public sealed class HipExternalClaimsMapper
{
    private const int MaxIssuerClaimLength = HipProductionAuthenticationOptions.MaxAuthorityLength;
    private const int MaxSubjectClaimLength = 1024;
    private readonly string roleClaimType;
    private readonly IReadOnlyDictionary<string, string> roleMappings;

    /// <summary>
    /// Creates a mapper from validated, immutable production authentication configuration.
    /// </summary>
    /// <param name="configuredOptions">Production authentication options.</param>
    /// <exception cref="OptionsValidationException">Thrown when configuration is unsafe or incomplete.</exception>
    public HipExternalClaimsMapper(IOptions<HipProductionAuthenticationOptions> configuredOptions)
    {
        ArgumentNullException.ThrowIfNull(configuredOptions);
        var options = configuredOptions.Value;
        var validation = new HipProductionAuthenticationOptionsValidator().Validate(Options.DefaultName, options);
        if (validation.Failed)
        {
            throw new OptionsValidationException(
                Options.DefaultName,
                typeof(HipProductionAuthenticationOptions),
                validation.Failures);
        }

        roleClaimType = options.RoleClaimType;
        roleMappings = options.RoleMappings.ToDictionary(
            mapping => mapping.Key,
            mapping => CanonicalHipRole(mapping.Value),
            StringComparer.Ordinal);
    }

    /// <summary>
    /// Maps one validated external principal to HIP-owned identity, consumer, and role claims.
    /// </summary>
    /// <param name="externalPrincipal">Principal produced by the validated external OIDC ticket.</param>
    /// <returns>A deterministic, privacy-safe set of HIP claims.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the required external identity is missing or ambiguous.</exception>
    public IReadOnlyCollection<Claim> Map(ClaimsPrincipal externalPrincipal)
    {
        ArgumentNullException.ThrowIfNull(externalPrincipal);
        var issuer = RequiredUniqueClaim(
            externalPrincipal,
            HipAuthenticationClaimTypes.Issuer,
            MaxIssuerClaimLength);
        var subject = RequiredUniqueClaim(
            externalPrincipal,
            HipAuthenticationClaimTypes.Subject,
            MaxSubjectClaimLength);
        var actorId = CreateActorId(issuer, subject);

        var externalRoles = externalPrincipal.Claims
            .Where(claim => string.Equals(claim.Type, roleClaimType, StringComparison.Ordinal))
            .ToArray();
        if (externalRoles.Length > HipProductionAuthenticationOptions.MaxExternalRoleClaims)
        {
            throw new InvalidOperationException("Validated external identity contains too many role claims.");
        }

        var roles = externalRoles
            .Select(claim => roleMappings.TryGetValue(claim.Value, out var role) ? role : null)
            .Where(role => role is not null)
            .Cast<string>()
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal);

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, actorId),
            new(HipAuthenticationClaimTypes.ActorId, actorId),
            new(HipAuthenticationClaimTypes.ConsumerId, actorId)
        };
        var displayName = OptionalDisplayName(externalPrincipal);
        if (displayName is not null)
        {
            claims.Add(new Claim(HipAuthenticationClaimTypes.DisplayName, displayName));
        }
        if (HasVerifiedAccountContact(externalPrincipal))
        {
            claims.Add(new Claim(
                HipAuthenticationClaimTypes.AccountContactVerified,
                "true",
                ClaimValueTypes.Boolean));
        }
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));
        return claims.ToArray();
    }

    private static string? OptionalDisplayName(ClaimsPrincipal principal)
    {
        var names = principal.Claims
            .Where(claim => string.Equals(claim.Type, ClaimTypes.Name, StringComparison.Ordinal) ||
                            string.Equals(claim.Type, "name", StringComparison.Ordinal))
            .Select(claim => string.Join(' ', claim.Value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)))
            .Distinct(StringComparer.Ordinal)
            .Take(2)
            .ToArray();
        if (names.Length != 1)
        {
            return null;
        }

        var name = names[0];
        return name.Length is >= 2 and <= 80 &&
               !name.Contains('@', StringComparison.Ordinal) &&
               !name.Any(char.IsControl)
            ? name
            : null;
    }

    private static bool HasVerifiedAccountContact(ClaimsPrincipal principal)
    {
        var matches = principal.Claims
            .Where(claim => string.Equals(claim.Type, "email_verified", StringComparison.Ordinal))
            .Take(2)
            .ToArray();
        return matches.Length == 1 &&
               bool.TryParse(matches[0].Value, out var verified) &&
               verified;
    }

    private static string RequiredUniqueClaim(
        ClaimsPrincipal principal,
        string claimType,
        int maximumLength)
    {
        var matches = principal.Claims
            .Where(claim => string.Equals(claim.Type, claimType, StringComparison.Ordinal))
            .ToArray();
        if (matches.Length != 1 ||
            string.IsNullOrWhiteSpace(matches[0].Value) ||
            matches[0].Value.Length > maximumLength)
        {
            throw new InvalidOperationException(
                $"Validated external identity must contain exactly one bounded, nonblank '{claimType}' claim.");
        }

        return matches[0].Value;
    }

    private static string CreateActorId(string issuer, string subject)
    {
        var identityMaterial = $"hip-actor:v1\0{issuer.Length}:{issuer}{subject.Length}:{subject}";
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(identityMaterial));
        return $"hip-user:v1:{Convert.ToHexString(digest).ToLowerInvariant()}";
    }

    private static string CanonicalHipRole(string configuredRole) =>
        AdminRoles.All.Single(role => string.Equals(role, configuredRole, StringComparison.OrdinalIgnoreCase));
}
