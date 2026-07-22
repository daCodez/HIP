using Microsoft.Extensions.Options;

namespace HIP.Web.Security;

/// <summary>
/// Configures HIP's production OIDC authority, confidential client, role translation, and session bounds.
/// </summary>
/// <remarks>
/// Client secrets must come from an external secret provider or environment configuration and must never be
/// committed to an appsettings file. Registration is intentionally owned by the host so Development can retain
/// its isolated local authentication scheme.
/// </remarks>
public sealed class HipProductionAuthenticationOptions
{
    /// <summary>Gets the configuration section used by the production web host.</summary>
    public const string SectionName = "HipAuthentication";

    /// <summary>Gets the maximum accepted authority URI length.</summary>
    public const int MaxAuthorityLength = 2048;

    /// <summary>Gets the maximum accepted OIDC client identifier length.</summary>
    public const int MaxClientIdLength = 512;

    /// <summary>Gets the maximum accepted secret length without exposing the secret value.</summary>
    public const int MaxClientSecretLength = 4096;

    /// <summary>Gets the maximum configured external claim-type length.</summary>
    public const int MaxClaimTypeLength = 256;

    /// <summary>Gets the maximum configured external role value length.</summary>
    public const int MaxExternalRoleLength = 256;

    /// <summary>Gets the maximum number of explicit external-to-HIP role mappings.</summary>
    public const int MaxRoleMappings = 32;

    /// <summary>Gets the maximum number of role claims accepted from one validated external identity.</summary>
    public const int MaxExternalRoleClaims = 64;

    /// <summary>Gets the maximum number of exact OIDC ACR values trusted as MFA evidence.</summary>
    public const int MaxTrustedMfaAcrValues = 16;

    /// <summary>Gets the maximum length of one exact trusted OIDC ACR value.</summary>
    public const int MaxTrustedMfaAcrValueLength = 256;

    /// <summary>Gets the shortest permitted idle session lifetime.</summary>
    public static readonly TimeSpan MinimumIdleSessionLifetime = TimeSpan.FromMinutes(5);

    /// <summary>Gets the longest permitted idle session lifetime.</summary>
    public static readonly TimeSpan MaximumIdleSessionLifetime = TimeSpan.FromHours(8);

    /// <summary>Gets the longest permitted absolute session lifetime.</summary>
    public static readonly TimeSpan MaximumAbsoluteSessionLifetime = TimeSpan.FromDays(7);

    /// <summary>Gets the shortest permitted recent-authentication window.</summary>
    public static readonly TimeSpan MinimumRecentAuthenticationLifetime = TimeSpan.FromMinutes(1);

    /// <summary>Gets the longest permitted recent-authentication window.</summary>
    public static readonly TimeSpan MaximumRecentAuthenticationLifetime = TimeSpan.FromMinutes(30);

    /// <summary>Gets or sets the HTTPS OIDC authority that validates the external issuer.</summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>Gets or sets HIP Web's confidential OIDC client identifier.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Gets or sets HIP Web's OIDC client secret supplied by protected configuration.</summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>Gets or sets the exact external claim type containing provider roles.</summary>
    public string RoleClaimType { get; set; } = string.Empty;

    /// <summary>Gets or sets exact, allowlisted external role values and their HIP role targets.</summary>
    public Dictionary<string, string> RoleMappings { get; set; } = new(StringComparer.Ordinal);

    /// <summary>Gets or sets whether the exact standard OIDC <c>amr</c> value <c>mfa</c> is trusted.</summary>
    public bool AcceptStandardMfaAmr { get; set; }

    /// <summary>Gets or sets exact, case-sensitive OIDC <c>acr</c> values trusted as MFA evidence.</summary>
    public List<string> TrustedMfaAcrValues { get; set; } = [];

    /// <summary>Gets or sets how recently the external provider must have authenticated a privileged actor.</summary>
    public TimeSpan RecentAuthenticationLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>Gets or sets the idle lifetime used when renewing an active HIP session.</summary>
    public TimeSpan IdleSessionLifetime { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>Gets or sets the non-renewable upper bound for one HIP login session.</summary>
    public TimeSpan AbsoluteSessionLifetime { get; set; } = TimeSpan.FromHours(8);
}

/// <summary>
/// Validates production authentication configuration without logging or returning secret material.
/// </summary>
public sealed class HipProductionAuthenticationOptionsValidator : IValidateOptions<HipProductionAuthenticationOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, HipProductionAuthenticationOptions options)
    {
        if (options is null)
        {
            return ValidateOptionsResult.Fail("HIP production authentication options are required.");
        }

        var failures = new List<string>();
        ValidateAuthority(options.Authority, failures);
        ValidateBoundedRequired(
            options.ClientId,
            HipProductionAuthenticationOptions.MaxClientIdLength,
            "OIDC client ID",
            failures);
        ValidateBoundedRequired(
            options.ClientSecret,
            HipProductionAuthenticationOptions.MaxClientSecretLength,
            "OIDC client secret",
            failures);
        ValidateRoleConfiguration(options, failures);
        ValidateAssuranceConfiguration(options, failures);
        ValidateSessionLifetimes(options, failures);

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }

    private static void ValidateAuthority(string? authority, ICollection<string> failures)
    {
        if (string.IsNullOrWhiteSpace(authority) ||
            authority.Length > HipProductionAuthenticationOptions.MaxAuthorityLength ||
            !Uri.TryCreate(authority, UriKind.Absolute, out var uri) ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment))
        {
            failures.Add("OIDC authority must be a bounded absolute HTTPS URI without credentials, query, or fragment.");
        }
    }

    private static void ValidateRoleConfiguration(
        HipProductionAuthenticationOptions options,
        ICollection<string> failures)
    {
        ValidateBoundedRequired(
            options.RoleClaimType,
            HipProductionAuthenticationOptions.MaxClaimTypeLength,
            "OIDC role claim type",
            failures);

        if (options.RoleMappings is null ||
            options.RoleMappings.Count is < 1 or > HipProductionAuthenticationOptions.MaxRoleMappings)
        {
            failures.Add($"OIDC role mappings must contain between 1 and {HipProductionAuthenticationOptions.MaxRoleMappings} entries.");
            return;
        }

        foreach (var mapping in options.RoleMappings)
        {
            if (string.IsNullOrWhiteSpace(mapping.Key) ||
                mapping.Key.Length > HipProductionAuthenticationOptions.MaxExternalRoleLength)
            {
                failures.Add("Each external OIDC role value must be nonblank and within the configured length limit.");
            }

            if (string.IsNullOrWhiteSpace(mapping.Value) || !AdminRoles.All.Contains(mapping.Value))
            {
                failures.Add("Each external OIDC role may map only to an existing HIP role.");
            }
        }
    }

    private static void ValidateSessionLifetimes(
        HipProductionAuthenticationOptions options,
        ICollection<string> failures)
    {
        if (options.IdleSessionLifetime < HipProductionAuthenticationOptions.MinimumIdleSessionLifetime ||
            options.IdleSessionLifetime > HipProductionAuthenticationOptions.MaximumIdleSessionLifetime)
        {
            failures.Add("HIP idle session lifetime is outside the allowed security bounds.");
        }

        if (options.AbsoluteSessionLifetime < HipProductionAuthenticationOptions.MinimumIdleSessionLifetime ||
            options.AbsoluteSessionLifetime > HipProductionAuthenticationOptions.MaximumAbsoluteSessionLifetime)
        {
            failures.Add("HIP absolute session lifetime is outside the allowed security bounds.");
        }

        if (options.AbsoluteSessionLifetime < options.IdleSessionLifetime)
        {
            failures.Add("HIP absolute session lifetime must be greater than or equal to the idle lifetime.");
        }
    }

    private static void ValidateAssuranceConfiguration(
        HipProductionAuthenticationOptions options,
        ICollection<string> failures)
    {
        var trustedAcrValues = options.TrustedMfaAcrValues;
        if (trustedAcrValues is null ||
            trustedAcrValues.Count > HipProductionAuthenticationOptions.MaxTrustedMfaAcrValues)
        {
            failures.Add(
                $"Trusted OIDC MFA ACR values must contain no more than {HipProductionAuthenticationOptions.MaxTrustedMfaAcrValues} entries.");
            return;
        }

        var validAcrValues = true;
        foreach (var acrValue in trustedAcrValues)
        {
            if (string.IsNullOrWhiteSpace(acrValue) ||
                acrValue.Length > HipProductionAuthenticationOptions.MaxTrustedMfaAcrValueLength ||
                acrValue.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)))
            {
                validAcrValues = false;
                break;
            }
        }

        if (!validAcrValues ||
            trustedAcrValues.Distinct(StringComparer.Ordinal).Count() != trustedAcrValues.Count)
        {
            failures.Add("Trusted OIDC MFA ACR values must be exact, unique, bounded protocol values.");
        }

        if (!options.AcceptStandardMfaAmr && trustedAcrValues.Count == 0)
        {
            failures.Add("At least one explicit OIDC MFA evidence source must be enabled.");
        }

        if (options.RecentAuthenticationLifetime <
                HipProductionAuthenticationOptions.MinimumRecentAuthenticationLifetime ||
            options.RecentAuthenticationLifetime >
                HipProductionAuthenticationOptions.MaximumRecentAuthenticationLifetime)
        {
            failures.Add("HIP recent-authentication lifetime is outside the allowed security bounds.");
        }
    }

    private static void ValidateBoundedRequired(
        string? value,
        int maximumLength,
        string settingName,
        ICollection<string> failures)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength)
        {
            failures.Add($"{settingName} must be nonblank and no longer than {maximumLength} characters.");
        }
    }
}
