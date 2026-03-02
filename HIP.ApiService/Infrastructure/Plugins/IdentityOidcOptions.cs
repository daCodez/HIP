namespace HIP.ApiService.Infrastructure.Plugins;

/// <summary>
/// Configuration options for OIDC identity plugin validation.
/// </summary>
public sealed class IdentityOidcOptions
{
    /// <summary>Configuration section name.</summary>
    public const string SectionName = "HIP:IdentityOidc";

    /// <summary>Allowed issuer list. Empty means allow all (development default).</summary>
    public string[] AllowedIssuers { get; set; } = [];

    /// <summary>When true, email must be verified for high assurance classification.</summary>
    public bool RequireVerifiedEmailForHighAssurance { get; set; } = true;
}
