namespace HIP.ApiService.Options;

/// <summary>
/// OIDC/JWT settings for admin API authorization.
/// Keeps provider details in config so Authentik can be swapped without code changes.
/// </summary>
public sealed class AdminApiAuthOptions
{
    /// <summary>
    /// Configuration section path.
    /// </summary>
    public const string SectionName = "HIP:AdminAuth";

    /// <summary>
    /// Enables OIDC JWT authentication for admin API access.
    /// </summary>
    public bool EnableOidcJwt { get; set; }

    /// <summary>
    /// OIDC authority/issuer URL (e.g., Authentik issuer).
    /// </summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>
    /// Expected token audience for this API.
    /// </summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// Provider claim names to scan for role/group values before normalization into app:role.
    /// </summary>
    public string[] RoleClaimSources { get; set; } = ["role", "roles", "groups"];
}
