namespace HIP.Web.Security;

/// <summary>
/// Holds local-development administrator credentials without placing passwords in source control.
/// </summary>
public sealed class HipAdminLoginOptions
{
    public const string SectionName = "HipAdminLogin";

    /// <summary>
    /// Gets or sets the legacy local administrator email address.
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the legacy ASP.NET Core password hash loaded from private configuration.
    /// </summary>
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets distinct local accounts used to exercise multi-user authorization flows.
    /// </summary>
    public IReadOnlyCollection<HipAdminLocalAccountOptions> Accounts { get; set; } = [];

    /// <summary>
    /// Gets or sets whether unknown local emails may use the bootstrap Owner password as unprivileged test personas.
    /// </summary>
    public bool AllowTestPersonas { get; set; }
}

/// <summary>One configured local-development identity with its own stable HIP actor ID.</summary>
public sealed class HipAdminLocalAccountOptions
{
    /// <summary>Gets or sets the account email used only by the local credential provider.</summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>Gets or sets a privacy-safe team-facing name.</summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>Gets or sets the ASP.NET Core password hash loaded from private configuration.</summary>
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the bootstrap role claim. Persisted HIP assignments replace this claim after the directory exists.
    /// </summary>
    public string Role { get; set; } = AdminRoles.ReadOnly;
}
