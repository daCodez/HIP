namespace HIP.Web.Security;

/// <summary>
/// Holds the single local-development administrator credential without placing its password in source control.
/// </summary>
public sealed class HipAdminLoginOptions
{
    public const string SectionName = "HipAdminLogin";

    /// <summary>
    /// Gets or sets the local administrator email address.
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the ASP.NET Core password hash loaded from user secrets or an environment variable.
    /// </summary>
    public string PasswordHash { get; set; } = string.Empty;
}
