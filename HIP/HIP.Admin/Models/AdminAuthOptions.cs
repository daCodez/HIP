namespace HIP.Admin.Models;

public sealed class AdminAuthOptions
{
    public bool EnableOidc { get; set; }
    public bool EnableLocalAuth { get; set; }
    public bool EnforceLogin { get; set; }
    public string Provider { get; set; } = "Authentik";
    public string Authority { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string CallbackPath { get; set; } = "/signin-oidc";
    public string SignedOutCallbackPath { get; set; } = "/signout-callback-oidc";
    public string[] Scopes { get; set; } = ["openid", "profile", "email"];

    /// <summary>
    /// Provider claim names to scan for role/group values before normalizing into app:role.
    /// </summary>
    public string[] RoleClaimSources { get; set; } = ["role", "roles", "groups"];

    /// <summary>
    /// Local break-glass admin account for environments without OIDC.
    /// </summary>
    public LocalAdminAccountOptions LocalAdmin { get; set; } = new();
}

public sealed class LocalAdminAccountOptions
{
    public string Username { get; set; } = "admin";
    public string Password { get; set; } = string.Empty;
    public string[] Roles { get; set; } = ["Admin"];
}
