namespace HIP.Admin.Models;

public sealed class AdminAuthOptions
{
    public bool EnableOidc { get; set; }
    public bool EnforceLogin { get; set; }
    public string Provider { get; set; } = "Authentik";
    public string Authority { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string CallbackPath { get; set; } = "/signin-oidc";
    public string SignedOutCallbackPath { get; set; } = "/signout-callback-oidc";
    public string[] Scopes { get; set; } = ["openid", "profile", "email"];
    public string RoleClaimType { get; set; } = "role";
}
