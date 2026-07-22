namespace HIP.Web.Security;

/// <summary>Stable authentication scheme names shared by HIP's host and login endpoints.</summary>
public static class HipAuthenticationSchemes
{
    /// <summary>Gets the encrypted production browser-session cookie scheme.</summary>
    public const string SessionCookie = "Hip.Session";

    /// <summary>Gets the confidential production OpenID Connect scheme.</summary>
    public const string OpenIdConnect = "Hip.Oidc";

    /// <summary>Gets the production challenge router that keeps API failures from redirecting to an identity provider.</summary>
    public const string Challenge = "Hip.Challenge";
}
