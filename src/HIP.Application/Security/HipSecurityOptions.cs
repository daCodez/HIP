namespace HIP.Application.Security;

/// <summary>
/// Configures host-level security switches that protect public HIP API surfaces.
/// </summary>
public sealed class HipSecurityOptions
{
    /// <summary>
    /// Configuration section name used by hosts to bind HIP security options.
    /// </summary>
    public const string SectionName = "HipSecurity";

    /// <summary>
    /// Gets or sets whether unauthenticated browser instances may write scoped external-provider preferences.
    /// </summary>
    /// <remarks>
    /// This is disabled by default because provider toggles can consume outbound scan capacity. Admin-managed
    /// provider settings remain available through protected admin routes.
    /// </remarks>
    public bool AllowClientProviderPreferenceWrites { get; set; }

    /// <summary>
    /// Gets or sets explicit origins allowed to send public HIP write requests.
    /// </summary>
    public string[] AllowedClientWriteOrigins { get; set; } = [];

    /// <summary>
    /// Gets or sets whether localhost origins are allowed for browser-extension MVP testing.
    /// </summary>
    public bool AllowLocalhostClientWriteOrigins { get; set; } = true;

    /// <summary>
    /// Gets or sets whether browser extension origins are allowed for public HIP write requests.
    /// </summary>
    public bool AllowBrowserExtensionOrigins { get; set; } = true;
}

/// <summary>
/// Names CORS policies used by HIP public and client API routes.
/// </summary>
public static class HipCorsPolicies
{
    /// <summary>
    /// Allows public read-only HIP endpoints to be embedded or queried broadly.
    /// </summary>
    public const string PublicRead = "PublicHipReadOnly";

    /// <summary>
    /// Allows privacy-safe write requests only from configured HIP clients and local development origins.
    /// </summary>
    public const string ClientWrite = "HipClientWrite";
}
