using Microsoft.Extensions.Options;

namespace HIP.Web.Navigation;

/// <summary>Configures the canonical public origins for HIP's separately hosted applications.</summary>
public sealed class HipPortalLinkOptions
{
    /// <summary>Gets the configuration section name.</summary>
    public const string SectionName = "HipPortalLinks";

    /// <summary>Gets or sets the public lookup and certificate origin.</summary>
    public string PublicOrigin { get; set; } = string.Empty;

    /// <summary>Gets or sets the Consumer application origin.</summary>
    public string ConsumerOrigin { get; set; } = string.Empty;

    /// <summary>Gets or sets the Admin application origin.</summary>
    public string AdminOrigin { get; set; } = string.Empty;

    /// <summary>Gets or sets the public API origin.</summary>
    public string ApiOrigin { get; set; } = string.Empty;

    /// <summary>Gets or sets the identity-provider origin.</summary>
    public string IdentityOrigin { get; set; } = string.Empty;

    /// <summary>Returns whether every configured value is a bounded HTTPS origin without extra URI parts.</summary>
    public bool HasValidOrigins() =>
        IsValidOrigin(PublicOrigin) &&
        IsValidOrigin(ConsumerOrigin) &&
        IsValidOrigin(AdminOrigin) &&
        IsValidOrigin(ApiOrigin) &&
        IsValidOrigin(IdentityOrigin);

    private static bool IsValidOrigin(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 2048 &&
        Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
        string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
        string.IsNullOrEmpty(uri.UserInfo) &&
        string.IsNullOrEmpty(uri.Query) &&
        string.IsNullOrEmpty(uri.Fragment) &&
        (string.IsNullOrEmpty(uri.AbsolutePath) || string.Equals(uri.AbsolutePath, "/", StringComparison.Ordinal));
}

/// <summary>Builds canonical, same-product links without accepting arbitrary redirect destinations.</summary>
public sealed class HipPortalLinks(IOptions<HipPortalLinkOptions> configuredOptions)
{
    private readonly HipPortalLinkOptions options =
        configuredOptions?.Value ?? throw new ArgumentNullException(nameof(configuredOptions));

    /// <summary>Builds a link to the public lookup application.</summary>
    public string Public(string localPath) => Build(options.PublicOrigin, localPath);

    /// <summary>Builds a link to the Consumer application.</summary>
    public string Consumer(string localPath) => Build(options.ConsumerOrigin, localPath);

    /// <summary>Builds a link to the Admin application.</summary>
    public string Admin(string localPath) => Build(options.AdminOrigin, localPath);

    /// <summary>Builds a link to the public API.</summary>
    public string Api(string localPath) => Build(options.ApiOrigin, localPath);

    /// <summary>Builds a link to the identity provider.</summary>
    public string Identity(string localPath) => Build(options.IdentityOrigin, localPath);

    private static string Build(string origin, string localPath)
    {
        if (string.IsNullOrWhiteSpace(localPath) ||
            localPath[0] != '/' ||
            localPath.StartsWith("//", StringComparison.Ordinal) ||
            Uri.TryCreate(localPath, UriKind.Absolute, out _))
        {
            throw new ArgumentException("HIP portal links require a local absolute path.", nameof(localPath));
        }

        return $"{origin.TrimEnd('/')}{localPath}";
    }
}
