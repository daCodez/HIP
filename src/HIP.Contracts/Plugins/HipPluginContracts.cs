namespace HIP.Application.Entitlements;

/// <summary>Declares whether an installed plugin needs administrator configuration.</summary>
public enum HipPluginConfigurationRequirement
{
    None = 0,
    Optional = 1,
    Required = 2
}

/// <summary>Runtime state reported by an installed plugin without exposing credentials or configuration values.</summary>
public enum HipPluginState
{
    Ready = 0,
    NeedsConfiguration = 1,
    Unavailable = 2
}

/// <summary>Versioned, privacy-safe identity and setup metadata for one installed plugin provider.</summary>
public sealed record HipPluginManifest(
    string ProviderId,
    string DisplayName,
    string Version,
    string Description,
    HipPluginConfigurationRequirement ConfigurationRequirement,
    string? AdminSetupPath);

/// <summary>Allows a provider to declare its installed plugin manifest separately from plan feature grants.</summary>
public interface IHipPluginManifestProvider
{
    HipPluginManifest Manifest { get; }
}

/// <summary>Privacy-safe operational status supplied by a plugin. Implementations must never return secret values.</summary>
public interface IHipPluginStatusProvider
{
    HipPluginManifest Manifest { get; }

    Task<HipPluginRuntimeStatus> GetStatusAsync(CancellationToken cancellationToken);
}

/// <summary>Current plugin status and a bounded administrator-facing explanation.</summary>
public sealed record HipPluginRuntimeStatus(HipPluginState State, string Message);

/// <summary>Privacy-safe description of a product feature supplied by HIP or a plugin.</summary>
public sealed record HipFeatureDescriptor(
    string FeatureId,
    string ProviderId,
    string Category,
    string DisplayName,
    string Description);

/// <summary>
/// Extension boundary through which a plugin declares product features. Providers declare metadata only and never
/// receive credentials, billing records, trust evidence, score inputs, or certificate authority access.
/// </summary>
public interface IHipPlanFeatureProvider
{
    IReadOnlyCollection<HipFeatureDescriptor> Features { get; }
}
