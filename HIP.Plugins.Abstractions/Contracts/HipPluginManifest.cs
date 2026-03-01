namespace HIP.Plugins.Abstractions.Contracts;

/// <summary>
/// Declares metadata and capability claims for a HIP plugin.
/// </summary>
public sealed record HipPluginManifest(
    string Id,
    string Version,
    IReadOnlyList<string> Capabilities,
    string? Description = null);
