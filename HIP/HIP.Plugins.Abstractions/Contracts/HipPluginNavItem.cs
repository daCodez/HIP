namespace HIP.Plugins.Abstractions.Contracts;

/// <summary>
/// Navigation contribution declared by a plugin.
/// </summary>
public sealed record HipPluginNavItem(
    string Label,
    string Route,
    string? Icon = null,
    int Order = 100,
    string? Capability = null,
    string Display = "page");
