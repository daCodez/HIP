namespace HIP.ApiService.Infrastructure.Plugins;

/// <summary>
/// Configuration options for the default policy pack plugin.
/// </summary>
public sealed class PolicyPackOptions
{
    /// <summary>Configuration section name.</summary>
    public const string SectionName = "HIP:Policy";

    /// <summary>Semantic/version label for policy decisions emitted by this pack.</summary>
    public string Version { get; set; } = "default-v1";

    /// <summary>Low risk minimum trust score.</summary>
    public int LowRiskRequiredScore { get; set; } = 20;

    /// <summary>Medium risk minimum trust score.</summary>
    public int MediumRiskRequiredScore { get; set; } = 50;

    /// <summary>High risk minimum trust score.</summary>
    public int HighRiskRequiredScore { get; set; } = 80;
}
