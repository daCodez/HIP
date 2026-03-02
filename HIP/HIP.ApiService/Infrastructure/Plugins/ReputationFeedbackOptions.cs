namespace HIP.ApiService.Infrastructure.Plugins;

/// <summary>
/// Configuration options for reputation feedback anti-abuse behavior.
/// </summary>
public sealed class ReputationFeedbackOptions
{
    /// <summary>Configuration section name.</summary>
    public const string SectionName = "HIP:ReputationFeedback";

    /// <summary>Duplicate suppression window (minutes) per reporter+subject.</summary>
    public int DuplicateWindowMinutes { get; set; } = 10;

    /// <summary>Maximum feedback submissions per reporter in a rolling minute.</summary>
    public int MaxPerReporterPerMinute { get; set; } = 20;

    /// <summary>Multiplier applied to legit feedback impact.</summary>
    public double LegitWeight { get; set; } = 1.0;

    /// <summary>Multiplier applied to suspicious feedback impact.</summary>
    public double SuspiciousWeight { get; set; } = 1.0;

    /// <summary>Multiplier applied to malicious feedback impact.</summary>
    public double MaliciousWeight { get; set; } = 1.0;
}
