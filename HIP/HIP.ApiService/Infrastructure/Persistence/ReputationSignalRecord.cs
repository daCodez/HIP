namespace HIP.ApiService.Infrastructure.Persistence;

/// <summary>
/// Represents a publicly visible API member.
/// </summary>
public sealed class ReputationSignalRecord
{
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public string IdentityId { get; set; } = string.Empty;
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public double AcceptanceRatio { get; set; }
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public double FeedbackScore { get; set; }
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public int DaysActive { get; set; }
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public int AbuseReports { get; set; }
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public int AuthFailures { get; set; }
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public int SpamFlags { get; set; }
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public DateTimeOffset UpdatedAtUtc { get; set; }
}
