namespace HIP.ApiService.Infrastructure.Persistence;

public sealed class ReputationSignalRecord
{
    public string IdentityId { get; set; } = string.Empty;
    public double AcceptanceRatio { get; set; }
    public double FeedbackScore { get; set; }
    public int DaysActive { get; set; }
    public int AbuseReports { get; set; }
    public int AuthFailures { get; set; }
    public int SpamFlags { get; set; }
    public DateTimeOffset UpdatedAtUtc { get; set; }
}
