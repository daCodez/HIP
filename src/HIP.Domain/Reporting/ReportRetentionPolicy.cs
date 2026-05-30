namespace HIP.Domain.Reporting;

public enum ReportRetentionCategory
{
    NormalRiskyFinding,
    ConfirmedDangerousPattern,
    UserLinkedPrivateData
}

public sealed record ReportRetentionPolicy(
    ReportRetentionCategory Category,
    TimeSpan? RetentionPeriod,
    string Reason);
