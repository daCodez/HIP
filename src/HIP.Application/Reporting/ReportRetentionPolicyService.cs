using HIP.Domain.Reporting;
using HIP.Domain.Risk;

namespace HIP.Application.Reporting;

public sealed class ReportRetentionPolicyService : IReportRetentionPolicyService
{
    public ReportRetentionPolicy GetPolicy(PrivacySafeReport report)
    {
        if (report.Status == ReportStatus.Confirmed && report.RiskLevel is RiskStatus.Dangerous or RiskStatus.Critical)
        {
            return GetPolicy(ReportRetentionCategory.ConfirmedDangerousPattern);
        }

        if (!string.IsNullOrWhiteSpace(report.SenderHash) || !string.IsNullOrWhiteSpace(report.DeviceHash))
        {
            return GetPolicy(ReportRetentionCategory.UserLinkedPrivateData);
        }

        return GetPolicy(ReportRetentionCategory.NormalRiskyFinding);
    }

    public ReportRetentionPolicy GetPolicy(ReportRetentionCategory category) =>
        category switch
        {
            ReportRetentionCategory.NormalRiskyFinding => new(category, TimeSpan.FromDays(90), "Normal risky findings are retained for about 90 days."),
            ReportRetentionCategory.ConfirmedDangerousPattern => new(category, null, "Confirmed dangerous patterns may be retained long-term to protect users."),
            ReportRetentionCategory.UserLinkedPrivateData => new(category, TimeSpan.FromDays(30), "User-linked or private-adjacent data should be retained for the shortest practical period."),
            _ => new(category, TimeSpan.FromDays(90), "Default MVP retention.")
        };
}
