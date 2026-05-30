using HIP.Domain.Reporting;

namespace HIP.Application.Reporting;

public interface IReportRetentionPolicyService
{
    ReportRetentionPolicy GetPolicy(PrivacySafeReport report);

    ReportRetentionPolicy GetPolicy(ReportRetentionCategory category);
}
