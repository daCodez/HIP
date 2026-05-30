using HIP.Domain.Reporting;

namespace HIP.Application.Reporting;

public interface IPrivacySafeReportService
{
    Task<PrivacySafeReportResponse> SubmitAsync(PrivacySafeReport report, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<PrivacySafeReport>> ListAsync(CancellationToken cancellationToken);
}
