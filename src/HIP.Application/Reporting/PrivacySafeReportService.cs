using FluentValidation;
using HIP.Application.PublicLookup;
using HIP.Application.Reputation;
using HIP.Domain.Reputation;
using HIP.Domain.Reporting;
using HIP.Domain.Risk;

namespace HIP.Application.Reporting;

public sealed class PrivacySafeReportService(
    IValidator<PrivacySafeReport> validator,
    IPrivacyHashingService hashingService,
    IReportRetentionPolicyService? retentionPolicyService = null,
    IReputationService? reputationService = null,
    PrivacySafeReportStore? reportStore = null) : IPrivacySafeReportService
{
    private readonly IReportRetentionPolicyService retentionPolicy = retentionPolicyService ?? new ReportRetentionPolicyService();
    private readonly PrivacySafeReportStore store = reportStore ?? new PrivacySafeReportStore();

    public async Task<PrivacySafeReportResponse> SubmitAsync(PrivacySafeReport report, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(report);
        PrivacySafeReport normalized;
        try
        {
            normalized = Normalize(report);
        }
        catch (ArgumentException ex)
        {
            return new PrivacySafeReportResponse(false, null, ReportStatus.Submitted, null, null, ex.Message);
        }

        var validation = await validator.ValidateAsync(normalized, cancellationToken);
        if (!validation.IsValid)
        {
            return new PrivacySafeReportResponse(false, null, ReportStatus.Submitted, null, null, string.Join(" ", validation.Errors.Select(error => error.ErrorMessage)));
        }

        await ApplySenderReputationAsync(normalized, cancellationToken).ConfigureAwait(false);

        store.Reports[normalized.ReportId] = normalized;
        return new PrivacySafeReportResponse(true, normalized.ReportId, normalized.Status, normalized.Domain, normalized.UrlHash, "Privacy-safe report accepted.");
    }

    public Task<IReadOnlyCollection<PrivacySafeReport>> ListAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyCollection<PrivacySafeReport>>(store.Reports.Values.OrderByDescending(report => report.ReportedAtUtc).ToArray());

    public Task<int> DeleteExpiredAsync(DateTimeOffset nowUtc, int maximumDeletes, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (maximumDeletes is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(maximumDeletes));
        var expired = store.Reports.Values
            .Where(report => retentionPolicy.GetPolicy(report).RetentionPeriod is { } period && report.ReportedAtUtc <= nowUtc.Subtract(period))
            .OrderBy(report => report.ReportedAtUtc)
            .Take(maximumDeletes)
            .Select(report => report.ReportId)
            .ToArray();
        return Task.FromResult(expired.Count(id => store.Reports.TryRemove(id, out _)));
    }

    private Task ApplySenderReputationAsync(PrivacySafeReport report, CancellationToken cancellationToken)
    {
        if (reputationService is null ||
            report.ReportType != ReportType.SuspiciousSender ||
            string.IsNullOrWhiteSpace(report.SenderHash))
        {
            return Task.CompletedTask;
        }

        return reputationService.SubmitFeedbackAsync(
            new ReputationFeedbackRequest(
                ReputationSubjectType.Sender,
                report.SenderHash,
                ReputationEventType.SuspiciousReport,
                ToSeverity(report.RiskLevel),
                ReporterTrustLevel.Anonymous,
                report.ReasonSummary,
                report.Platform.ToString(),
                report.UrlHash),
            cancellationToken);
    }

    private static ReputationEventSeverity ToSeverity(RiskStatus riskLevel) =>
        riskLevel switch
        {
            RiskStatus.Critical => ReputationEventSeverity.Critical,
            RiskStatus.Dangerous => ReputationEventSeverity.Dangerous,
            RiskStatus.HighRisk => ReputationEventSeverity.High,
            RiskStatus.Suspicious or RiskStatus.Caution => ReputationEventSeverity.Medium,
            _ => ReputationEventSeverity.Low
        };

    private PrivacySafeReport Normalize(PrivacySafeReport report)
    {
        var domain = DomainInputValidator.ValidateAndNormalize(report.Domain);
        var urlHash = string.IsNullOrWhiteSpace(report.UrlHash) && !string.IsNullOrWhiteSpace(report.RiskyUrl)
            ? hashingService.Hash(report.RiskyUrl)
            : report.UrlHash;

        return report with
        {
            ReportId = string.IsNullOrWhiteSpace(report.ReportId) ? $"report-{Guid.NewGuid():N}" : report.ReportId,
            Domain = domain,
            UrlHash = urlHash,
            SenderHash = HashIfRaw(report.SenderHash),
            DeviceHash = HashIfRaw(report.DeviceHash),
            ReportedAtUtc = report.ReportedAtUtc == default ? DateTimeOffset.UtcNow : report.ReportedAtUtc,
            Status = ReportStatus.Submitted,
            PrivacySafeEvidence = report.PrivacySafeEvidence with { ContainsPrivateContent = false }
        };
    }

    private string? HashIfRaw(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return value.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) ? value : hashingService.Hash(value);
    }
}
