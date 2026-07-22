using System.Collections.Concurrent;
using FluentValidation;
using HIP.Application.PublicLookup;
using HIP.Domain.Reporting;

namespace HIP.Application.Reporting;

public sealed class PrivacySafeReportService(
    IValidator<PrivacySafeReport> validator,
    IPrivacyHashingService hashingService,
    IReportRetentionPolicyService? retentionPolicyService = null) : IPrivacySafeReportService
{
    private readonly ConcurrentDictionary<string, PrivacySafeReport> _reports = new(StringComparer.OrdinalIgnoreCase);
    private readonly IReportRetentionPolicyService retentionPolicy = retentionPolicyService ?? new ReportRetentionPolicyService();

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

        _reports[normalized.ReportId] = normalized;
        return new PrivacySafeReportResponse(true, normalized.ReportId, normalized.Status, normalized.Domain, normalized.UrlHash, "Privacy-safe report accepted.");
    }

    public Task<IReadOnlyCollection<PrivacySafeReport>> ListAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyCollection<PrivacySafeReport>>(_reports.Values.OrderByDescending(report => report.ReportedAtUtc).ToArray());

    public Task<int> DeleteExpiredAsync(DateTimeOffset nowUtc, int maximumDeletes, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (maximumDeletes is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(maximumDeletes));
        var expired = _reports.Values
            .Where(report => retentionPolicy.GetPolicy(report).RetentionPeriod is { } period && report.ReportedAtUtc <= nowUtc.Subtract(period))
            .OrderBy(report => report.ReportedAtUtc)
            .Take(maximumDeletes)
            .Select(report => report.ReportId)
            .ToArray();
        return Task.FromResult(expired.Count(id => _reports.TryRemove(id, out _)));
    }

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
