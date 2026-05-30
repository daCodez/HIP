using FluentValidation;
using HIP.Application.Review;
using HIP.Application.SelfHealing;
using HIP.Domain.Reporting;
using HIP.Domain.Review;
using HIP.Domain.Risk;
using HIP.Domain.SelfHealing;

namespace HIP.Application.Reporting;

public sealed class RiskFindingIngestionService(
    IValidator<RiskFindingReport> validator,
    IRiskFindingReportRepository repository,
    IReviewQueueService reviewQueueService,
    IPatternDetectionService patternDetectionService,
    IPrivacyHashingService hashingService) : IRiskFindingIngestionService
{
    public async Task<RiskFindingIngestionResponse> IngestAsync(RiskFindingReport report, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(report);
        var validation = await validator.ValidateAsync(report, cancellationToken);
        if (!validation.IsValid)
        {
            return new RiskFindingIngestionResponse(false, null, null, report.RiskLevel, false, string.Join(" ", validation.Errors.Select(error => error.ErrorMessage)));
        }

        var normalizedDomain = NormalizeDomain(report.Domain, report.OriginalUrl);
        var normalized = report with
        {
            ReportId = string.IsNullOrWhiteSpace(report.ReportId) ? $"risk-report-{Guid.NewGuid():N}" : report.ReportId,
            Domain = normalizedDomain,
            UrlHash = string.IsNullOrWhiteSpace(report.UrlHash) ? hashingService.Hash(report.OriginalUrl!) : report.UrlHash,
            DetectedAtUtc = report.DetectedAtUtc == default ? DateTimeOffset.UtcNow : report.DetectedAtUtc,
            PrivacySafeEvidence = report.PrivacySafeEvidence with { ContainsPrivateContent = false }
        };

        await repository.AddAsync(normalized, cancellationToken);
        var reviewCreated = CreateReviewIfNeeded(normalized);

        return new RiskFindingIngestionResponse(true, normalized.ReportId, normalized.Domain, normalized.RiskLevel, reviewCreated, "Risk finding accepted with privacy-safe evidence only.");
    }

    public Task<IReadOnlyCollection<RiskFindingReport>> ListReportsAsync(CancellationToken cancellationToken) =>
        repository.ListAsync(cancellationToken);

    public async Task<IReadOnlyCollection<PatternCluster>> DetectPatternsAsync(CancellationToken cancellationToken)
    {
        var reports = await repository.ListAsync(cancellationToken);
        var findings = reports.Select(ToSuspiciousFinding).ToArray();
        return patternDetectionService.DetectPatterns(findings);
    }

    private bool CreateReviewIfNeeded(RiskFindingReport report)
    {
        if (report.RiskLevel is not (RiskStatus.HighRisk or RiskStatus.Dangerous or RiskStatus.Critical))
        {
            return false;
        }

        reviewQueueService.Create(new ReviewItem(
            "",
            ReviewType.SuspiciousFinding,
            report.TargetType,
            report.Domain,
            $"Review {report.RiskLevel} report for {report.Domain}",
            report.Reason,
            report.RiskLevel,
            ReviewStatus.Open,
            report.RiskLevel == RiskStatus.Critical ? ReviewPriority.Critical : ReviewPriority.High,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            report.SourceClient.ToString(),
            null,
            report.Platform.ToString(),
            report.PrivacySafeEvidence.Summary,
            report.PrivacySafeEvidence.Facts,
            "Review privacy-safe evidence and decide whether to adjust rules or reputation.",
            null,
            null));

        return true;
    }

    private static SuspiciousFinding ToSuspiciousFinding(RiskFindingReport report) =>
        new(
            report.ReportId,
            ToFindingType(report),
            report.Domain,
            report.UrlHash ?? string.Empty,
            report.Platform.ToString(),
            report.RiskLevel,
            report.Reason,
            report.DetectedAtUtc,
            ToFindingSourceType(report.SourceClient),
            report.ReporterTrustLevel,
            report.PrivacySafeEvidence.Facts);

    private static FindingType ToFindingType(RiskFindingReport report)
    {
        var reason = report.Reason.ToLowerInvariant();
        if (reason.Contains("shortener", StringComparison.Ordinal) || reason.Contains("shortened", StringComparison.Ordinal))
        {
            return FindingType.ShortenedUrlAbuse;
        }

        if (reason.Contains("obfuscat", StringComparison.Ordinal))
        {
            return FindingType.ObfuscatedUrl;
        }

        if (reason.Contains("redirect", StringComparison.Ordinal))
        {
            return FindingType.SuspiciousRedirectChain;
        }

        if (reason.Contains("phishing", StringComparison.Ordinal))
        {
            return FindingType.PhishingLanguage;
        }

        return FindingType.Unknown;
    }

    private static FindingSourceType ToFindingSourceType(SourceClient sourceClient) => sourceClient switch
    {
        SourceClient.BrowserPlugin => FindingSourceType.BrowserExtension,
        SourceClient.SecondLifeHud => FindingSourceType.VirtualWorld,
        SourceClient.ApiClient => FindingSourceType.Api,
        SourceClient.ManualReport => FindingSourceType.Api,
        _ => FindingSourceType.Unknown
    };

    private static string NormalizeDomain(string domain, string? originalUrl)
    {
        var value = string.IsNullOrWhiteSpace(domain) && !string.IsNullOrWhiteSpace(originalUrl) && Uri.TryCreate(originalUrl, UriKind.Absolute, out var uri)
            ? uri.Host
            : domain;

        return (value ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant().Replace("www.", string.Empty, StringComparison.OrdinalIgnoreCase);
    }

}
