using FluentValidation;
using HIP.Domain.Reporting;

namespace HIP.Application.Reporting;

public sealed class PrivacySafeReportValidator : AbstractValidator<PrivacySafeReport>
{
    public const int MaxReasonLength = 500;
    public const int MaxEvidenceSummaryLength = 500;

    public PrivacySafeReportValidator()
    {
        RuleFor(report => report.ReportType).IsInEnum();
        RuleFor(report => report.Source).IsInEnum();
        RuleFor(report => report.Platform).IsInEnum();
        RuleFor(report => report.RiskLevel).IsInEnum();
        RuleFor(report => report.Domain).NotEmpty().MaximumLength(253).Must(BeSafeDomain).WithMessage("Domain format is invalid.");
        RuleFor(report => report.RiskyUrl)
            .Must(url => string.IsNullOrWhiteSpace(url) || Uri.TryCreate(url, UriKind.Absolute, out _))
            .WithMessage("Risky URL must be an absolute URL when supplied.");
        RuleFor(report => report.ReasonSummary).NotEmpty().MaximumLength(MaxReasonLength).Must(NotContainPrivateContent).WithMessage("Reason summary appears to contain private content.");
        RuleFor(report => report.PrivacySafeEvidence).NotNull();
        RuleFor(report => report.PrivacySafeEvidence.Summary).MaximumLength(MaxEvidenceSummaryLength).Must(NotContainPrivateContent).WithMessage("Evidence summary appears to contain private content.");
        RuleFor(report => report.PrivacySafeEvidence.ContainsPrivateContent).Equal(false).WithMessage("Reports containing private content are rejected.");
        RuleFor(report => report.PrivacySafeEvidence.Facts)
            .Must(facts => facts is null || facts.Count <= 20)
            .WithMessage("Reports contain too many evidence facts.");
        RuleFor(report => report.PrivacySafeEvidence.Facts)
            .Must(facts => facts is null || facts.All(pair => NotContainPrivateContent(pair.Key) && NotContainPrivateContent(pair.Value)))
            .WithMessage("Evidence facts appear to contain private content.");
    }

    private static bool BeSafeDomain(string domain) =>
        Uri.CheckHostName(domain.Trim().TrimEnd('.')) is UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6;

    public static bool NotContainPrivateContent(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        var markers = new[]
        {
            "private chat",
            "private message",
            "password",
            "token=",
            "authorization:",
            "form contents",
            "full chat log",
            "raw private"
        };

        return !markers.Any(marker => value.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }
}
