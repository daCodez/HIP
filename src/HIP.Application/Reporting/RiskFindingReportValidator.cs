using FluentValidation;
using HIP.Domain.Reporting;

namespace HIP.Application.Reporting;

public sealed class RiskFindingReportValidator : AbstractValidator<RiskFindingReport>
{
    public RiskFindingReportValidator()
    {
        RuleFor(report => report.SourceClient).IsInEnum();
        RuleFor(report => report.Platform).IsInEnum();
        RuleFor(report => report.TargetType).IsInEnum();
        RuleFor(report => report.RiskLevel).IsInEnum();
        RuleFor(report => report.ReporterTrustLevel).IsInEnum();
        RuleFor(report => report.Reason).NotEmpty();
        RuleFor(report => report.PrivacySafeEvidence).NotNull();
        RuleFor(report => report)
            .Must(report => !string.IsNullOrWhiteSpace(report.Domain) || !string.IsNullOrWhiteSpace(report.OriginalUrl))
            .WithMessage("A domain or original URL is required.");
        RuleFor(report => report)
            .Must(report => !string.IsNullOrWhiteSpace(report.UrlHash) || !string.IsNullOrWhiteSpace(report.OriginalUrl))
            .WithMessage("A URL hash or original URL is required.");
        RuleFor(report => report.PrivacySafeEvidence.ContainsPrivateContent)
            .Equal(false)
            .WithMessage("Reports containing private content are rejected.");
    }
}
