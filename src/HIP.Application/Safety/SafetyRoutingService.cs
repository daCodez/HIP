using HIP.Domain.Risk;
using HIP.Domain.Safety;
using HIP.Domain.Scoring;

namespace HIP.Application.Safety;

public sealed class SafetyRoutingService : ISafetyRoutingService
{
    public SafetyResult CreateUrlSafetyResult(string originalUrl, string? finalDestinationUrl, int domainScore, int? senderScore, IReadOnlyCollection<string> reasons)
    {
        if (!Uri.TryCreate(originalUrl, UriKind.Absolute, out var parsedOriginal) ||
            parsedOriginal.Scheme is not ("http" or "https"))
        {
            throw new ArgumentException("Original URL must be an absolute HTTP or HTTPS URL.", nameof(originalUrl));
        }

        if (finalDestinationUrl is not null &&
            !Uri.TryCreate(finalDestinationUrl, UriKind.Absolute, out _))
        {
            throw new ArgumentException("Final destination URL must be absolute when provided.", nameof(finalDestinationUrl));
        }

        var risk = RiskStatusMapper.FromScore(ScoreValue.From(domainScore));
        var shouldRoute = risk is RiskStatus.HighRisk or RiskStatus.Dangerous or RiskStatus.Critical;
        var allowContinue = risk is not (RiskStatus.Dangerous or RiskStatus.Critical);

        return new SafetyResult(
            originalUrl,
            finalDestinationUrl,
            risk,
            reasons.Count == 0 ? "HIP found limited public trust data for this URL." : string.Join(" ", reasons),
            domainScore,
            senderScore,
            allowContinue,
            shouldRoute,
            true,
            true);
    }
}
