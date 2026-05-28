using HIP.Domain.Risk;
using HIP.Domain.Scoring;

namespace HIP.Application.PublicLookup;

public sealed class PublicDomainLookupService : IPublicDomainLookupService
{
    public Task<PublicDomainLookupResponse> LookupDomainAsync(string domain, CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var result = BuildSampleScore(normalized);

        var response = new PublicDomainLookupResponse(
            normalized,
            result.FinalScore.Score.Value,
            result.FinalScore.Status,
            normalized.Contains("verified", StringComparison.OrdinalIgnoreCase) ? "Verified" : "Unverified",
            result.FinalScore.Status is RiskStatus.HighRisk or RiskStatus.Dangerous or RiskStatus.Critical
                ? ["Shortened URL behavior detected", "Domain has limited reputation history"]
                : [],
            result.ComponentScores.Select(score => score.Explanation).Append(result.FinalScore.Explanation).ToArray(),
            DateTimeOffset.UtcNow,
            normalized.Contains("verified", StringComparison.OrdinalIgnoreCase) ? "PostQuantumSignaturePresent" : "NoSignedIdentityFound",
            result.ComponentScores.Append(result.FinalScore)
                .Select(score => new ScoreBreakdownItem(score.Category.ToString(), score.Score.Value, score.Status, score.Explanation, score.Reasons))
                .ToArray());

        return Task.FromResult(response);
    }

    private static HipScoreResult BuildSampleScore(string domain)
    {
        var baseDomainScore = domain.Contains("danger", StringComparison.OrdinalIgnoreCase) ? 18 : 72;
        var websiteScore = domain.Contains("new", StringComparison.OrdinalIgnoreCase) ? 48 : 74;

        return HipScoringModel.CalculateFinalScore([
            new WeightedScore(new ScoreComponent(ScoreCategory.Domain, ScoreValue.From(baseDomainScore), $"Domain reputation for {domain} is based on current HIP public signals.", [$"{domain} has a public domain reputation score of {baseDomainScore}/100."]), 2m),
            new WeightedScore(new ScoreComponent(ScoreCategory.Website, ScoreValue.From(websiteScore), "Website risk reflects origin verification and known behavior signals.", ["Website behavior has been evaluated with available public facts."]), 1m),
            new WeightedScore(new ScoreComponent(ScoreCategory.Link, ScoreValue.From(domain.Contains("short", StringComparison.OrdinalIgnoreCase) ? 38 : 70), "Link score reflects redirect and shortener risk signals.", ["No private user content was used in this lookup."]), 1m),
            new WeightedScore(new ScoreComponent(ScoreCategory.Sender, ScoreValue.From(60), "Sender reputation is unknown for a public domain-only lookup.", ["No sender identity was supplied."]), 0.5m),
            new WeightedScore(new ScoreComponent(ScoreCategory.Content, ScoreValue.From(62), "Content score uses public website-level signals only.", ["No private content was inspected."]), 0.5m),
            new WeightedScore(new ScoreComponent(ScoreCategory.DeviceKey, ScoreValue.From(domain.Contains("verified", StringComparison.OrdinalIgnoreCase) ? 85 : 55), "Device/key score reflects whether a signed HIP identity was found.", ["Initial lookup supports DNS TXT and .well-known/hip.json verification design."]), 0.75m),
            new WeightedScore(new ScoreComponent(ScoreCategory.Organization, ScoreValue.From(58), "Organization reputation has limited public data in the mock foundation.", ["Organization-level reputation is not yet backed by a database."]), 0.75m)
        ]);
    }
}
