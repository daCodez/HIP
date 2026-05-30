using HIP.Domain.Risk;
using HIP.Domain.Scoring;

namespace HIP.Application.PublicLookup;

public sealed class PublicDomainLookupService : IPublicDomainLookupService
{
    private static readonly HashSet<string> ShortenerDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "buff.ly",
        "ow.ly",
        "rebrand.ly",
        "cutt.ly"
    };

    public Task<PublicDomainLookupResponse> LookupDomainAsync(string domain, CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var result = BuildSampleScore(normalized);
        var isVerified = normalized.Contains("verified", StringComparison.OrdinalIgnoreCase);
        var reasons = BuildReasons(normalized, result);
        var knownRisks = BuildKnownRisks(normalized, result.FinalScore.Status);

        var response = new PublicDomainLookupResponse(
            normalized,
            result.FinalScore.Score.Value,
            result.FinalScore.Score.Value,
            result.FinalScore.Status,
            isVerified ? "Verified" : "Unverified",
            knownRisks,
            reasons,
            result.ComponentScores.Select(score => score.Explanation).Append(result.FinalScore.Explanation).ToArray(),
            RecommendedActionFor(result.FinalScore.Status),
            DateTimeOffset.UtcNow,
            isVerified ? "PostQuantumSignaturePresent" : "NotConfigured",
            isVerified ? "WellKnownHipJsonPlaceholder" : "NotConfigured",
            isVerified ? "Verified Example Organization" : null,
            isVerified ? "ValidPlaceholder" : "Unknown",
            isVerified ? "Verified" : "Unverified",
            isVerified,
            isVerified,
            $"/lookup/{normalized}",
            result.ComponentScores.Append(result.FinalScore)
                .Select(score => new ScoreBreakdownItem(score.Category.ToString(), score.Score.Value, score.Status, score.Explanation, score.Reasons))
                .ToArray());

        return Task.FromResult(response);
    }

    private static HipScoreResult BuildSampleScore(string domain)
    {
        var isDangerousTestDomain = domain.Contains("danger", StringComparison.OrdinalIgnoreCase) ||
            domain.Contains("phishing", StringComparison.OrdinalIgnoreCase) ||
            domain.Contains("scam", StringComparison.OrdinalIgnoreCase);
        var isShortener = ShortenerDomains.Contains(domain) || domain.Contains("short", StringComparison.OrdinalIgnoreCase);
        var isVerified = domain.Contains("verified", StringComparison.OrdinalIgnoreCase);

        var baseDomainScore = isDangerousTestDomain ? 10 : isShortener ? 42 : isVerified ? 92 : 72;
        var websiteScore = isDangerousTestDomain ? 16 : domain.Contains("new", StringComparison.OrdinalIgnoreCase) ? 48 : isVerified ? 88 : 74;
        var linkScore = isDangerousTestDomain ? 18 : isShortener ? 38 : 70;
        var contentScore = isDangerousTestDomain ? 24 : 62;
        var organizationScore = isVerified ? 86 : 58;
        var deviceKeyScore = isVerified ? 90 : 55;

        return HipScoringModel.CalculateFinalScore([
            new WeightedScore(new ScoreComponent(ScoreCategory.Domain, ScoreValue.From(baseDomainScore), $"Domain reputation for {domain} is based on current HIP public signals.", [$"{domain} has a public domain reputation score of {baseDomainScore}/100."]), 2m),
            new WeightedScore(new ScoreComponent(ScoreCategory.Website, ScoreValue.From(websiteScore), "Website risk reflects origin verification and known behavior signals.", ["Website behavior has been evaluated with available public facts."]), 1m),
            new WeightedScore(new ScoreComponent(ScoreCategory.Link, ScoreValue.From(linkScore), "Link score reflects redirect and shortener risk signals.", ["No private user content was used in this lookup."]), 1m),
            new WeightedScore(new ScoreComponent(ScoreCategory.Sender, ScoreValue.From(60), "Sender reputation is unknown for a public domain-only lookup.", ["No sender identity was supplied."]), 0.5m),
            new WeightedScore(new ScoreComponent(ScoreCategory.Content, ScoreValue.From(contentScore), "Content score uses public website-level signals only.", ["No private content was inspected."]), 0.5m),
            new WeightedScore(new ScoreComponent(ScoreCategory.DeviceKey, ScoreValue.From(deviceKeyScore), "Device/key score reflects whether a signed HIP identity was found.", ["Initial lookup supports DNS TXT and .well-known/hip.json verification design."]), 0.75m),
            new WeightedScore(new ScoreComponent(ScoreCategory.Organization, ScoreValue.From(organizationScore), "Organization reputation has limited public data in the mock foundation.", ["Organization-level reputation is not yet backed by a database."]), 0.75m)
        ]);
    }

    public static RiskStatus StatusForScore(int score) => score switch
    {
        <= 20 => RiskStatus.Dangerous,
        <= 40 => RiskStatus.HighRisk,
        <= 60 => RiskStatus.Caution,
        <= 80 => RiskStatus.ProbablySafe,
        _ => RiskStatus.Trusted
    };

    public static string RecommendedActionFor(RiskStatus status) => status switch
    {
        RiskStatus.Trusted or RiskStatus.ProbablySafe => "Allow",
        RiskStatus.Caution or RiskStatus.Unknown => "ShowCaution",
        RiskStatus.HighRisk => "ShowWarning",
        RiskStatus.Dangerous => "RouteToSafetyPage",
        RiskStatus.Critical => "Block",
        _ => "ShowCaution"
    };

    private static IReadOnlyCollection<string> BuildReasons(string domain, HipScoreResult result)
    {
        var reasons = new List<string>
        {
            "HIP MVP scoring uses public-safe demo signals until live reputation, rules, AI, and threat data are connected.",
            "No private chat logs, browsing history, or raw user-submitted private content were used in this lookup."
        };

        if (domain.Contains("verified", StringComparison.OrdinalIgnoreCase))
        {
            reasons.Add("A placeholder signed identity signal is present for this demo domain.");
        }
        else
        {
            reasons.Add("No HIP signed website identity is configured yet.");
        }

        reasons.Add(result.FinalScore.Explanation);
        return reasons;
    }

    private static IReadOnlyCollection<string> BuildKnownRisks(string domain, RiskStatus status)
    {
        if (domain.Contains("danger", StringComparison.OrdinalIgnoreCase) ||
            domain.Contains("phishing", StringComparison.OrdinalIgnoreCase) ||
            domain.Contains("scam", StringComparison.OrdinalIgnoreCase))
        {
            return ["Known suspicious test-domain pattern detected", "MVP demo scoring classified this domain as dangerous."];
        }

        if (ShortenerDomains.Contains(domain) || domain.Contains("short", StringComparison.OrdinalIgnoreCase))
        {
            return ["Shortened URL behavior detected", "Shorteners can hide final destinations from users."];
        }

        return status is RiskStatus.HighRisk or RiskStatus.Dangerous or RiskStatus.Critical
            ? ["Domain has limited reputation history"]
            : [];
    }
}
