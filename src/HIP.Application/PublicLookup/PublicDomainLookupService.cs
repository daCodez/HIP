using HIP.Application.Browser;
using HIP.Domain.Risk;
using HIP.Domain.Scoring;

namespace HIP.Application.PublicLookup;

/// <summary>
/// Builds public-safe HIP domain lookup results from stored scan data, falling back to a clear no-data state.
/// </summary>
/// <param name="browserScanResultRepository">Repository containing privacy-safe browser plugin scan summaries.</param>
public sealed class PublicDomainLookupService(IBrowserScanResultRepository browserScanResultRepository) : IPublicDomainLookupService
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

    /// <summary>
    /// Creates a lookup service with in-memory scan storage for isolated tests and simple development usage.
    /// </summary>
    public PublicDomainLookupService()
        : this(new InMemoryBrowserScanResultRepository())
    {
    }

    /// <summary>
    /// Looks up a domain using stored browser scan data when available and avoids exposing private scan payloads.
    /// </summary>
    /// <param name="domain">Domain requested by the public lookup API or page.</param>
    /// <param name="cancellationToken">Token used to cancel persistence reads.</param>
    /// <returns>Public-safe lookup result.</returns>
    public async Task<PublicDomainLookupResponse> LookupDomainAsync(string domain, CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var storedScan = await browserScanResultRepository.GetLatestByDomainAsync(normalized, cancellationToken);
        if (storedScan is null)
        {
            return BuildNoStoredDataResponse(normalized);
        }

        return BuildStoredScanResponse(normalized, storedScan);
    }

    /// <summary>
    /// Converts a stored browser plugin scan result into the public lookup shape without exposing page URL hashes or user identity.
    /// </summary>
    /// <param name="normalized">Normalized domain.</param>
    /// <param name="storedScan">Stored privacy-safe browser scan result.</param>
    /// <returns>Public lookup response sourced from the browser plugin scan.</returns>
    private static PublicDomainLookupResponse BuildStoredScanResponse(string normalized, BrowserScanResultRecord storedScan)
    {
        var status = ParseStatus(storedScan.Status, storedScan.Score);
        var isVerified = normalized.Contains("verified", StringComparison.OrdinalIgnoreCase);
        var reasons = storedScan.Reasons.Count > 0
            ? storedScan.Reasons
            : ["Last browser scan completed without sending page text, form values, or private messages."];
        var knownRisks = status is RiskStatus.HighRisk or RiskStatus.Dangerous or RiskStatus.Critical
            ? reasons
            : [];

        return new PublicDomainLookupResponse(
            normalized,
            storedScan.Score,
            storedScan.Score,
            status,
            storedScan.RiskLevel,
            isVerified ? "Verified" : "Unverified",
            knownRisks,
            reasons,
            reasons.Append("This lookup is based on the latest privacy-safe browser plugin scan summary.").ToArray(),
            storedScan.RecommendedAction,
            storedScan.LastCheckedUtc,
            isVerified ? "PostQuantumSignaturePresent" : "NotConfigured",
            isVerified ? "WellKnownHipJsonPlaceholder" : "NotConfigured",
            isVerified ? "Verified Example Organization" : null,
            isVerified ? "ValidPlaceholder" : "Unknown",
            isVerified ? "Verified" : "Unverified",
            isVerified,
            isVerified,
            $"/lookup/{normalized}",
            BuildStoredScanBreakdown(storedScan, status),
            storedScan.LinksScanned,
            storedScan.RiskyLinksFound,
            storedScan.SuspiciousLinksFound,
            storedScan.DangerousLinksFound,
            "BrowserPluginScan",
            "HIP is showing the latest privacy-safe browser plugin scan for this domain.");
    }

    /// <summary>
    /// Builds the explicit no-data state used when HIP has not yet stored a scan for the domain.
    /// </summary>
    /// <param name="normalized">Normalized domain.</param>
    /// <returns>Public lookup response with Unknown status and no private data.</returns>
    private static PublicDomainLookupResponse BuildNoStoredDataResponse(string normalized)
    {
        var message = "HIP has not scanned this domain yet.";
        return new PublicDomainLookupResponse(
            normalized,
            0,
            0,
            RiskStatus.Unknown,
            RiskStatus.Unknown.ToString(),
            "Unverified",
            [],
            [message, "No private reports, user identities, page URLs, or browsing history are exposed in public lookup."],
            [message],
            "ShowCaution",
            DateTimeOffset.UtcNow,
            "NotConfigured",
            "NotConfigured",
            null,
            "Unknown",
            "Unverified",
            null,
            false,
            $"/lookup/{normalized}",
            [
                new ScoreBreakdownItem("Domain", 0, RiskStatus.Unknown, "No stored HIP browser scan exists for this domain yet.", [message]),
                new ScoreBreakdownItem("Final", 0, RiskStatus.Unknown, "HIP needs a privacy-safe scan before assigning a domain-level score.", [message])
            ],
            null,
            null,
            null,
            null,
            "NoStoredData",
            message);
    }

    /// <summary>
    /// Builds a lightweight score breakdown from stored browser scan counts.
    /// </summary>
    /// <param name="storedScan">Stored privacy-safe browser scan result.</param>
    /// <param name="status">Mapped public risk status.</param>
    /// <returns>Public-safe score breakdown items.</returns>
    private static IReadOnlyCollection<ScoreBreakdownItem> BuildStoredScanBreakdown(BrowserScanResultRecord storedScan, RiskStatus status) =>
    [
        new ScoreBreakdownItem(
            "Website",
            storedScan.Score,
            status,
            "Website score reflects the latest stored browser plugin scan summary.",
            storedScan.Reasons),
        new ScoreBreakdownItem(
            "Link",
            LinkScoreFromCounts(storedScan),
            StatusForScore(LinkScoreFromCounts(storedScan)),
            $"Browser plugin scanned {storedScan.LinksScanned} links and found {storedScan.RiskyLinksFound} risky links.",
            [$"{storedScan.SuspiciousLinksFound} suspicious links and {storedScan.DangerousLinksFound} dangerous links were found."]),
        new ScoreBreakdownItem(
            "Final",
            storedScan.Score,
            status,
            "Final HIP score is sourced from the latest stored browser plugin scan.",
            storedScan.Reasons)
    ];

    /// <summary>
    /// Derives a simple link score from browser scan counts for public display.
    /// </summary>
    /// <param name="storedScan">Stored privacy-safe browser scan result.</param>
    /// <returns>Link score clamped to 0-100.</returns>
    private static int LinkScoreFromCounts(BrowserScanResultRecord storedScan)
    {
        if (storedScan.LinksScanned == 0)
        {
            return 60;
        }

        var penalty = storedScan.RiskyLinksFound * 10 + storedScan.DangerousLinksFound * 20;
        return Math.Clamp(100 - penalty, 0, 100);
    }

    /// <summary>
    /// Parses stored status text and falls back to score mapping when old clients send non-standard labels.
    /// </summary>
    /// <param name="status">Stored status label.</param>
    /// <param name="score">Stored score.</param>
    /// <returns>Mapped risk status.</returns>
    private static RiskStatus ParseStatus(string status, int score) =>
        Enum.TryParse<RiskStatus>(status, ignoreCase: true, out var parsed)
            ? parsed
            : StatusForScore(score);

    /// <summary>
    /// Legacy demo scoring helper retained for tests or future fallback experiments.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <returns>Demo HIP score result.</returns>
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

    /// <summary>
    /// Maps a 0-100 HIP score to a public risk status band.
    /// </summary>
    /// <param name="score">HIP score.</param>
    /// <returns>Risk status.</returns>
    public static RiskStatus StatusForScore(int score) => score switch
    {
        <= 20 => RiskStatus.Dangerous,
        <= 40 => RiskStatus.HighRisk,
        <= 60 => RiskStatus.Caution,
        <= 80 => RiskStatus.ProbablySafe,
        _ => RiskStatus.Trusted
    };

    /// <summary>
    /// Maps public risk status to a user-facing recommended action.
    /// </summary>
    /// <param name="status">Risk status.</param>
    /// <returns>Recommended action text.</returns>
    public static string RecommendedActionFor(RiskStatus status) => status switch
    {
        RiskStatus.Trusted or RiskStatus.ProbablySafe => "Allow",
        RiskStatus.Caution or RiskStatus.Unknown => "ShowCaution",
        RiskStatus.HighRisk => "ShowWarning",
        RiskStatus.Dangerous => "RouteToSafetyPage",
        RiskStatus.Critical => "Block",
        _ => "ShowCaution"
    };

    /// <summary>
    /// Builds legacy demo reasons without private data.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="result">Demo scoring result.</param>
    /// <returns>Public-safe reason list.</returns>
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

    /// <summary>
    /// Builds legacy demo risk labels without private report details.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="status">Risk status.</param>
    /// <returns>Known public risk summaries.</returns>
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
