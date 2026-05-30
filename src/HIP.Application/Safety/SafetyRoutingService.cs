using HIP.Domain.Risk;
using HIP.Domain.Safety;
using HIP.Domain.Scoring;

namespace HIP.Application.Safety;

public sealed class SafetyRoutingService : ISafetyRoutingService
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
        var allowContinue = risk is not RiskStatus.Critical;

        return new SafetyResult(
            originalUrl,
            finalDestinationUrl,
            risk,
            reasons.Count == 0 ? "HIP found limited public trust data for this URL." : string.Join(" ", reasons),
            domainScore,
            senderScore,
            RecommendedActionFor(risk),
            allowContinue,
            shouldRoute,
            true,
            true);
    }

    public SafetyResult EvaluateUrl(string url, string? source)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var parsed) ||
            parsed.Scheme is not ("http" or "https"))
        {
            throw new ArgumentException("URL must be an absolute HTTP or HTTPS URL.", nameof(url));
        }

        var host = parsed.Host.Replace("www.", string.Empty, StringComparison.OrdinalIgnoreCase).ToLowerInvariant();
        var domainScore = ScoreFor(host);
        var reasons = ReasonsFor(host, source).ToArray();
        if (host.Contains("critical", StringComparison.OrdinalIgnoreCase))
        {
            return new SafetyResult(
                parsed.ToString(),
                null,
                RiskStatus.Critical,
                string.Join(" ", reasons),
                domainScore,
                null,
                RecommendedActionFor(RiskStatus.Critical),
                false,
                true,
                true,
                true);
        }

        return CreateUrlSafetyResult(parsed.ToString(), null, domainScore, null, reasons);
    }

    public static string DisplayRiskLevel(RiskStatus risk) => risk switch
    {
        RiskStatus.HighRisk => "Suspicious",
        _ => risk.ToString()
    };

    public static string RecommendedActionFor(RiskStatus risk) => risk switch
    {
        RiskStatus.Trusted or RiskStatus.ProbablySafe => "Allow",
        RiskStatus.Unknown or RiskStatus.Caution => "ShowCaution",
        RiskStatus.HighRisk => "RouteToSafetyPage",
        RiskStatus.Dangerous => "RouteToSafetyPage",
        RiskStatus.Critical => "Block",
        _ => "ShowCaution"
    };

    private static int ScoreFor(string host)
    {
        if (host.Contains("critical", StringComparison.OrdinalIgnoreCase))
        {
            return 5;
        }

        if (host.Contains("danger", StringComparison.OrdinalIgnoreCase) ||
            host.Contains("phishing", StringComparison.OrdinalIgnoreCase) ||
            host.Contains("scam", StringComparison.OrdinalIgnoreCase))
        {
            return 12;
        }

        if (ShortenerDomains.Contains(host) || host.Contains("short", StringComparison.OrdinalIgnoreCase))
        {
            return 35;
        }

        if (host.Contains("unknown", StringComparison.OrdinalIgnoreCase) ||
            host.Contains("new", StringComparison.OrdinalIgnoreCase))
        {
            return 55;
        }

        return 72;
    }

    private static IEnumerable<string> ReasonsFor(string host, string? source)
    {
        if (host.Contains("critical", StringComparison.OrdinalIgnoreCase))
        {
            yield return "Critical test-domain pattern detected.";
        }
        else if (host.Contains("danger", StringComparison.OrdinalIgnoreCase) ||
                 host.Contains("phishing", StringComparison.OrdinalIgnoreCase) ||
                 host.Contains("scam", StringComparison.OrdinalIgnoreCase))
        {
            yield return "Known dangerous test-domain pattern detected.";
        }
        else if (ShortenerDomains.Contains(host) || host.Contains("short", StringComparison.OrdinalIgnoreCase))
        {
            yield return "Shortened or suspicious link pattern detected.";
        }
        else
        {
            yield return "HIP found limited public trust data for this URL.";
        }

        yield return $"Source context: {NormalizeSource(source)}.";
    }

    private static string NormalizeSource(string? source) =>
        string.IsNullOrWhiteSpace(source) ? "unknown" : source.Trim().ToLowerInvariant();
}
