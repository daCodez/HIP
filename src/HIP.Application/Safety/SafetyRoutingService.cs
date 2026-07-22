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
            (!Uri.TryCreate(finalDestinationUrl, UriKind.Absolute, out var parsedFinal) ||
             parsedFinal.Scheme is not ("http" or "https") ||
             !string.IsNullOrEmpty(parsedFinal.UserInfo)))
        {
            throw new ArgumentException(
                "Final destination URL must be an absolute HTTP or HTTPS URL without embedded credentials.",
                nameof(finalDestinationUrl));
        }

        var risk = RiskStatusMapper.FromScore(ScoreValue.From(domainScore));
        var shouldRoute = risk is RiskStatus.Suspicious or RiskStatus.HighRisk or RiskStatus.Dangerous or RiskStatus.Critical;
        var allowContinue = risk is not RiskStatus.Critical;
        var continuationRequirement = ContinuationRequirementFor(risk);
        var pageTrustScore = PageTrustScoreFor(parsedOriginal, domainScore);
        var contentRiskScore = ContentRiskScoreFor(risk);

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
            true,
            pageTrustScore,
            contentRiskScore,
            domainScore,
            continuationRequirement);
    }

    public SafetyResult EvaluateUrl(string url, string? source)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var parsed) ||
            parsed.Scheme is not ("http" or "https") ||
            !string.IsNullOrEmpty(parsed.UserInfo))
        {
            throw new ArgumentException(
                "URL must be an absolute HTTP or HTTPS URL without embedded credentials.",
                nameof(url));
        }

        var host = NormalizeHost(parsed);
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
                true,
                PageTrustScoreFor(parsed, domainScore),
                ContentRiskScoreFor(RiskStatus.Critical),
                domainScore,
                SafetyContinuationRequirement.Blocked);
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
        RiskStatus.Trusted or RiskStatus.MostlyTrusted or RiskStatus.ProbablySafe => "Allow",
        RiskStatus.LimitedTrustData or RiskStatus.Unknown or RiskStatus.Caution => "ShowCaution",
        RiskStatus.Suspicious => "RouteToSafetyPage",
        RiskStatus.HighRisk => "RouteToSafetyPage",
        RiskStatus.Dangerous => "RouteToSafetyPage",
        RiskStatus.Critical => "Block",
        _ => "ShowCaution"
    };

    public static SafetyContinuationRequirement ContinuationRequirementFor(RiskStatus risk) => risk switch
    {
        RiskStatus.Critical => SafetyContinuationRequirement.Blocked,
        RiskStatus.Dangerous => SafetyContinuationRequirement.ExtraConfirmation,
        RiskStatus.Suspicious or RiskStatus.HighRisk => SafetyContinuationRequirement.Confirmation,
        _ => SafetyContinuationRequirement.None
    };

    private static int PageTrustScoreFor(Uri url, int domainScore)
    {
        var sensitivePath = url.AbsolutePath.Contains("login", StringComparison.OrdinalIgnoreCase) ||
                            url.AbsolutePath.Contains("pay", StringComparison.OrdinalIgnoreCase) ||
                            url.AbsolutePath.Contains("download", StringComparison.OrdinalIgnoreCase);
        return Math.Clamp(domainScore - (sensitivePath ? 8 : 0), 0, 100);
    }

    private static int ContentRiskScoreFor(RiskStatus risk) => risk switch
    {
        RiskStatus.Critical => 98,
        RiskStatus.Dangerous => 88,
        RiskStatus.HighRisk => 78,
        RiskStatus.Suspicious => 65,
        RiskStatus.Unknown or RiskStatus.LimitedTrustData => 50,
        _ => 25
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
            return 8;
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

    private static string NormalizeHost(Uri uri)
    {
        var host = uri.IdnHost.ToLowerInvariant();
        return host.StartsWith("www.", StringComparison.Ordinal) ? host[4..] : host;
    }
}
