using HIP.Application.PublicLookup;
using HIP.Domain.Risk;

namespace HIP.Application.Browser;

public sealed class BrowserPluginService(IPublicDomainLookupService publicDomainLookupService) : IBrowserPluginService
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

    public async Task<BrowserScoreSiteResponse> ScoreSiteAsync(BrowserScoreSiteRequest request, CancellationToken cancellationToken)
    {
        var domain = NormalizeDomainFromRequest(request.Domain, request.Url);
        var lookup = await publicDomainLookupService.LookupDomainAsync(domain, cancellationToken);
        var reasons = PlainEnglishReasons(lookup);

        return new BrowserScoreSiteResponse(
            lookup.Domain,
            lookup.FinalHipScore,
            lookup.FinalHipScore,
            lookup.Status.ToString(),
            reasons,
            lookup.VerificationStatus,
            lookup.SignedIdentityStatus,
            lookup.LastCheckedUtc,
            lookup.PublicLookupUrl);
    }

    public async Task<BrowserScanLinksResponse> ScanLinksAsync(BrowserScanLinksRequest request, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(request.PageUrl, UriKind.Absolute, out var pageUri) ||
            pageUri.Scheme is not ("http" or "https"))
        {
            throw new ArgumentException("A valid HTTP or HTTPS page URL is required.", nameof(request));
        }

        var results = new List<BrowserLinkRiskResult>();

        foreach (var link in request.Links.Where(link => !string.IsNullOrWhiteSpace(link)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(link, UriKind.Absolute, out var linkUri) ||
                linkUri.Scheme is not ("http" or "https"))
            {
                continue;
            }

            var domain = NormalizeHost(linkUri.Host);
            if (ShortenerDomains.Contains(domain))
            {
                results.Add(new BrowserLinkRiskResult(
                    linkUri.ToString(),
                    domain,
                    RiskStatus.HighRisk.ToString(),
                    38,
                    ["Shortened link detected"],
                    "ShowWarning",
                    true,
                    "Suspicious",
                    $"/lookup/domain/{Uri.EscapeDataString(domain)}"));
                continue;
            }

            var lookup = await publicDomainLookupService.LookupDomainAsync(domain, cancellationToken);
            var requiresIcon = RequiresAttention(lookup.Status) || IsVerifiedTrusted(lookup);
            results.Add(new BrowserLinkRiskResult(
                linkUri.ToString(),
                lookup.Domain,
                lookup.Status.ToString(),
                lookup.FinalHipScore,
                PlainEnglishReasons(lookup),
                RecommendedAction(lookup.Status),
                requiresIcon,
                LabelFor(lookup.Status, IsVerifiedTrusted(lookup)),
                lookup.PublicLookupUrl));
        }

        return new BrowserScanLinksResponse(pageUri.ToString(), results);
    }

    private static string NormalizeDomainFromRequest(string? domain, string? url)
    {
        if (!string.IsNullOrWhiteSpace(domain))
        {
            return DomainInputValidator.ValidateAndNormalize(domain);
        }

        if (Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https")
        {
            return DomainInputValidator.ValidateAndNormalize(uri.Host);
        }

        throw new ArgumentException("A valid domain or URL is required.");
    }

    private static string NormalizeHost(string host) => host.Replace("www.", string.Empty, StringComparison.OrdinalIgnoreCase).ToLowerInvariant();

    private static IReadOnlyCollection<string> PlainEnglishReasons(PublicDomainLookupResponse lookup)
    {
        var reasons = lookup.KnownRisks.Count > 0 ? lookup.KnownRisks : lookup.Explanations;
        return reasons.Count > 0
            ? reasons
            : ["HIP returned a score from public domain and origin signals without inspecting private page content."];
    }

    private static bool RequiresAttention(RiskStatus status) =>
        status is RiskStatus.Unknown or RiskStatus.Caution or RiskStatus.HighRisk or RiskStatus.Dangerous or RiskStatus.Critical;

    private static bool IsVerifiedTrusted(PublicDomainLookupResponse lookup) =>
        lookup.Status is RiskStatus.Trusted && lookup.VerificationStatus.Equals("Verified", StringComparison.OrdinalIgnoreCase);

    private static string RecommendedAction(RiskStatus status) => status switch
    {
        RiskStatus.HighRisk => "ShowWarning",
        RiskStatus.Dangerous or RiskStatus.Critical => "RouteToSafetyPage",
        RiskStatus.Unknown or RiskStatus.Caution => "ShowLabel",
        _ => "Allow"
    };

    private static string? LabelFor(RiskStatus status, bool verifiedTrusted)
    {
        if (verifiedTrusted)
        {
            return "Verified";
        }

        return status switch
        {
            RiskStatus.Unknown => "Unknown",
            RiskStatus.Caution => "Caution",
            RiskStatus.HighRisk => "Suspicious",
            RiskStatus.Dangerous or RiskStatus.Critical => "Dangerous",
            _ => null
        };
    }
}
