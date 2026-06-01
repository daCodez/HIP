using HIP.Application.PublicLookup;
using HIP.Domain.Risk;

namespace HIP.Application.Browser;

/// <summary>
/// Provides privacy-safe browser extension scoring operations for the current site and page links.
/// </summary>
/// <remarks>
/// The service only evaluates domains and URLs supplied by the extension; it does not inspect page text,
/// form values, credentials, or private message content.
/// </remarks>
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

    /// <summary>
    /// Scores the active website domain for display in the browser extension popup.
    /// </summary>
    /// <param name="request">The current website URL and optional normalized domain.</param>
    /// <param name="cancellationToken">Token used to cancel lookup work.</param>
    /// <returns>A public-safe site score summary with plain-English reasons.</returns>
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

    /// <summary>
    /// Scans page links and returns only the public-safe risk signals needed by the extension UI.
    /// </summary>
    /// <param name="request">The current page URL and discovered links. Page text and form values are intentionally absent.</param>
    /// <param name="cancellationToken">Token used to cancel lookup work.</param>
    /// <returns>Per-link risk results including labels and safety-page routing decisions.</returns>
    public async Task<BrowserScanLinksResponse> ScanLinksAsync(BrowserScanLinksRequest request, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(request.PageUrl, UriKind.Absolute, out var pageUri) ||
            pageUri.Scheme is not ("http" or "https"))
        {
            throw new ArgumentException("A valid HTTP or HTTPS page URL is required.", nameof(request));
        }

        var pageDomain = NormalizeHost(pageUri.Host);
        var results = new List<BrowserLinkRiskResult>();

        foreach (var link in request.Links.Where(link => !string.IsNullOrWhiteSpace(link)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(link, UriKind.Absolute, out var linkUri) ||
                linkUri.Scheme is not ("http" or "https"))
            {
                continue;
            }

            var domain = NormalizeHost(linkUri.Host);
            if (IsSameDomainLink(pageDomain, domain))
            {
                results.Add(InternalLinkResult(linkUri, domain));
                continue;
            }

            if (ShortenerDomains.Contains(domain))
            {
                results.Add(new BrowserLinkRiskResult(
                    linkUri.ToString(),
                    domain,
                    RiskStatus.HighRisk.ToString(),
                    38,
                    ["Shortened link detected"],
                    "RouteToSafetyPage",
                    true,
                    "Suspicious",
                    $"/lookup/domain/{Uri.EscapeDataString(domain)}",
                    SafetyPageUrl(linkUri.ToString(), RiskStatus.HighRisk)));
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
                lookup.PublicLookupUrl,
                RequiresSafetyRoute(lookup.Status) ? SafetyPageUrl(linkUri.ToString(), lookup.Status) : null));
        }

        return new BrowserScanLinksResponse(pageUri.ToString(), results);
    }

    /// <summary>
    /// Normalizes user-supplied domain input, falling back to the host from the current URL.
    /// </summary>
    /// <param name="domain">The optional domain supplied by the browser extension.</param>
    /// <param name="url">The optional current page URL supplied by the browser extension.</param>
    /// <returns>A validated lowercase domain suitable for public lookup.</returns>
    /// <exception cref="ArgumentException">Thrown when neither input contains a valid domain.</exception>
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

    /// <summary>
    /// Normalizes a host for comparison and lookup without preserving a leading www prefix.
    /// </summary>
    /// <param name="host">The host name extracted from a URL.</param>
    /// <returns>A lowercase host value used for duplicate and same-domain checks.</returns>
    private static string NormalizeHost(string host) => host.Replace("www.", string.Empty, StringComparison.OrdinalIgnoreCase).ToLowerInvariant();

    /// <summary>
    /// Determines whether a link points to the same domain as the current page.
    /// </summary>
    /// <param name="pageDomain">The normalized current page domain.</param>
    /// <param name="linkDomain">The normalized link target domain.</param>
    /// <returns>True when the link is internal to the active website.</returns>
    private static bool IsSameDomainLink(string pageDomain, string linkDomain) =>
        pageDomain.Equals(linkDomain, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Creates the safe result used for same-domain links.
    /// </summary>
    /// <param name="linkUri">The parsed link URI.</param>
    /// <param name="domain">The normalized link domain.</param>
    /// <returns>A result that leaves normal internal links unmodified by the browser extension.</returns>
    /// <remarks>
    /// The current site is scored separately by the popup and warning banner. Internal links should not
    /// receive labels or safety-page redirects just because the public lookup has limited data.
    /// </remarks>
    private static BrowserLinkRiskResult InternalLinkResult(Uri linkUri, string domain) =>
        new(
            linkUri.ToString(),
            domain,
            RiskStatus.ProbablySafe.ToString(),
            80,
            ["Internal link on the current website; no external-domain risk signal was found."],
            "Allow",
            false,
            null,
            $"/lookup/domain/{Uri.EscapeDataString(domain)}",
            null);

    /// <summary>
    /// Selects the plain-English reasons returned to the extension without exposing private evidence.
    /// </summary>
    /// <param name="lookup">The public domain lookup result.</param>
    /// <returns>Public-safe reasons for score and status display.</returns>
    private static IReadOnlyCollection<string> PlainEnglishReasons(PublicDomainLookupResponse lookup)
    {
        var reasons = lookup.KnownRisks.Count > 0 ? lookup.KnownRisks : lookup.Explanations;
        return reasons.Count > 0
            ? reasons
            : ["HIP returned a score from public domain and origin signals without inspecting private page content."];
    }

    /// <summary>
    /// Determines whether the API should force a link badge regardless of browser scan mode.
    /// </summary>
    /// <param name="status">The public lookup status for the target domain.</param>
    /// <returns>True when the link is high-risk enough that the extension should always show a badge.</returns>
    /// <remarks>
    /// Unknown and caution links are left to the extension's scan-mode settings so normal browsing is not
    /// cluttered with low-confidence labels. High-risk or worse statuses are always surfaced.
    /// </remarks>
    private static bool RequiresAttention(RiskStatus status) =>
        status is RiskStatus.HighRisk or RiskStatus.Dangerous or RiskStatus.Critical;

    /// <summary>
    /// Determines whether a trusted link should show a positive verified-content label.
    /// </summary>
    /// <param name="lookup">The public lookup result for the target domain.</param>
    /// <returns>True when the target is both trusted and identity verified.</returns>
    private static bool IsVerifiedTrusted(PublicDomainLookupResponse lookup) =>
        lookup.Status is RiskStatus.Trusted && lookup.VerificationStatus.Equals("Verified", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Maps risk status to the action the browser extension should apply.
    /// </summary>
    /// <param name="status">The risk status from public lookup or MVP link heuristics.</param>
    /// <returns>The extension action name, such as Allow or RouteToSafetyPage.</returns>
    private static string RecommendedAction(RiskStatus status) => status switch
    {
        RiskStatus.HighRisk => "RouteToSafetyPage",
        RiskStatus.Dangerous or RiskStatus.Critical => "RouteToSafetyPage",
        RiskStatus.Unknown or RiskStatus.Caution => "ShowLabel",
        _ => "Allow"
    };

    /// <summary>
    /// Determines whether the link should be routed through HIP's safety page.
    /// </summary>
    /// <param name="status">The risk status for the target URL.</param>
    /// <returns>True for high-risk or worse statuses.</returns>
    private static bool RequiresSafetyRoute(RiskStatus status) =>
        status is RiskStatus.HighRisk or RiskStatus.Dangerous or RiskStatus.Critical;

    /// <summary>
    /// Builds a relative safety-page URL with the original target encoded to avoid unsafe HTML or URL injection.
    /// </summary>
    /// <param name="originalUrl">The original target URL selected by the user.</param>
    /// <param name="status">The risk status included for safety-page context.</param>
    /// <returns>A relative HIP safety-page URL.</returns>
    private static string SafetyPageUrl(string originalUrl, RiskStatus status) =>
        $"/safety?url={Uri.EscapeDataString(originalUrl)}&source=browser&risk={Uri.EscapeDataString(status.ToString())}";

    /// <summary>
    /// Maps a risk status to the compact label displayed beside a link.
    /// </summary>
    /// <param name="status">The public lookup status for the target domain.</param>
    /// <param name="verifiedTrusted">Whether the target has a trusted verified identity.</param>
    /// <returns>The optional label text to render beside the link.</returns>
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
