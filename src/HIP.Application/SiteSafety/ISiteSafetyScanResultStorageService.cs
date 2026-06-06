using HIP.Application.Browser;

namespace HIP.Application.SiteSafety;

/// <summary>
/// Persists privacy-safe Site Safety scan summaries for lookup and dashboard aggregation.
/// </summary>
/// <remarks>
/// The storage boundary intentionally reuses the browser scan result store because browser-observed Site Safety scans
/// are the live data source currently consumed by the public lookup and admin dashboard. The service stores hashes,
/// scores, labels, counts, provider names, rule identifiers, and timestamps only; it must never store page text,
/// form values, credentials, cookies, private messages, or raw browsing history.
/// </remarks>
public interface ISiteSafetyScanResultStorageService
{
    /// <summary>
    /// Saves a Site Safety scan result as a privacy-safe domain/page summary.
    /// </summary>
    /// <param name="request">Original scan request containing the validated URL and structural observations.</param>
    /// <param name="result">Completed Site Safety scan result.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>A task that completes when the summary has been saved.</returns>
    Task SaveAsync(SiteSafetyScanRequest request, SiteSafetyScanResult result, CancellationToken cancellationToken);
}

/// <summary>
/// Bridges Site Safety scan output into HIP's existing privacy-safe browser scan result repository.
/// </summary>
public sealed class SiteSafetyScanResultStorageService(IBrowserScanResultService browserScanResultService) : ISiteSafetyScanResultStorageService
{
    private const string UnknownPluginVersion = "unknown";

    /// <inheritdoc />
    public async Task SaveAsync(SiteSafetyScanRequest request, SiteSafetyScanResult result, CancellationToken cancellationToken)
    {
        var signals = request.ObservedSignals ?? new SiteSafetyObservedSignals();
        var saveRequest = new BrowserScanResultSaveRequest(
            result.Domain,
            result.Url,
            result.FinalHipScore,
            MapDashboardStatus(result.Status),
            MapDashboardStatus(result.Status),
            BuildReasons(result),
            EstimateObservedLinkCount(signals),
            EstimateRiskyLinkCount(result, signals),
            EstimateSuspiciousLinkCount(result, signals),
            EstimateDangerousLinkCount(result, signals),
            MapRecommendedAction(result.Status),
            BuildMetadata(request, result),
            result.ScannedAtUtc);

        await browserScanResultService.SaveAsync(saveRequest, cancellationToken);
    }

    /// <summary>
    /// Converts Site Safety labels to the dashboard/public lookup labels already used by stored browser scans.
    /// </summary>
    /// <param name="status">Site Safety status.</param>
    /// <returns>Dashboard-compatible status label.</returns>
    private static string MapDashboardStatus(SiteSafetyScanStatus status) =>
        status switch
        {
            SiteSafetyScanStatus.Clean => "MostlyTrusted",
            SiteSafetyScanStatus.LimitedData => "LimitedTrustData",
            SiteSafetyScanStatus.Unknown => "Unknown",
            SiteSafetyScanStatus.Suspicious => "Suspicious",
            SiteSafetyScanStatus.HighRisk => "HighRisk",
            SiteSafetyScanStatus.Dangerous => "Dangerous",
            SiteSafetyScanStatus.ScanFailed => "Unknown",
            _ => "Unknown"
        };

    /// <summary>
    /// Maps Site Safety status to the action language used by browser scan storage and public lookup.
    /// </summary>
    /// <param name="status">Site Safety status.</param>
    /// <returns>Recommended action label.</returns>
    private static string MapRecommendedAction(SiteSafetyScanStatus status) =>
        status switch
        {
            SiteSafetyScanStatus.Clean => "Allow",
            SiteSafetyScanStatus.LimitedData => "ShowCaution",
            SiteSafetyScanStatus.Unknown => "ShowCaution",
            SiteSafetyScanStatus.Suspicious => "RouteToSafetyPage",
            SiteSafetyScanStatus.HighRisk => "RouteToSafetyPage",
            SiteSafetyScanStatus.Dangerous => "Block",
            SiteSafetyScanStatus.ScanFailed => "RequireReview",
            _ => "ShowCaution"
        };

    /// <summary>
    /// Builds concise public-safe reasons from scan reasons, warnings, and summary text.
    /// </summary>
    /// <param name="result">Site Safety scan result.</param>
    /// <returns>Plain-English reasons suitable for dashboard and lookup surfaces.</returns>
    private static IReadOnlyCollection<string> BuildReasons(SiteSafetyScanResult result)
    {
        var reasons = result.Reasons
            .Concat(result.Warnings.Select(warning => $"Warning: {warning}"))
            .Prepend(result.Summary)
            .Where(reason => !string.IsNullOrWhiteSpace(reason))
            .Select(reason => reason.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(10)
            .ToArray();

        return reasons.Length == 0
            ? ["HIP completed a privacy-safe Site Safety scan without storing page text or form values."]
            : reasons;
    }

    /// <summary>
    /// Estimates the amount of link-like structure observed without requiring the browser to upload all page links.
    /// </summary>
    /// <param name="signals">Privacy-safe browser observations.</param>
    /// <returns>Count used for live dashboard trend cards.</returns>
    private static int EstimateObservedLinkCount(SiteSafetyObservedSignals signals) =>
        Count(signals.RedirectChain) +
        Count(signals.ExternalScriptUrls) +
        Count(signals.DownloadLinks) +
        signals.ShortenedLinkCount +
        signals.ObfuscatedLinkCount;

    /// <summary>
    /// Estimates risk-bearing link signals from scan status and browser-observed counts.
    /// </summary>
    /// <param name="result">Site Safety scan result.</param>
    /// <param name="signals">Privacy-safe browser observations.</param>
    /// <returns>Risky link count for dashboard summaries.</returns>
    private static int EstimateRiskyLinkCount(SiteSafetyScanResult result, SiteSafetyObservedSignals signals)
    {
        var structuralRiskCount = signals.ShortenedLinkCount +
            signals.ObfuscatedLinkCount +
            Count(signals.DownloadLinks) +
            Math.Max(0, Count(signals.RedirectChain) - 1);

        return result.Status is SiteSafetyScanStatus.Suspicious or SiteSafetyScanStatus.HighRisk or SiteSafetyScanStatus.Dangerous
            ? Math.Max(1, structuralRiskCount)
            : structuralRiskCount;
    }

    /// <summary>
    /// Estimates suspicious link signals while keeping dangerous signals separate.
    /// </summary>
    /// <param name="result">Site Safety scan result.</param>
    /// <param name="signals">Privacy-safe browser observations.</param>
    /// <returns>Suspicious link count for dashboard summaries.</returns>
    private static int EstimateSuspiciousLinkCount(SiteSafetyScanResult result, SiteSafetyObservedSignals signals)
    {
        var suspiciousSignals = signals.ShortenedLinkCount +
            signals.ObfuscatedLinkCount +
            Math.Max(0, Count(signals.RedirectChain) - 1);

        return result.Status is SiteSafetyScanStatus.Suspicious or SiteSafetyScanStatus.HighRisk
            ? Math.Max(1, suspiciousSignals)
            : suspiciousSignals;
    }

    /// <summary>
    /// Estimates dangerous link signals from authoritative malware/phishing and dangerous scan outcomes.
    /// </summary>
    /// <param name="result">Site Safety scan result.</param>
    /// <param name="signals">Privacy-safe browser observations.</param>
    /// <returns>Dangerous link count for dashboard summaries.</returns>
    private static int EstimateDangerousLinkCount(SiteSafetyScanResult result, SiteSafetyObservedSignals signals)
    {
        var dangerousSignals = (signals.KnownMalwareIndicator ? 1 : 0) + (signals.KnownPhishingPattern ? 1 : 0);
        return result.Status is SiteSafetyScanStatus.Dangerous ? Math.Max(1, dangerousSignals) : dangerousSignals;
    }

    /// <summary>
    /// Builds bounded metadata that keeps provider and rule provenance visible without storing raw URLs or private data.
    /// </summary>
    /// <param name="request">Original scan request containing optional client provenance.</param>
    /// <param name="result">Site Safety scan result.</param>
    /// <returns>Privacy-safe metadata dictionary accepted by browser scan storage validation.</returns>
    private static IReadOnlyDictionary<string, string> BuildMetadata(SiteSafetyScanRequest request, SiteSafetyScanResult result) =>
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["source"] = "SiteSafetyScan",
            ["targetType"] = "Url",
            ["scanId"] = result.ScanId,
            ["siteSafetyStatus"] = result.Status.ToString(),
            ["confidence"] = result.ConfidenceLevel,
            ["domainTrustScore"] = result.DomainTrustScore.ToString(),
            ["pageTrustScore"] = result.PageTrustScore.ToString(),
            ["contentRiskScore"] = result.ContentRiskScore.ToString(),
            ["finalHipScore"] = result.FinalHipScore.ToString(),
            ["malwareRiskScore"] = result.MalwareRiskScore.ToString(),
            ["phishingRiskScore"] = result.PhishingRiskScore.ToString(),
            ["redirectRiskScore"] = result.RedirectRiskScore.ToString(),
            ["downloadRiskScore"] = result.DownloadRiskScore.ToString(),
            ["scriptRiskScore"] = result.ScriptRiskScore.ToString(),
            ["formRiskScore"] = result.FormRiskScore.ToString(),
            ["providerNames"] = JoinDistinct(result.ProviderEvidence.Select(evidence => evidence.ProviderName), 6),
            ["providerErrorCount"] = result.ProviderEvidence.Sum(evidence => evidence.Errors.Count).ToString(),
            ["matchedRuleIds"] = JoinDistinct((result.MatchedRules ?? Array.Empty<SiteSafetyRuleResult>()).Select(rule => rule.RuleId), 8),
            ["pluginVersion"] = string.IsNullOrWhiteSpace(request.PluginVersion) ? UnknownPluginVersion : request.PluginVersion.Trim(),
            ["scannedAtUtc"] = result.ScannedAtUtc.ToString("O")
        };

    /// <summary>
    /// Counts an optional collection without forcing callers to allocate empty arrays.
    /// </summary>
    /// <param name="items">Optional collection.</param>
    /// <returns>Collection count, or zero when null.</returns>
    private static int Count<T>(IReadOnlyCollection<T>? items) => items?.Count ?? 0;

    /// <summary>
    /// Joins short distinct values into a metadata-safe string under the storage service's value limit.
    /// </summary>
    /// <param name="values">Values to join.</param>
    /// <param name="take">Maximum number of values to include.</param>
    /// <returns>Comma-separated metadata value or "none".</returns>
    private static string JoinDistinct(IEnumerable<string> values, int take)
    {
        var joined = string.Join(",", values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(take));

        return string.IsNullOrWhiteSpace(joined) ? "none" : joined;
    }
}
