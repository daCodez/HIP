using FluentValidation;
using HIP.Domain.Scoring;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HIP.Application.SiteSafety;

/// <summary>
/// MVP implementation of HIP's Site Safety Scan layer.
/// </summary>
/// <param name="validator">Validator that blocks unsafe scan targets and malformed input.</param>
/// <param name="logger">Structured logger for safe scan telemetry.</param>
public sealed class SiteSafetyScanner(
    IValidator<SiteSafetyScanRequest> validator,
    ILogger<SiteSafetyScanner> logger) : ISiteSafetyScanner
{
    private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(5);

    private static readonly ConcurrentDictionary<string, CachedSiteSafetyScan> RecentScans = new();

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

    private static readonly HashSet<string> RiskyTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "zip",
        "mov",
        "top",
        "xyz",
        "ru",
        "tk"
    };

    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe",
        ".dll",
        ".bat",
        ".cmd",
        ".scr",
        ".ps1",
        ".vbs",
        ".js",
        ".jar",
        ".apk",
        ".msi"
    };

    private static readonly HashSet<string> ArchiveExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip",
        ".rar",
        ".7z",
        ".iso"
    };

    /// <summary>
    /// Runs a Site Safety Scan using URL structure and privacy-safe observed facts.
    /// </summary>
    /// <param name="request">The scan request.</param>
    /// <param name="cancellationToken">Token used to cancel scan work.</param>
    /// <returns>A Site Safety Scan result with score impact across page, content, and final HIP score.</returns>
    public async Task<SiteSafetyScanResult> ScanAsync(SiteSafetyScanRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        logger.LogInformation("Starting HIP Site Safety Scan for URL host.");

        try
        {
            await validator.ValidateAndThrowAsync(request, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();

            var uri = new Uri(request.Url, UriKind.Absolute);
            var domain = NormalizeHost(uri.Host);
            var cacheKey = BuildCacheKey(request);
            if (TryGetCachedResult(cacheKey, out var cached))
            {
                logger.LogInformation("Returned cached HIP Site Safety Scan for domain {Domain}.", domain);
                return cached;
            }

            var signals = request.ObservedSignals ?? new SiteSafetyObservedSignals();
            var context = Analyze(uri, domain, signals);
            var scores = BuildScoreImpact(context);
            var status = DetermineStatus(context);
            var summary = BuildSummary(status, context);

            logger.LogInformation("Completed HIP Site Safety Scan with status {Status} for domain {Domain}.", status, domain);
            var result = new SiteSafetyScanResult(
                $"site-safety-{Guid.NewGuid():N}",
                SanitizeUrl(uri),
                domain,
                DateTimeOffset.UtcNow,
                context.MalwareRiskScore,
                context.PhishingRiskScore,
                context.RedirectRiskScore,
                context.ScriptRiskScore,
                context.DownloadRiskScore,
                context.FormRiskScore,
                context.ReputationRiskScore,
                context.OverallSafetyRiskScore,
                status,
                summary,
                context.Reasons,
                context.Warnings,
                context.PositiveSignals,
                context.NegativeSignals,
                ConfidenceLevel(context),
                scores.DomainTrustScore,
                scores.PageTrustScore,
                scores.ContentRiskScore,
                scores.FinalHipScore,
                scores);
            RecentScans[cacheKey] = new CachedSiteSafetyScan(result, DateTimeOffset.UtcNow.Add(CacheDuration));
            return result;
        }
        catch (ValidationException)
        {
            logger.LogWarning("HIP Site Safety Scan rejected invalid or unsafe input.");
            throw;
        }
        catch (ArgumentException)
        {
            logger.LogWarning("HIP Site Safety Scan rejected invalid input.");
            throw;
        }
        catch (OperationCanceledException)
        {
            logger.LogWarning("HIP Site Safety Scan was cancelled.");
            throw;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "HIP Site Safety Scan failed safely.");
            return FailedResult(request.Url);
        }
    }

    /// <summary>
    /// Converts the URL and observed signals into individual risk scores and explanations.
    /// </summary>
    /// <param name="uri">Validated scan URI.</param>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="signals">Privacy-safe observed scan facts.</param>
    /// <returns>Internal scan context used for status and score impact calculation.</returns>
    private static SiteSafetyContext Analyze(Uri uri, string domain, SiteSafetyObservedSignals signals)
    {
        var reasons = new List<string>();
        var warnings = new List<string>();
        var positive = new List<string>();
        var negative = new List<string>();

        var malwareRisk = signals.KnownMalwareIndicator ? 95 : 0;
        var phishingRisk = signals.KnownPhishingPattern ? 85 : 0;
        var redirectRisk = RedirectRisk(uri, signals, reasons, negative);
        var scriptRisk = ScriptRisk(signals, reasons, warnings, negative);
        var downloadRisk = DownloadRisk(signals, reasons, warnings, negative);
        var formRisk = FormRisk(signals, reasons, warnings, negative);
        var reputationRisk = ReputationRisk(domain, signals, reasons, negative);

        if (uri.Scheme == "https")
        {
            positive.Add("HTTPS is present, which protects transport encryption but does not prove the site is trusted.");
        }
        else
        {
            warnings.Add("This page does not use HTTPS.");
            negative.Add("Missing HTTPS increases page trust risk.");
            phishingRisk = Math.Max(phishingRisk, 20);
        }

        if (ShortenerDomains.Contains(domain))
        {
            redirectRisk = Math.Max(redirectRisk, 45);
            phishingRisk = Math.Max(phishingRisk, 35);
            negative.Add("The URL uses a known URL shortener, which can hide the final destination.");
        }

        if (HasStrangeQuery(uri))
        {
            phishingRisk = Math.Max(phishingRisk, 35);
            negative.Add("The URL contains unusual query parameters often seen in tracking or redirect abuse.");
        }

        if (signals.ContainsScamWording || signals.ContainsUrgencyWording || signals.ContainsImpersonationWording)
        {
            phishingRisk = Math.Max(phishingRisk, signals.KnownPhishingPattern ? phishingRisk : 55);
            negative.Add("Scam, urgency, or impersonation wording was detected by a privacy-safe client scan.");
            reasons.Add("Scam-like wording raises phishing risk.");
        }

        if (signals.KnownMalwareIndicator)
        {
            warnings.Add("HIP found a strong malware indicator.");
            negative.Add("Known malware indicator matched.");
            reasons.Add("HIP found strong malware or phishing indicators. Avoid this page.");
        }

        if (signals.KnownPhishingPattern)
        {
            warnings.Add("HIP found a known phishing pattern.");
            negative.Add("Known phishing pattern matched.");
        }

        if (downloadRisk == 0)
        {
            reasons.Add("No dangerous downloads were found.");
        }

        if (redirectRisk == 0)
        {
            reasons.Add("No suspicious redirects were found.");
        }

        if (!signals.TrustDataAvailable)
        {
            reasons.Add("The domain has limited reputation history.");
        }

        var overallRisk = WeightedRisk(malwareRisk, phishingRisk, redirectRisk, scriptRisk, downloadRisk, formRisk, reputationRisk);
        return new SiteSafetyContext(
            malwareRisk,
            phishingRisk,
            redirectRisk,
            scriptRisk,
            downloadRisk,
            formRisk,
            reputationRisk,
            overallRisk,
            signals.TrustDataAvailable,
            reasons.Distinct().ToArray(),
            warnings.Distinct().ToArray(),
            positive.Distinct().ToArray(),
            negative.Distinct().ToArray());
    }

    /// <summary>
    /// Scores redirect risk without following unlimited redirects or probing private networks.
    /// </summary>
    /// <param name="uri">Validated URL.</param>
    /// <param name="signals">Observed redirect signals.</param>
    /// <param name="reasons">Reason list to update.</param>
    /// <param name="negative">Negative signal list to update.</param>
    /// <returns>0-100 redirect risk score.</returns>
    private static int RedirectRisk(Uri uri, SiteSafetyObservedSignals signals, ICollection<string> reasons, ICollection<string> negative)
    {
        var chain = signals.RedirectChain ?? [];
        var risk = chain.Count > 3 ? 45 : 0;

        if (chain.Any(link => Uri.TryCreate(link, UriKind.Absolute, out var redirectUri) && IsSuspiciousRedirect(uri, redirectUri)))
        {
            risk = Math.Max(risk, 60);
            negative.Add("This page redirects through one or more unusual URLs, which may increase risk.");
            reasons.Add("This page redirects through one or more unusual URLs, which may increase risk.");
        }

        return risk;
    }

    /// <summary>
    /// Scores script risk using counts and source URLs only, never script contents.
    /// </summary>
    /// <param name="signals">Observed script facts.</param>
    /// <param name="reasons">Reason list to update.</param>
    /// <param name="warnings">Warning list to update.</param>
    /// <param name="negative">Negative signal list to update.</param>
    /// <returns>0-100 script risk score.</returns>
    private static int ScriptRisk(SiteSafetyObservedSignals signals, ICollection<string> reasons, ICollection<string> warnings, ICollection<string> negative)
    {
        var externalScripts = signals.ExternalScriptUrls?.Count ?? 0;
        var risk = Math.Min(70, signals.SuspiciousScriptPatternCount * 25 + Math.Max(0, signals.InlineScriptCount - 8) * 3 + Math.Max(0, externalScripts - 12) * 2);
        if (risk > 0)
        {
            warnings.Add("Script structure should be reviewed before trusting this page.");
            negative.Add("External, inline, or suspicious JavaScript patterns increased script risk.");
            reasons.Add("HIP saw script signals that increase content risk without executing scripts.");
        }

        return risk;
    }

    /// <summary>
    /// Scores download risk and treats archives as review-needed rather than automatically dangerous.
    /// </summary>
    /// <param name="signals">Observed download links.</param>
    /// <param name="reasons">Reason list to update.</param>
    /// <param name="warnings">Warning list to update.</param>
    /// <param name="negative">Negative signal list to update.</param>
    /// <returns>0-100 download risk score.</returns>
    private static int DownloadRisk(SiteSafetyObservedSignals signals, ICollection<string> reasons, ICollection<string> warnings, ICollection<string> negative)
    {
        var links = signals.DownloadLinks ?? [];
        var executableCount = links.Count(link => ExecutableExtensions.Contains(Path.GetExtension(SafePath(link))));
        var archiveCount = links.Count(link => ArchiveExtensions.Contains(Path.GetExtension(SafePath(link))));
        var risk = Math.Clamp(executableCount * 45 + archiveCount * 18, 0, 95);

        if (executableCount > 0)
        {
            warnings.Add("This page links to executable files that should not be downloaded unless the source is trusted.");
            negative.Add("Executable download links raised download risk.");
            reasons.Add("This page links to executable files that should be reviewed before downloading.");
        }

        if (archiveCount > 0)
        {
            warnings.Add("This page links to compressed or disk image files that need review.");
            negative.Add("Archive download links require review but are not automatically dangerous.");
            reasons.Add("This page links to compressed files that should be reviewed before downloading.");
        }

        return risk;
    }

    /// <summary>
    /// Scores login, password, and payment form risk without reading or sending field values.
    /// </summary>
    /// <param name="signals">Observed form facts.</param>
    /// <param name="reasons">Reason list to update.</param>
    /// <param name="warnings">Warning list to update.</param>
    /// <param name="negative">Negative signal list to update.</param>
    /// <returns>0-100 form risk score.</returns>
    private static int FormRisk(SiteSafetyObservedSignals signals, ICollection<string> reasons, ICollection<string> warnings, ICollection<string> negative)
    {
        var risk = 0;
        if (signals.HasLoginForm || signals.HasPasswordField)
        {
            risk += signals.TrustDataAvailable ? 18 : 45;
            warnings.Add("This page contains login fields; verify the domain before entering credentials.");
            negative.Add("Login or password fields increased form risk.");
            reasons.Add("This page contains login fields, but HIP has limited trust data for the domain.");
        }

        if (signals.HasPaymentField)
        {
            risk += signals.TrustDataAvailable ? 20 : 50;
            warnings.Add("This page contains payment fields; review the domain and identity before entering payment details.");
            negative.Add("Payment fields increased form risk.");
        }

        return Math.Clamp(risk, 0, 90);
    }

    /// <summary>
    /// Scores reputation risk from public-safe reports, risky TLDs, and optional reputation scores.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="signals">Observed reputation facts.</param>
    /// <param name="reasons">Reason list to update.</param>
    /// <param name="negative">Negative signal list to update.</param>
    /// <returns>0-100 reputation risk score.</returns>
    private static int ReputationRisk(string domain, SiteSafetyObservedSignals signals, ICollection<string> reasons, ICollection<string> negative)
    {
        var risk = 0;
        if (RiskyTlds.Contains(domain.Split('.').LastOrDefault() ?? string.Empty))
        {
            risk = Math.Max(risk, 25);
            negative.Add("The domain uses a TLD that can require extra review in early HIP scoring.");
        }

        if (signals.KnownAbuseReports > 0)
        {
            risk = Math.Max(risk, Math.Min(85, 30 + signals.KnownAbuseReports * 10));
            negative.Add("Known abuse reports increased reputation risk.");
            reasons.Add("Known abuse reports are present for this page or domain.");
        }

        if (signals.DomainReputationScore is < 50)
        {
            risk = Math.Max(risk, 100 - signals.DomainReputationScore.Value);
            negative.Add("Domain reputation is weak.");
        }

        if (signals.PageReputationScore is < 50)
        {
            risk = Math.Max(risk, 100 - signals.PageReputationScore.Value);
            negative.Add("Page reputation is weak.");
        }

        return Math.Clamp(risk, 0, 100);
    }

    /// <summary>
    /// Builds HIP score impact without replacing domain, reputation, or identity scoring.
    /// </summary>
    /// <param name="context">Safety scan context.</param>
    /// <returns>Score impact used by the larger HIP scoring model.</returns>
    private static SiteSafetyScoreImpact BuildScoreImpact(SiteSafetyContext context)
    {
        var domainTrust = Math.Clamp(80 - context.ReputationRiskScore, 0, 100);
        var pageTrust = Math.Clamp(82 - context.PhishingRiskScore / 2 - context.RedirectRiskScore / 3 - context.FormRiskScore / 3 - context.ReputationRiskScore / 4, 0, 100);
        var contentRisk = Math.Clamp(context.MalwareRiskScore / 2 + context.ScriptRiskScore / 3 + context.DownloadRiskScore / 3 + context.PhishingRiskScore / 3, 0, 100);
        var contentTrust = Math.Clamp(100 - contentRisk, 0, 100);

        if (context.MalwareRiskScore >= 90)
        {
            pageTrust = Math.Min(pageTrust, 35);
            contentTrust = Math.Min(contentTrust, 30);
        }

        if (context.DownloadRiskScore >= 45)
        {
            pageTrust = Math.Min(pageTrust, 58);
            contentTrust = Math.Min(contentTrust, 70);
        }

        if (!context.TrustDataAvailable)
        {
            domainTrust = Math.Min(domainTrust, 60);
            pageTrust = Math.Min(pageTrust, 60);
            contentTrust = Math.Min(contentTrust, context.OverallSafetyRiskScore > 0 ? 70 : 60);
        }

        var final = HipScoringModel.CalculateFinalScore([
            new WeightedScore(new ScoreComponent(ScoreCategory.Domain, ScoreValue.From(domainTrust), "DomainTrustScore is only partially affected by Site Safety reputation signals.", ["Site Safety does not replace domain reputation or identity."]), 1.25m),
            new WeightedScore(new ScoreComponent(ScoreCategory.Website, ScoreValue.From(pageTrust), "PageTrustScore is affected by phishing, redirect, form, and reputation risk.", ["Page-level safety findings adjust page trust."]), 1.5m),
            new WeightedScore(new ScoreComponent(ScoreCategory.Content, ScoreValue.From(contentTrust), "ContentRiskScore is derived from malware, scripts, downloads, and phishing indicators.", ["Content risk lowers content trust but does not alone prove identity."]), 1.5m)
        ]);

        return new SiteSafetyScoreImpact(domainTrust, pageTrust, contentRisk, final.FinalScore.Score.Value, final.ComponentScores);
    }

    /// <summary>
    /// Determines the status label from risk scores and trust-data availability.
    /// </summary>
    /// <param name="context">Safety scan context.</param>
    /// <returns>Scan status.</returns>
    private static SiteSafetyScanStatus DetermineStatus(SiteSafetyContext context)
    {
        if (context.MalwareRiskScore >= 90 || context.PhishingRiskScore >= 85)
        {
            return SiteSafetyScanStatus.Dangerous;
        }

        if (context.DownloadRiskScore >= 45)
        {
            return SiteSafetyScanStatus.Suspicious;
        }

        if (context.OverallSafetyRiskScore >= 65)
        {
            return SiteSafetyScanStatus.HighRisk;
        }

        if (context.OverallSafetyRiskScore >= 30)
        {
            return SiteSafetyScanStatus.Suspicious;
        }

        return context.TrustDataAvailable ? SiteSafetyScanStatus.Clean : SiteSafetyScanStatus.LimitedData;
    }

    /// <summary>
    /// Builds a plain-English summary that avoids overclaiming trust for clean scans.
    /// </summary>
    /// <param name="status">Scan status.</param>
    /// <param name="context">Safety scan context.</param>
    /// <returns>User-facing summary.</returns>
    private static string BuildSummary(SiteSafetyScanStatus status, SiteSafetyContext context) => status switch
    {
        SiteSafetyScanStatus.Dangerous => "HIP found strong malware or phishing indicators. Avoid this page.",
        SiteSafetyScanStatus.HighRisk => "HIP found high-risk safety signals on this page.",
        SiteSafetyScanStatus.Suspicious => "HIP found suspicious page behavior that should be reviewed.",
        SiteSafetyScanStatus.Clean => "HIP did not find obvious malware or phishing on this page.",
        SiteSafetyScanStatus.LimitedData => "HIP did not find obvious malware or phishing on this page, but this website has limited trust data.",
        SiteSafetyScanStatus.ScanFailed => "HIP could not complete the site safety scan safely.",
        _ => "HIP has limited safety information for this page."
    };

    /// <summary>
    /// Combines individual risk scores with heavier weighting for malware and phishing.
    /// </summary>
    /// <returns>0-100 overall risk score.</returns>
    private static int WeightedRisk(int malware, int phishing, int redirects, int scripts, int downloads, int forms, int reputation) =>
        Math.Clamp((int)Math.Round(malware * 0.26 + phishing * 0.24 + redirects * 0.12 + scripts * 0.11 + downloads * 0.12 + forms * 0.09 + reputation * 0.06), 0, 100);

    /// <summary>
    /// Produces a simple confidence label from trust data and signal volume.
    /// </summary>
    /// <param name="context">Safety scan context.</param>
    /// <returns>Low, Medium, or High confidence.</returns>
    private static string ConfidenceLevel(SiteSafetyContext context)
    {
        if (context.NegativeSignals.Count >= 3 || context.TrustDataAvailable)
        {
            return "High";
        }

        return context.PositiveSignals.Count > 0 || context.NegativeSignals.Count > 0 ? "Medium" : "Low";
    }

    /// <summary>
    /// Detects cross-domain or shortener redirects without performing new redirect requests.
    /// </summary>
    /// <param name="original">Original scan URI.</param>
    /// <param name="redirect">Observed redirect URI.</param>
    /// <returns>True when the redirect appears suspicious.</returns>
    private static bool IsSuspiciousRedirect(Uri original, Uri redirect) =>
        !NormalizeHost(original.Host).Equals(NormalizeHost(redirect.Host), StringComparison.OrdinalIgnoreCase) ||
        ShortenerDomains.Contains(NormalizeHost(redirect.Host));

    /// <summary>
    /// Detects unusually long or risky query strings without logging full secret-bearing query values.
    /// </summary>
    /// <param name="uri">Validated scan URI.</param>
    /// <returns>True when the query shape is suspicious.</returns>
    private static bool HasStrangeQuery(Uri uri) =>
        uri.Query.Length > 180 ||
        uri.Query.Contains("redirect=", StringComparison.OrdinalIgnoreCase) ||
        uri.Query.Contains("url=", StringComparison.OrdinalIgnoreCase) ||
        uri.Query.Contains("token=", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Normalizes a host for scan output and comparison.
    /// </summary>
    /// <param name="host">Host from a URL.</param>
    /// <returns>Lowercase host without leading www.</returns>
    private static string NormalizeHost(string host) =>
        host.Replace("www.", string.Empty, StringComparison.OrdinalIgnoreCase).ToLowerInvariant();

    /// <summary>
    /// Removes query and fragment from output URLs to avoid returning secrets or tokens.
    /// </summary>
    /// <param name="uri">Validated scan URI.</param>
    /// <returns>Sanitized absolute URL.</returns>
    private static string SanitizeUrl(Uri uri) =>
        new UriBuilder(uri) { Query = string.Empty, Fragment = string.Empty }.Uri.ToString();

    /// <summary>
    /// Extracts a path from an observed URL-like value without throwing on malformed input.
    /// </summary>
    /// <param name="value">Observed URL or path.</param>
    /// <returns>Path used for extension detection.</returns>
    private static string SafePath(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) ? uri.AbsolutePath : value;

    /// <summary>
    /// Builds a non-reversible cache key so recent scans can be reused without storing raw URL query values.
    /// </summary>
    /// <param name="request">Validated scan request.</param>
    /// <returns>Cache key for the request shape.</returns>
    private static string BuildCacheKey(SiteSafetyScanRequest request)
    {
        var serialized = JsonSerializer.Serialize(request);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(serialized));
        return $"site-safety:{Convert.ToHexString(hash)}";
    }

    /// <summary>
    /// Gets a recent scan result if it has not expired.
    /// </summary>
    /// <param name="cacheKey">Hashed cache key.</param>
    /// <param name="result">Cached scan result when available.</param>
    /// <returns>True when a valid cached result exists.</returns>
    private static bool TryGetCachedResult(string cacheKey, out SiteSafetyScanResult result)
    {
        result = default!;
        if (!RecentScans.TryGetValue(cacheKey, out var cached))
        {
            return false;
        }

        if (cached.ExpiresAtUtc <= DateTimeOffset.UtcNow)
        {
            RecentScans.TryRemove(cacheKey, out _);
            return false;
        }

        result = cached.Result;
        return true;
    }

    /// <summary>
    /// Creates a safe failed scan result that does not crash scoring.
    /// </summary>
    /// <param name="url">Original URL text.</param>
    /// <returns>Failed scan result.</returns>
    private static SiteSafetyScanResult FailedResult(string url)
    {
        var impact = new SiteSafetyScoreImpact(50, 50, 0, 50, []);
        return new SiteSafetyScanResult(
            $"site-safety-{Guid.NewGuid():N}",
            string.Empty,
            string.Empty,
            DateTimeOffset.UtcNow,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            SiteSafetyScanStatus.ScanFailed,
            "HIP could not complete the site safety scan safely.",
            ["The scan failed before HIP could evaluate the page."],
            ["No trust boost was applied because the scan failed."],
            [],
            [],
            "Low",
            impact.DomainTrustScore,
            impact.PageTrustScore,
            impact.ContentRiskScore,
            impact.FinalHipScore,
            impact);
    }

    /// <summary>
    /// Internal scan context used to keep scoring logic readable.
    /// </summary>
    private sealed record SiteSafetyContext(
        int MalwareRiskScore,
        int PhishingRiskScore,
        int RedirectRiskScore,
        int ScriptRiskScore,
        int DownloadRiskScore,
        int FormRiskScore,
        int ReputationRiskScore,
        int OverallSafetyRiskScore,
        bool TrustDataAvailable,
        IReadOnlyCollection<string> Reasons,
        IReadOnlyCollection<string> Warnings,
        IReadOnlyCollection<string> PositiveSignals,
        IReadOnlyCollection<string> NegativeSignals);

    /// <summary>
    /// Cached scan result with expiration metadata; raw private page contents are never cached.
    /// </summary>
    private sealed record CachedSiteSafetyScan(SiteSafetyScanResult Result, DateTimeOffset ExpiresAtUtc);
}
