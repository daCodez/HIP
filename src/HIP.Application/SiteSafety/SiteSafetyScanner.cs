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
    ILogger<SiteSafetyScanner> logger,
    IEnumerable<ISiteSafetyEvidenceProvider>? evidenceProviders = null,
    SiteSafetyRuleOptions? ruleOptions = null,
    IAdminSiteSafetyRuleRepository? adminRuleRepository = null) : ISiteSafetyScanner
{
    private static readonly ConcurrentDictionary<string, CachedSiteSafetyScan> RecentScans = new();

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

    private static readonly HashSet<string> KnownTrustedDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "github.com",
        "microsoft.com",
        "google.com",
        "apple.com",
        "wikipedia.org"
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
            var providers = ActiveEvidenceProviders();
            var cacheKey = BuildCacheKey(request, providers);
            var canUseCache = CanUseCache(providers);
            if (canUseCache && TryGetCachedResult(cacheKey, out var cached))
            {
                logger.LogInformation("Returned cached HIP Site Safety Scan for domain {Domain}.", domain);
                return cached;
            }

            var signals = request.ObservedSignals ?? new SiteSafetyObservedSignals();
            var evidence = await CollectEvidenceAsync(uri, domain, signals, providers, cancellationToken);
            var options = ruleOptions ?? new SiteSafetyRuleOptions();
            var ruleInput = BuildRuleInput(uri, domain, signals, evidence);
            var matchedRules = await EvaluateRulesAsync(ruleInput, cancellationToken);
            var context = Analyze(uri, domain, signals, matchedRules, options);
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
                evidence,
                scores,
                matchedRules);
            if (canUseCache)
            {
                RecentScans[cacheKey] = new CachedSiteSafetyScan(result, DateTimeOffset.UtcNow.Add(options.ScanCacheDuration));
            }

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
    /// <param name="signals">Privacy-safe observed scan facts.</param>
    /// <returns>Internal scan context used for status and score impact calculation.</returns>
    private static SiteSafetyContext Analyze(Uri uri, string domain, SiteSafetyObservedSignals signals, IReadOnlyCollection<SiteSafetyRuleResult> matchedRules, SiteSafetyRuleOptions options)
    {
        var reasons = new List<string>();
        var warnings = new List<string>();
        var positive = new List<string>();
        var negative = new List<string>();
        var knownTrustedDomain = IsKnownTrustedDomain(domain);
        var effectiveTrustDataAvailable = signals.TrustDataAvailable || knownTrustedDomain;
        var userGeneratedContentSurface = IsUserGeneratedContentSurface(uri, domain);

        var enforcedRules = matchedRules.Where(rule => !rule.IsSimulationOnly).ToArray();
        var malwareRisk = MaxRisk(enforcedRules, SiteSafetyRiskCategory.Malware);
        var phishingRisk = MaxRisk(enforcedRules, SiteSafetyRiskCategory.Phishing);
        var redirectRisk = MaxRisk(enforcedRules, SiteSafetyRiskCategory.Redirect);
        var scriptRisk = MaxRisk(enforcedRules, SiteSafetyRiskCategory.Script);
        var downloadRisk = MaxRisk(enforcedRules, SiteSafetyRiskCategory.Download);
        var formRisk = MaxRisk(enforcedRules, SiteSafetyRiskCategory.Form);
        var reputationRisk = MaxRisk(enforcedRules, SiteSafetyRiskCategory.Reputation);
        var externalTrustBoost = Math.Clamp(enforcedRules
            .Where(rule => rule.CollectionType is SiteSafetyRuleCollectionType.ExternalEvidenceRules or SiteSafetyRuleCollectionType.ReputationRiskRules)
            .Sum(rule => rule.TrustImpact), 0, Math.Max(0, options.MaxExternalTrustBoost));
        var confidencePenalty = enforcedRules.Select(rule => rule.ConfidencePenalty).DefaultIfEmpty(0).Max();
        var hasAuthoritativeRiskHit = enforcedRules.Any(rule => rule.CollectionType == SiteSafetyRuleCollectionType.ExternalEvidenceRules && rule.Severity == SiteSafetyRuleSeverity.Critical);
        var hasConflictingEvidence = enforcedRules.Any(rule => rule.RuleId.Equals("external-conflict", StringComparison.OrdinalIgnoreCase));
        var statusOverride = StrongestStatusOverride(enforcedRules);

        foreach (var rule in matchedRules)
        {
            reasons.Add(rule.Reason);
            if (!string.IsNullOrWhiteSpace(rule.Warning))
            {
                warnings.Add(rule.Warning);
            }

            if (!rule.IsSimulationOnly && rule.RiskImpact > 0)
            {
                negative.Add(rule.NegativeSignal ?? rule.Reason);
            }

            if (!rule.IsSimulationOnly && rule.TrustImpact > 0)
            {
                positive.Add(rule.PositiveSignal ?? rule.Reason);
            }
        }

        if (downloadRisk == 0)
        {
            reasons.Add("No dangerous downloads were found.");
        }

        if (redirectRisk == 0)
        {
            reasons.Add("No suspicious redirects were found.");
        }

        if (knownTrustedDomain)
        {
            reasons.Add("The parent domain has strong public trust signals, but HIP still evaluates this specific page and content separately.");
        }

        if (userGeneratedContentSurface)
        {
            reasons.Add("This page appears to contain user-generated or repository content, so parent-domain trust does not automatically make it safe.");
        }

        if (!effectiveTrustDataAvailable)
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
            effectiveTrustDataAvailable,
            knownTrustedDomain,
            userGeneratedContentSurface,
            knownTrustedDomain ? 95 : signals.TrustDataAvailable ? 80 : 58,
            externalTrustBoost,
            confidencePenalty,
            hasAuthoritativeRiskHit,
            hasConflictingEvidence,
            statusOverride,
            reasons.Distinct().ToArray(),
            warnings.Distinct().ToArray(),
            positive.Distinct().ToArray(),
            negative.Distinct().ToArray());
    }

    /// <summary>
    /// Builds the privacy-safe rule input used by built-in and admin-managed Site Safety rules.
    /// </summary>
    private static SiteSafetyRuleInput BuildRuleInput(Uri uri, string domain, SiteSafetyObservedSignals signals, IReadOnlyCollection<SiteSafetyEvidence> evidence)
    {
        var downloads = signals.DownloadLinks ?? [];
        var matchedTerms = new List<string>(signals.MatchedRiskTerms ?? []);
        AddTerm(matchedTerms, signals.ContainsScamWording, "ScamWording");
        AddTerm(matchedTerms, signals.ContainsUrgencyWording, "UrgencyWording");
        AddTerm(matchedTerms, signals.ContainsImpersonationWording, "ImpersonationWording");
        AddTerm(matchedTerms, signals.KnownPhishingPattern, "KnownPhishingPattern");
        AddTerm(matchedTerms, signals.KnownMalwareIndicator, "KnownMalwareIndicator");

        var shortenerRedirectCount = signals.RedirectChain?
            .Count(link => Uri.TryCreate(link, UriKind.Absolute, out var redirectUri) && SiteSafetyRuleHelpers.ShortenerDomains.Contains(NormalizeHost(redirectUri.Host))) ?? 0;

        return new SiteSafetyRuleInput(
            uri,
            domain,
            domain.Split('.').LastOrDefault() ?? string.Empty,
            uri.Scheme == "https",
            signals.RedirectChain?.Count ?? 0,
            signals.ShortenedLinkCount + shortenerRedirectCount + (SiteSafetyRuleHelpers.ShortenerDomains.Contains(domain) ? 1 : 0),
            signals.ObfuscatedLinkCount,
            HasStrangeQuery(uri),
            signals.ExternalScriptUrls?.Count ?? 0,
            signals.InlineScriptCount,
            signals.SuspiciousScriptPatternCount,
            downloads.Count(link => ExecutableExtensions.Contains(Path.GetExtension(SafePath(link)))),
            downloads.Count(link => ArchiveExtensions.Contains(Path.GetExtension(SafePath(link)))),
            signals.HasLoginForm,
            signals.HasPasswordField,
            signals.HasPaymentField,
            signals.KnownAbuseReports,
            signals.DomainReputationScore,
            signals.PageReputationScore,
            matchedTerms.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            evidence,
            signals.TrustDataAvailable || IsKnownTrustedDomain(domain));
    }

    /// <summary>
    /// Evaluates built-in code rules and admin-managed structured rules.
    /// </summary>
    private async Task<IReadOnlyCollection<SiteSafetyRuleResult>> EvaluateRulesAsync(SiteSafetyRuleInput input, CancellationToken cancellationToken)
    {
        var options = ruleOptions ?? new SiteSafetyRuleOptions();
        var results = BuiltInSiteSafetyRules.Create(options)
            .Select(rule => rule.Evaluate(input))
            .OfType<SiteSafetyRuleResult>()
            .ToList();

        if (adminRuleRepository is not null)
        {
            var adminRules = await adminRuleRepository.ListAsync(cancellationToken);
            foreach (var rule in adminRules)
            {
                results.AddRange(AdminSiteSafetyRuleEvaluator.Evaluate(rule, input));
            }
        }

        return results;
    }

    /// <summary>
    /// Adds a privacy-safe matched-risk label when the corresponding signal exists.
    /// </summary>
    private static void AddTerm(ICollection<string> terms, bool condition, string term)
    {
        if (condition)
        {
            terms.Add(term);
        }
    }

    /// <summary>
    /// Gets the maximum enforced risk impact for one risk category.
    /// </summary>
    private static int MaxRisk(IEnumerable<SiteSafetyRuleResult> results, SiteSafetyRiskCategory category) =>
        Math.Clamp(results.Where(result => result.RiskCategory == category).Select(result => result.RiskImpact).DefaultIfEmpty(0).Max(), 0, 100);

    /// <summary>
    /// Selects the strongest safe status override from matched enforced rules.
    /// </summary>
    private static SiteSafetyScanStatus? StrongestStatusOverride(IEnumerable<SiteSafetyRuleResult> results)
    {
        var overrides = results.Select(result => result.StatusOverride).OfType<SiteSafetyScanStatus>().ToArray();
        if (overrides.Contains(SiteSafetyScanStatus.Dangerous))
        {
            return SiteSafetyScanStatus.Dangerous;
        }

        if (overrides.Contains(SiteSafetyScanStatus.HighRisk))
        {
            return SiteSafetyScanStatus.HighRisk;
        }

        if (overrides.Contains(SiteSafetyScanStatus.Suspicious))
        {
            return SiteSafetyScanStatus.Suspicious;
        }

        return null;
    }

    /// <summary>
    /// Resolves the active evidence providers, falling back to browser-observed evidence when none are registered.
    /// </summary>
    /// <returns>Evidence providers to use for this scan.</returns>
    private IReadOnlyCollection<ISiteSafetyEvidenceProvider> ActiveEvidenceProviders()
    {
        var providers = evidenceProviders?.ToArray() ?? [];
        if (providers.Length == 0)
        {
            providers = [new BrowserObservedSignalProvider()];
        }

        return providers;
    }

    /// <summary>
    /// Determines whether scan results can be cached without hiding mutable admin review decisions.
    /// </summary>
    /// <param name="providers">Evidence providers active for the scan.</param>
    /// <returns>True when none of the active providers depend on live admin review decisions.</returns>
    private static bool CanUseCache(IReadOnlyCollection<ISiteSafetyEvidenceProvider> providers) =>
        providers.All(provider => provider.ProviderType != SiteSafetyEvidenceProviderType.AdminReview);

    /// <summary>
    /// Collects normalized provider evidence and converts provider failures into safe error evidence.
    /// </summary>
    /// <param name="uri">Validated scan URI.</param>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="signals">Privacy-safe observed scan facts.</param>
    /// <param name="providers">Evidence providers active for this scan.</param>
    /// <param name="cancellationToken">Token used to cancel provider work.</param>
    /// <returns>Normalized provider evidence records.</returns>
    private async Task<IReadOnlyCollection<SiteSafetyEvidence>> CollectEvidenceAsync(Uri uri, string domain, SiteSafetyObservedSignals signals, IReadOnlyCollection<ISiteSafetyEvidenceProvider> providers, CancellationToken cancellationToken)
    {
        var checkedAt = DateTimeOffset.UtcNow;
        var context = new SiteSafetyEvidenceContext(
            uri,
            domain,
            SiteSafetyEvidenceHashing.HashUrl(SanitizeUrl(uri)),
            signals,
            checkedAt);

        var evidence = new List<SiteSafetyEvidence>();
        foreach (var provider in providers)
        {
            try
            {
                evidence.Add(await provider.CollectEvidenceAsync(context, cancellationToken));
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                evidence.Add(FailedProviderEvidence(provider, context, "Provider timed out."));
            }
            catch (TimeoutException)
            {
                evidence.Add(FailedProviderEvidence(provider, context, "Provider timed out."));
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "HIP Site Safety evidence provider {ProviderName} failed safely.", provider.ProviderName);
                evidence.Add(FailedProviderEvidence(provider, context, "Provider failed safely."));
            }
        }

        return evidence;
    }

    /// <summary>
    /// Creates safe provider-failure evidence that lowers confidence without crashing the scan.
    /// </summary>
    private static SiteSafetyEvidence FailedProviderEvidence(ISiteSafetyEvidenceProvider provider, SiteSafetyEvidenceContext context, string error) =>
        new(
            provider.ProviderName,
            provider.ProviderType,
            SiteSafetyEvidenceTargetType.Domain,
            context.Domain,
            context.UrlHash,
            [],
            Confidence: 0,
            context.CheckedAtUtc,
            context.CheckedAtUtc.AddMinutes(10),
            [error],
            IsAuthoritativeForRisk: false,
            IsAuthoritativeForTrust: false);

    /// <summary>
    /// Builds HIP score impact without replacing domain, reputation, or identity scoring.
    /// </summary>
    /// <param name="context">Safety scan context.</param>
    /// <returns>Score impact used by the larger HIP scoring model.</returns>
    private static SiteSafetyScoreImpact BuildScoreImpact(SiteSafetyContext context)
    {
        var domainTrust = Math.Clamp(context.DomainTrustBase - context.ReputationRiskScore + context.ExternalTrustBoost, 0, 100);
        var pageTrust = Math.Clamp(82 - context.PhishingRiskScore / 2 - context.RedirectRiskScore / 3 - context.FormRiskScore / 3 - context.ReputationRiskScore / 4, 0, 100);
        var rawContentRisk = Math.Clamp(context.MalwareRiskScore / 2 + context.ScriptRiskScore / 3 + context.DownloadRiskScore / 3 + context.PhishingRiskScore / 3, 0, 100);
        var contentTrust = Math.Clamp(100 - rawContentRisk, 0, 100);

        if (context.KnownTrustedDomain)
        {
            pageTrust = Math.Max(pageTrust, 78);
        }

        if (context.UserGeneratedContentSurface)
        {
            pageTrust = Math.Min(pageTrust, 76);
        }

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
            domainTrust = Math.Min(domainTrust, 60 + Math.Min(context.ExternalTrustBoost, 3));
            pageTrust = Math.Min(pageTrust, 60);
            contentTrust = Math.Min(contentTrust, context.OverallSafetyRiskScore > 0 ? 70 : 60);
        }

        var final = HipScoringModel.CalculateFinalScore([
            new WeightedScore(new ScoreComponent(ScoreCategory.Domain, ScoreValue.From(domainTrust), "DomainTrustScore is only partially affected by Site Safety reputation signals.", ["Site Safety does not replace domain reputation or identity."]), 1.25m),
            new WeightedScore(new ScoreComponent(ScoreCategory.Website, ScoreValue.From(pageTrust), "PageTrustScore is affected by phishing, redirect, form, and reputation risk.", ["Page-level safety findings adjust page trust."]), 1.5m),
            new WeightedScore(new ScoreComponent(ScoreCategory.Content, ScoreValue.From(contentTrust), "ContentRiskScore is derived from malware, scripts, downloads, and phishing indicators.", ["Content risk lowers content trust but does not alone prove identity."]), 1.5m)
        ]);
        var finalScore = final.FinalScore.Score.Value;
        if (!context.TrustDataAvailable)
        {
            finalScore = Math.Min(finalScore, 60 + Math.Min(context.ExternalTrustBoost, 3));
        }

        return new SiteSafetyScoreImpact(domainTrust, pageTrust, contentTrust, finalScore, final.ComponentScores);
    }

    /// <summary>
    /// Determines the status label from risk scores and trust-data availability.
    /// </summary>
    /// <param name="context">Safety scan context.</param>
    /// <returns>Scan status.</returns>
    private static SiteSafetyScanStatus DetermineStatus(SiteSafetyContext context)
    {
        var evaluationContext = new SiteSafetyRuleEvaluationContext(
            context.MalwareRiskScore,
            context.PhishingRiskScore,
            context.RedirectRiskScore,
            context.ScriptRiskScore,
            context.DownloadRiskScore,
            context.FormRiskScore,
            context.ReputationRiskScore,
            context.OverallSafetyRiskScore,
            context.TrustDataAvailable,
            context.HasAuthoritativeRiskHit,
            context.StatusOverride);

        return SiteSafetyRuleEvaluator.EvaluateStatus(evaluationContext, BuiltInSiteSafetyRules.CreateStatusRules());
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
        if (context.HasConflictingEvidence || context.ExternalConfidencePenalty >= 35)
        {
            return "Low";
        }

        if (context.ExternalConfidencePenalty >= 20)
        {
            return "Medium";
        }

        if (context.NegativeSignals.Count >= 3 || context.TrustDataAvailable)
        {
            return "High";
        }

        return context.PositiveSignals.Count > 0 || context.NegativeSignals.Count > 0 ? "Medium" : "Low";
    }

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
    /// Determines whether HIP has a built-in high-trust baseline for a public domain.
    /// This earns only domain trust; page and content scores are still evaluated independently.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <returns>True for a small allow-list of well-known public domains.</returns>
    private static bool IsKnownTrustedDomain(string domain) =>
        KnownTrustedDomains.Contains(domain);

    /// <summary>
    /// Detects surfaces on trusted domains where users can publish content that HIP must score separately.
    /// </summary>
    /// <param name="uri">Validated scan URI.</param>
    /// <param name="domain">Normalized domain.</param>
    /// <returns>True when parent-domain trust should be capped at the page layer.</returns>
    private static bool IsUserGeneratedContentSurface(Uri uri, string domain)
    {
        if (!domain.Equals("github.com", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        return segments.Length >= 2 &&
               !segments[0].Equals("orgs", StringComparison.OrdinalIgnoreCase) &&
               !segments[0].Equals("features", StringComparison.OrdinalIgnoreCase) &&
               !segments[0].Equals("enterprise", StringComparison.OrdinalIgnoreCase);
    }

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
    private static string BuildCacheKey(SiteSafetyScanRequest request, IReadOnlyCollection<ISiteSafetyEvidenceProvider> providers)
    {
        var serialized = JsonSerializer.Serialize(new
        {
            Request = request,
            Providers = providers.Select(provider => provider.ProviderName).OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToArray()
        });
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
            [],
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
        bool KnownTrustedDomain,
        bool UserGeneratedContentSurface,
        int DomainTrustBase,
        int ExternalTrustBoost,
        int ExternalConfidencePenalty,
        bool HasAuthoritativeRiskHit,
        bool HasConflictingEvidence,
        SiteSafetyScanStatus? StatusOverride,
        IReadOnlyCollection<string> Reasons,
        IReadOnlyCollection<string> Warnings,
        IReadOnlyCollection<string> PositiveSignals,
        IReadOnlyCollection<string> NegativeSignals);

    /// <summary>
    /// Cached scan result with expiration metadata; raw private page contents are never cached.
    /// </summary>
    private sealed record CachedSiteSafetyScan(SiteSafetyScanResult Result, DateTimeOffset ExpiresAtUtc);
}
