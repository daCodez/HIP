using System.Security.Cryptography;
using System.Text;

namespace HIP.Application.SiteSafety;

/// <summary>
/// Identifies the kind of evidence provider that contributed normalized site safety facts.
/// </summary>
public enum SiteSafetyEvidenceProviderType
{
    /// <summary>
    /// Evidence observed locally by a HIP client such as the browser extension.
    /// </summary>
    BrowserObserved,

    /// <summary>
    /// Evidence from HIP's own stored scan, report, or reputation history.
    /// </summary>
    HipHistory,

    /// <summary>
    /// Evidence from weighted user feedback.
    /// </summary>
    UserFeedback,

    /// <summary>
    /// Evidence from moderator or administrator review.
    /// </summary>
    AdminReview,

    /// <summary>
    /// Evidence from TLS configuration scanners such as SSL Labs.
    /// </summary>
    TlsScanner,

    /// <summary>
    /// Evidence from threat-intelligence providers such as Google Web Risk or Safe Browsing.
    /// </summary>
    ThreatIntel,

    /// <summary>
    /// Evidence from URL reputation providers.
    /// </summary>
    UrlReputation,

    /// <summary>
    /// Evidence from domain reputation providers.
    /// </summary>
    DomainReputation,

    /// <summary>
    /// Evidence from malware scanners.
    /// </summary>
    MalwareScanner,

    /// <summary>
    /// Evidence from phishing scanners.
    /// </summary>
    PhishingScanner
}

/// <summary>
/// Identifies the target scope for normalized provider evidence.
/// </summary>
public enum SiteSafetyEvidenceTargetType
{
    /// <summary>
    /// Evidence applies to the root domain.
    /// </summary>
    Domain,

    /// <summary>
    /// Evidence applies to the exact URL or page hash.
    /// </summary>
    Url,

    /// <summary>
    /// Evidence applies to page content signals without storing raw content.
    /// </summary>
    Content,

    /// <summary>
    /// Evidence applies to downloadable file signals.
    /// </summary>
    Download
}

/// <summary>
/// Normalized evidence status returned by providers without exposing provider-specific response bodies.
/// </summary>
public enum SiteSafetyEvidenceStatus
{
    /// <summary>
    /// The provider did not find a risk signal.
    /// </summary>
    Clean,

    /// <summary>
    /// The provider found a positive security or trust signal.
    /// </summary>
    Positive,

    /// <summary>
    /// The provider found a weak or cautionary signal.
    /// </summary>
    Weak,

    /// <summary>
    /// The provider found a suspicious signal.
    /// </summary>
    Suspicious,

    /// <summary>
    /// The provider found a high-risk signal.
    /// </summary>
    HighRisk,

    /// <summary>
    /// The provider found a confirmed dangerous signal.
    /// </summary>
    Dangerous,

    /// <summary>
    /// The provider failed or timed out.
    /// </summary>
    Error
}

/// <summary>
/// Represents one normalized provider finding that can influence scoring.
/// </summary>
/// <param name="Category">Provider-neutral evidence category, such as TlsGrade or PhishingMatch.</param>
/// <param name="Value">Provider-neutral value, such as A, F, Clean, or Hit.</param>
/// <param name="Status">Normalized evidence status.</param>
/// <param name="RiskImpact">0-100 risk impact where higher means riskier.</param>
/// <param name="TrustImpact">0-100 trust impact where higher means more positive trust signal.</param>
/// <param name="Summary">Plain-English explanation that is safe to show to users or admins.</param>
public sealed record SiteSafetyEvidenceItem(
    string Category,
    string Value,
    SiteSafetyEvidenceStatus Status,
    int RiskImpact,
    int TrustImpact,
    string Summary);

/// <summary>
/// Normalized evidence returned by a site safety provider.
/// </summary>
/// <param name="ProviderName">Human-readable provider name.</param>
/// <param name="ProviderType">Provider category.</param>
/// <param name="TargetType">Evidence target scope.</param>
/// <param name="Domain">Normalized domain checked by the provider.</param>
/// <param name="UrlHash">Optional URL hash. Full private URLs are not required.</param>
/// <param name="EvidenceItems">Normalized evidence items.</param>
/// <param name="Confidence">0-100 provider confidence.</param>
/// <param name="CheckedAtUtc">UTC time when the provider checked the target.</param>
/// <param name="ExpiresAtUtc">UTC time after which this evidence should not be reused.</param>
/// <param name="Errors">Safe provider errors, excluding secrets and raw private content.</param>
/// <param name="IsAuthoritativeForRisk">Whether risk hits from this provider can force stronger safety status.</param>
/// <param name="IsAuthoritativeForTrust">Whether clean or positive results from this provider are allowed to provide trust boost.</param>
public sealed record SiteSafetyEvidence(
    string ProviderName,
    SiteSafetyEvidenceProviderType ProviderType,
    SiteSafetyEvidenceTargetType TargetType,
    string Domain,
    string? UrlHash,
    IReadOnlyCollection<SiteSafetyEvidenceItem> EvidenceItems,
    int Confidence,
    DateTimeOffset CheckedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    IReadOnlyCollection<string> Errors,
    bool IsAuthoritativeForRisk,
    bool IsAuthoritativeForTrust);

/// <summary>
/// Context passed to evidence providers so they can return normalized facts without receiving page text or form values.
/// </summary>
/// <param name="Url">Validated URL. External providers should avoid using this unless policy explicitly allows full URL checks.</param>
/// <param name="Domain">Normalized domain.</param>
/// <param name="UrlHash">SHA-256 URL hash for providers or caches that can use hashes.</param>
/// <param name="ObservedSignals">Privacy-safe browser observations.</param>
/// <param name="CheckedAtUtc">UTC time for this evidence collection pass.</param>
public sealed record SiteSafetyEvidenceContext(
    Uri Url,
    string Domain,
    string UrlHash,
    SiteSafetyObservedSignals ObservedSignals,
    DateTimeOffset CheckedAtUtc);

/// <summary>
/// Provides normalized site safety evidence without deciding the final HIP score.
/// </summary>
public interface ISiteSafetyEvidenceProvider
{
    /// <summary>
    /// Gets the provider name used for evidence records and diagnostics.
    /// </summary>
    string ProviderName { get; }

    /// <summary>
    /// Gets the provider category.
    /// </summary>
    SiteSafetyEvidenceProviderType ProviderType { get; }

    /// <summary>
    /// Collects normalized evidence for a validated scan context.
    /// </summary>
    /// <param name="context">Privacy-safe scan context.</param>
    /// <param name="cancellationToken">Token used to cancel provider work.</param>
    /// <returns>Provider evidence. Empty evidence is allowed.</returns>
    Task<SiteSafetyEvidence> CollectEvidenceAsync(SiteSafetyEvidenceContext context, CancellationToken cancellationToken);
}

/// <summary>
/// Marker interface for evidence providers that may call third-party services when explicitly configured.
/// </summary>
public interface IExternalSiteEvidenceProvider : ISiteSafetyEvidenceProvider
{
}

/// <summary>
/// Configuration for external site evidence providers.
/// </summary>
public sealed class ExternalSiteEvidenceOptions
{
    /// <summary>
    /// Gets or sets whether third-party external evidence providers are allowed to run.
    /// Disabled by default so HIP never calls external scanners accidentally.
    /// </summary>
    public bool ExternalProvidersEnabled { get; set; }

    /// <summary>
    /// Gets or sets whether external providers may receive full URLs. Domain-only or hash-based checks are preferred.
    /// </summary>
    public bool AllowFullUrlChecks { get; set; }

    /// <summary>
    /// Gets or sets the maximum time an external provider should spend before HIP fails safely.
    /// </summary>
    public TimeSpan ProviderTimeout { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Gets or sets the default evidence cache duration.
    /// </summary>
    public TimeSpan DefaultCacheDuration { get; set; } = TimeSpan.FromHours(6);
}

/// <summary>
/// Caches normalized external evidence so HIP can prefer recent evidence and avoid unnecessary scanner calls.
/// </summary>
public interface IExternalSiteEvidenceCache
{
    /// <summary>
    /// Gets cached evidence when it exists and has not expired.
    /// </summary>
    /// <param name="providerName">Provider name.</param>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="urlHash">Optional URL hash.</param>
    /// <returns>Cached evidence or null.</returns>
    SiteSafetyEvidence? GetFresh(string providerName, string domain, string? urlHash);

    /// <summary>
    /// Stores normalized evidence with expiry metadata.
    /// </summary>
    /// <param name="evidence">Evidence to cache.</param>
    void Store(SiteSafetyEvidence evidence);
}

/// <summary>
/// In-memory external evidence cache for development and tests.
/// </summary>
public sealed class InMemoryExternalSiteEvidenceCache : IExternalSiteEvidenceCache
{
    private readonly Dictionary<string, SiteSafetyEvidence> cache = new(StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc />
    public SiteSafetyEvidence? GetFresh(string providerName, string domain, string? urlHash)
    {
        var key = CacheKey(providerName, domain, urlHash);
        if (!cache.TryGetValue(key, out var evidence))
        {
            return null;
        }

        if (evidence.ExpiresAtUtc <= DateTimeOffset.UtcNow)
        {
            cache.Remove(key);
            return null;
        }

        return evidence;
    }

    /// <inheritdoc />
    public void Store(SiteSafetyEvidence evidence)
    {
        cache[CacheKey(evidence.ProviderName, evidence.Domain, evidence.UrlHash)] = evidence;
    }

    /// <summary>
    /// Builds a deterministic cache key without storing raw private URLs.
    /// </summary>
    /// <param name="providerName">Provider name.</param>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="urlHash">Optional URL hash.</param>
    /// <returns>Cache key.</returns>
    private static string CacheKey(string providerName, string domain, string? urlHash) =>
        $"{providerName}:{domain}:{urlHash ?? "domain"}";
}

/// <summary>
/// Converts privacy-safe browser observations into normalized provider evidence.
/// </summary>
public sealed class BrowserObservedSignalProvider : ISiteSafetyEvidenceProvider
{
    /// <inheritdoc />
    public string ProviderName => "BrowserObservedSignalProvider";

    /// <inheritdoc />
    public SiteSafetyEvidenceProviderType ProviderType => SiteSafetyEvidenceProviderType.BrowserObserved;

    /// <inheritdoc />
    public Task<SiteSafetyEvidence> CollectEvidenceAsync(SiteSafetyEvidenceContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var signals = context.ObservedSignals;
        var items = new List<SiteSafetyEvidenceItem>();

        AddCountEvidence(items, "ExecutableDownloads", signals.DownloadLinks?.Count(link => HasExtension(link, [".exe", ".dll", ".bat", ".cmd", ".scr", ".ps1", ".vbs", ".js", ".jar", ".apk", ".msi"])) ?? 0, 70, "Executable download links were observed by the browser plugin.");
        AddCountEvidence(items, "ArchiveDownloads", signals.DownloadLinks?.Count(link => HasExtension(link, [".zip", ".rar", ".7z", ".iso"])) ?? 0, 35, "Archive download links were observed by the browser plugin.");
        AddCountEvidence(items, "SuspiciousScripts", signals.SuspiciousScriptPatternCount, 45, "Suspicious script structure was observed without sending script contents.");
        AddBooleanEvidence(items, "LoginForm", signals.HasLoginForm || signals.HasPasswordField, 45, "Login or password fields were observed without sending form values.");
        AddBooleanEvidence(items, "PaymentForm", signals.HasPaymentField, 55, "Payment fields were observed without sending form values.");
        AddBooleanEvidence(items, "KnownPhishingPattern", signals.KnownPhishingPattern, 90, "A privacy-safe phishing pattern matched.");
        AddBooleanEvidence(items, "KnownMalwareIndicator", signals.KnownMalwareIndicator, 95, "A privacy-safe malware indicator matched.");
        AddBooleanEvidence(items, "ScamWordingSignal", signals.ContainsScamWording || signals.ContainsUrgencyWording || signals.ContainsImpersonationWording, 55, "Risk wording labels were observed without sending page text.");

        if (items.Count == 0)
        {
            items.Add(new SiteSafetyEvidenceItem("BrowserObserved", "NoRiskSignals", SiteSafetyEvidenceStatus.Clean, 0, 5, "The browser plugin did not observe obvious page safety risk signals."));
        }

        return Task.FromResult(new SiteSafetyEvidence(
            ProviderName,
            ProviderType,
            SiteSafetyEvidenceTargetType.Url,
            context.Domain,
            context.UrlHash,
            items,
            Confidence: items.Any(item => item.Status is SiteSafetyEvidenceStatus.HighRisk or SiteSafetyEvidenceStatus.Dangerous) ? 80 : 60,
            context.CheckedAtUtc,
            context.CheckedAtUtc.AddMinutes(5),
            [],
            IsAuthoritativeForRisk: true,
            IsAuthoritativeForTrust: false));
    }

    /// <summary>
    /// Adds a count-based evidence item when the count is positive.
    /// </summary>
    private static void AddCountEvidence(ICollection<SiteSafetyEvidenceItem> items, string category, int count, int riskImpact, string summary)
    {
        if (count > 0)
        {
            items.Add(new SiteSafetyEvidenceItem(category, count.ToString(), riskImpact >= 70 ? SiteSafetyEvidenceStatus.HighRisk : SiteSafetyEvidenceStatus.Suspicious, riskImpact, 0, summary));
        }
    }

    /// <summary>
    /// Adds a boolean evidence item when the signal is present.
    /// </summary>
    private static void AddBooleanEvidence(ICollection<SiteSafetyEvidenceItem> items, string category, bool present, int riskImpact, string summary)
    {
        if (present)
        {
            items.Add(new SiteSafetyEvidenceItem(category, "true", riskImpact >= 85 ? SiteSafetyEvidenceStatus.Dangerous : SiteSafetyEvidenceStatus.Suspicious, riskImpact, 0, summary));
        }
    }

    /// <summary>
    /// Checks a URL or path extension without fetching or opening the resource.
    /// </summary>
    private static bool HasExtension(string value, IReadOnlyCollection<string> extensions)
    {
        var path = Uri.TryCreate(value, UriKind.Absolute, out var uri) ? uri.AbsolutePath : value;
        return extensions.Contains(Path.GetExtension(path), StringComparer.OrdinalIgnoreCase);
    }
}

/// <summary>
/// Base class for disabled-by-default third-party evidence providers.
/// </summary>
public abstract class ExternalSiteEvidenceProviderBase(
    IExternalSiteEvidenceCache cache,
    ExternalSiteEvidenceOptions options) : IExternalSiteEvidenceProvider
{
    /// <inheritdoc />
    public abstract string ProviderName { get; }

    /// <inheritdoc />
    public abstract SiteSafetyEvidenceProviderType ProviderType { get; }

    /// <inheritdoc />
    public async Task<SiteSafetyEvidence> CollectEvidenceAsync(SiteSafetyEvidenceContext context, CancellationToken cancellationToken)
    {
        var cached = cache.GetFresh(ProviderName, context.Domain, context.UrlHash);
        if (cached is not null)
        {
            return cached;
        }

        if (!options.ExternalProvidersEnabled)
        {
            return EmptyDisabledEvidence(context);
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.ProviderTimeout);

        var evidence = await CollectExternalEvidenceAsync(context, timeout.Token);
        cache.Store(evidence);
        return evidence;
    }

    /// <summary>
    /// Collects provider-specific evidence after configuration allows external scanner calls.
    /// </summary>
    protected abstract Task<SiteSafetyEvidence> CollectExternalEvidenceAsync(SiteSafetyEvidenceContext context, CancellationToken cancellationToken);

    /// <summary>
    /// Returns an empty evidence record explaining that the external provider is disabled.
    /// </summary>
    private SiteSafetyEvidence EmptyDisabledEvidence(SiteSafetyEvidenceContext context) =>
        new(
            ProviderName,
            ProviderType,
            SiteSafetyEvidenceTargetType.Domain,
            context.Domain,
            context.UrlHash,
            [],
            Confidence: 0,
            context.CheckedAtUtc,
            context.CheckedAtUtc.Add(options.DefaultCacheDuration),
            ["External provider disabled by configuration."],
            IsAuthoritativeForRisk: false,
            IsAuthoritativeForTrust: false);
}

/// <summary>
/// Hashing helper for provider contexts so full URLs do not need to be persisted or sent externally.
/// </summary>
public static class SiteSafetyEvidenceHashing
{
    /// <summary>
    /// Hashes a URL with SHA-256 for privacy-safe cache keys and providers that support URL hashes.
    /// </summary>
    /// <param name="url">URL to hash.</param>
    /// <returns>Hex-encoded SHA-256 hash.</returns>
    public static string HashUrl(string url) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(url))).ToLowerInvariant();
}
