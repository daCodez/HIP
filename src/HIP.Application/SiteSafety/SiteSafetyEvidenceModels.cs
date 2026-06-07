using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

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
/// Provider-neutral evidence item severity.
/// </summary>
public enum SiteSafetyEvidenceSeverity
{
    /// <summary>
    /// Informational evidence that should not increase risk by itself.
    /// </summary>
    Info,

    /// <summary>
    /// Low-severity evidence.
    /// </summary>
    Low,

    /// <summary>
    /// Medium-severity evidence.
    /// </summary>
    Medium,

    /// <summary>
    /// High-severity evidence.
    /// </summary>
    High,

    /// <summary>
    /// Critical evidence that can support HighRisk or Dangerous outcomes.
    /// </summary>
    Critical
}

/// <summary>
/// Provider-neutral evidence quality for normalized evidence items.
/// </summary>
public enum SiteSafetyEvidenceItemQuality
{
    /// <summary>
    /// Unknown quality when a provider does not expose enough metadata.
    /// </summary>
    Unknown,

    /// <summary>
    /// Weak evidence that should mainly affect confidence or review state.
    /// </summary>
    Weak,

    /// <summary>
    /// Medium-quality evidence.
    /// </summary>
    Medium,

    /// <summary>
    /// Strong evidence that can materially affect scoring.
    /// </summary>
    Strong
}

/// <summary>
/// Represents one normalized provider finding that can influence scoring.
/// </summary>
/// <param name="EvidenceType">Provider-neutral evidence type, such as TlsGrade or ThreatMatch.</param>
/// <param name="Category">Provider-neutral evidence category, such as TlsGrade or PhishingMatch.</param>
/// <param name="Value">Provider-neutral value, such as A, F, Clean, or Hit.</param>
/// <param name="Status">Normalized evidence status.</param>
/// <param name="RiskImpact">0-100 risk impact where higher means riskier.</param>
/// <param name="TrustImpact">0-100 trust impact where higher means more positive trust signal.</param>
/// <param name="Summary">Plain-English explanation that is safe to show to users or admins.</param>
/// <param name="Confidence">0-100 confidence for this individual evidence item.</param>
/// <param name="Severity">Provider-neutral severity.</param>
/// <param name="EvidenceQuality">Provider-neutral evidence quality.</param>
/// <param name="SourceReference">Optional safe source reference. Must never contain secrets or private page content.</param>
/// <param name="IsPositiveSignal">Whether this is a positive signal.</param>
/// <param name="IsNegativeSignal">Whether this is a negative signal.</param>
/// <param name="IsBlockingSignal">Whether this signal can support a block or strong warning.</param>
public sealed record SiteSafetyEvidenceItem(
    string Category,
    string Value,
    SiteSafetyEvidenceStatus Status,
    int RiskImpact,
    int TrustImpact,
    string Summary,
    string EvidenceType = "ProviderEvidence",
    int Confidence = 50,
    SiteSafetyEvidenceSeverity Severity = SiteSafetyEvidenceSeverity.Low,
    SiteSafetyEvidenceItemQuality EvidenceQuality = SiteSafetyEvidenceItemQuality.Medium,
    string? SourceReference = null,
    bool IsPositiveSignal = false,
    bool IsNegativeSignal = false,
    bool IsBlockingSignal = false);

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
    /// Disabled by default so HIP never calls external scanners unless an operator explicitly opts in.
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

    /// <summary>
    /// Gets or sets SSL Labs/Qualys-style TLS provider configuration.
    /// </summary>
    public ExternalProviderOptions SslLabs { get; set; } = new() { Enabled = true };

    /// <summary>
    /// Gets or sets Google Web Risk or Safe Browsing-style provider configuration.
    /// </summary>
    public ExternalProviderOptions GoogleWebRisk { get; set; } = new();

    /// <summary>
    /// Gets or sets VirusTotal provider configuration.
    /// </summary>
    public ExternalProviderOptions VirusTotal { get; set; } = new();
}

/// <summary>
/// Configuration for one named third-party evidence provider.
/// </summary>
public sealed class ExternalProviderOptions
{
    /// <summary>
    /// Gets or sets whether this specific provider may run when the global external provider switch is enabled.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Gets or sets the provider endpoint. This is optional for MVP and must not include secrets.
    /// </summary>
    public string? Endpoint { get; set; }

    /// <summary>
    /// Gets or sets the secret name or API key placeholder used by the provider.
    /// </summary>
    public string? ApiKey { get; set; }

    /// <summary>
    /// Gets or sets whether this provider may receive a full URL. Domain-only or hash-based checks remain preferred.
    /// </summary>
    public bool AllowFullUrl { get; set; }

    /// <summary>
    /// Gets or sets the cache duration for this provider.
    /// </summary>
    public TimeSpan? CacheDuration { get; set; }
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
            items.Add(new SiteSafetyEvidenceItem(
                "BrowserObserved",
                "NoRiskSignals",
                SiteSafetyEvidenceStatus.Clean,
                0,
                5,
                "The browser plugin did not observe obvious page safety risk signals.",
                EvidenceType: "BrowserObserved",
                Confidence: 60,
                Severity: SiteSafetyEvidenceSeverity.Info,
                EvidenceQuality: SiteSafetyEvidenceItemQuality.Weak,
                IsPositiveSignal: true));
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
            items.Add(new SiteSafetyEvidenceItem(
                category,
                count.ToString(),
                riskImpact >= 70 ? SiteSafetyEvidenceStatus.HighRisk : SiteSafetyEvidenceStatus.Suspicious,
                riskImpact,
                0,
                summary,
                EvidenceType: "BrowserObservedCount",
                Confidence: 75,
                Severity: riskImpact >= 70 ? SiteSafetyEvidenceSeverity.High : SiteSafetyEvidenceSeverity.Medium,
                EvidenceQuality: SiteSafetyEvidenceItemQuality.Medium,
                IsNegativeSignal: true,
                IsBlockingSignal: riskImpact >= 70));
        }
    }

    /// <summary>
    /// Adds a boolean evidence item when the signal is present.
    /// </summary>
    private static void AddBooleanEvidence(ICollection<SiteSafetyEvidenceItem> items, string category, bool present, int riskImpact, string summary)
    {
        if (present)
        {
            items.Add(new SiteSafetyEvidenceItem(
                category,
                "true",
                riskImpact >= 85 ? SiteSafetyEvidenceStatus.Dangerous : SiteSafetyEvidenceStatus.Suspicious,
                riskImpact,
                0,
                summary,
                EvidenceType: "BrowserObservedBoolean",
                Confidence: 75,
                Severity: riskImpact >= 85 ? SiteSafetyEvidenceSeverity.Critical : SiteSafetyEvidenceSeverity.Medium,
                EvidenceQuality: SiteSafetyEvidenceItemQuality.Medium,
                IsNegativeSignal: true,
                IsBlockingSignal: riskImpact >= 85));
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
    /// <summary>
    /// Gets external provider options shared by concrete providers.
    /// </summary>
    protected ExternalSiteEvidenceOptions Options => options;

    /// <inheritdoc />
    public abstract string ProviderName { get; }

    /// <inheritdoc />
    public abstract SiteSafetyEvidenceProviderType ProviderType { get; }

    /// <summary>
    /// Gets the provider-specific options used by the concrete provider.
    /// </summary>
    protected virtual ExternalProviderOptions ProviderOptions => new();

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

        if (!ProviderOptions.Enabled)
        {
            return EmptyProviderDisabledEvidence(context);
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

    /// <summary>
    /// Returns an empty evidence record explaining that this named provider is disabled.
    /// </summary>
    private SiteSafetyEvidence EmptyProviderDisabledEvidence(SiteSafetyEvidenceContext context) =>
        new(
            ProviderName,
            ProviderType,
            SiteSafetyEvidenceTargetType.Domain,
            context.Domain,
            context.UrlHash,
            [],
            Confidence: 0,
            context.CheckedAtUtc,
            context.CheckedAtUtc.Add(ProviderOptions.CacheDuration ?? options.DefaultCacheDuration),
            [$"{ProviderName} disabled by provider configuration."],
            IsAuthoritativeForRisk: false,
            IsAuthoritativeForTrust: false);
}

/// <summary>
/// SSL Labs/Qualys-style TLS evidence provider that performs domain-only TLS assessments.
/// </summary>
/// <remarks>
/// The adapter intentionally sends only the normalized domain to SSL Labs. It never sends page body text,
/// form values, passwords, tokens, cookies, email content, or raw private messages. Strong TLS creates only a
/// small trust boost because TLS quality is not proof that the website is safe.
/// </remarks>
public sealed class SslLabsSiteEvidenceProvider : ExternalSiteEvidenceProviderBase
{
    private const string DefaultEndpoint = "https://api.ssllabs.com/api/v3/analyze";
    private readonly HttpClient httpClient;

    /// <summary>
    /// Creates a TLS evidence provider with a cache, options, and optional HTTP client for tests.
    /// </summary>
    /// <param name="cache">Evidence cache used to avoid repeated third-party scanner calls.</param>
    /// <param name="options">External provider options controlling whether this provider may run.</param>
    /// <param name="httpClient">Optional HTTP client. Tests pass a stub client; production DI supplies one.</param>
    public SslLabsSiteEvidenceProvider(
        IExternalSiteEvidenceCache cache,
        ExternalSiteEvidenceOptions options,
        HttpClient? httpClient = null)
        : base(cache, options)
    {
        this.httpClient = httpClient ?? new HttpClient();
    }

    /// <inheritdoc />
    public override string ProviderName => "SSL Labs / Qualys TLS";

    /// <inheritdoc />
    public override SiteSafetyEvidenceProviderType ProviderType => SiteSafetyEvidenceProviderType.TlsScanner;

    /// <inheritdoc />
    protected override ExternalProviderOptions ProviderOptions => Options.SslLabs;

    /// <inheritdoc />
    protected override async Task<SiteSafetyEvidence> CollectExternalEvidenceAsync(SiteSafetyEvidenceContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var requestUri = BuildSslLabsUri(context.Domain);

        using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
        request.Headers.UserAgent.ParseAdd("HIP-Dev/0.1");
        request.Headers.Accept.ParseAdd("application/json");

        try
        {
            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return CreateProviderErrorEvidence(context, $"SSL Labs TLS check returned HTTP {(int)response.StatusCode}.");
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            return ParseSslLabsEvidence(context, document.RootElement);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return CreateProviderErrorEvidence(context, "SSL Labs TLS check timed out.");
        }
        catch (HttpRequestException)
        {
            return CreateProviderErrorEvidence(context, "SSL Labs TLS check could not be reached.");
        }
        catch (JsonException)
        {
            return CreateProviderErrorEvidence(context, "SSL Labs TLS check returned an unreadable response.");
        }
    }

    /// <summary>
    /// Creates a normalized TLS grade item for future concrete SSL Labs or Qualys API adapters.
    /// </summary>
    /// <param name="context">Privacy-safe scan context.</param>
    /// <param name="grade">Provider grade such as A, B, C, or F.</param>
    /// <param name="summary">Plain-English summary safe for users and admins.</param>
    /// <returns>Normalized TLS evidence.</returns>
    public SiteSafetyEvidence CreateTlsGradeEvidence(SiteSafetyEvidenceContext context, string grade, string summary)
    {
        var normalizedGrade = string.IsNullOrWhiteSpace(grade) ? "Unknown" : grade.Trim().ToUpperInvariant();
        var isStrong = normalizedGrade is "A+" or "A" or "A-";
        var isWeak = normalizedGrade is "C" or "D" or "E" or "F" or "T" or "M";
        var status = isStrong ? SiteSafetyEvidenceStatus.Positive : isWeak ? SiteSafetyEvidenceStatus.Weak : SiteSafetyEvidenceStatus.Clean;
        var riskImpact = isWeak ? 25 : 0;
        var trustImpact = isStrong ? 5 : 0;

        return new SiteSafetyEvidence(
            ProviderName,
            ProviderType,
            SiteSafetyEvidenceTargetType.Domain,
            context.Domain,
            context.UrlHash,
            [new SiteSafetyEvidenceItem(
                "TlsGrade",
                normalizedGrade,
                status,
                riskImpact,
                trustImpact,
                summary,
                EvidenceType: "TlsGrade",
                Confidence: isStrong || isWeak ? 80 : 50,
                Severity: isWeak ? SiteSafetyEvidenceSeverity.Medium : SiteSafetyEvidenceSeverity.Low,
                EvidenceQuality: SiteSafetyEvidenceItemQuality.Medium,
                SourceReference: "SSL Labs domain assessment",
                IsPositiveSignal: isStrong,
                IsNegativeSignal: isWeak)],
            Confidence: isStrong || isWeak ? 80 : 50,
            context.CheckedAtUtc,
            context.CheckedAtUtc.Add(ProviderOptions.CacheDuration ?? TimeSpan.FromHours(6)),
            [],
            IsAuthoritativeForRisk: false,
            IsAuthoritativeForTrust: true);
    }

    /// <summary>
    /// Builds the SSL Labs API request using only the domain, never the full page URL.
    /// </summary>
    /// <param name="domain">Normalized domain to check.</param>
    /// <returns>SSL Labs API URI.</returns>
    private Uri BuildSslLabsUri(string domain)
    {
        var endpoint = string.IsNullOrWhiteSpace(ProviderOptions.Endpoint) ? DefaultEndpoint : ProviderOptions.Endpoint.Trim();
        var builder = new UriBuilder(endpoint);
        // Do not force a brand-new SSL Labs assessment for every HIP scan. SSL Labs assessments are asynchronous;
        // repeatedly sending startNew=on keeps returning pending/Unknown evidence instead of reusing completed grades.
        var query = $"host={Uri.EscapeDataString(domain)}&publish=off&startNew=off&all=done&ignoreMismatch=on";

        builder.Query = string.IsNullOrWhiteSpace(builder.Query)
            ? query
            : $"{builder.Query.TrimStart('?')}&{query}";

        return builder.Uri;
    }

    /// <summary>
    /// Converts the SSL Labs JSON response into normalized HIP evidence without storing the raw response.
    /// </summary>
    /// <param name="context">Privacy-safe scan context.</param>
    /// <param name="root">Root SSL Labs JSON element.</param>
    /// <returns>Normalized TLS evidence.</returns>
    private SiteSafetyEvidence ParseSslLabsEvidence(SiteSafetyEvidenceContext context, JsonElement root)
    {
        var status = TryGetString(root, "status") ?? "Unknown";
        if (!status.Equals("READY", StringComparison.OrdinalIgnoreCase))
        {
            var statusSummary = status.Equals("ERROR", StringComparison.OrdinalIgnoreCase)
                ? "SSL Labs could not complete the TLS assessment."
                : $"SSL Labs TLS assessment is {status}; HIP did not apply a trust boost yet.";

            return CreateStatusEvidence(context, status, statusSummary, status.Equals("ERROR", StringComparison.OrdinalIgnoreCase));
        }

        var grades = new List<string>();
        if (root.TryGetProperty("endpoints", out var endpoints) && endpoints.ValueKind == JsonValueKind.Array)
        {
            foreach (var endpoint in endpoints.EnumerateArray())
            {
                var grade = TryGetString(endpoint, "grade");
                if (!string.IsNullOrWhiteSpace(grade))
                {
                    grades.Add(grade);
                }
            }
        }

        var selectedGrade = grades.Count == 0 ? "Unknown" : grades.OrderBy(GradeRiskRank).First();
        var summary = selectedGrade.Equals("Unknown", StringComparison.OrdinalIgnoreCase)
            ? "SSL Labs completed the TLS check, but no endpoint grade was available."
            : $"SSL Labs reported TLS grade {selectedGrade} for this domain.";

        return CreateTlsGradeEvidence(context, selectedGrade, summary);
    }

    /// <summary>
    /// Creates normalized status evidence for pending or errored SSL Labs assessments.
    /// </summary>
    /// <param name="context">Privacy-safe scan context.</param>
    /// <param name="status">Provider status label.</param>
    /// <param name="summary">Plain-English summary.</param>
    /// <param name="isError">Whether the provider returned a terminal error.</param>
    /// <returns>Normalized status evidence.</returns>
    private SiteSafetyEvidence CreateStatusEvidence(SiteSafetyEvidenceContext context, string status, string summary, bool isError) =>
        new(
            ProviderName,
            ProviderType,
            SiteSafetyEvidenceTargetType.Domain,
            context.Domain,
            context.UrlHash,
            [new SiteSafetyEvidenceItem(
                "TlsAssessmentStatus",
                status,
                isError ? SiteSafetyEvidenceStatus.Error : SiteSafetyEvidenceStatus.Weak,
                0,
                0,
                summary,
                EvidenceType: "ProviderStatus",
                Confidence: isError ? 0 : 30,
                Severity: isError ? SiteSafetyEvidenceSeverity.Low : SiteSafetyEvidenceSeverity.Info,
                EvidenceQuality: SiteSafetyEvidenceItemQuality.Weak,
                SourceReference: "SSL Labs domain assessment")],
            Confidence: isError ? 0 : 30,
            context.CheckedAtUtc,
            context.CheckedAtUtc.AddMinutes(isError ? 5 : 2),
            isError ? [summary] : [],
            IsAuthoritativeForRisk: false,
            IsAuthoritativeForTrust: false);

    /// <summary>
    /// Creates safe provider error evidence without leaking request URLs, secrets, or raw provider bodies.
    /// </summary>
    /// <param name="context">Privacy-safe scan context.</param>
    /// <param name="message">Safe error message.</param>
    /// <returns>Normalized error evidence.</returns>
    private SiteSafetyEvidence CreateProviderErrorEvidence(SiteSafetyEvidenceContext context, string message) =>
        new(
            ProviderName,
            ProviderType,
            SiteSafetyEvidenceTargetType.Domain,
            context.Domain,
            context.UrlHash,
            [],
            Confidence: 0,
            context.CheckedAtUtc,
            context.CheckedAtUtc.AddMinutes(5),
            [message],
            IsAuthoritativeForRisk: false,
            IsAuthoritativeForTrust: false);

    /// <summary>
    /// Reads a string property from provider JSON without throwing for missing or non-string values.
    /// </summary>
    /// <param name="element">JSON element to inspect.</param>
    /// <param name="propertyName">Property name to read.</param>
    /// <returns>String value or null.</returns>
    private static string? TryGetString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;

    /// <summary>
    /// Ranks TLS grades so the weakest endpoint grade is selected when a domain has multiple endpoints.
    /// </summary>
    /// <param name="grade">SSL Labs grade.</param>
    /// <returns>Lower values represent weaker grades.</returns>
    private static int GradeRiskRank(string grade) =>
        grade.Trim().ToUpperInvariant() switch
        {
            "T" or "M" => 0,
            "F" => 1,
            "E" => 2,
            "D" => 3,
            "C" => 4,
            "B" => 5,
            "A-" => 6,
            "A" => 7,
            "A+" => 8,
            _ => 9
        };
}

/// <summary>
/// Google Web Risk / Safe Browsing-style threat-intelligence evidence provider.
/// </summary>
/// <remarks>
/// This provider is disabled by default. Future concrete adapters should use hash-prefix or domain checks where
/// possible and must not send page body text, form values, passwords, email content, cookies, or tokens.
/// </remarks>
public sealed class GoogleWebRiskSiteEvidenceProvider(
    IExternalSiteEvidenceCache cache,
    ExternalSiteEvidenceOptions options) : ExternalSiteEvidenceProviderBase(cache, options)
{
    /// <inheritdoc />
    public override string ProviderName => "Google Web Risk / Safe Browsing";

    /// <inheritdoc />
    public override SiteSafetyEvidenceProviderType ProviderType => SiteSafetyEvidenceProviderType.ThreatIntel;

    /// <inheritdoc />
    protected override ExternalProviderOptions ProviderOptions => Options.GoogleWebRisk;

    /// <inheritdoc />
    protected override Task<SiteSafetyEvidence> CollectExternalEvidenceAsync(SiteSafetyEvidenceContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(ExternalSiteEvidenceProviderHelpers.ConfigurationRequiredEvidence(
            context,
            "Google Web Risk provider is enabled, but API credentials and adapter implementation are not configured yet.",
            SiteSafetyEvidenceTargetType.Url,
            ProviderName,
            ProviderType,
            authoritativeRisk: false,
            authoritativeTrust: false));
    }

    /// <summary>
    /// Creates normalized phishing evidence for future Google Web Risk or Safe Browsing API adapters.
    /// </summary>
    /// <param name="context">Privacy-safe scan context.</param>
    /// <param name="matchedThreatType">Matched provider threat label.</param>
    /// <returns>Authoritative risk evidence.</returns>
    public SiteSafetyEvidence CreateThreatMatchEvidence(SiteSafetyEvidenceContext context, string matchedThreatType) =>
        ExternalSiteEvidenceProviderHelpers.CreateThreatEvidence(context, ProviderName, ProviderType, "PhishingMatch", matchedThreatType, "Google threat-intelligence provider matched a phishing indicator.");
}

/// <summary>
/// VirusTotal URL/domain reputation evidence provider.
/// </summary>
/// <remarks>
/// This provider is disabled by default. Future concrete adapters should prefer domain checks or URL hashes and
/// must not send page body text, form values, passwords, email content, cookies, or tokens.
/// </remarks>
public sealed class VirusTotalSiteEvidenceProvider(
    IExternalSiteEvidenceCache cache,
    ExternalSiteEvidenceOptions options) : ExternalSiteEvidenceProviderBase(cache, options)
{
    /// <inheritdoc />
    public override string ProviderName => "VirusTotal";

    /// <inheritdoc />
    public override SiteSafetyEvidenceProviderType ProviderType => SiteSafetyEvidenceProviderType.UrlReputation;

    /// <inheritdoc />
    protected override ExternalProviderOptions ProviderOptions => Options.VirusTotal;

    /// <inheritdoc />
    protected override Task<SiteSafetyEvidence> CollectExternalEvidenceAsync(SiteSafetyEvidenceContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(ExternalSiteEvidenceProviderHelpers.ConfigurationRequiredEvidence(
            context,
            "VirusTotal provider is enabled, but API credentials and adapter implementation are not configured yet.",
            SiteSafetyEvidenceTargetType.Url,
            ProviderName,
            ProviderType,
            authoritativeRisk: false,
            authoritativeTrust: false));
    }

    /// <summary>
    /// Creates normalized malware evidence for future VirusTotal API adapters.
    /// </summary>
    /// <param name="context">Privacy-safe scan context.</param>
    /// <param name="matchLabel">Provider match label.</param>
    /// <returns>Authoritative risk evidence.</returns>
    public SiteSafetyEvidence CreateMalwareMatchEvidence(SiteSafetyEvidenceContext context, string matchLabel) =>
        ExternalSiteEvidenceProviderHelpers.CreateThreatEvidence(context, ProviderName, ProviderType, "MalwareMatch", matchLabel, "VirusTotal matched a malware or malicious URL indicator.");
}

/// <summary>
/// Shared helpers for concrete external provider adapters.
/// </summary>
internal static class ExternalSiteEvidenceProviderHelpers
{
    /// <summary>
    /// Creates a safe configuration-required record without exposing secrets or private content.
    /// </summary>
    /// <param name="context">Privacy-safe scan context.</param>
    /// <param name="message">Safe operator-facing message.</param>
    /// <param name="targetType">Evidence target type.</param>
    /// <param name="providerName">Provider name.</param>
    /// <param name="providerType">Provider type.</param>
    /// <param name="authoritativeRisk">Whether this provider can be authoritative for risk.</param>
    /// <param name="authoritativeTrust">Whether this provider can be authoritative for trust.</param>
    /// <returns>Provider evidence with no score impact.</returns>
    public static SiteSafetyEvidence ConfigurationRequiredEvidence(
        SiteSafetyEvidenceContext context,
        string message,
        SiteSafetyEvidenceTargetType targetType,
        string providerName,
        SiteSafetyEvidenceProviderType providerType,
        bool authoritativeRisk,
        bool authoritativeTrust) =>
        new(
            providerName,
            providerType,
            targetType,
            context.Domain,
            context.UrlHash,
            [],
            Confidence: 0,
            context.CheckedAtUtc,
            context.CheckedAtUtc.AddMinutes(5),
            [message],
            IsAuthoritativeForRisk: authoritativeRisk,
            IsAuthoritativeForTrust: authoritativeTrust);

    /// <summary>
    /// Creates normalized authoritative threat evidence without storing provider-specific raw response bodies.
    /// </summary>
    /// <param name="context">Privacy-safe scan context.</param>
    /// <param name="providerName">Provider name.</param>
    /// <param name="providerType">Provider type.</param>
    /// <param name="category">Provider-neutral category.</param>
    /// <param name="value">Provider-neutral value.</param>
    /// <param name="summary">Plain-English summary.</param>
    /// <returns>Authoritative risk evidence.</returns>
    public static SiteSafetyEvidence CreateThreatEvidence(
        SiteSafetyEvidenceContext context,
        string providerName,
        SiteSafetyEvidenceProviderType providerType,
        string category,
        string value,
        string summary) =>
        new(
            providerName,
            providerType,
            SiteSafetyEvidenceTargetType.Url,
            context.Domain,
            context.UrlHash,
            [new SiteSafetyEvidenceItem(
                category,
                value,
                SiteSafetyEvidenceStatus.Dangerous,
                95,
                0,
                summary,
                EvidenceType: "ThreatMatch",
                Confidence: 90,
                Severity: SiteSafetyEvidenceSeverity.Critical,
                EvidenceQuality: SiteSafetyEvidenceItemQuality.Strong,
                SourceReference: providerName,
                IsNegativeSignal: true,
                IsBlockingSignal: true)],
            Confidence: 90,
            context.CheckedAtUtc,
            context.CheckedAtUtc.AddHours(6),
            [],
            IsAuthoritativeForRisk: true,
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
