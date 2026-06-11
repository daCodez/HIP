using HIP.Application.PublicLookup;
using HIP.Application.Reporting;
using HIP.Application.Scalability;
using HIP.Application.Security;

namespace HIP.Application.Browser;

/// <summary>
/// Validates and stores browser plugin scan summaries while preserving HIP privacy boundaries.
/// </summary>
public sealed class BrowserScanResultService : IBrowserScanResultService, IBrowserScanResultWriteService, IBrowserScanResultQueryService
{
    private const int MaxReasonLength = 300;
    private const int MaxMetadataKeyLength = 80;
    private const int MaxMetadataValueLength = 200;
    private const int MaxPluginVersionLength = 80;
    private static readonly TimeSpan HotPathCacheDuration = TimeSpan.FromMinutes(15);
    private readonly IBrowserScanResultRepository repository;
    private readonly IPrivacyHashingService hashingService;
    private readonly IScanResultCache scanResultCache;
    private readonly IDashboardScanAggregateStore dashboardAggregateStore;
    private readonly IPrivacyStoragePolicy privacyStoragePolicy;
    private readonly IOutboxEventWriter? outboxEventWriter;

    /// <summary>
    /// Creates the service with no-op scalability adapters for isolated tests or simple single-node hosts.
    /// </summary>
    /// <param name="repository">Repository used for durable scan result storage.</param>
    /// <param name="hashingService">Privacy hashing service used when clients send raw page URLs.</param>
    public BrowserScanResultService(
        IBrowserScanResultRepository repository,
        IPrivacyHashingService hashingService)
        : this(
            repository,
            hashingService,
            new InMemoryScanResultCache(),
            new InMemoryDashboardScanAggregateStore(),
            new DefaultPrivacyStoragePolicy(),
            null)
    {
    }

    /// <summary>
    /// Creates the service with explicit scalability adapters.
    /// </summary>
    /// <param name="repository">Repository used for durable scan result storage.</param>
    /// <param name="hashingService">Privacy hashing service used when clients send raw page URLs.</param>
    /// <param name="scanResultCache">Hot-path cache for latest domain scan summaries.</param>
    /// <param name="dashboardAggregateStore">Pre-aggregated dashboard counter store.</param>
    public BrowserScanResultService(
        IBrowserScanResultRepository repository,
        IPrivacyHashingService hashingService,
        IScanResultCache scanResultCache,
        IDashboardScanAggregateStore dashboardAggregateStore)
        : this(repository, hashingService, scanResultCache, dashboardAggregateStore, new DefaultPrivacyStoragePolicy(), null)
    {
    }

    /// <summary>
    /// Creates the service with explicit scalability adapters, storage policy, and optional outbox writer.
    /// </summary>
    /// <param name="repository">Repository used for durable scan result storage.</param>
    /// <param name="hashingService">Privacy hashing service used when clients send raw page URLs.</param>
    /// <param name="scanResultCache">Hot-path cache for latest domain scan summaries.</param>
    /// <param name="dashboardAggregateStore">Pre-aggregated dashboard counter store.</param>
    /// <param name="privacyStoragePolicy">Policy that decides which metadata can be stored.</param>
    /// <param name="outboxEventWriter">Optional durable outbox writer used for retry-safe downstream workflows.</param>
    public BrowserScanResultService(
        IBrowserScanResultRepository repository,
        IPrivacyHashingService hashingService,
        IScanResultCache scanResultCache,
        IDashboardScanAggregateStore dashboardAggregateStore,
        IPrivacyStoragePolicy privacyStoragePolicy,
        IOutboxEventWriter? outboxEventWriter = null)
    {
        this.repository = repository;
        this.hashingService = hashingService;
        this.scanResultCache = scanResultCache;
        this.dashboardAggregateStore = dashboardAggregateStore;
        this.privacyStoragePolicy = privacyStoragePolicy;
        this.outboxEventWriter = outboxEventWriter;
    }

    /// <summary>
    /// Saves a browser scan summary after normalizing the domain, hashing the page URL, and rejecting private metadata.
    /// </summary>
    /// <param name="request">Browser plugin scan result request.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Save confirmation with the normalized domain and assigned timestamp.</returns>
    public async Task<BrowserScanResultSaveResponse> SaveAsync(BrowserScanResultSaveRequest request, CancellationToken cancellationToken)
    {
        var domain = DomainInputValidator.ValidateAndNormalize(request.Domain);
        ValidateScore(request.Score);
        ValidateCounts(request);
        var pageUrlHash = ResolvePageUrlHash(request);

        var now = request.ScannedAtUtc ?? DateTimeOffset.UtcNow;
        var metadata = AddScalabilityMetadata(AddPluginVersion(ValidateMetadata(request.PrivacySafeMetadata), request.PluginVersion), request);
        var reasons = NormalizeReasons(request.Reasons);
        var record = new BrowserScanResultRecord(
            $"browser-scan:{domain}:{Guid.NewGuid():N}",
            domain,
            pageUrlHash,
            null,
            "BrowserPlugin",
            request.Score,
            RequiredText(request.RiskLevel, "Risk level is required."),
            RequiredText(request.Status, "Status is required."),
            reasons,
            request.LinksScanned,
            request.RiskyLinksFound,
            request.SuspiciousLinksFound,
            request.DangerousLinksFound,
            now,
            RequiredText(request.RecommendedAction, "Recommended action is required."),
            metadata);

        await repository.SaveAsync(record, cancellationToken);
        await scanResultCache.StoreAsync(record, HotPathCacheDuration, cancellationToken);
        await dashboardAggregateStore.UpdateAsync(record, cancellationToken);
        await EnqueueScanStoredEventAsync(record, cancellationToken);
        return new BrowserScanResultSaveResponse(true, domain, now);
    }

    /// <summary>
    /// Retrieves the latest browser scan result by normalized domain without exposing page URL hashes or private fields.
    /// </summary>
    /// <param name="domain">Domain requested by the client.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>A privacy-safe API response or null when no result exists.</returns>
    public async Task<BrowserScanResultResponse?> GetLatestByDomainAsync(string domain, CancellationToken cancellationToken)
    {
        var normalizedDomain = DomainInputValidator.ValidateAndNormalize(domain);
        var cached = await scanResultCache.GetFreshAsync(normalizedDomain, cancellationToken);
        if (cached is not null)
        {
            return BrowserScanResultResponse.From(cached.Result);
        }

        var record = await repository.GetLatestByDomainAsync(normalizedDomain, cancellationToken);
        return record is null ? null : BrowserScanResultResponse.From(record);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<BrowserScanResultResponse>> ListRecentAsync(int maxCount, CancellationToken cancellationToken)
    {
        var boundedMax = Math.Clamp(maxCount, 0, 200);
        var records = await repository.ListAsync(cancellationToken);
        return records
            .OrderByDescending(record => record.LastCheckedUtc)
            .Take(boundedMax)
            .Select(BrowserScanResultResponse.From)
            .ToArray();
    }

    /// <summary>
    /// Rejects scores outside the HIP 0-100 range so bad client data cannot corrupt downstream scoring.
    /// </summary>
    /// <param name="score">Client-provided score.</param>
    private static void ValidateScore(int score)
    {
        if (score is < 0 or > 100)
        {
            throw new ArgumentException("Score must be between 0 and 100.");
        }
    }

    /// <summary>
    /// Validates scan counters and their basic relationships to avoid impossible summary data.
    /// </summary>
    /// <param name="request">Browser plugin scan result request.</param>
    private static void ValidateCounts(BrowserScanResultSaveRequest request)
    {
        if (request.LinksScanned < 0 ||
            request.RiskyLinksFound < 0 ||
            request.SuspiciousLinksFound < 0 ||
            request.DangerousLinksFound < 0)
        {
            throw new ArgumentException("Scan counts cannot be negative.");
        }

        if (request.RiskyLinksFound > request.LinksScanned)
        {
            throw new ArgumentException("Risky link count cannot exceed links scanned.");
        }
    }

    /// <summary>
    /// Ensures HIP only accepts web page URLs and hashes them instead of storing raw URLs by default.
    /// </summary>
    /// <param name="pageUrl">Page URL supplied by the browser plugin.</param>
    private static void ValidateHttpUrl(string pageUrl)
    {
        if (!Uri.TryCreate(pageUrl, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
        {
            throw new ArgumentException("A valid HTTP or HTTPS page URL is required.");
        }
    }

    /// <summary>
    /// Resolves the stored URL hash from the browser-provided hash or by hashing a valid HTTP URL.
    /// </summary>
    /// <param name="request">Browser plugin scan result request.</param>
    /// <returns>Safe hash value used for storage.</returns>
    /// <remarks>
    /// New extension builds send <see cref="BrowserScanResultSaveRequest.PageUrlHash" /> so HIP does not need a raw
    /// full URL for persistence. Older builds can still send <see cref="BrowserScanResultSaveRequest.PageUrl" />,
    /// which HIP validates and hashes immediately.
    /// </remarks>
    private string ResolvePageUrlHash(BrowserScanResultSaveRequest request)
    {
        if (!string.IsNullOrWhiteSpace(request.PageUrlHash))
        {
            return ValidateSha256Hash(request.PageUrlHash);
        }

        ValidateHttpUrl(RequiredText(request.PageUrl, "A valid HTTP or HTTPS page URL or page URL hash is required."));
        return hashingService.Hash(request.PageUrl!);
    }

    /// <summary>
    /// Validates a client-provided SHA-256 URL hash before accepting it for storage.
    /// </summary>
    /// <param name="hash">Client-supplied hash.</param>
    /// <returns>Normalized hash.</returns>
    private static string ValidateSha256Hash(string hash)
    {
        var trimmed = hash.Trim().ToLowerInvariant();
        if (!System.Text.RegularExpressions.Regex.IsMatch(trimmed, "^sha256:[0-9a-f]{64}$"))
        {
            throw new ArgumentException("Page URL hash must be a sha256 hash.");
        }

        return trimmed;
    }

    /// <summary>
    /// Normalizes user-facing reasons and trims oversized entries so responses stay display-safe.
    /// </summary>
    /// <param name="reasons">Optional plain-English reasons.</param>
    /// <returns>Sanitized reasons collection.</returns>
    private static IReadOnlyCollection<string> NormalizeReasons(IReadOnlyCollection<string>? reasons)
    {
        var normalized = (reasons ?? Array.Empty<string>())
            .Where(reason => !string.IsNullOrWhiteSpace(reason))
            .Select(reason => reason.Trim())
            .Select(reason => reason.Length > MaxReasonLength ? reason[..MaxReasonLength] : reason)
            .Take(10)
            .ToArray();

        return normalized.Length > 0
            ? normalized
            : ["Browser plugin completed a privacy-safe scan without sending page text or form values."];
    }

    /// <summary>
    /// Validates privacy-safe metadata and rejects keys commonly associated with private content.
    /// </summary>
    /// <param name="metadata">Client-provided metadata dictionary.</param>
    /// <returns>Sanitized metadata dictionary.</returns>
    private IReadOnlyDictionary<string, string> ValidateMetadata(IReadOnlyDictionary<string, string>? metadata)
    {
        if (metadata is null || metadata.Count == 0)
        {
            return new Dictionary<string, string>();
        }

        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in metadata.Take(20))
        {
            var trimmedKey = RequiredText(key, "Metadata keys cannot be empty.");
            var decision = privacyStoragePolicy.CanStoreMetadataKey(trimmedKey);
            if (!decision.Allowed)
            {
                throw new ArgumentException(decision.Reason);
            }

            if (trimmedKey.Length > MaxMetadataKeyLength)
            {
                throw new ArgumentException("Metadata keys are too long.");
            }

            result[trimmedKey] = privacyStoragePolicy.SanitizeMetadataValue(value, MaxMetadataValueLength);
        }

        return result;
    }

    /// <summary>
    /// Emits a privacy-safe outbox event so downstream scan history, dashboard, and review workers can retry safely.
    /// </summary>
    /// <param name="record">Saved browser scan record.</param>
    /// <param name="cancellationToken">Token used to cancel outbox persistence.</param>
    private async Task EnqueueScanStoredEventAsync(BrowserScanResultRecord record, CancellationToken cancellationToken)
    {
        if (outboxEventWriter is null)
        {
            return;
        }

        var durableEvent = HipDurableEventFactory.Create(
            "BrowserScanResultStored",
            "BrowserScanResult",
            record.ScanResultId,
            new
            {
                record.Domain,
                record.PageUrlHash,
                record.Score,
                record.Status,
                record.RiskLevel,
                record.RecommendedAction,
                record.LinksScanned,
                record.RiskyLinksFound,
                record.LastCheckedUtc,
                PluginVersion = record.PrivacySafeMetadata.TryGetValue("pluginVersion", out var version) ? version : null,
                SignalHash = record.PrivacySafeMetadata.TryGetValue("signalHash", out var signalHash) ? signalHash : null
            },
            HipDurableEventPrivacyLevel.HashedSensitive);

        await outboxEventWriter.EnqueueAsync(durableEvent, cancellationToken);
    }

    /// <summary>
    /// Adds plugin version provenance to metadata after bounding its length and avoiding duplicate hardcoded fields.
    /// </summary>
    /// <param name="metadata">Validated metadata.</param>
    /// <param name="pluginVersion">Optional plugin version from the browser extension.</param>
    /// <returns>Metadata with plugin version when provided.</returns>
    private static IReadOnlyDictionary<string, string> AddPluginVersion(IReadOnlyDictionary<string, string> metadata, string? pluginVersion)
    {
        var result = new Dictionary<string, string>(metadata, StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(pluginVersion))
        {
            var safeVersion = pluginVersion.Trim();
            result["pluginVersion"] = safeVersion.Length > MaxPluginVersionLength
                ? safeVersion[..MaxPluginVersionLength]
                : safeVersion;
        }

        return result;
    }

    /// <summary>
    /// Adds privacy-safe scalability metadata used for dedupe, cache provenance, and dashboard live-data tracing.
    /// </summary>
    /// <param name="metadata">Validated metadata.</param>
    /// <param name="request">Original save request.</param>
    /// <returns>Metadata with a deterministic signal hash.</returns>
    private static IReadOnlyDictionary<string, string> AddScalabilityMetadata(IReadOnlyDictionary<string, string> metadata, BrowserScanResultSaveRequest request)
    {
        var result = new Dictionary<string, string>(metadata, StringComparer.OrdinalIgnoreCase)
        {
            ["signalHash"] = ScanScalabilityKeys.CreateSignalHash(request),
            ["scalabilityPath"] = "HotPathStoredSummary"
        };

        return result;
    }

    /// <summary>
    /// Validates required text fields and returns the trimmed value.
    /// </summary>
    /// <param name="value">Value to validate.</param>
    /// <param name="message">Message used when validation fails.</param>
    /// <returns>Trimmed value.</returns>
    private static string RequiredText(string? value, string message)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(message);
        }

        return value.Trim();
    }
}
