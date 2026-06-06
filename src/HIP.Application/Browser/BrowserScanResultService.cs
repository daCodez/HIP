using HIP.Application.PublicLookup;
using HIP.Application.Reporting;

namespace HIP.Application.Browser;

/// <summary>
/// Validates and stores browser plugin scan summaries while preserving HIP privacy boundaries.
/// </summary>
public sealed class BrowserScanResultService(
    IBrowserScanResultRepository repository,
    IPrivacyHashingService hashingService) : IBrowserScanResultService
{
    private const int MaxReasonLength = 300;
    private const int MaxMetadataKeyLength = 80;
    private const int MaxMetadataValueLength = 200;

    private static readonly HashSet<string> PrivateMetadataKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "pageText",
        "bodyText",
        "formContents",
        "password",
        "username",
        "token",
        "privateMessage",
        "emailBody",
        "chatLog"
    };

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
        ValidateHttpUrl(request.PageUrl);

        var now = request.ScannedAtUtc ?? DateTimeOffset.UtcNow;
        var metadata = ValidateMetadata(request.PrivacySafeMetadata);
        var reasons = NormalizeReasons(request.Reasons);
        var record = new BrowserScanResultRecord(
            $"browser-scan:{domain}:{Guid.NewGuid():N}",
            domain,
            hashingService.Hash(request.PageUrl),
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
        var record = await repository.GetLatestByDomainAsync(normalizedDomain, cancellationToken);
        return record is null ? null : BrowserScanResultResponse.From(record);
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
    private static IReadOnlyDictionary<string, string> ValidateMetadata(IReadOnlyDictionary<string, string>? metadata)
    {
        if (metadata is null || metadata.Count == 0)
        {
            return new Dictionary<string, string>();
        }

        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in metadata.Take(20))
        {
            var trimmedKey = RequiredText(key, "Metadata keys cannot be empty.");
            if (PrivateMetadataKeys.Contains(trimmedKey))
            {
                throw new ArgumentException($"Metadata field '{trimmedKey}' is not privacy-safe.");
            }

            if (trimmedKey.Length > MaxMetadataKeyLength)
            {
                throw new ArgumentException("Metadata keys are too long.");
            }

            var safeValue = value?.Trim() ?? string.Empty;
            result[trimmedKey] = safeValue.Length > MaxMetadataValueLength
                ? safeValue[..MaxMetadataValueLength]
                : safeValue;
        }

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
