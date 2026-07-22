namespace HIP.Application.SiteSafety;

/// <summary>
/// Validates and normalizes untrusted provider results before rules or scoring can consume them.
/// Provider-specific response bodies and private page data are never retained by this boundary.
/// </summary>
public static class SiteSafetyProviderResultContract
{
    /// <summary>Maximum normalized signals retained from one provider result.</summary>
    public const int MaximumEvidenceItems = 64;
    /// <summary>Maximum safe error summaries retained from one provider result.</summary>
    public const int MaximumErrors = 8;
    /// <summary>Maximum registered provider name length.</summary>
    public const int MaximumProviderNameLength = 128;
    /// <summary>Maximum provider-neutral category or type token length.</summary>
    public const int MaximumTokenLength = 128;
    /// <summary>Maximum normalized value or source-reference length.</summary>
    public const int MaximumValueLength = 256;
    /// <summary>Maximum plain-language evidence summary length.</summary>
    public const int MaximumSummaryLength = 512;
    /// <summary>Maximum safe provider error length.</summary>
    public const int MaximumErrorLength = 256;
    /// <summary>Age after which otherwise valid evidence is classified as stale.</summary>
    public static readonly TimeSpan PreferredFreshnessWindow = TimeSpan.FromHours(1);
    /// <summary>Maximum provider evidence lifetime accepted at the boundary.</summary>
    public static readonly TimeSpan MaximumEvidenceLifetime = TimeSpan.FromDays(30);
    /// <summary>Maximum provider latency retained in the normalized contract.</summary>
    public static readonly TimeSpan MaximumRecordedLatency = TimeSpan.FromHours(1);

    /// <summary>Validates a provider return value and attaches normalized operational metadata.</summary>
    public static SiteSafetyEvidence Normalize(
        SiteSafetyEvidence evidence,
        string expectedProviderName,
        SiteSafetyEvidenceProviderType expectedProviderType,
        SiteSafetyEvidenceContext context,
        TimeSpan latency,
        DateTimeOffset completedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        ArgumentNullException.ThrowIfNull(context);
        ValidateProviderIdentity(evidence, expectedProviderName, expectedProviderType);
        ValidateTarget(evidence, context);
        ValidateBounds(evidence);

        var checkedAtUtc = evidence.CheckedAtUtc.ToUniversalTime();
        var expiresAtUtc = evidence.ExpiresAtUtc.ToUniversalTime();
        var completedUtc = completedAtUtc.ToUniversalTime();
        if (expiresAtUtc <= checkedAtUtc ||
            expiresAtUtc - checkedAtUtc > MaximumEvidenceLifetime ||
            checkedAtUtc > completedUtc.AddMinutes(5))
        {
            throw new ArgumentException("Provider evidence timestamps are inconsistent or outside supported bounds.", nameof(evidence));
        }

        var latencyMilliseconds = NormalizeLatency(latency);
        var items = Array.AsReadOnly(evidence.EvidenceItems
            .Select(NormalizeItem)
            .ToArray());
        var errors = Array.AsReadOnly(evidence.Errors
            .Select(error => RequiredText(error, MaximumErrorLength, nameof(evidence.Errors)))
            .Distinct(StringComparer.Ordinal)
            .ToArray());
        var resultStatus = errors.Count == 0
            ? SiteSafetyProviderResultStatus.Succeeded
            : items.Count == 0
                ? SiteSafetyProviderResultStatus.Failed
                : SiteSafetyProviderResultStatus.Partial;
        var freshness = expiresAtUtc <= completedUtc
            ? SiteSafetyProviderFreshness.Expired
            : checkedAtUtc < completedUtc - PreferredFreshnessWindow
                ? SiteSafetyProviderFreshness.Stale
                : SiteSafetyProviderFreshness.Fresh;
        var privacy = expectedProviderType == SiteSafetyEvidenceProviderType.BrowserObserved
            ? SiteSafetyProviderPrivacyClassification.PrivacySafeObservedSignals
            : evidence.TargetType is not SiteSafetyEvidenceTargetType.Domain || evidence.UrlHash is not null
                ? SiteSafetyProviderPrivacyClassification.HashedUrlMetadata
                : SiteSafetyProviderPrivacyClassification.PublicDomainMetadata;

        return evidence with
        {
            ProviderName = evidence.ProviderName.Trim(),
            Domain = evidence.Domain.Trim().ToLowerInvariant(),
            EvidenceItems = items,
            Errors = errors,
            CheckedAtUtc = checkedAtUtc,
            ExpiresAtUtc = expiresAtUtc,
            ResultStatus = resultStatus,
            LatencyMilliseconds = latencyMilliseconds,
            Freshness = freshness,
            PrivacyClassification = privacy,
            IsAuthoritativeForRisk = resultStatus != SiteSafetyProviderResultStatus.Failed && evidence.IsAuthoritativeForRisk,
            IsAuthoritativeForTrust = resultStatus != SiteSafetyProviderResultStatus.Failed && evidence.IsAuthoritativeForTrust
        };
    }

    /// <summary>Creates a bounded timeout or failure result without trusting provider-authored content.</summary>
    public static SiteSafetyEvidence CreateFailure(
        string providerName,
        SiteSafetyEvidenceProviderType providerType,
        SiteSafetyEvidenceContext context,
        SiteSafetyProviderResultStatus status,
        TimeSpan latency,
        DateTimeOffset completedAtUtc,
        string safeError)
    {
        if (status is not SiteSafetyProviderResultStatus.TimedOut and not SiteSafetyProviderResultStatus.Failed)
        {
            throw new ArgumentException("A provider failure result must be timed out or failed.", nameof(status));
        }

        var completedUtc = completedAtUtc.ToUniversalTime();
        var normalized = Normalize(
            new SiteSafetyEvidence(
                providerName,
                providerType,
                SiteSafetyEvidenceTargetType.Domain,
                context.Domain,
                context.UrlHash,
                [],
                Confidence: 0,
                completedUtc,
                completedUtc.AddMinutes(10),
                [RequiredText(safeError, MaximumErrorLength, nameof(safeError))],
                IsAuthoritativeForRisk: false,
                IsAuthoritativeForTrust: false),
            providerName,
            providerType,
            context,
            latency,
            completedUtc);
        return normalized with { ResultStatus = status };
    }

    private static void ValidateProviderIdentity(
        SiteSafetyEvidence evidence,
        string expectedProviderName,
        SiteSafetyEvidenceProviderType expectedProviderType)
    {
        var expectedName = RequiredText(
            expectedProviderName,
            MaximumProviderNameLength,
            nameof(expectedProviderName));
        if (!Enum.IsDefined(expectedProviderType))
        {
            throw new ArgumentOutOfRangeException(nameof(expectedProviderType));
        }

        if (!string.Equals(evidence.ProviderName, expectedName, StringComparison.Ordinal) ||
            evidence.ProviderType != expectedProviderType)
        {
            throw new ArgumentException("Provider evidence identity does not match the registered provider.", nameof(evidence));
        }
    }

    private static void ValidateTarget(SiteSafetyEvidence evidence, SiteSafetyEvidenceContext context)
    {
        if (!Enum.IsDefined(evidence.TargetType))
        {
            throw new ArgumentOutOfRangeException(nameof(evidence), "Provider evidence target type is unsupported.");
        }

        if (!IsCanonicalSha256Hash(context.UrlHash) ||
            evidence.TargetType is not SiteSafetyEvidenceTargetType.Domain && evidence.UrlHash is null ||
            !string.Equals(evidence.Domain, context.Domain, StringComparison.Ordinal) ||
            evidence.UrlHash is not null &&
            (!IsCanonicalSha256Hash(evidence.UrlHash) ||
             !string.Equals(evidence.UrlHash, context.UrlHash, StringComparison.Ordinal)))
        {
            throw new ArgumentException("Provider evidence is not bound to the requested target.", nameof(evidence));
        }
    }

    private static void ValidateBounds(SiteSafetyEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence.EvidenceItems);
        ArgumentNullException.ThrowIfNull(evidence.Errors);
        if (evidence.EvidenceItems.Count > MaximumEvidenceItems)
        {
            throw new ArgumentOutOfRangeException(nameof(evidence), $"A provider result accepts no more than {MaximumEvidenceItems} evidence items.");
        }

        if (evidence.Errors.Count > MaximumErrors)
        {
            throw new ArgumentOutOfRangeException(nameof(evidence), $"A provider result accepts no more than {MaximumErrors} safe errors.");
        }

        if (evidence.Confidence is < 0 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(evidence), "Provider confidence must be between 0 and 100.");
        }
    }

    private static SiteSafetyEvidenceItem NormalizeItem(SiteSafetyEvidenceItem item)
    {
        ArgumentNullException.ThrowIfNull(item);
        if (!Enum.IsDefined(item.Status) || !Enum.IsDefined(item.Severity) || !Enum.IsDefined(item.EvidenceQuality))
        {
            throw new ArgumentOutOfRangeException(nameof(item), "Provider evidence contains an unsupported classification.");
        }

        if (item.RiskImpact is < 0 or > 100 || item.TrustImpact is < 0 or > 100 || item.Confidence is < 0 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(item), "Provider evidence scores must be between 0 and 100.");
        }

        if (item.IsPositiveSignal && item.IsNegativeSignal)
        {
            throw new ArgumentException("Provider evidence cannot be both a positive and negative signal.", nameof(item));
        }

        return item with
        {
            Category = RequiredText(item.Category, MaximumTokenLength, nameof(item.Category)),
            EvidenceType = RequiredText(item.EvidenceType, MaximumTokenLength, nameof(item.EvidenceType)),
            Value = RequiredText(item.Value, MaximumValueLength, nameof(item.Value)),
            Summary = RequiredText(item.Summary, MaximumSummaryLength, nameof(item.Summary)),
            SourceReference = item.SourceReference is null
                ? null
                : RequiredText(item.SourceReference, MaximumValueLength, nameof(item.SourceReference))
        };
    }

    private static long NormalizeLatency(TimeSpan latency)
    {
        if (latency < TimeSpan.Zero || latency > MaximumRecordedLatency)
        {
            throw new ArgumentOutOfRangeException(nameof(latency));
        }

        return checked((long)Math.Round(latency.TotalMilliseconds, MidpointRounding.AwayFromZero));
    }

    private static string RequiredText(string value, int maximumLength, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        var trimmed = value.Trim();
        if (trimmed.Length > maximumLength || trimmed.Any(char.IsControl))
        {
            throw new ArgumentException("Provider metadata must be bounded plain text.", parameterName);
        }

        return trimmed;
    }

    private static bool IsCanonicalSha256Hash(string value) =>
        value.Length == 64 && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}
