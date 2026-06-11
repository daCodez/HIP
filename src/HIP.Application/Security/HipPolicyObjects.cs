using HIP.Application.Reputation;
using HIP.Application.SiteSafety;
using HIP.Domain.Reputation;

namespace HIP.Application.Security;

/// <summary>
/// Represents whether a privacy-sensitive storage operation is allowed.
/// </summary>
/// <param name="Allowed">Whether the operation may continue.</param>
/// <param name="Reason">Plain-English reason safe for logs and validation errors.</param>
public sealed record PrivacyStorageDecision(bool Allowed, string Reason);

/// <summary>
/// Centralizes HIP's privacy-at-rest decisions so scan services do not each maintain their own deny lists.
/// </summary>
public interface IPrivacyStoragePolicy
{
    /// <summary>
    /// Determines whether a metadata key is safe to store in a scan summary.
    /// </summary>
    /// <param name="key">Metadata key submitted by a HIP client.</param>
    /// <returns>Storage decision.</returns>
    PrivacyStorageDecision CanStoreMetadataKey(string key);

    /// <summary>
    /// Sanitizes a metadata value before persistence.
    /// </summary>
    /// <param name="value">Client-provided value.</param>
    /// <param name="maxLength">Maximum safe value length.</param>
    /// <returns>Trimmed and bounded value.</returns>
    string SanitizeMetadataValue(string? value, int maxLength);

    /// <summary>
    /// Determines whether HIP may store a raw URL for the supplied purpose.
    /// </summary>
    /// <param name="purpose">Purpose such as BrowserScanResult or ProviderEvidence.</param>
    /// <returns>Storage decision.</returns>
    PrivacyStorageDecision CanStoreRawUrl(string purpose);
}

/// <summary>
/// Default privacy storage policy for HIP scan and feedback data.
/// </summary>
/// <remarks>
/// This policy is intentionally conservative. HIP stores hashes and domain summaries by default because full URLs,
/// form content, and message text can reveal private browsing or communication context.
/// </remarks>
public sealed class DefaultPrivacyStoragePolicy : IPrivacyStoragePolicy
{
    private static readonly HashSet<string> PrivateMetadataKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "pageText",
        "bodyText",
        "formContents",
        "formValues",
        "password",
        "username",
        "token",
        "cookie",
        "cookies",
        "privateMessage",
        "emailBody",
        "chatLog",
        "rawUrl",
        "fullUrl"
    };

    /// <inheritdoc />
    public PrivacyStorageDecision CanStoreMetadataKey(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return new PrivacyStorageDecision(false, "Metadata keys cannot be empty.");
        }

        return PrivateMetadataKeys.Contains(key.Trim())
            ? new PrivacyStorageDecision(false, $"Metadata field '{key.Trim()}' is not privacy-safe.")
            : new PrivacyStorageDecision(true, "Metadata key is privacy-safe.");
    }

    /// <inheritdoc />
    public string SanitizeMetadataValue(string? value, int maxLength)
    {
        var safeValue = value?.Trim() ?? string.Empty;
        return safeValue.Length > maxLength ? safeValue[..maxLength] : safeValue;
    }

    /// <inheritdoc />
    public PrivacyStorageDecision CanStoreRawUrl(string purpose) =>
        new(false, $"Raw URLs are disabled for {purpose}; store a normalized domain and URL hash instead.");
}

/// <summary>
/// Represents whether an external provider may receive the current scan target.
/// </summary>
/// <param name="Allowed">Whether the provider may run.</param>
/// <param name="Reason">Plain-English reason safe for logs and evidence errors.</param>
public sealed record ProviderSubmissionDecision(bool Allowed, string Reason);

/// <summary>
/// Controls what HIP may submit to external scanners such as SSL Labs, Google Web Risk, or VirusTotal.
/// </summary>
public interface IProviderSubmissionPolicy
{
    /// <summary>
    /// Checks whether a configured provider may receive this privacy-safe evidence context.
    /// </summary>
    /// <param name="providerName">Human-readable provider name.</param>
    /// <param name="context">Privacy-safe scan context.</param>
    /// <param name="globalOptions">Global provider configuration.</param>
    /// <param name="providerOptions">Provider-specific configuration.</param>
    /// <returns>Provider submission decision.</returns>
    ProviderSubmissionDecision CanSubmit(
        string providerName,
        SiteSafetyEvidenceContext context,
        ExternalSiteEvidenceOptions globalOptions,
        ExternalProviderOptions providerOptions);
}

/// <summary>
/// Default provider submission policy that prefers domain-only or hash-based checks.
/// </summary>
public sealed class DefaultProviderSubmissionPolicy : IProviderSubmissionPolicy
{
    /// <inheritdoc />
    public ProviderSubmissionDecision CanSubmit(
        string providerName,
        SiteSafetyEvidenceContext context,
        ExternalSiteEvidenceOptions globalOptions,
        ExternalProviderOptions providerOptions)
    {
        if (!globalOptions.ExternalProvidersEnabled)
        {
            return new ProviderSubmissionDecision(false, "External providers are disabled by configuration.");
        }

        if (!providerOptions.Enabled)
        {
            return new ProviderSubmissionDecision(false, $"{providerName} is disabled by provider configuration.");
        }

        if (providerOptions.AllowFullUrl && !globalOptions.AllowFullUrlChecks)
        {
            return new ProviderSubmissionDecision(false, $"{providerName} requested full URL checks, but HIP is configured for domain/hash checks only.");
        }

        if (string.IsNullOrWhiteSpace(context.Domain))
        {
            return new ProviderSubmissionDecision(false, "A normalized domain is required before external provider checks.");
        }

        return new ProviderSubmissionDecision(true, "Provider may run with privacy-safe domain/hash context.");
    }
}

/// <summary>
/// Calculates conservative feedback weights so user feedback is evidence, not popularity voting.
/// </summary>
public interface IFeedbackWeightingPolicy
{
    /// <summary>
    /// Calculates the evidence weight for one feedback submission.
    /// </summary>
    /// <param name="feedbackType">Feedback type submitted by a HIP client.</param>
    /// <param name="reporterTrustLevel">Reporter trust level.</param>
    /// <param name="source">Client or portal source.</param>
    /// <returns>Small bounded evidence weight.</returns>
    int CalculateWeight(HipFeedbackType feedbackType, ReporterTrustLevel reporterTrustLevel, HipFeedbackSource source);
}

/// <summary>
/// Default feedback weighting policy with deliberately small weights for anonymous browser feedback.
/// </summary>
public sealed class DefaultFeedbackWeightingPolicy : IFeedbackWeightingPolicy
{
    /// <inheritdoc />
    public int CalculateWeight(HipFeedbackType feedbackType, ReporterTrustLevel reporterTrustLevel, HipFeedbackSource source)
    {
        var trustWeight = reporterTrustLevel switch
        {
            ReporterTrustLevel.Admin => 10,
            ReporterTrustLevel.Moderator => 7,
            ReporterTrustLevel.Trusted => 5,
            ReporterTrustLevel.Verified => 3,
            ReporterTrustLevel.KnownFalseReporter => 0,
            ReporterTrustLevel.Anonymous => 1,
            _ => 1
        };

        var sourceWeight = source is HipFeedbackSource.AdminPortal ? 2 : 0;
        var issueWeight = feedbackType is HipFeedbackType.ReportIssue ? 1 : 0;
        return Math.Clamp(trustWeight + sourceWeight + issueWeight, 1, 12);
    }
}
