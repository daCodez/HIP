using FluentValidation;
using Microsoft.Extensions.Logging;

namespace HIP.Application.SiteSafety;

/// <summary>
/// Collects third-party site safety evidence through an explicit slow-path service.
/// </summary>
/// <remarks>
/// New 2026-06-21 10:31 UTC by HIP Development Team. Assisted by Codex.
/// This service exists so HIP can run SSL Labs, Web Risk, VirusTotal, and future provider checks
/// on demand without putting third-party latency directly on every browser page visit.
/// </remarks>
public interface IExternalSiteEvidenceCollector
{
    /// <summary>
    /// Collects external evidence for a validated URL using privacy-safe browser observations.
    /// </summary>
    /// <param name="request">The site safety scan request containing the URL and privacy-safe counts.</param>
    /// <param name="cancellationToken">Token used to cancel provider work.</param>
    /// <returns>Normalized external evidence records. Provider failures are returned as evidence errors.</returns>
    Task<IReadOnlyCollection<SiteSafetyEvidence>> CollectAsync(SiteSafetyScanRequest request, CancellationToken cancellationToken);
}

/// <summary>Privacy-safe durable provider work that excludes the raw URL and all page values.</summary>
public sealed record ExternalSiteEvidenceWorkItem(
    string Domain,
    string UrlHash,
    SiteSafetyObservedSignals ObservedSignals)
{
    /// <summary>Returns a safe operational label without observed-signal details.</summary>
    public override string ToString() => $"ExternalSiteEvidenceWorkItem {{ Domain = {Domain} }}";
}

/// <summary>Collects provider evidence from a persisted domain/hash work item outside the request path.</summary>
public interface IExternalSiteEvidenceWorkCollector
{
    /// <summary>Collects normalized evidence without requiring HIP to persist the original URL.</summary>
    Task<IReadOnlyCollection<SiteSafetyEvidence>> CollectAsync(
        ExternalSiteEvidenceWorkItem workItem,
        CancellationToken cancellationToken);
}

/// <summary>
/// Default implementation that runs only external evidence providers.
/// </summary>
/// <param name="validator">Validator that blocks malformed, local, or private-network targets.</param>
/// <param name="providers">Registered site safety evidence providers.</param>
/// <param name="logger">Logger used for safe provider diagnostics.</param>
/// <param name="timeProvider">Clock used for deterministic evidence timestamps.</param>
/// <remarks>
/// New 2026-06-21 10:31 UTC by HIP Development Team. Assisted by Codex.
/// The collector strips URL query strings from hashes and logs so passwords, tokens, and private form
/// values are not accidentally forwarded or persisted.
/// </remarks>
public sealed class ExternalSiteEvidenceCollector(
    IValidator<SiteSafetyScanRequest> validator,
    IEnumerable<ISiteSafetyEvidenceProvider> providers,
    ILogger<ExternalSiteEvidenceCollector> logger,
    TimeProvider? timeProvider = null) : IExternalSiteEvidenceCollector, IExternalSiteEvidenceWorkCollector
{
    private readonly TimeProvider timeProvider = timeProvider ?? TimeProvider.System;

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<SiteSafetyEvidence>> CollectAsync(SiteSafetyScanRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        await validator.ValidateAndThrowAsync(request, cancellationToken);

        var uri = new Uri(request.Url, UriKind.Absolute);
        var domain = NormalizeHost(uri.Host);
        var signals = SiteSafetyObservedSignalSanitizer.Sanitize(request.ObservedSignals);
        return await CollectAsync(
            new ExternalSiteEvidenceWorkItem(
                domain,
                SiteSafetyEvidenceHashing.HashUrl(SanitizeUrl(uri)),
                signals),
            cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<SiteSafetyEvidence>> CollectAsync(
        ExternalSiteEvidenceWorkItem workItem,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(workItem);
        var normalizedDomain = workItem.Domain.Trim().TrimEnd('.').ToLowerInvariant();
        if (!string.Equals(workItem.Domain, normalizedDomain, StringComparison.Ordinal) ||
            !Uri.TryCreate($"https://{normalizedDomain}/", UriKind.Absolute, out var safeUri) ||
            workItem.UrlHash.Length != 64 ||
            workItem.UrlHash.Any(character => character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
        {
            throw new ArgumentException("Queued provider work is not bound to a normalized public target.", nameof(workItem));
        }

        await validator.ValidateAndThrowAsync(new SiteSafetyScanRequest(safeUri.ToString()), cancellationToken);
        var context = new SiteSafetyEvidenceContext(
            safeUri,
            normalizedDomain,
            workItem.UrlHash,
            SiteSafetyObservedSignalSanitizer.Sanitize(workItem.ObservedSignals),
            timeProvider.GetUtcNow());

        var externalProviders = providers.OfType<IExternalSiteEvidenceProvider>().ToArray();
        if (externalProviders.Length == 0)
        {
            logger.LogInformation("No external HIP evidence providers are registered for domain {Domain}.", normalizedDomain);
            return [];
        }

        var evidence = new List<SiteSafetyEvidence>(externalProviders.Length);
        foreach (var provider in externalProviders)
        {
            evidence.Add(await CollectProviderEvidenceAsync(provider, context, cancellationToken));
        }

        return evidence;
    }

    /// <summary>
    /// Collects one provider result and converts provider failures into safe evidence errors.
    /// </summary>
    /// <param name="provider">External evidence provider to run.</param>
    /// <param name="context">Privacy-safe provider context.</param>
    /// <param name="cancellationToken">Token used to cancel provider work.</param>
    /// <returns>Provider evidence or a safe failure record.</returns>
    private async Task<SiteSafetyEvidence> CollectProviderEvidenceAsync(
        IExternalSiteEvidenceProvider provider,
        SiteSafetyEvidenceContext context,
        CancellationToken cancellationToken)
    {
        var startedAt = timeProvider.GetTimestamp();
        try
        {
            var evidence = await provider.CollectEvidenceAsync(context, cancellationToken);
            return SiteSafetyProviderResultContract.Normalize(
                evidence,
                provider.ProviderName,
                provider.ProviderType,
                context,
                timeProvider.GetElapsedTime(startedAt),
                timeProvider.GetUtcNow());
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return FailedProviderEvidence(provider, context, SiteSafetyProviderResultStatus.TimedOut, startedAt, "Provider timed out.");
        }
        catch (TimeoutException)
        {
            return FailedProviderEvidence(provider, context, SiteSafetyProviderResultStatus.TimedOut, startedAt, "Provider timed out.");
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "External HIP evidence provider {ProviderName} failed safely for domain {Domain}.", provider.ProviderName, context.Domain);
            return FailedProviderEvidence(provider, context, SiteSafetyProviderResultStatus.Failed, startedAt, "Provider failed safely.");
        }
    }

    /// <summary>
    /// Creates safe provider-failure evidence that lowers confidence without exposing private URL details.
    /// </summary>
    /// <param name="provider">Provider that failed.</param>
    /// <param name="context">Privacy-safe provider context.</param>
    /// <param name="status">Normalized timeout or failure status.</param>
    /// <param name="startedAt">Provider start timestamp from the injected clock.</param>
    /// <param name="error">Plain-English safe error summary.</param>
    /// <returns>A normalized provider failure record.</returns>
    private SiteSafetyEvidence FailedProviderEvidence(
        IExternalSiteEvidenceProvider provider,
        SiteSafetyEvidenceContext context,
        SiteSafetyProviderResultStatus status,
        long startedAt,
        string error) =>
        SiteSafetyProviderResultContract.CreateFailure(
            provider.ProviderName,
            provider.ProviderType,
            context,
            status,
            timeProvider.GetElapsedTime(startedAt),
            timeProvider.GetUtcNow(),
            error);

    /// <summary>
    /// Normalizes a host name for provider cache keys and public-safe evidence.
    /// </summary>
    /// <param name="host">Host name from a validated URI.</param>
    /// <returns>Lowercase host without a trailing dot.</returns>
    private static string NormalizeHost(string host) => host.Trim().TrimEnd('.').ToLowerInvariant();

    /// <summary>
    /// Removes query and fragment values before hashing or sending context to providers.
    /// </summary>
    /// <param name="uri">Validated site URL.</param>
    /// <returns>Absolute URL without query or fragment values.</returns>
    private static string SanitizeUrl(Uri uri) =>
        new UriBuilder(uri) { Query = string.Empty, Fragment = string.Empty }.Uri.ToString();
}
