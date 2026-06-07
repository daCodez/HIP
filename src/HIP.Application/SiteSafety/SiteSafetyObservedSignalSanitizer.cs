namespace HIP.Application.SiteSafety;

/// <summary>
/// Sanitizes URL-like browser-observed signal collections before scoring or persistence.
/// </summary>
public static class SiteSafetyObservedSignalSanitizer
{
    /// <summary>
    /// Returns observed signals with URL collections stripped to scheme, host, and path only.
    /// </summary>
    /// <param name="signals">Signals supplied by a HIP client.</param>
    /// <returns>Signals with sanitized URL-like fields.</returns>
    public static SiteSafetyObservedSignals Sanitize(SiteSafetyObservedSignals? signals)
    {
        var source = signals ?? new SiteSafetyObservedSignals();
        return source with
        {
            RedirectChain = SanitizeUrls(source.RedirectChain),
            ExternalScriptUrls = SanitizeUrls(source.ExternalScriptUrls),
            DownloadLinks = SanitizeUrls(source.DownloadLinks),
            MatchedRiskTerms = source.MatchedRiskTerms?
                .Where(term => !string.IsNullOrWhiteSpace(term))
                .Select(term => term.Trim())
                .Take(20)
                .ToArray()
        };
    }

    /// <summary>
    /// Checks whether a URL is public HTTP(S) and not localhost, loopback, private, or link-local.
    /// </summary>
    /// <param name="value">URL text to validate.</param>
    /// <returns>True when the URL is acceptable for privacy-safe structural scanning.</returns>
    public static bool IsSafePublicHttpUrl(string? value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            uri.Scheme is not ("http" or "https") ||
            string.IsNullOrWhiteSpace(uri.Host))
        {
            return false;
        }

        return !IsInternalHost(uri.Host);
    }

    /// <summary>
    /// Strips query strings and fragments from a safe URL.
    /// </summary>
    /// <param name="value">URL text.</param>
    /// <returns>Sanitized URL, or null when the URL is not safe for HIP processing.</returns>
    public static string? StripQueryAndFragment(string? value)
    {
        if (!IsSafePublicHttpUrl(value) || !Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            return null;
        }

        var builder = new UriBuilder(uri)
        {
            Query = string.Empty,
            Fragment = string.Empty
        };

        return builder.Uri.ToString();
    }

    /// <summary>
    /// Sanitizes a URL collection while preserving only bounded, valid entries.
    /// </summary>
    /// <param name="urls">Raw URL-like values.</param>
    /// <returns>Sanitized URL collection or null when no values remain.</returns>
    private static IReadOnlyCollection<string>? SanitizeUrls(IReadOnlyCollection<string>? urls)
    {
        var sanitized = urls?
            .Select(StripQueryAndFragment)
            .Where(url => !string.IsNullOrWhiteSpace(url))
            .Select(url => url!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(50)
            .ToArray();

        return sanitized is { Length: > 0 } ? sanitized : null;
    }

    /// <summary>
    /// Blocks hosts that should never be accepted from public scan payloads.
    /// </summary>
    /// <param name="host">Host extracted from a URL.</param>
    /// <returns>True when the host is internal or local-only.</returns>
    private static bool IsInternalHost(string host)
    {
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!System.Net.IPAddress.TryParse(host, out var address))
        {
            return false;
        }

        if (System.Net.IPAddress.IsLoopback(address) || address.IsIPv6LinkLocal || address.IsIPv6SiteLocal)
        {
            return true;
        }

        var bytes = address.GetAddressBytes();
        return bytes.Length == 4 &&
            (bytes[0] == 10 ||
             bytes[0] == 127 ||
             bytes[0] == 169 && bytes[1] == 254 ||
             bytes[0] == 172 && bytes[1] is >= 16 and <= 31 ||
             bytes[0] == 192 && bytes[1] == 168);
    }
}
