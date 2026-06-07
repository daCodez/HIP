namespace HIP.Web.Security;

/// <summary>
/// Builds privacy-safe URL display strings for safety pages and API responses.
/// </summary>
public static class SafetyUrlDisplay
{
    /// <summary>
    /// Removes query strings and fragments from a URL before displaying or echoing it.
    /// </summary>
    /// <param name="url">Original URL supplied by a safety flow.</param>
    /// <returns>Scheme, host, and path only, or an empty string when the URL is invalid.</returns>
    public static string StripQueryAndFragment(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
        {
            return string.Empty;
        }

        var builder = new UriBuilder(uri)
        {
            Query = string.Empty,
            Fragment = string.Empty
        };

        return builder.Uri.ToString();
    }
}
