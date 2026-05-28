using System.Text.RegularExpressions;

namespace HIP.Application.PublicLookup;

public static partial class DomainInputValidator
{
    public static string ValidateAndNormalize(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new ArgumentException("Domain is required.", nameof(domain));
        }

        var normalized = domain.Trim().TrimEnd('.').ToLowerInvariant();
        if (normalized.Length > 253 ||
            normalized.Contains('/') ||
            normalized.Contains(':') ||
            Uri.CheckHostName(normalized) == UriHostNameType.Unknown ||
            !DomainPattern().IsMatch(normalized))
        {
            throw new ArgumentException("Domain must be a valid public host name.", nameof(domain));
        }

        return normalized;
    }

    [GeneratedRegex(@"^(?=.{1,253}$)(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DomainPattern();
}
