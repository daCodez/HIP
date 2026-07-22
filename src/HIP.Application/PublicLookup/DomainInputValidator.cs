using System.Globalization;

namespace HIP.Application.PublicLookup;

public static class DomainInputValidator
{
    public static string ValidateAndNormalize(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new ArgumentException("Domain is required.", nameof(domain));
        }

        var candidate = domain.Trim().TrimEnd('.');
        if (candidate.Contains('/') || candidate.Contains(':') || candidate.Any(char.IsControl))
        {
            throw new ArgumentException("Domain must be a valid public host name.", nameof(domain));
        }

        string normalized;
        try
        {
            normalized = new IdnMapping { UseStd3AsciiRules = true }
                .GetAscii(candidate)
                .ToLowerInvariant();
        }
        catch (ArgumentException exception)
        {
            throw new ArgumentException("Domain must be a valid public host name.", nameof(domain), exception);
        }

        var labels = normalized.Split('.', StringSplitOptions.None);
        if (normalized.Length > 253 ||
            Uri.CheckHostName(normalized) != UriHostNameType.Dns ||
            labels.Length < 2 ||
            labels[^1].Length < 2 ||
            labels.Any(label =>
                label.Length is < 1 or > 63 ||
                label[0] == '-' ||
                label[^1] == '-' ||
                label.Any(character => character is not (>= 'a' and <= 'z') and not (>= '0' and <= '9') and not '-')))
        {
            throw new ArgumentException("Domain must be a valid public host name.", nameof(domain));
        }

        return normalized;
    }
}
