using System.Net;
using HIP.Application.PublicLookup;

namespace HIP.Application.Certificates;

/// <summary>Resolves the registrable domain for a canonical host using a Public Suffix List implementation.</summary>
public interface IPublicSuffixResolver
{
    /// <summary>Returns the registrable domain, or null when the host is not beneath a recognized public suffix.</summary>
    string? RegistrableDomain(string canonicalDomain);
}

/// <summary>
/// Reduces owner-supplied domain or URL input to a canonical public host before enrollment.
/// </summary>
public sealed class DomainRegistrationNormalizer(IPublicSuffixResolver publicSuffixResolver)
{
    private static readonly string[] InternalSuffixes =
    [
        ".internal",
        ".local",
        ".localhost",
        ".home.arpa",
        ".invalid",
        ".onion"
    ];

    /// <summary>Normalizes an owner-supplied domain or URL and rejects non-public targets.</summary>
    public string Normalize(string input)
    {
        if (string.IsNullOrWhiteSpace(input) || input.Any(char.IsControl))
        {
            throw new ArgumentException("A public domain is required.", nameof(input));
        }

        var candidate = input.Trim();
        var hasScheme = candidate.Contains("://", StringComparison.Ordinal);
        if (!Uri.TryCreate(hasScheme ? candidate : $"https://{candidate}", UriKind.Absolute, out var uri) ||
            (hasScheme && uri.Scheme is not ("http" or "https")) ||
            !string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new ArgumentException("Domain must be a public HTTP or HTTPS host.", nameof(input));
        }

        var host = uri.IdnHost.TrimEnd('.');
        var ipCandidate = host.Trim('[', ']');
        if (IPAddress.TryParse(ipCandidate, out _) ||
            host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            InternalSuffixes.Any(suffix => host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException("Private, reserved, and IP hosts cannot be enrolled.", nameof(input));
        }

        var canonical = DomainInputValidator.ValidateAndNormalize(host);
        var registrable = publicSuffixResolver.RegistrableDomain(canonical);
        if (string.IsNullOrWhiteSpace(registrable))
        {
            throw new ArgumentException("Domain is not beneath a recognized public suffix.", nameof(input));
        }

        return canonical;
    }
}
