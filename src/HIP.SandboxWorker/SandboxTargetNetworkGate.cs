using System.Globalization;
using System.Net;
using HIP.Infrastructure.Security;

namespace HIP.SandboxWorker;

public interface ISandboxDnsResolver
{
    Task<IReadOnlyCollection<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken);
}

public sealed class SystemSandboxDnsResolver : ISandboxDnsResolver
{
    public async Task<IReadOnlyCollection<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken) =>
        await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
}

public sealed record AuthorizedSandboxTarget(Uri Url, IReadOnlyCollection<IPAddress> ResolvedAddresses, int RedirectCount);

/// <summary>Pre-resolves each browser target and verifies its actual connection against that exact address set.</summary>
public sealed class SandboxTargetNetworkGate(ISandboxDnsResolver resolver)
{
    public Task<AuthorizedSandboxTarget> AuthorizeInitialAsync(string targetUrl, CancellationToken cancellationToken) =>
        AuthorizeAsync(targetUrl, 0, cancellationToken);

    public Task<AuthorizedSandboxTarget> AuthorizeRedirectAsync(
        AuthorizedSandboxTarget current,
        string location,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(current);
        if (current.RedirectCount >= 3) throw new InvalidOperationException("Sandbox redirect limit was exceeded.");
        if (!Uri.TryCreate(current.Url, location, out var redirect)) throw new InvalidOperationException("Sandbox redirect target is invalid.");
        return AuthorizeAsync(redirect.AbsoluteUri, current.RedirectCount + 1, cancellationToken);
    }

    public static bool IsConnectedAddressAuthorized(AuthorizedSandboxTarget target, IPAddress connectedAddress)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(connectedAddress);
        var normalized = Normalize(connectedAddress);
        return PublicNetworkAddressPolicy.IsPublic(normalized) &&
            target.ResolvedAddresses.Select(Normalize).Any(address => address.Equals(normalized));
    }

    private async Task<AuthorizedSandboxTarget> AuthorizeAsync(string targetUrl, int redirectCount, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(targetUrl) || targetUrl.Length > 2048 ||
            !Uri.TryCreate(targetUrl, UriKind.Absolute, out var uri) ||
            uri.Scheme is not ("http" or "https") || string.IsNullOrWhiteSpace(uri.Host) ||
            !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment) ||
            uri.Port is not (80 or 443))
        {
            throw new InvalidOperationException("Sandbox target must be a bounded public HTTP or HTTPS URL without credentials or fragments.");
        }

        var asciiHost = new IdnMapping { UseStd3AsciiRules = true }.GetAscii(uri.IdnHost).ToLowerInvariant();
        var addresses = (await resolver.ResolveAsync(asciiHost, cancellationToken).ConfigureAwait(false))
            .Select(Normalize).Distinct().ToArray();
        if (addresses.Length is < 1 or > 16 || addresses.Any(address => !PublicNetworkAddressPolicy.IsPublic(address)))
        {
            throw new InvalidOperationException("Sandbox target did not resolve exclusively to a bounded set of public addresses.");
        }

        return new AuthorizedSandboxTarget(
            new UriBuilder(uri) { Host = asciiHost }.Uri,
            Array.AsReadOnly(addresses),
            redirectCount);
    }

    private static IPAddress Normalize(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
}
