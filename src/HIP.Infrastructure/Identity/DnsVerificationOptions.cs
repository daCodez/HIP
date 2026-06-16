namespace HIP.Infrastructure.Identity;

/// <summary>
/// Configuration for HIP DNS TXT verification lookups.
/// </summary>
public sealed class DnsVerificationOptions
{
    /// <summary>
    /// Configuration section name used by HIP hosts.
    /// </summary>
    public const string SectionName = "DnsVerification";

    /// <summary>
    /// Optional DNS server host used for local CoreDNS or custom resolvers.
    /// </summary>
    public string? NameServerHost { get; init; }

    /// <summary>
    /// Optional DNS server port. CoreDNS local development uses 1053 by default.
    /// </summary>
    public int? NameServerPort { get; init; }

    /// <summary>
    /// DNS timeout in milliseconds so verification failures do not hang request processing.
    /// </summary>
    public int TimeoutMilliseconds { get; init; } = 3000;

    /// <summary>
    /// Whether lookups should use TCP only. This is useful for local Aspire port mapping.
    /// </summary>
    public bool UseTcpOnly { get; init; }
}
