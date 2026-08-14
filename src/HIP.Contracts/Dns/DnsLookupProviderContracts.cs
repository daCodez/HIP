namespace HIP.Application.Dns;

/// <summary>DNS record types supported by the bounded public lookup contract.</summary>
public enum DnsLookupRecordType
{
    /// <summary>IPv4 address record.</summary>
    A = 1,

    /// <summary>IPv6 address record.</summary>
    Aaaa = 28
}

/// <summary>A public DNS answer returned by a replaceable lookup provider.</summary>
/// <param name="Name">Canonical DNS owner name.</param>
/// <param name="Type">DNS record type.</param>
/// <param name="TtlSeconds">Provider-supplied time to live in seconds.</param>
/// <param name="Data">Public DNS record value.</param>
public sealed record DnsLookupAnswer(
    string Name,
    DnsLookupRecordType Type,
    int TtlSeconds,
    string Data);

/// <summary>DNSSEC validation state reported by the configured recursive resolver.</summary>
public enum DnssecValidationStatus
{
    /// <summary>The resolver did not provide enough evidence to classify the answer.</summary>
    Indeterminate = 0,

    /// <summary>The resolver cryptographically validated the answer chain.</summary>
    Secure = 1,

    /// <summary>The resolver proved that the answer comes from an unsigned delegation.</summary>
    Insecure = 2,

    /// <summary>The resolver proved that DNSSEC validation failed.</summary>
    Bogus = 3
}

/// <summary>Provider-neutral result for one bounded public DNS lookup.</summary>
/// <param name="Status">DNS response code, where zero is NoError and three is NXDOMAIN.</param>
/// <param name="IsTruncated">Whether the upstream response was truncated.</param>
/// <param name="IsRecursionAvailable">Whether the upstream provider supports recursion.</param>
/// <param name="DnssecStatus">Resolver-reported DNSSEC validation state.</param>
/// <param name="Answers">Public DNS answers.</param>
public sealed record DnsProviderLookupResult(
    int Status,
    bool IsTruncated,
    bool IsRecursionAvailable,
    DnssecValidationStatus DnssecStatus,
    IReadOnlyCollection<DnsLookupAnswer> Answers);

/// <summary>Resolves bounded public DNS records without coupling callers to a specific recursive resolver.</summary>
public interface IDnsLookupProvider
{
    /// <summary>Stable provider name safe for diagnostics and API responses.</summary>
    string Name { get; }

    /// <summary>Resolves one bounded public DNS query.</summary>
    Task<DnsProviderLookupResult> LookupAsync(
        string domain,
        DnsLookupRecordType recordType,
        CancellationToken cancellationToken);
}
