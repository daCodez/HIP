using DnsClient;
using DnsClient.Protocol;
using HIP.Application.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Net;

namespace HIP.Infrastructure.Identity;

/// <summary>
/// Resolves DNS TXT records through DnsClient.NET for HIP domain ownership verification.
/// </summary>
public sealed class DnsClientTxtRecordResolver : IDnsTxtRecordResolver
{
    private readonly LookupClient _lookupClient;
    private readonly ILogger<DnsClientTxtRecordResolver> _logger;

    /// <summary>
    /// Creates a resolver using configured CoreDNS or system DNS settings.
    /// </summary>
    /// <param name="options">DNS verification options.</param>
    /// <param name="logger">Logger used for safe, token-free diagnostics.</param>
    public DnsClientTxtRecordResolver(IOptions<DnsVerificationOptions> options, ILogger<DnsClientTxtRecordResolver> logger)
    {
        _logger = logger;
        _lookupClient = CreateLookupClient(options.Value);
    }

    /// <summary>
    /// Resolves flattened TXT values for a DNS record.
    /// </summary>
    /// <param name="recordName">Record name such as _hip.example.com.</param>
    /// <param name="cancellationToken">Token used to cancel the lookup.</param>
    /// <returns>Flattened TXT values, or an empty collection when the record is missing.</returns>
    public async Task<IReadOnlyCollection<string>> ResolveTxtRecordsAsync(string recordName, CancellationToken cancellationToken)
    {
        try
        {
            var result = await _lookupClient.QueryAsync(recordName, QueryType.TXT, cancellationToken: cancellationToken);
            return result.Answers
                .TxtRecords()
                .SelectMany(record => record.Text)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .ToArray();
        }
        catch (DnsResponseException ex) when (ex.Code == DnsResponseCode.NotExistentDomain)
        {
            _logger.LogInformation("HIP DNS TXT record {RecordName} was not configured.", recordName);
            return Array.Empty<string>();
        }
    }

    /// <summary>
    /// Builds the DNS lookup client from safe, validated options.
    /// </summary>
    /// <param name="options">Configured DNS verification options.</param>
    /// <returns>DNS lookup client.</returns>
    private static LookupClient CreateLookupClient(DnsVerificationOptions options)
    {
        var lookupOptions = !string.IsNullOrWhiteSpace(options.NameServerHost) && options.NameServerPort is > 0 and <= 65535
            ? new LookupClientOptions(new IPEndPoint(IPAddress.Parse(options.NameServerHost), options.NameServerPort.Value))
            : new LookupClientOptions();

        lookupOptions.Timeout = TimeSpan.FromMilliseconds(Math.Clamp(options.TimeoutMilliseconds, 500, 15000));
        lookupOptions.UseCache = true;
        lookupOptions.UseTcpOnly = options.UseTcpOnly;

        return new LookupClient(lookupOptions);
    }
}
