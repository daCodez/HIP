using DnsClient;
using DnsClient.Protocol;
using HIP.Application.Dns;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Net;

namespace HIP.Infrastructure.Identity;

/// <summary>Resolves bounded A and AAAA requests through DnsClient.NET.</summary>
public sealed class DnsClientLookupProvider : IDnsLookupProvider
{
    private readonly LookupClient lookupClient;
    private readonly ILogger<DnsClientLookupProvider> logger;

    /// <summary>Creates the default provider from HIP's validated DNS resolver configuration.</summary>
    public DnsClientLookupProvider(
        IOptions<DnsVerificationOptions> options,
        ILogger<DnsClientLookupProvider> logger)
    {
        this.logger = logger;
        lookupClient = CreateLookupClient(options.Value);
    }

    /// <inheritdoc />
    public string Name => "DnsClient.NET";

    /// <inheritdoc />
    public async Task<DnsProviderLookupResult> LookupAsync(
        string domain,
        DnsLookupRecordType recordType,
        CancellationToken cancellationToken)
    {
        var queryType = recordType switch
        {
            DnsLookupRecordType.A => QueryType.A,
            DnsLookupRecordType.Aaaa => QueryType.AAAA,
            _ => throw new ArgumentException("HIP DNS currently supports A and AAAA queries only.", nameof(recordType))
        };

        try
        {
            var response = await lookupClient.QueryAsync(domain, queryType, cancellationToken: cancellationToken);
            var answers = response.Answers
                .Select(record => ToAnswer(record, recordType))
                .Where(answer => answer is not null)
                .Cast<DnsLookupAnswer>()
                .ToArray();

            return new DnsProviderLookupResult(
                (int)response.Header.ResponseCode,
                response.Header.ResultTruncated,
                response.Header.RecursionAvailable,
                response.Header.IsAuthenticData
                    ? DnssecValidationStatus.Secure
                    : DnssecValidationStatus.Indeterminate,
                answers);
        }
        catch (DnsResponseException exception) when (exception.Code == DnsResponseCode.NotExistentDomain)
        {
            return new DnsProviderLookupResult(3, false, true, DnssecValidationStatus.Indeterminate, []);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "HIP DNS provider could not resolve {Domain} as {RecordType}.", domain, recordType);
            return new DnsProviderLookupResult(2, false, true, DnssecValidationStatus.Indeterminate, []);
        }
    }

    private static DnsLookupAnswer? ToAnswer(DnsResourceRecord record, DnsLookupRecordType recordType) => record switch
    {
        ARecord ipv4 when recordType == DnsLookupRecordType.A =>
            new DnsLookupAnswer(ipv4.DomainName.Value, recordType, ipv4.InitialTimeToLive, ipv4.Address.ToString()),
        AaaaRecord ipv6 when recordType == DnsLookupRecordType.Aaaa =>
            new DnsLookupAnswer(ipv6.DomainName.Value, recordType, ipv6.InitialTimeToLive, ipv6.Address.ToString()),
        _ => null
    };

    private static LookupClient CreateLookupClient(DnsVerificationOptions options)
    {
        var lookupOptions = !string.IsNullOrWhiteSpace(options.NameServerHost) && options.NameServerPort is > 0 and <= 65535
            ? new LookupClientOptions(new IPEndPoint(IPAddress.Parse(options.NameServerHost), options.NameServerPort.Value))
            : new LookupClientOptions();

        lookupOptions.Timeout = TimeSpan.FromMilliseconds(Math.Clamp(options.TimeoutMilliseconds, 500, 15000));
        lookupOptions.UseCache = true;
        lookupOptions.UseTcpOnly = options.UseTcpOnly;
        lookupOptions.RequestDnsSecRecords = true;
        return new LookupClient(lookupOptions);
    }
}
