using DnsClient;
using DnsClient.Protocol;
using DnsClient.Protocol.Options;
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
    private readonly bool trustDnssecValidation;

    /// <summary>Creates the default provider from HIP's validated DNS resolver configuration.</summary>
    public DnsClientLookupProvider(
        IOptions<DnsVerificationOptions> options,
        ILogger<DnsClientLookupProvider> logger)
    {
        this.logger = logger;
        trustDnssecValidation = options.Value.TrustDnssecValidation;
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

            var responseCode = (int)response.Header.ResponseCode;
            return new DnsProviderLookupResult(
                responseCode,
                response.Header.ResultTruncated,
                response.Header.RecursionAvailable,
                ClassifyDnssec(
                    trustDnssecValidation,
                    response.Header.IsAuthenticData,
                    responseCode,
                    response.Additionals.OfType<OptRecord>().SelectMany(record => ReadExtendedDnsErrorCodes(record.Data))),
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
            ? new LookupClientOptions(new IPEndPoint(ResolveNameServer(options.NameServerHost), options.NameServerPort.Value))
            : new LookupClientOptions();

        lookupOptions.Timeout = TimeSpan.FromMilliseconds(Math.Clamp(options.TimeoutMilliseconds, 500, 15000));
        lookupOptions.UseCache = true;
        lookupOptions.UseTcpOnly = options.UseTcpOnly;
        lookupOptions.RequestDnsSecRecords = true;
        lookupOptions.ThrowDnsErrors = false;
        return new LookupClient(lookupOptions);
    }

    /// <summary>Classifies resolver evidence without treating a generic failure as a DNSSEC failure.</summary>
    internal static DnssecValidationStatus ClassifyDnssec(
        bool trustDnssecValidation,
        bool authenticData,
        int responseCode,
        IEnumerable<ushort> extendedDnsErrorCodes)
    {
        if (!trustDnssecValidation)
        {
            return DnssecValidationStatus.Indeterminate;
        }

        if (authenticData)
        {
            return DnssecValidationStatus.Secure;
        }

        if (extendedDnsErrorCodes.Any(code => code is >= 6 and <= 12))
        {
            return DnssecValidationStatus.Bogus;
        }

        return responseCode is 0 or 3
            ? DnssecValidationStatus.Insecure
            : DnssecValidationStatus.Indeterminate;
    }

    /// <summary>Reads RFC 8914 Extended DNS Error option codes from an OPT record payload.</summary>
    internal static IEnumerable<ushort> ReadExtendedDnsErrorCodes(byte[] data)
    {
        var offset = 0;
        while (offset + 4 <= data.Length)
        {
            var optionCode = (ushort)((data[offset] << 8) | data[offset + 1]);
            var optionLength = (data[offset + 2] << 8) | data[offset + 3];
            offset += 4;
            if (offset + optionLength > data.Length)
            {
                yield break;
            }

            if (optionCode == 15 && optionLength >= 2)
            {
                yield return (ushort)((data[offset] << 8) | data[offset + 1]);
            }

            offset += optionLength;
        }
    }

    private static IPAddress ResolveNameServer(string host)
    {
        if (IPAddress.TryParse(host, out var address))
        {
            return address;
        }

        return Dns.GetHostAddresses(host)
            .FirstOrDefault(candidate => candidate.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            ?? Dns.GetHostAddresses(host).First();
    }
}
