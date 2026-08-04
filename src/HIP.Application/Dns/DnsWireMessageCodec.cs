using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace HIP.Application.Dns;

/// <summary>A validated single-question DNS query decoded from RFC 1035 wire format.</summary>
/// <param name="Id">DNS transaction identifier.</param>
/// <param name="Domain">Uncompressed question name.</param>
/// <param name="RecordType">Requested record type.</param>
/// <param name="IsRecursionDesired">Whether the client requested recursion.</param>
/// <param name="IsCheckingDisabled">Whether the client disabled DNSSEC checking.</param>
public sealed record DnsWireQuery(
    ushort Id,
    string Domain,
    DnsLookupRecordType RecordType,
    bool IsRecursionDesired,
    bool IsCheckingDisabled);

/// <summary>
/// Parses and writes the bounded DNS wire messages used by HIP's RFC 8484 endpoint.
/// </summary>
public static class DnsWireMessageCodec
{
    /// <summary>Maximum accepted wire query size, including a bounded EDNS request.</summary>
    public const int MaximumQueryBytes = 4096;

    private const ushort ResponseFlag = 0x8000;
    private const ushort TruncatedFlag = 0x0200;
    private const ushort RecursionDesiredFlag = 0x0100;
    private const ushort RecursionAvailableFlag = 0x0080;
    private const ushort AuthenticDataFlag = 0x0020;
    private const ushort CheckingDisabledFlag = 0x0010;

    /// <summary>Parses one standard IN-class DNS question.</summary>
    /// <param name="message">Untrusted DNS wire bytes.</param>
    /// <param name="allowUnsupportedRecordType">Whether the caller needs to construct a DNS NOTIMP response.</param>
    /// <returns>A bounded query safe to pass to the lookup service.</returns>
    public static DnsWireQuery ParseQuery(
        ReadOnlySpan<byte> message,
        bool allowUnsupportedRecordType = false)
    {
        if (message.Length is < 17 or > MaximumQueryBytes)
        {
            throw new ArgumentException("DNS wire query length is invalid.", nameof(message));
        }

        var flags = ReadUInt16(message, 2);
        var questionCount = ReadUInt16(message, 4);
        if ((flags & ResponseFlag) != 0 || (flags & 0x7800) != 0 || questionCount != 1)
        {
            throw new ArgumentException("DNS wire requests must contain one standard query question.", nameof(message));
        }

        var offset = 12;
        var domain = ReadDomainName(message, ref offset);
        if (offset + 4 > message.Length)
        {
            throw new ArgumentException("DNS wire question is incomplete.", nameof(message));
        }

        var recordTypeCode = ReadUInt16(message, offset);
        var recordClass = ReadUInt16(message, offset + 2);
        if (recordClass != 1)
        {
            throw new ArgumentException("HIP DoH supports internet-class DNS questions only.", nameof(message));
        }

        var recordType = (DnsLookupRecordType)recordTypeCode;
        if (!allowUnsupportedRecordType && recordType is not DnsLookupRecordType.A and not DnsLookupRecordType.Aaaa)
        {
            throw new ArgumentException("HIP DNS currently supports A and AAAA queries only.", nameof(message));
        }

        return new DnsWireQuery(
            ReadUInt16(message, 0),
            domain,
            recordType,
            (flags & RecursionDesiredFlag) != 0,
            (flags & CheckingDisabledFlag) != 0);
    }

    /// <summary>Encodes a successful or DNS-level failure response from provider-neutral lookup data.</summary>
    public static byte[] EncodeResponse(DnsWireQuery query, HipAwareDnsLookupResponse response)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(response);

        var answers = response.Answer
            .Select(answer => TryEncodeAnswer(query, answer))
            .Where(answer => answer is not null)
            .Cast<EncodedAnswer>()
            .ToArray();
        var bytes = new List<byte>(64 + answers.Sum(answer => answer.Data.Length));
        WriteHeader(
            bytes,
            query,
            response.Status,
            response.IsTruncated,
            response.IsRecursionAvailable,
            response.IsAuthenticData && !query.IsCheckingDisabled,
            answers.Length);
        WriteQuestion(bytes, query);
        foreach (var answer in answers)
        {
            WriteAnswer(bytes, query, answer);
        }

        return bytes.ToArray();
    }

    /// <summary>Encodes a DNS error response while preserving HTTP-success semantics for a valid DNS question.</summary>
    public static byte[] EncodeErrorResponse(DnsWireQuery query, int dnsResponseCode)
    {
        ArgumentNullException.ThrowIfNull(query);
        var bytes = new List<byte>(64);
        WriteHeader(bytes, query, dnsResponseCode, false, true, false, 0);
        WriteQuestion(bytes, query);
        return bytes.ToArray();
    }

    private static EncodedAnswer? TryEncodeAnswer(DnsWireQuery query, DnsJsonAnswer answer)
    {
        if (answer.Type != (int)query.RecordType || !IPAddress.TryParse(answer.Data, out var address))
        {
            return null;
        }

        var data = address.GetAddressBytes();
        if ((query.RecordType == DnsLookupRecordType.A && data.Length != 4) ||
            (query.RecordType == DnsLookupRecordType.Aaaa && data.Length != 16))
        {
            return null;
        }

        var owner = answer.Name.TrimEnd('.');
        return new EncodedAnswer(owner, Math.Max(0, answer.TtlSeconds), data);
    }

    private static void WriteHeader(
        List<byte> bytes,
        DnsWireQuery query,
        int responseCode,
        bool isTruncated,
        bool isRecursionAvailable,
        bool isAuthenticData,
        int answerCount)
    {
        ushort flags = ResponseFlag;
        if (query.IsRecursionDesired)
        {
            flags |= RecursionDesiredFlag;
        }
        if (query.IsCheckingDisabled)
        {
            flags |= CheckingDisabledFlag;
        }
        if (isTruncated)
        {
            flags |= TruncatedFlag;
        }
        if (isRecursionAvailable)
        {
            flags |= RecursionAvailableFlag;
        }
        if (isAuthenticData)
        {
            flags |= AuthenticDataFlag;
        }
        flags |= (ushort)Math.Clamp(responseCode, 0, 15);

        WriteUInt16(bytes, query.Id);
        WriteUInt16(bytes, flags);
        WriteUInt16(bytes, 1);
        WriteUInt16(bytes, checked((ushort)answerCount));
        WriteUInt16(bytes, 0);
        WriteUInt16(bytes, 0);
    }

    private static void WriteQuestion(List<byte> bytes, DnsWireQuery query)
    {
        WriteDomainName(bytes, query.Domain);
        WriteUInt16(bytes, (ushort)query.RecordType);
        WriteUInt16(bytes, 1);
    }

    private static void WriteAnswer(List<byte> bytes, DnsWireQuery query, EncodedAnswer answer)
    {
        if (string.Equals(answer.Owner, query.Domain, StringComparison.OrdinalIgnoreCase))
        {
            WriteUInt16(bytes, 0xC00C);
        }
        else
        {
            WriteDomainName(bytes, answer.Owner);
        }

        WriteUInt16(bytes, (ushort)query.RecordType);
        WriteUInt16(bytes, 1);
        WriteUInt32(bytes, checked((uint)answer.TtlSeconds));
        WriteUInt16(bytes, checked((ushort)answer.Data.Length));
        bytes.AddRange(answer.Data);
    }

    private static string ReadDomainName(ReadOnlySpan<byte> message, ref int offset)
    {
        var labels = new List<string>();
        var current = offset;
        var jumped = false;
        var pointerHops = 0;

        while (true)
        {
            if ((uint)current >= (uint)message.Length)
            {
                throw new ArgumentException("DNS question name is incomplete.", nameof(message));
            }

            var length = message[current];
            if (length == 0)
            {
                if (!jumped)
                {
                    offset = current + 1;
                }
                break;
            }

            if ((length & 0xC0) == 0xC0)
            {
                if (current + 1 >= message.Length || ++pointerHops > 16)
                {
                    throw new ArgumentException("DNS question compression pointer is invalid.", nameof(message));
                }
                if (!jumped)
                {
                    offset = current + 2;
                    jumped = true;
                }
                current = ((length & 0x3F) << 8) | message[current + 1];
                continue;
            }

            if ((length & 0xC0) != 0 || length > 63 || current + 1 + length > message.Length)
            {
                throw new ArgumentException("DNS question label is invalid.", nameof(message));
            }

            labels.Add(Encoding.ASCII.GetString(message.Slice(current + 1, length)));
            current += length + 1;
            if (!jumped)
            {
                offset = current;
            }
        }

        if (labels.Count == 0)
        {
            throw new ArgumentException("DNS root queries are not supported by HIP DoH.", nameof(message));
        }
        return string.Join('.', labels);
    }

    private static void WriteDomainName(List<byte> bytes, string domain)
    {
        foreach (var label in domain.TrimEnd('.').Split('.'))
        {
            var encoded = Encoding.ASCII.GetBytes(label);
            if (encoded.Length is < 1 or > 63)
            {
                throw new ArgumentException("DNS response label is invalid.", nameof(domain));
            }
            bytes.Add((byte)encoded.Length);
            bytes.AddRange(encoded);
        }
        bytes.Add(0);
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> bytes, int offset) =>
        BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(offset, 2));

    private static void WriteUInt16(List<byte> bytes, ushort value)
    {
        bytes.Add((byte)(value >> 8));
        bytes.Add((byte)value);
    }

    private static void WriteUInt32(List<byte> bytes, uint value)
    {
        bytes.Add((byte)(value >> 24));
        bytes.Add((byte)(value >> 16));
        bytes.Add((byte)(value >> 8));
        bytes.Add((byte)value);
    }

    private sealed record EncodedAnswer(string Owner, int TtlSeconds, byte[] Data);
}
