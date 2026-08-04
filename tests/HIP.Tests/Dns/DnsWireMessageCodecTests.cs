using HIP.Application.Dns;

namespace HIP.Tests.Dns;

/// <summary>Verifies the bounded RFC 1035 wire codec used by HIP's RFC 8484 endpoint.</summary>
[TestFixture]
public sealed class DnsWireMessageCodecTests
{
    private const string Rfc8484ExampleQueryHex =
        "00000100000100000000000003777777076578616d706c6503636f6d0000010001";

    /// <summary>Confirms the RFC 8484 example query is decoded without reading unrelated message data.</summary>
    [Test]
    public void Parse_reads_single_in_a_question_from_rfc_example()
    {
        var query = DnsWireMessageCodec.ParseQuery(Convert.FromHexString(Rfc8484ExampleQueryHex));

        Assert.Multiple(() =>
        {
            Assert.That(query.Id, Is.EqualTo(0));
            Assert.That(query.Domain, Is.EqualTo("www.example.com"));
            Assert.That(query.RecordType, Is.EqualTo(DnsLookupRecordType.A));
            Assert.That(query.IsRecursionDesired, Is.True);
            Assert.That(query.IsCheckingDisabled, Is.False);
        });
    }

    /// <summary>Confirms a DNS response preserves the question and encodes a compressed IPv4 answer.</summary>
    [Test]
    public void Encode_writes_valid_a_response_with_provider_ttl()
    {
        var query = DnsWireMessageCodec.ParseQuery(Convert.FromHexString(Rfc8484ExampleQueryHex));
        var response = CreateResponse(
            query,
            [new DnsJsonAnswer("www.example.com.", 1, 30, "192.0.2.20")]);

        var encoded = DnsWireMessageCodec.EncodeResponse(query, response);

        Assert.That(Convert.ToHexString(encoded), Is.EqualTo(
            "00008180000100010000000003777777076578616D706C6503636F6D0000010001" +
            "C00C000100010000001E0004C0000214"));
    }

    /// <summary>Confirms multiple-question messages are rejected before provider resolution.</summary>
    [Test]
    public void Parse_rejects_multiple_questions()
    {
        var bytes = Convert.FromHexString(Rfc8484ExampleQueryHex);
        bytes[5] = 2;

        Assert.That(
            () => DnsWireMessageCodec.ParseQuery(bytes),
            Throws.TypeOf<ArgumentException>());
    }

    /// <summary>Confirms unsupported record types produce a DNS NOTIMP response with HTTP-success semantics.</summary>
    [Test]
    public void Encode_error_writes_not_implemented_dns_response()
    {
        var bytes = Convert.FromHexString(Rfc8484ExampleQueryHex);
        bytes[^3] = 15;
        var query = DnsWireMessageCodec.ParseQuery(bytes, allowUnsupportedRecordType: true);

        var encoded = DnsWireMessageCodec.EncodeErrorResponse(query, dnsResponseCode: 4);

        Assert.Multiple(() =>
        {
            Assert.That(encoded[3] & 0x0F, Is.EqualTo(4));
            Assert.That(encoded[7], Is.EqualTo(0));
            Assert.That(encoded.AsSpan(12, bytes.Length - 12).ToArray(), Is.EqualTo(bytes.AsSpan(12).ToArray()));
        });
    }

    private static HipAwareDnsLookupResponse CreateResponse(
        DnsWireQuery query,
        IReadOnlyCollection<DnsJsonAnswer> answers) =>
        new(
            0,
            false,
            query.IsRecursionDesired,
            true,
            false,
            query.IsCheckingDisabled,
            [new DnsJsonQuestion($"{query.Domain}.", (int)query.RecordType)],
            answers,
            "test-provider",
            new HipDnsTrustSummary(
                query.Domain,
                82,
                "Trusted",
                "Low risk",
                "Verified",
                "Sufficient",
                "High",
                "Allow",
                DateTimeOffset.Parse("2026-08-04T12:00:00Z"),
                $"/lookup/{query.Domain}",
                "StoredScan",
                false));
}
