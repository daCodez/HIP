using HIP.Application.Dns;
using HIP.Application.PublicLookup;
using HIP.Domain.Risk;

namespace HIP.Tests.Dns;

/// <summary>
/// Verifies HIP combines replaceable DNS provider answers with public-safe trust evidence.
/// </summary>
[TestFixture]
public sealed class HipAwareDnsLookupServiceTests
{
    /// <summary>Confirms DNS answers and HIP trust data retain their separate semantics.</summary>
    [Test]
    public async Task Lookup_combines_provider_answers_with_public_safe_trust_summary()
    {
        var service = new HipAwareDnsLookupService(
            new StubDnsLookupProvider(),
            new StubPublicLookupService());

        var result = await service.LookupAsync("Example.COM.", DnsLookupRecordType.A, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(0));
            Assert.That(result.Provider, Is.EqualTo("test-provider"));
            Assert.That(result.Question.Single().Name, Is.EqualTo("example.com."));
            Assert.That(result.Answer.Single().Data, Is.EqualTo("192.0.2.10"));
            Assert.That(result.Hip.Domain, Is.EqualTo("example.com"));
            Assert.That(result.Hip.DisplayScore, Is.EqualTo(82));
            Assert.That(result.Hip.Status, Is.EqualTo("Trusted"));
            Assert.That(result.Hip.IsAuthoritative, Is.False);
        });
    }

    /// <summary>Confirms unsupported DNS record types are rejected at the application boundary.</summary>
    [Test]
    public void Lookup_rejects_record_types_outside_the_bounded_milestone()
    {
        var service = new HipAwareDnsLookupService(
            new StubDnsLookupProvider(),
            new StubPublicLookupService());

        Assert.That(
            async () => await service.LookupAsync("example.com", (DnsLookupRecordType)15, CancellationToken.None),
            Throws.TypeOf<ArgumentException>());
    }

    private sealed class StubDnsLookupProvider : IDnsLookupProvider
    {
        public string Name => "test-provider";

        public Task<DnsProviderLookupResult> LookupAsync(
            string domain,
            DnsLookupRecordType recordType,
            CancellationToken cancellationToken) =>
            Task.FromResult(new DnsProviderLookupResult(
                0,
                false,
                true,
                [new DnsLookupAnswer($"{domain}.", recordType, 60, "192.0.2.10")]));
    }

    private sealed class StubPublicLookupService : IPublicDomainLookupService
    {
        public Task<PublicDomainLookupResponse> LookupDomainAsync(string domain, CancellationToken cancellationToken) =>
            Task.FromResult(new PublicDomainLookupResponse(
                domain,
                82,
                82,
                RiskStatus.Trusted,
                "Low risk",
                "Verified",
                [],
                ["Stored public scan available."],
                [],
                "Proceed normally",
                DateTimeOffset.Parse("2026-08-04T12:00:00Z"),
                "Verified",
                "DNS TXT",
                null,
                "Valid",
                "Verified",
                true,
                true,
                $"https://guardwithhip.com/lookup/{domain}",
                84,
                80,
                12,
                "Stored evidence",
                [],
                12,
                0,
                0,
                0,
                "StoredScan",
                "Stored public scan available.")
            {
                DisplayScore = 82,
                EvidenceCoverage = "Sufficient",
                EvidenceConfidence = "High"
            });
    }
}
