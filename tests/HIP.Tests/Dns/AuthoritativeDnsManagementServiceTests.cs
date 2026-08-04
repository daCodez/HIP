using HIP.Application.Certificates;
using HIP.Application.Dns;
using HIP.Application.Review;
using HIP.Domain.Certificates;

namespace HIP.Tests.Dns;

/// <summary>Focused security and publication tests for HIP authoritative DNS management.</summary>
public sealed class AuthoritativeDnsManagementServiceTests
{
    [Test]
    public async Task Verified_zone_is_normalized_published_persisted_and_audited()
    {
        var repository = new MemoryZoneRepository();
        var publisher = new RecordingPublisher();
        var auditRepository = new InMemoryAuditLogRepository();
        var service = Service(repository, publisher, VerifiedCertificateQuery(), auditRepository);

        var result = await service.PublishAsync(
            new PublishAuthoritativeDnsZoneRequest(
                "Example.COM",
                [
                    new("@", AuthoritativeDnsRecordType.A, "203.0.113.10", 300),
                    new("www", AuthoritativeDnsRecordType.Cname, "example.com", 600),
                    new("@", AuthoritativeDnsRecordType.Txt, "hip-site-verification=test", 300)
                ],
                "Publish the initial website records."),
            "owner-test",
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Domain, Is.EqualTo("example.com"));
            Assert.That(result.Status, Is.EqualTo(AuthoritativeDnsZoneStatus.Published));
            Assert.That(result.DnssecEnabled, Is.True);
            Assert.That(result.DsRecords, Is.EqualTo(new[] { "12345 13 2 ABCDEF" }));
            Assert.That(result.Records.Select(record => record.Name), Does.Contain("example.com."));
            Assert.That(result.Records.Select(record => record.Name), Does.Contain("www.example.com."));
            Assert.That(result.Records.Single(record => record.Type == AuthoritativeDnsRecordType.Txt).Content,
                Is.EqualTo("\"hip-site-verification=test\""));
            Assert.That(publisher.PublishCount, Is.EqualTo(1));
        });

        var stored = await repository.GetAsync("example.com", CancellationToken.None);
        var audits = await auditRepository.ListAsync(CancellationToken.None);
        Assert.Multiple(() =>
        {
            Assert.That(stored, Is.EqualTo(result));
            Assert.That(audits.Single().Action, Is.EqualTo("AuthoritativeDns.ZonePublished"));
            Assert.That(audits.Single().TargetId, Is.EqualTo("example.com"));
        });
    }

    [Test]
    public void Unverified_zone_fails_before_provider_publication()
    {
        var publisher = new RecordingPublisher();
        var service = Service(new MemoryZoneRepository(), publisher, new StubCertificateQuery([]), new InMemoryAuditLogRepository());

        Assert.That(async () => await service.PublishAsync(
                Request("unverified.example"),
                "owner-test",
                CancellationToken.None),
            Throws.TypeOf<InvalidOperationException>()
                .With.Message.EqualTo("HIP must verify domain ownership before authoritative DNS can be published."));
        Assert.That(publisher.PublishCount, Is.EqualTo(0));
    }

    [TestCase("outside.example.net", AuthoritativeDnsRecordType.A, "203.0.113.10")]
    [TestCase("*.example.com", AuthoritativeDnsRecordType.A, "203.0.113.10")]
    [TestCase("@", AuthoritativeDnsRecordType.Cname, "target.example.net")]
    public void Unsafe_record_names_and_apex_cname_are_rejected(
        string name,
        AuthoritativeDnsRecordType type,
        string content)
    {
        var service = Service(new MemoryZoneRepository(), new RecordingPublisher(), VerifiedCertificateQuery(), new InMemoryAuditLogRepository());

        Assert.That(async () => await service.PublishAsync(
                new PublishAuthoritativeDnsZoneRequest(
                    "example.com",
                    [new(name, type, content, 300)],
                    "Test rejected record."),
                "owner-test",
                CancellationToken.None),
            Throws.TypeOf<ArgumentException>());
    }

    [Test]
    public async Task Provider_failure_keeps_bounded_failed_state_for_operator_recovery()
    {
        var repository = new MemoryZoneRepository();
        var publisher = new RecordingPublisher { FailPublication = true };
        var service = Service(repository, publisher, VerifiedCertificateQuery(), new InMemoryAuditLogRepository());

        Assert.That(async () => await service.PublishAsync(Request("example.com"), "owner-test", CancellationToken.None),
            Throws.TypeOf<InvalidOperationException>()
                .With.Message.EqualTo("The authoritative DNS provider rejected or could not complete publication."));

        var stored = await repository.GetAsync("example.com", CancellationToken.None);
        Assert.Multiple(() =>
        {
            Assert.That(stored, Is.Not.Null);
            Assert.That(stored!.Status, Is.EqualTo(AuthoritativeDnsZoneStatus.PublicationFailed));
            Assert.That(stored.SafeStatusDetail, Does.Not.Contain("provider exploded"));
        });
    }

    private static PublishAuthoritativeDnsZoneRequest Request(string domain) =>
        new(domain, [new("@", AuthoritativeDnsRecordType.A, "203.0.113.10")], "Publish a test zone.");

    private static IAuthoritativeDnsManagementService Service(
        IAuthoritativeDnsZoneRepository repository,
        IAuthoritativeDnsPublisher publisher,
        IDomainCertificateAdminQuery certificateQuery,
        IAuditLogRepository auditRepository) =>
        new AuthoritativeDnsManagementService(
            repository,
            publisher,
            certificateQuery,
            new DomainRegistrationNormalizer(new StubPublicSuffixResolver()),
            new AuditLogService(auditRepository),
            TimeProvider.System);

    private static IDomainCertificateAdminQuery VerifiedCertificateQuery() =>
        new StubCertificateQuery([
            new AdminDomainCertificateSummary(
                "enrollment-1",
                "example.com",
                DomainEnrollmentStatus.OwnershipVerified,
                "policy-v1",
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow,
                null,
                null,
                null,
                null,
                null,
                0,
                null,
                null,
                null,
                null,
                null,
                null)
        ]);

    private sealed class StubPublicSuffixResolver : IPublicSuffixResolver
    {
        public string? RegistrableDomain(string canonicalDomain) =>
            canonicalDomain.EndsWith(".example", StringComparison.Ordinal) ? canonicalDomain : "example.com";
    }

    private sealed class StubCertificateQuery(IReadOnlyList<AdminDomainCertificateSummary> items) : IDomainCertificateAdminQuery
    {
        public Task<IReadOnlyList<AdminDomainCertificateSummary>> ListForAdminAsync(
            int offset,
            int limit,
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<AdminDomainCertificateSummary>>(items.Skip(offset).Take(limit).ToArray());
    }

    private sealed class MemoryZoneRepository : IAuthoritativeDnsZoneRepository
    {
        private readonly Dictionary<string, AuthoritativeDnsZone> zones = new(StringComparer.Ordinal);

        public Task<AuthoritativeDnsZone?> GetAsync(string domain, CancellationToken cancellationToken) =>
            Task.FromResult(zones.GetValueOrDefault(domain));

        public Task<IReadOnlyCollection<AuthoritativeDnsZone>> ListAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyCollection<AuthoritativeDnsZone>>(zones.Values.ToArray());

        public Task<bool> TrySaveAsync(
            AuthoritativeDnsZone zone,
            long expectedVersion,
            CancellationToken cancellationToken)
        {
            var currentVersion = zones.GetValueOrDefault(zone.Domain)?.Version ?? 0;
            if (currentVersion != expectedVersion)
            {
                return Task.FromResult(false);
            }

            zones[zone.Domain] = zone;
            return Task.FromResult(true);
        }
    }

    private sealed class RecordingPublisher : IAuthoritativeDnsPublisher
    {
        public int PublishCount { get; private set; }
        public bool FailPublication { get; init; }

        public Task<AuthoritativeDnsPublication> PublishAsync(
            string domain,
            IReadOnlyCollection<AuthoritativeDnsRecord> records,
            CancellationToken cancellationToken)
        {
            PublishCount++;
            if (FailPublication)
            {
                throw new HttpRequestException("provider exploded with internal detail");
            }

            return Task.FromResult(new AuthoritativeDnsPublication(
                ["ns1.guardwithhip.com.", "ns2.guardwithhip.com."],
                ["12345 13 2 ABCDEF"]));
        }

        public Task DisableAsync(string domain, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
