using System.Security.Cryptography;
using System.Text;
using HIP.Application.Certificates;
using HIP.Application.Protocol;
using HIP.Domain.Certificates;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Entities;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Certificates;

public sealed class DomainCertificateRepositoryTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 24, 16, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Certificate_and_issuance_event_are_created_together()
    {
        await using var context = Context();
        var repository = Repository(context);
        var record = Record();

        var result = await repository.TryCreateIssuedAsync(record, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateRepositoryWriteStatus.Created));
            Assert.That(result.StoredCertificate, Is.EqualTo(record));
            Assert.That(context.DomainCertificates.Count(), Is.EqualTo(1));
            Assert.That(context.DomainCertificateEvents.Count(), Is.EqualTo(1));
            Assert.That(context.DomainCertificateEvents.Single().EventType, Is.EqualTo("CertificateIssued"));
            Assert.That(context.DomainCertificateEvents.Single().EvidenceDigest,
                Is.EqualTo(record.SourceDecisionDigest));
        });
    }

    [Test]
    public async Task Exact_retry_returns_existing_without_duplicate_audit_event()
    {
        await using var context = Context();
        var repository = Repository(context);
        var record = Record();
        await repository.TryCreateIssuedAsync(record, CancellationToken.None);

        var retry = await repository.TryCreateIssuedAsync(record, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(retry.Status, Is.EqualTo(DomainCertificateRepositoryWriteStatus.ExistingSame));
            Assert.That(retry.StoredCertificate?.SignedCertificateJson,
                Is.EqualTo(record.SignedCertificateJson));
            Assert.That(context.DomainCertificates.Count(), Is.EqualTo(1));
            Assert.That(context.DomainCertificateEvents.Count(), Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Changed_decision_digest_for_same_certificate_id_is_a_conflict()
    {
        await using var context = Context();
        var repository = Repository(context);
        var record = Record();
        await repository.TryCreateIssuedAsync(record, CancellationToken.None);

        var conflict = await repository.TryCreateIssuedAsync(
            record with { SourceDecisionDigest = $"sha256:{new string('b', 64)}" },
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(conflict.Status, Is.EqualTo(DomainCertificateRepositoryWriteStatus.Conflict));
            Assert.That(context.DomainCertificates.Count(), Is.EqualTo(1));
            Assert.That(context.DomainCertificateEvents.Count(), Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Indexed_data_that_disagrees_with_signed_certificate_is_rejected()
    {
        await using var context = Context();
        var repository = Repository(context);
        var record = Record();
        await repository.TryCreateIssuedAsync(record, CancellationToken.None);
        context.ChangeTracker.Clear();
        var entity = await context.DomainCertificates.SingleAsync();
        entity.Domain = "tampered.example";
        await context.SaveChangesAsync();
        context.ChangeTracker.Clear();

        Assert.That(
            async () => await repository.GetByIdAsync(
                record.Certificate.Payload.CertificateId,
                CancellationToken.None),
            Throws.TypeOf<InvalidOperationException>());
    }

    private static HipDbContext Context()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-domain-certificate-repository-{Guid.NewGuid():N}")
            .Options;
        var context = new HipDbContext(options);
        context.DomainEnrollments.Add(new HipDomainEnrollmentEntity
        {
            EnrollmentId = "enrollment-1",
            OwnerId = "owner-1",
            Domain = "example.com",
            Status = DomainEnrollmentStatus.Verified,
            PolicyVersion = DomainCertificatePolicy.V1.Version,
            CreatedAtUtc = Now.AddHours(-1),
            UpdatedAtUtc = Now,
            AggregateVersion = 1
        });
        context.SaveChanges();
        return context;
    }

    private static EfDomainCertificateRepository Repository(HipDbContext context) =>
        new(context, new Rfc8785CanonicalJsonService());

    private static HipStoredDomainCertificate Record()
    {
        var payload = new DomainTrustCertificatePayload(
            "hip-domain-cert-0001",
            1,
            DomainCertificatePolicy.V1.Version,
            "example.com",
            "Example Site",
            "Example Organization",
            DomainCertificateLevel.Verified,
            DomainCertificateStatus.Active,
            Now,
            Now.AddDays(365),
            Now.AddMinutes(-10),
            null,
            "registrant-key-1",
            [VerificationMethod.DnsTxt, VerificationMethod.WellKnownHipJson],
            DomainCertificatePublicRiskClassification.Low,
            ["scan.no-critical", "tls.valid"],
            "https://hiptrust.com/api/v1/certificates/hip-domain-cert-0001/status",
            "https://hiptrust.com/certificate/hip-domain-cert-0001");
        var certificate = new SignedDomainTrustCertificate(
            payload,
            new DomainTrustCertificateSignature(
                "hip:service:domain-certificate-authority",
                "certificate-key-1",
                "test-signature-v1",
                SignatureAlgorithmFamily.Unknown,
                HipProtocolSignature.Rfc8785Canonicalization,
                "test-signature"));
        var json = DomainTrustCertificateJson.Serialize(certificate);
        return new HipStoredDomainCertificate(
            "enrollment-1",
            "owner-1",
            certificate,
            json,
            Digest(json),
            $"sha256:{new string('c', 64)}",
            new DomainCertificateAuditEvent(
                "certificate-event-1",
                "actor-1",
                "CertificateIssued",
                null,
                DomainCertificateStatus.Active,
                null,
                "HIP issued the domain certificate.",
                Now));
    }
    private static string Digest(string json)
    {
        var canonical = new Rfc8785CanonicalJsonService()
            .Canonicalize(Encoding.UTF8.GetBytes(json));
        return $"sha256:{Convert.ToHexString(SHA256.HashData(canonical)).ToLowerInvariant()}";
    }
}
