using HIP.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace HIP.Tests.Persistence;

/// <summary>Locks the indexed, history-preserving storage shape for domain enrollments and certificates.</summary>
public sealed class DomainCertificatePersistenceModelTests
{
    [Test]
    public void Certificate_tables_and_lookup_indexes_are_present()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-certificate-model-{Guid.NewGuid():N}")
            .Options;
        using var context = new HipDbContext(options);
        var model = context.Model;

        var enrollment = model.FindEntityType("HIP.Infrastructure.Persistence.Entities.HipDomainEnrollmentEntity");
        var certificate = model.FindEntityType("HIP.Infrastructure.Persistence.Entities.HipDomainCertificateEntity");
        var auditEvent = model.FindEntityType("HIP.Infrastructure.Persistence.Entities.HipDomainCertificateEventEntity");

        Assert.Multiple(() =>
        {
            Assert.That(enrollment, Is.Not.Null);
            Assert.That(certificate, Is.Not.Null);
            Assert.That(auditEvent, Is.Not.Null);
            Assert.That(enrollment!.GetTableName(), Is.EqualTo("hip_domain_enrollments"));
            Assert.That(certificate!.GetTableName(), Is.EqualTo("hip_domain_certificates"));
            Assert.That(auditEvent!.GetTableName(), Is.EqualTo("hip_domain_certificate_events"));
            Assert.That(HasIndex(enrollment!, "Domain"), Is.True);
            Assert.That(HasIndex(enrollment!, "OwnerId"), Is.True);
            Assert.That(HasIndex(enrollment!, "Status"), Is.True);
            Assert.That(HasIndex(certificate!, "Domain"), Is.True);
            Assert.That(HasIndex(certificate!, "Status"), Is.True);
            Assert.That(HasIndex(certificate!, "ExpiresAtUtc"), Is.True);
            Assert.That(HasIndex(auditEvent!, "CertificateId", "OccurredAtUtc"), Is.True);
        });
    }

    [Test]
    public void Current_domain_records_are_uniquely_constrained()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-certificate-uniqueness-{Guid.NewGuid():N}")
            .Options;
        using var context = new HipDbContext(options);

        var enrollment = context.Model.FindEntityType(
            "HIP.Infrastructure.Persistence.Entities.HipDomainEnrollmentEntity")!;
        var certificate = context.Model.FindEntityType(
            "HIP.Infrastructure.Persistence.Entities.HipDomainCertificateEntity")!;

        Assert.Multiple(() =>
        {
            Assert.That(FindIndex(enrollment, "Domain")!.IsUnique, Is.True);
            Assert.That(FindIndex(enrollment, "Domain")!.GetFilter(), Does.Contain("IsCurrent"));
            Assert.That(FindIndex(certificate, "Domain")!.IsUnique, Is.True);
            Assert.That(FindIndex(certificate, "Domain")!.GetFilter(), Does.Contain("IsCurrent"));
        });
    }

    private static bool HasIndex(IEntityType entity, params string[] properties) =>
        FindIndex(entity, properties) is not null;

    private static IIndex? FindIndex(IEntityType entity, params string[] properties) =>
        entity.GetIndexes().SingleOrDefault(index =>
            index.Properties.Select(property => property.Name).SequenceEqual(properties));
}
