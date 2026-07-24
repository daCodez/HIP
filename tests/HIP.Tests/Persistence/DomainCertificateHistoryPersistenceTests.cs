using HIP.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Persistence;

/// <summary>Protects certificate and audit history from cascading parent deletion.</summary>
public sealed class DomainCertificateHistoryPersistenceTests
{
    [Test]
    public void Certificate_history_rejects_cascading_parent_deletes()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-certificate-history-{Guid.NewGuid():N}")
            .Options;
        using var context = new HipDbContext(options);
        var certificate = context.DomainCertificates.EntityType;
        var auditEvent = context.DomainCertificateEvents.EntityType;

        Assert.Multiple(() =>
        {
            Assert.That(
                certificate.GetForeignKeys().Single().DeleteBehavior,
                Is.EqualTo(DeleteBehavior.Restrict));
            Assert.That(
                auditEvent.GetForeignKeys().All(key => key.DeleteBehavior == DeleteBehavior.Restrict),
                Is.True);
        });
    }
}
