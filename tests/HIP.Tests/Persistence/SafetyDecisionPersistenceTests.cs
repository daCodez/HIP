using HIP.Application.Reporting;
using HIP.Application.Safety;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Persistence;

[TestFixture]
public sealed class SafetyDecisionPersistenceTests
{
    [Test]
    public async Task Decision_is_create_only_encrypted_and_contains_no_raw_destination()
    {
        const string rawUrl = "https://danger-example.com/pay?token=private-marker#secret";
        await using var context = new HipDbContext(
            new DbContextOptionsBuilder<HipDbContext>()
                .UseInMemoryDatabase($"safety-decision-{Guid.NewGuid():N}")
                .Options);
        var repository = new EfSafetyDecisionRepository(
            new HipRecordStore(context, new DevelopmentHipRecordEncryptor()));
        var service = new SafetyDecisionService(
            new SafetyRoutingService(),
            repository,
            new Sha256PrivacyHashingService(),
            TimeProvider.System);

        var result = await service.RecordAsync(
            new SafetyDecisionRequest(
                rawUrl,
                "browser-extension",
                SafetyDecisionAction.ReportDangerous,
                DangerAcknowledged: false),
            CancellationToken.None);
        var row = await context.Records.AsNoTracking()
            .SingleAsync(record => record.Partition == "safety-decision");

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(SafetyDecisionStatus.Recorded));
            Assert.That(row.AggregateVersion, Is.EqualTo(1));
            Assert.That(new DevelopmentHipRecordEncryptor().IsProtectedPayload(row.Json), Is.True);
            Assert.That(row.Json, Does.Not.Contain(rawUrl));
            Assert.That(row.Json, Does.Not.Contain("private-marker"));
            Assert.That(row.Json, Does.Not.Contain("danger-example.com"));
        });
    }
}
