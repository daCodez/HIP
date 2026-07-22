using HIP.Application.Reporting;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using HIP.Tests.Reporting;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Persistence;

public sealed class RiskFindingRetentionPersistenceTests
{
    [Test]
    public async Task Expiration_removes_global_and_owner_index_copies_together()
    {
        var now = new DateTimeOffset(2026, 7, 21, 20, 0, 0, TimeSpan.Zero);
        await using var context = new HipDbContext(new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"risk-retention-{Guid.NewGuid():N}").Options);
        var encryptor = new DevelopmentHipRecordEncryptor();
        var repository = new EfRiskFindingReportRepository(new HipRecordStore(context, encryptor), context, encryptor);
        var ownerHash = $"sha256:{new string('a', 64)}";
        await repository.AddAsync(RiskFindingRetentionTests.Report("owned-expired", now.AddDays(-31), consumerScopeHash: ownerHash), CancellationToken.None);
        Assert.That(await context.Records.CountAsync(), Is.EqualTo(2));

        var deleted = await repository.DeleteExpiredAsync(now, 10, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(deleted, Is.EqualTo(1));
            Assert.That(context.Records, Is.Empty);
        });
    }
}
