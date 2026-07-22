using HIP.Application.Scalability;
using HIP.Application.SiteSafety;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Persistence;

/// <summary>Verifies HIP-0305 encrypted atomic enqueue and persistent compare-and-swap leases.</summary>
public sealed class ExternalSiteEvidenceJobPersistenceTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 20, 19, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Enqueue_commits_encrypted_job_and_outbox_together()
    {
        await using var context = CreateContext($"provider-job-atomic-{Guid.NewGuid():N}");
        var encryptor = new DevelopmentHipRecordEncryptor();
        var store = new HipRecordStore(context, encryptor);
        var repository = new EfExternalSiteEvidenceJobRepository(store);
        var service = new ExternalSiteEvidenceJobService(new SiteSafetyScanValidator(), repository, new FixedTimeProvider(Now));

        var queued = await service.QueueAsync(
            new SiteSafetyScanRequest("https://persistent-job.example/private?token=secret"),
            "owner",
            settingsScopeKey: null,
            CancellationToken.None);
        var restored = await repository.GetAsync(queued.JobId, CancellationToken.None);
        var outbox = await new EfOutboxEventRepository(store).ListPendingAsync(10, CancellationToken.None);
        var rows = await context.Records.AsNoTracking().ToArrayAsync();

        Assert.Multiple(() =>
        {
            Assert.That(restored, Is.Not.Null);
            Assert.That(restored!.JobId, Is.EqualTo(queued.JobId));
            Assert.That(restored.Domain, Is.EqualTo(queued.Domain));
            Assert.That(restored.UrlHash, Is.EqualTo(queued.UrlHash));
            Assert.That(restored.Status, Is.EqualTo(queued.Status));
            Assert.That(restored.Version, Is.EqualTo(queued.Version));
            Assert.That(outbox.Single().AggregateId, Is.EqualTo(queued.JobId));
            Assert.That(rows, Has.Length.EqualTo(2));
            Assert.That(rows, Has.All.Matches<HipDbRecord>(row => encryptor.IsProtectedPayload(row.Json)));
            Assert.That(rows.Select(row => row.Partition), Is.EquivalentTo(new[] { "external-site-evidence-job", "outbox-event" }));
            Assert.That(rows.Select(row => row.Json), Has.None.Contains("token=secret"));
        });
    }

    [Test]
    public async Task Separate_worker_scopes_cannot_both_claim_the_same_persistent_job()
    {
        var databaseName = $"provider-job-claim-{Guid.NewGuid():N}";
        await using var enqueueContext = CreateContext(databaseName);
        var enqueueRepository = Repository(enqueueContext);
        var service = new ExternalSiteEvidenceJobService(new SiteSafetyScanValidator(), enqueueRepository, new FixedTimeProvider(Now));
        await service.QueueAsync(
            new SiteSafetyScanRequest("https://persistent-claim.example/"),
            "owner",
            settingsScopeKey: null,
            CancellationToken.None);

        await using var contextA = CreateContext(databaseName);
        await using var contextB = CreateContext(databaseName);
        var claims = await Task.WhenAll(
            Repository(contextA).TryClaimNextAsync("worker-a", Now, TimeSpan.FromMinutes(1), 3, CancellationToken.None),
            Repository(contextB).TryClaimNextAsync("worker-b", Now, TimeSpan.FromMinutes(1), 3, CancellationToken.None));

        Assert.That(claims.Count(claim => claim is not null), Is.EqualTo(1));
    }

    private static EfExternalSiteEvidenceJobRepository Repository(HipDbContext context) =>
        new(new HipRecordStore(context, new DevelopmentHipRecordEncryptor()));

    private static HipDbContext CreateContext(string databaseName) =>
        new(new DbContextOptionsBuilder<HipDbContext>().UseInMemoryDatabase(databaseName).Options);

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
