using HIP.Application.SiteSafety;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Persistence;

public sealed class SandboxLinkScanJobPersistenceTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 21, 17, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Separate_worker_scopes_cannot_claim_the_same_durable_sandbox_job()
    {
        var databaseName = $"sandbox-job-claim-{Guid.NewGuid():N}";
        await using var enqueueContext = CreateContext(databaseName);
        await Queue(enqueueContext).EnqueueAsync(Request(), CancellationToken.None);

        await using var contextA = CreateContext(databaseName);
        await using var contextB = CreateContext(databaseName);
        var claims = await Task.WhenAll(
            Queue(contextA).TryClaimNextAsync("worker-a", Now, TimeSpan.FromMinutes(1), 3, CancellationToken.None),
            Queue(contextB).TryClaimNextAsync("worker-b", Now, TimeSpan.FromMinutes(1), 3, CancellationToken.None));

        Assert.That(claims.Count(claim => claim is not null), Is.EqualTo(1));
    }

    [Test]
    public async Task Durable_job_survives_retry_and_completes_only_with_current_lease()
    {
        var databaseName = $"sandbox-job-retry-{Guid.NewGuid():N}";
        await using var context = CreateContext(databaseName);
        var queue = Queue(context);
        await queue.EnqueueAsync(Request(), CancellationToken.None);
        var first = (await queue.TryClaimNextAsync("worker", Now, TimeSpan.FromMinutes(1), 3, CancellationToken.None))!;

        Assert.That(await queue.TryFailAsync(first.RequestId, first.LeaseToken!, "Temporary failure.", Now.AddSeconds(1), Now.AddMinutes(2), CancellationToken.None), Is.True);
        var retry = await queue.TryClaimNextAsync("worker", Now.AddMinutes(2), TimeSpan.FromMinutes(1), 3, CancellationToken.None);
        Assert.That(retry, Is.Not.Null);
        Assert.That(await queue.TryCompleteAsync(retry!.RequestId, first.LeaseToken!, Now.AddMinutes(2).AddSeconds(1), CancellationToken.None), Is.False);
        Assert.That(await queue.TryCompleteAsync(retry.RequestId, retry.LeaseToken!, Now.AddMinutes(2).AddSeconds(2), CancellationToken.None), Is.True);
    }

    private static EfSandboxLinkScanQueue Queue(HipDbContext context) =>
        new(new HipRecordStore(context, new DevelopmentHipRecordEncryptor()));

    private static HipDbContext CreateContext(string databaseName) =>
        new(new DbContextOptionsBuilder<HipDbContext>().UseInMemoryDatabase(databaseName).Options);

    private static SandboxLinkScanRequest Request() => new(
        $"sandbox-link-{Guid.NewGuid():N}",
        "risky.example",
        "sha256:test",
        null,
        SandboxLinkScanReason.RiskyPageStatus,
        "scan-test",
        SiteSafetyScanStatus.HighRisk,
        Now);
}
