using HIP.Application.SiteSafety;

namespace HIP.Tests.SiteSafety;

public sealed class SandboxLinkScanJobLifecycleTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 21, 16, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Active_lease_prevents_double_claim_and_expired_lease_can_be_reclaimed()
    {
        var queue = new InMemorySandboxLinkScanQueue();
        await queue.EnqueueAsync(Request(), CancellationToken.None);

        var first = await queue.TryClaimNextAsync("worker-a", Now, TimeSpan.FromMinutes(1), 3, CancellationToken.None);
        var blocked = await queue.TryClaimNextAsync("worker-b", Now.AddSeconds(30), TimeSpan.FromMinutes(1), 3, CancellationToken.None);
        var reclaimed = await queue.TryClaimNextAsync("worker-b", Now.AddMinutes(1), TimeSpan.FromMinutes(1), 3, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(first, Is.Not.Null);
            Assert.That(blocked, Is.Null);
            Assert.That(reclaimed, Is.Not.Null);
            Assert.That(reclaimed!.AttemptCount, Is.EqualTo(2));
            Assert.That(reclaimed.LeaseToken, Is.Not.EqualTo(first!.LeaseToken));
        });
    }

    [Test]
    public async Task Failure_waits_for_retry_and_terminal_failure_dead_letters_job()
    {
        var queue = new InMemorySandboxLinkScanQueue();
        await queue.EnqueueAsync(Request(), CancellationToken.None);
        var first = (await queue.TryClaimNextAsync("worker", Now, TimeSpan.FromMinutes(1), 2, CancellationToken.None))!;

        Assert.That(await queue.TryFailAsync(first.RequestId, first.LeaseToken!, "Transient runner failure.", Now.AddSeconds(1), Now.AddMinutes(2), CancellationToken.None), Is.True);
        Assert.That(await queue.TryClaimNextAsync("worker", Now.AddMinutes(1), TimeSpan.FromMinutes(1), 2, CancellationToken.None), Is.Null);
        var retry = (await queue.TryClaimNextAsync("worker", Now.AddMinutes(2), TimeSpan.FromMinutes(1), 2, CancellationToken.None))!;
        Assert.That(await queue.TryFailAsync(retry.RequestId, retry.LeaseToken!, "Runner failed permanently.", Now.AddMinutes(2).AddSeconds(1), null, CancellationToken.None), Is.True);
        Assert.That(await queue.TryClaimNextAsync("worker", Now.AddMinutes(5), TimeSpan.FromMinutes(1), 2, CancellationToken.None), Is.Null);
    }

    [Test]
    public async Task Stale_lease_cannot_complete_and_cancelled_job_cannot_be_claimed()
    {
        var queue = new InMemorySandboxLinkScanQueue();
        await queue.EnqueueAsync(Request(), CancellationToken.None);
        var claim = (await queue.TryClaimNextAsync("worker", Now, TimeSpan.FromMinutes(1), 3, CancellationToken.None))!;

        Assert.That(await queue.TryCompleteAsync(claim.RequestId, "wrong-lease", Now.AddSeconds(1), CancellationToken.None), Is.False);
        Assert.That(await queue.TryCancelAsync(claim.RequestId, Now.AddSeconds(2), CancellationToken.None), Is.True);
        Assert.That(await queue.TryCompleteAsync(claim.RequestId, claim.LeaseToken!, Now.AddSeconds(3), CancellationToken.None), Is.False);
        Assert.That(await queue.TryClaimNextAsync("worker", Now.AddMinutes(2), TimeSpan.FromMinutes(1), 3, CancellationToken.None), Is.Null);
    }

    [Test]
    public void Operational_string_excludes_raw_target_and_hash()
    {
        var request = Request() with { RawTargetUrl = "https://risky.example/private?token=secret" };

        Assert.Multiple(() =>
        {
            Assert.That(request.ToString(), Does.Not.Contain("private"));
            Assert.That(request.ToString(), Does.Not.Contain(request.TargetUrlHash));
        });
    }

    private static SandboxLinkScanRequest Request() => new(
        "sandbox-link-test",
        "risky.example",
        "sha256:test",
        null,
        SandboxLinkScanReason.RiskyPageStatus,
        "scan-test",
        SiteSafetyScanStatus.HighRisk,
        Now);
}
