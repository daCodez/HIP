using HIP.Application.Scalability;
using HIP.Application.SiteSafety;
using Microsoft.Extensions.Logging.Abstractions;

namespace HIP.Tests.SiteSafety;

/// <summary>Locks the HIP-0305 durable provider-job state and privacy boundaries.</summary>
public sealed class ExternalSiteEvidenceJobTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 20, 18, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Queue_persists_only_domain_hash_safe_signals_and_atomic_outbox_event()
    {
        var outbox = new InMemoryOutboxEventRepository();
        var repository = new InMemoryExternalSiteEvidenceJobRepository(outbox);
        var service = new ExternalSiteEvidenceJobService(
            new SiteSafetyScanValidator(),
            repository,
            new FixedTimeProvider(Now));

        var job = await service.QueueAsync(
            new SiteSafetyScanRequest(
                "https://jobs.example/private/login?password=secret",
                new SiteSafetyObservedSignals(HasLoginForm: true, HasPasswordField: true)),
            "admin@example.com",
            "admin@example.com",
            CancellationToken.None);

        var events = await outbox.ListPendingAsync(10, CancellationToken.None);
        Assert.Multiple(() =>
        {
            Assert.That(job.Status, Is.EqualTo(ExternalSiteEvidenceJobStatus.Pending));
            Assert.That(job.Domain, Is.EqualTo("jobs.example"));
            Assert.That(job.UrlHash, Does.Match("^[0-9a-f]{64}$"));
            Assert.That(job.RequesterKeyDigest, Does.Match("^[0-9a-f]{64}$"));
            Assert.That(job.ObservedSignals.HasLoginForm, Is.True);
            Assert.That(job.ObservedSignals.HasPasswordField, Is.True);
            Assert.That(job.ToString(), Does.Not.Contain("private/login"));
            Assert.That(job.ToString(), Does.Not.Contain("password=secret"));
            Assert.That(events, Has.Count.EqualTo(1));
            Assert.That(events.Single().AggregateId, Is.EqualTo(job.JobId));
            Assert.That(events.Single().PayloadJson, Does.Not.Contain("password=secret"));
        });
    }

    [Test]
    public async Task Concurrent_workers_can_claim_a_queued_job_only_once()
    {
        var repository = new InMemoryExternalSiteEvidenceJobRepository(new InMemoryOutboxEventRepository());
        var service = Service(repository);
        var job = await service.QueueAsync(
            new SiteSafetyScanRequest("https://claim.example/path"),
            "owner",
            settingsScopeKey: null,
            CancellationToken.None);

        var claims = await Task.WhenAll(
            repository.TryClaimNextAsync("worker-a", Now, TimeSpan.FromMinutes(1), 3, CancellationToken.None),
            repository.TryClaimNextAsync("worker-b", Now, TimeSpan.FromMinutes(1), 3, CancellationToken.None));

        Assert.Multiple(() =>
        {
            Assert.That(claims.Count(claim => claim is not null), Is.EqualTo(1));
            Assert.That(claims.Single(claim => claim is not null)!.JobId, Is.EqualTo(job.JobId));
            Assert.That(claims.Single(claim => claim is not null)!.Status, Is.EqualTo(ExternalSiteEvidenceJobStatus.Processing));
            Assert.That(claims.Single(claim => claim is not null)!.AttemptCount, Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Expired_processing_lease_makes_abandoned_job_retryable()
    {
        var repository = new InMemoryExternalSiteEvidenceJobRepository(new InMemoryOutboxEventRepository());
        var service = Service(repository);
        await service.QueueAsync(
            new SiteSafetyScanRequest("https://lease.example/"),
            "owner",
            settingsScopeKey: null,
            CancellationToken.None);

        var first = await repository.TryClaimNextAsync("worker-a", Now, TimeSpan.FromSeconds(30), 3, CancellationToken.None);
        var beforeExpiry = await repository.TryClaimNextAsync("worker-b", Now.AddSeconds(29), TimeSpan.FromSeconds(30), 3, CancellationToken.None);
        var staleCompletion = await repository.TryCompleteAsync(
            first!.JobId,
            first.LeaseToken!,
            [],
            Now.AddSeconds(31),
            CancellationToken.None);
        var recovered = await repository.TryClaimNextAsync("worker-b", Now.AddSeconds(31), TimeSpan.FromSeconds(30), 3, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(first, Is.Not.Null);
            Assert.That(beforeExpiry, Is.Null);
            Assert.That(staleCompletion, Is.False);
            Assert.That(recovered, Is.Not.Null);
            Assert.That(recovered!.LeaseToken, Is.Not.EqualTo(first!.LeaseToken));
            Assert.That(recovered.AttemptCount, Is.EqualTo(2));
        });
    }

    [Test]
    public async Task Repeated_expired_leases_stop_at_the_maximum_attempt_count()
    {
        var repository = new InMemoryExternalSiteEvidenceJobRepository(new InMemoryOutboxEventRepository());
        var service = Service(repository);
        var queued = await service.QueueAsync(
            new SiteSafetyScanRequest("https://crash-loop.example/"),
            "owner",
            settingsScopeKey: null,
            CancellationToken.None);

        var first = await repository.TryClaimNextAsync("worker-a", Now, TimeSpan.FromSeconds(30), 2, CancellationToken.None);
        var second = await repository.TryClaimNextAsync("worker-b", Now.AddSeconds(31), TimeSpan.FromSeconds(30), 2, CancellationToken.None);
        var exhaustedClaim = await repository.TryClaimNextAsync("worker-c", Now.AddSeconds(62), TimeSpan.FromSeconds(30), 2, CancellationToken.None);
        var stored = await repository.GetAsync(queued.JobId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(first!.AttemptCount, Is.EqualTo(1));
            Assert.That(second!.AttemptCount, Is.EqualTo(2));
            Assert.That(exhaustedClaim, Is.Null);
            Assert.That(stored!.Status, Is.EqualTo(ExternalSiteEvidenceJobStatus.Failed));
            Assert.That(stored.AttemptCount, Is.EqualTo(2));
            Assert.That(stored.LeaseToken, Is.Null);
            Assert.That(stored.CompletedAtUtc, Is.EqualTo(Now.AddSeconds(62)));
        });
    }

    [Test]
    public async Task Lookup_rejects_noncanonical_job_ids_before_repository_access()
    {
        var repository = new RecordingJobRepository();
        var service = Service(repository);

        var result = await service.GetForRequesterAsync(
            $"provider-job:{new string('a', 4_096)}",
            "owner",
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.Null);
            Assert.That(repository.GetWasCalled, Is.False);
        });
    }

    [Test]
    public async Task Processor_persists_normalized_results_and_completes_the_job()
    {
        var clock = new MutableTimeProvider(Now);
        var repository = new InMemoryExternalSiteEvidenceJobRepository(new InMemoryOutboxEventRepository());
        var service = new ExternalSiteEvidenceJobService(new SiteSafetyScanValidator(), repository, clock);
        var queued = await service.QueueAsync(
            new SiteSafetyScanRequest("https://worker.example/private?token=secret"),
            "owner",
            settingsScopeKey: null,
            CancellationToken.None);
        var collector = new RecordingWorkCollector(clock);
        var processor = Processor(repository, collector, clock, maxAttempts: 3);

        var processed = await processor.ProcessNextAsync("worker-1", CancellationToken.None);
        var stored = await repository.GetAsync(queued.JobId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(processed, Is.True);
            Assert.That(collector.Received, Is.Not.Null);
            Assert.That(collector.Received!.Domain, Is.EqualTo("worker.example"));
            Assert.That(collector.Received.ToString(), Does.Not.Contain("private"));
            Assert.That(stored!.Status, Is.EqualTo(ExternalSiteEvidenceJobStatus.Succeeded));
            Assert.That(stored.ProviderEvidence, Has.Count.EqualTo(1));
            Assert.That(stored.LeaseToken, Is.Null);
            Assert.That(stored.CompletedAtUtc, Is.EqualTo(Now));
        });
    }

    [Test]
    public async Task Processor_retries_transient_failure_then_stops_at_maximum_attempts()
    {
        var clock = new MutableTimeProvider(Now);
        var repository = new InMemoryExternalSiteEvidenceJobRepository(new InMemoryOutboxEventRepository());
        var service = new ExternalSiteEvidenceJobService(new SiteSafetyScanValidator(), repository, clock);
        var queued = await service.QueueAsync(
            new SiteSafetyScanRequest("https://retry.example/"),
            "owner",
            settingsScopeKey: null,
            CancellationToken.None);
        var processor = Processor(repository, new ThrowingWorkCollector(), clock, maxAttempts: 2);

        await processor.ProcessNextAsync("worker-1", CancellationToken.None);
        var retry = await repository.GetAsync(queued.JobId, CancellationToken.None);
        clock.Advance(TimeSpan.FromMinutes(1));
        await processor.ProcessNextAsync("worker-1", CancellationToken.None);
        var terminal = await repository.GetAsync(queued.JobId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(retry!.Status, Is.EqualTo(ExternalSiteEvidenceJobStatus.RetryScheduled));
            Assert.That(retry.NextAttemptAtUtc, Is.GreaterThan(Now));
            Assert.That(retry.LastError, Is.EqualTo("External provider job failed transiently."));
            Assert.That(terminal!.Status, Is.EqualTo(ExternalSiteEvidenceJobStatus.Failed));
            Assert.That(terminal.AttemptCount, Is.EqualTo(2));
            Assert.That(terminal.NextAttemptAtUtc, Is.Null);
            Assert.That(terminal.CompletedAtUtc, Is.EqualTo(clock.GetUtcNow()));
        });
    }

    private static ExternalSiteEvidenceJobService Service(IExternalSiteEvidenceJobRepository repository) =>
        new(new SiteSafetyScanValidator(), repository, new FixedTimeProvider(Now));

    private static ExternalSiteEvidenceJobProcessor Processor(
        IExternalSiteEvidenceJobRepository repository,
        IExternalSiteEvidenceWorkCollector collector,
        TimeProvider clock,
        int maxAttempts) =>
        new(
            repository,
            collector,
            new InMemoryExternalSiteEvidenceSettingsStore(),
            new ExternalSiteEvidenceOptions(),
            new ExternalSiteEvidenceJobOptions { MaximumAttempts = maxAttempts },
            NullLogger<ExternalSiteEvidenceJobProcessor>.Instance,
            clock);

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class MutableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset now = now;

        public override DateTimeOffset GetUtcNow() => now;

        public void Advance(TimeSpan duration) => now = now.Add(duration);
    }

    private sealed class RecordingWorkCollector(TimeProvider clock) : IExternalSiteEvidenceWorkCollector
    {
        public ExternalSiteEvidenceWorkItem? Received { get; private set; }

        public Task<IReadOnlyCollection<SiteSafetyEvidence>> CollectAsync(
            ExternalSiteEvidenceWorkItem workItem,
            CancellationToken cancellationToken)
        {
            Received = workItem;
            var now = clock.GetUtcNow();
            return Task.FromResult<IReadOnlyCollection<SiteSafetyEvidence>>(
            [
                new SiteSafetyEvidence(
                    "QueuedTestProvider",
                    SiteSafetyEvidenceProviderType.ThreatIntel,
                    SiteSafetyEvidenceTargetType.Url,
                    workItem.Domain,
                    workItem.UrlHash,
                    [],
                    0,
                    now,
                    now.AddMinutes(5),
                    [],
                    false,
                    false,
                    SiteSafetyProviderResultStatus.Succeeded,
                    1,
                    SiteSafetyProviderFreshness.Fresh,
                    SiteSafetyProviderPrivacyClassification.HashedUrlMetadata)
            ]);
        }
    }

    private sealed class ThrowingWorkCollector : IExternalSiteEvidenceWorkCollector
    {
        public Task<IReadOnlyCollection<SiteSafetyEvidence>> CollectAsync(
            ExternalSiteEvidenceWorkItem workItem,
            CancellationToken cancellationToken) =>
            throw new HttpRequestException("Provider network unavailable.");
    }

    private sealed class RecordingJobRepository : IExternalSiteEvidenceJobRepository
    {
        public bool GetWasCalled { get; private set; }

        public Task EnqueueAsync(ExternalSiteEvidenceJob job, HipDurableEvent queuedEvent, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<ExternalSiteEvidenceJob?> GetAsync(string jobId, CancellationToken cancellationToken)
        {
            GetWasCalled = true;
            return Task.FromResult<ExternalSiteEvidenceJob?>(null);
        }

        public Task<ExternalSiteEvidenceJob?> TryClaimNextAsync(
            string workerId,
            DateTimeOffset nowUtc,
            TimeSpan leaseDuration,
            int maximumAttempts,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<bool> TryCompleteAsync(
            string jobId,
            string leaseToken,
            IReadOnlyCollection<SiteSafetyEvidence> providerEvidence,
            DateTimeOffset completedAtUtc,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<bool> TryFailAsync(
            string jobId,
            string leaseToken,
            string safeError,
            DateTimeOffset failedAtUtc,
            DateTimeOffset? nextAttemptAtUtc,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
