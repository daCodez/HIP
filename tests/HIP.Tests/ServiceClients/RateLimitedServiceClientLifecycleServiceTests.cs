using HIP.Application.Reporting;
using HIP.Application.Review;
using HIP.Application.ServiceClients;
using HIP.Domain.ServiceClients;

namespace HIP.Tests.ServiceClients;

/// <summary>Proves all privileged lifecycle entry points share one fail-closed pre-work budget.</summary>
[TestFixture]
public sealed class RateLimitedServiceClientLifecycleServiceTests
{
    [Test]
    public async Task Throttled_create_rotate_and_revoke_stop_before_repository_secret_or_PBKDF_work()
    {
        var fixture = Fixture.Create(new StubMutationLimiter(allowed: false));

        var created = await fixture.Service.CreateAsync(
            "actor-a", "owner-a", Request(), CancellationToken.None);
        var rotated = await fixture.Service.RotateCredentialAsync(
            "actor-a", "owner-a", ClientId, 1, CancellationToken.None);
        var revoked = await fixture.Service.RevokeAsync(
            "actor-a", "owner-a", ClientId, 1, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(created.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.Throttled));
            Assert.That(rotated.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.Throttled));
            Assert.That(revoked.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.Throttled));
            Assert.That(created.Message, Is.EqualTo(ServiceClientLifecycleMessages.Throttled));
            Assert.That(rotated.Message, Is.EqualTo(ServiceClientLifecycleMessages.Throttled));
            Assert.That(revoked.Message, Is.EqualTo(ServiceClientLifecycleMessages.Throttled));
            Assert.That(fixture.Limiter.Calls, Is.EqualTo(3));
            Assert.That(fixture.Repository.TotalCalls, Is.Zero);
            Assert.That(fixture.Generator.TotalCalls, Is.Zero);
            Assert.That(fixture.Protector.ProtectCalls, Is.Zero);
        });
    }

    [Test]
    public async Task Distributed_failure_returns_unavailable_without_falling_back_to_process_local_work()
    {
        var fixture = Fixture.Create(new StubMutationLimiter(
            failure: new InvalidOperationException("Distributed limiter unavailable.")));

        var result = await fixture.Service.CreateAsync(
            "actor-a", "owner-a", Request(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.Unavailable));
            Assert.That(result.Message, Is.EqualTo(ServiceClientLifecycleMessages.Unavailable));
            Assert.That(fixture.Repository.TotalCalls, Is.Zero);
            Assert.That(fixture.Generator.TotalCalls, Is.Zero);
            Assert.That(fixture.Protector.ProtectCalls, Is.Zero);
        });
    }

    [Test]
    public async Task List_bypasses_the_mutation_budget_and_allowed_create_consumes_it_exactly_once()
    {
        var fixture = Fixture.Create(new StubMutationLimiter(allowed: true));

        var listed = await fixture.Service.ListAsync("owner-a", null, 25, CancellationToken.None);
        var created = await fixture.Service.CreateAsync(
            "actor-a", "owner-a", Request(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(listed.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.Succeeded));
            Assert.That(created.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.Succeeded));
            Assert.That(fixture.Limiter.Calls, Is.EqualTo(1));
            Assert.That(fixture.Limiter.Actors, Is.EqualTo(new[] { "actor-a" }));
            Assert.That(fixture.Repository.ListCalls, Is.EqualTo(1));
            Assert.That(fixture.Repository.SaveCalls, Is.EqualTo(1));
            Assert.That(fixture.Generator.ClientIdCalls, Is.EqualTo(1));
            Assert.That(fixture.Generator.SecretCalls, Is.EqualTo(1));
            Assert.That(fixture.Protector.ProtectCalls, Is.EqualTo(1));
        });
    }

    [Test]
    public void Caller_cancellation_is_propagated_before_mutation_work()
    {
        var fixture = Fixture.Create(new StubMutationLimiter(allowed: true));
        using var source = new CancellationTokenSource();
        source.Cancel();

        Assert.That(
            async () => await fixture.Service.CreateAsync("actor-a", "owner-a", Request(), source.Token),
            Throws.InstanceOf<OperationCanceledException>());
        Assert.Multiple(() =>
        {
            Assert.That(fixture.Repository.TotalCalls, Is.Zero);
            Assert.That(fixture.Generator.TotalCalls, Is.Zero);
        });
    }

    [Test]
    public async Task Invalid_actor_is_rejected_before_distributed_or_mutation_work()
    {
        var fixture = Fixture.Create(new StubMutationLimiter(allowed: true));

        var result = await fixture.Service.CreateAsync(
            " actor-a", "owner-a", Request(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.InvalidRequest));
            Assert.That(result.Message, Is.EqualTo(ServiceClientLifecycleMessages.InvalidRequest));
            Assert.That(fixture.Limiter.Calls, Is.Zero);
            Assert.That(fixture.Repository.TotalCalls, Is.Zero);
            Assert.That(fixture.Generator.TotalCalls, Is.Zero);
        });
    }

    private const string ClientId = "hipc_v1_AAAAAAAAAAAAAAAAAAAAAA";

    private static CreateServiceClientRequest Request() =>
        new(
            "Evidence checker",
            [ServiceClientScopeValues.DomainVerificationCheck],
            ["example.test"],
            30);

    private sealed record Fixture(
        RateLimitedServiceClientLifecycleService Service,
        StubMutationLimiter Limiter,
        TrackingRepository Repository,
        TrackingCredentialGenerator Generator,
        TrackingSecretProtector Protector)
    {
        public static Fixture Create(StubMutationLimiter limiter)
        {
            var repository = new TrackingRepository();
            var generator = new TrackingCredentialGenerator();
            var protector = new TrackingSecretProtector();
            var core = new ServiceClientLifecycleService(
                repository,
                generator,
                protector,
                new ServiceClientOwnerScopeDerivation(
                    new PrivacyHashingOptions("management-limiter-owner-key", AllowDevelopmentKey: false)),
                new AuditLogService(new InMemoryAuditLogRepository()),
                TimeProvider.System);
            return new Fixture(
                new RateLimitedServiceClientLifecycleService(core, limiter),
                limiter,
                repository,
                generator,
                protector);
        }
    }

    private sealed class StubMutationLimiter(bool allowed = false, Exception? failure = null)
        : IServiceClientManagementMutationLimiter
    {
        private readonly List<string> actors = [];
        private int calls;

        public int Calls => Volatile.Read(ref calls);

        public IReadOnlyCollection<string> Actors => actors.ToArray();

        public ValueTask<bool> TryAcquireAsync(
            string actorId,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref calls);
            lock (actors)
            {
                actors.Add(actorId);
            }

            return failure is null
                ? ValueTask.FromResult(allowed)
                : ValueTask.FromException<bool>(failure);
        }
    }

    private sealed class TrackingRepository : IServiceClientRepository
    {
        private int getCalls;
        private int listCalls;
        private int saveCalls;

        public int ListCalls => Volatile.Read(ref listCalls);
        public int SaveCalls => Volatile.Read(ref saveCalls);
        public int TotalCalls => Volatile.Read(ref getCalls) + ListCalls + SaveCalls;

        public Task<ServiceClientRegistration?> GetAsync(
            string clientId,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref getCalls);
            return Task.FromResult<ServiceClientRegistration?>(null);
        }

        public Task<ServiceClientRepositoryPage> ListByOwnerAsync(
            string ownerScopeId,
            string? cursor,
            int pageSize,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref listCalls);
            return Task.FromResult(new ServiceClientRepositoryPage([], null));
        }

        public Task<ServiceClientSaveOutcome> TrySaveAsync(
            ServiceClientTransitionBatch transition,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref saveCalls);
            return Task.FromResult(ServiceClientSaveOutcome.Succeeded);
        }
    }

    private sealed class TrackingCredentialGenerator : IServiceClientCredentialGenerator
    {
        private int clientIdCalls;
        private int secretCalls;

        public int ClientIdCalls => Volatile.Read(ref clientIdCalls);
        public int SecretCalls => Volatile.Read(ref secretCalls);
        public int TotalCalls => ClientIdCalls + SecretCalls;

        public string GenerateClientId()
        {
            Interlocked.Increment(ref clientIdCalls);
            return ClientId;
        }

        public ServiceClientSecret GenerateSecret()
        {
            Interlocked.Increment(ref secretCalls);
            return new ServiceClientSecret("hips_v1_test-secret-material");
        }
    }

    private sealed class TrackingSecretProtector : IServiceClientSecretProtector
    {
        private int protectCalls;

        public int ProtectCalls => Volatile.Read(ref protectCalls);

        public string Protect(string clientId, ServiceClientSecret secret)
        {
            Interlocked.Increment(ref protectCalls);
            return "pbkdf2-sha256-v1$test-verifier-material-0001";
        }

        public bool Verify(
            string clientId,
            ServiceClientSecret presentedSecret,
            string credentialVerifier) =>
            false;
    }
}
