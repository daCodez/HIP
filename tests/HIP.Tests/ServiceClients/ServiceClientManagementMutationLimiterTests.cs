using HIP.Application;
using HIP.Application.Reporting;
using HIP.Application.ServiceClients;
using HIP.Infrastructure;
using HIP.Infrastructure.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace HIP.Tests.ServiceClients;

/// <summary>Guards the distributed, privacy-safe budget for privileged service-client mutations.</summary>
[TestFixture]
public sealed class ServiceClientManagementMutationLimiterTests
{
    private const string PrivacyKey = "test-service-client-management-limiter-privacy-key";

    [Test]
    public async Task Shared_instances_enforce_one_actor_budget_without_exposing_actor_identifiers_in_keys()
    {
        var store = new SharedFixedWindowCounterStore();
        var options = Options.Create(new ServiceClientManagementMutationLimiterOptions
        {
            Window = TimeSpan.FromMinutes(2),
            ActorMutationLimit = 2
        });
        var firstInstance = CreateLimiter(store, options);
        var secondInstance = CreateLimiter(store, options);

        var first = await firstInstance.TryAcquireAsync("actor-sensitive-a");
        var second = await secondInstance.TryAcquireAsync("actor-sensitive-a");
        var rejected = await firstInstance.TryAcquireAsync("actor-sensitive-a");
        var independentActor = await secondInstance.TryAcquireAsync("actor-sensitive-b");

        Assert.Multiple(() =>
        {
            Assert.That(first, Is.True);
            Assert.That(second, Is.True);
            Assert.That(rejected, Is.False);
            Assert.That(independentActor, Is.True);
            Assert.That(store.Keys, Has.Count.EqualTo(2));
            Assert.That(
                store.Keys.All(key => key.StartsWith(
                    "hip:v1:service-client-management-mutation:actor:",
                    StringComparison.Ordinal)),
                Is.True);
            Assert.That(string.Join("|", store.Keys), Does.Not.Contain("actor-sensitive-a"));
            Assert.That(string.Join("|", store.Keys), Does.Not.Contain("actor-sensitive-b"));
        });
    }

    [Test]
    public void Distributed_backend_failure_is_propagated_for_the_boundary_to_fail_closed()
    {
        var failure = new InvalidOperationException("Distributed management limiter unavailable.");
        var limiter = CreateLimiter(
            new ThrowingFixedWindowCounterStore(failure),
            Options.Create(new ServiceClientManagementMutationLimiterOptions()));

        var thrown = Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await limiter.TryAcquireAsync("actor-a"));

        Assert.That(thrown, Is.SameAs(failure));
    }

    [Test]
    public async Task Rolling_privacy_key_rotation_shares_the_legacy_actor_budget_with_old_instances()
    {
        const string oldKey = "service-client-management-limiter-old-key";
        const string newKey = "service-client-management-limiter-new-key";
        var store = new SharedFixedWindowCounterStore();
        var options = Options.Create(new ServiceClientManagementMutationLimiterOptions
        {
            Window = TimeSpan.FromMinutes(2),
            ActorMutationLimit = 2
        });
        var oldInstance = CreateLimiter(
            store,
            options,
            new PrivacyHashingOptions(oldKey, AllowDevelopmentKey: false));
        var rotatingInstance = CreateLimiter(
            store,
            options,
            new PrivacyHashingOptions(
                newKey,
                AllowDevelopmentKey: false,
                LegacyKeys: [oldKey]));

        var oldAttempt = await oldInstance.TryAcquireAsync("actor-rotation-a");
        var rotatingAttempt = await rotatingInstance.TryAcquireAsync("actor-rotation-a");
        var rejectedByOldInstance = await oldInstance.TryAcquireAsync("actor-rotation-a");

        Assert.Multiple(() =>
        {
            Assert.That(oldAttempt, Is.True);
            Assert.That(rotatingAttempt, Is.True);
            Assert.That(rejectedByOldInstance, Is.False);
            Assert.That(store.Keys, Has.Count.EqualTo(2));
            Assert.That(store.IncrementCalls, Is.EqualTo(4));
        });
    }

    [Test]
    public async Task Rotation_candidates_are_current_first_exact_deduplicated_and_all_counted_on_rejection()
    {
        const string oldKey = "service-client-management-order-old-key";
        const string newKey = "service-client-management-order-new-key";
        const string actor = "actor-sensitive-rotation";
        var options = Options.Create(new ServiceClientManagementMutationLimiterOptions
        {
            Window = TimeSpan.FromMinutes(2),
            ActorMutationLimit = 1
        });
        var newOnlyStore = new SharedFixedWindowCounterStore();
        var oldOnlyStore = new SharedFixedWindowCounterStore();
        var rotatingStore = new SharedFixedWindowCounterStore();
        var newOnly = CreateLimiter(
            newOnlyStore,
            options,
            new PrivacyHashingOptions(newKey, AllowDevelopmentKey: false));
        var oldOnly = CreateLimiter(
            oldOnlyStore,
            options,
            new PrivacyHashingOptions(oldKey, AllowDevelopmentKey: false));
        var rotating = CreateLimiter(
            rotatingStore,
            options,
            new PrivacyHashingOptions(
                newKey,
                AllowDevelopmentKey: false,
                LegacyKeys: [oldKey, newKey, oldKey]));

        Assert.That(await newOnly.TryAcquireAsync(actor), Is.True);
        Assert.That(await oldOnly.TryAcquireAsync(actor), Is.True);
        Assert.That(await rotating.TryAcquireAsync(actor), Is.True);
        Assert.That(await rotating.TryAcquireAsync(actor), Is.False);

        Assert.Multiple(() =>
        {
            Assert.That(rotatingStore.CallKeys, Is.EqualTo(new[]
            {
                newOnlyStore.CallKeys[0],
                oldOnlyStore.CallKeys[0],
                newOnlyStore.CallKeys[0],
                oldOnlyStore.CallKeys[0]
            }));
            Assert.That(rotatingStore.Counts.Values, Has.All.EqualTo(2L));
            Assert.That(string.Join("|", rotatingStore.Keys), Does.Not.Contain(actor));
        });
    }

    [Test]
    public void Legacy_counter_failure_and_unsafe_key_rings_fail_closed()
    {
        var failure = new InvalidOperationException("Legacy management counter unavailable.");
        var failingLimiter = CreateLimiter(
            new ThrowOnCallFixedWindowCounterStore(2, failure),
            Options.Create(new ServiceClientManagementMutationLimiterOptions()),
            new PrivacyHashingOptions(
                "service-client-management-failure-current-key",
                AllowDevelopmentKey: false,
                LegacyKeys: ["service-client-management-failure-legacy-key"]));
        var tooManyLegacyKeys = Enumerable.Range(0, PrivacyHashingOptions.MaximumLegacyKeyCount + 1)
            .Select(index => $"service-client-management-legacy-key-{index:D2}")
            .ToArray();

        var thrown = Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await failingLimiter.TryAcquireAsync("actor-failure-a"));

        Assert.Multiple(() =>
        {
            Assert.That(thrown, Is.SameAs(failure));
            Assert.Throws<InvalidOperationException>(() => CreateLimiter(
                new SharedFixedWindowCounterStore(),
                Options.Create(new ServiceClientManagementMutationLimiterOptions()),
                new PrivacyHashingOptions(
                    "service-client-management-current-key",
                    AllowDevelopmentKey: false,
                    LegacyKeys: tooManyLegacyKeys)));
            Assert.Throws<InvalidOperationException>(() => CreateLimiter(
                new SharedFixedWindowCounterStore(),
                Options.Create(new ServiceClientManagementMutationLimiterOptions()),
                new PrivacyHashingOptions(
                    "service-client-management-current-key",
                    AllowDevelopmentKey: false,
                    LegacyKeys: [Sha256PrivacyHashingService.DevelopmentOnlyKey])));
        });
    }

    [Test]
    public void Invalid_actor_identifiers_are_rejected_before_distributed_state_access()
    {
        var store = new SharedFixedWindowCounterStore();
        var limiter = CreateLimiter(
            store,
            Options.Create(new ServiceClientManagementMutationLimiterOptions()));

        Assert.Multiple(() =>
        {
            Assert.ThrowsAsync<ArgumentException>(async () => await limiter.TryAcquireAsync(" actor-a"));
            Assert.ThrowsAsync<ArgumentException>(async () => await limiter.TryAcquireAsync("actor\n-a"));
            Assert.ThrowsAsync<ArgumentException>(async () => await limiter.TryAcquireAsync(
                new string('a', ServiceClientManagementMutationLimiterOptions.MaximumActorIdentityUtf8Bytes + 1)));
            Assert.That(store.IncrementCalls, Is.Zero);
        });
    }

    [Test]
    public void Invalid_counter_values_and_options_fail_closed()
    {
        var limiter = CreateLimiter(
            new ConstantFixedWindowCounterStore(0),
            Options.Create(new ServiceClientManagementMutationLimiterOptions()));

        Assert.Multiple(() =>
        {
            Assert.ThrowsAsync<InvalidOperationException>(async () => await limiter.TryAcquireAsync("actor-a"));
            Assert.Throws<OptionsValidationException>(() => CreateLimiter(
                new SharedFixedWindowCounterStore(),
                Options.Create(new ServiceClientManagementMutationLimiterOptions
                {
                    Window = TimeSpan.Zero,
                    ActorMutationLimit = 0
                })));
        });
    }

    [Test]
    public void Production_rejects_the_development_privacy_key()
    {
        Assert.Throws<InvalidOperationException>(() =>
            new DistributedServiceClientManagementMutationLimiter(
                new SharedFixedWindowCounterStore(),
                new PrivacyHashingOptions(
                    Sha256PrivacyHashingService.DevelopmentOnlyKey,
                    AllowDevelopmentKey: false),
                Options.Create(new ServiceClientManagementMutationLimiterOptions())));
    }

    [Test]
    public void Conservative_defaults_are_bounded_and_infrastructure_registers_the_distributed_limiter()
    {
        var options = new ServiceClientManagementMutationLimiterOptions();
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:HipDatabase"] = "Host=localhost;Database=hip_tests;Username=hip",
                ["ConnectionStrings:redis"] = "localhost:6379,abortConnect=false",
                ["HipInfrastructure:DatabaseProvider"] = "PostgreSQL"
            })
            .Build();

        services.AddHipApplication();
        services.AddHipInfrastructure(configuration);
        var limiterRegistrations = services
            .Where(descriptor => descriptor.ServiceType == typeof(IServiceClientManagementMutationLimiter))
            .ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(options.Window, Is.EqualTo(TimeSpan.FromMinutes(1)));
            Assert.That(options.ActorMutationLimit, Is.EqualTo(10));
            Assert.That(options.Validate(), Is.Null);
            Assert.That(limiterRegistrations, Has.Length.EqualTo(2));
            Assert.That(
                limiterRegistrations[0].ImplementationType,
                Is.EqualTo(typeof(UnavailableServiceClientManagementMutationLimiter)));
            Assert.That(
                limiterRegistrations[^1].ImplementationType,
                Is.EqualTo(typeof(DistributedServiceClientManagementMutationLimiter)));
        });
    }

    private static DistributedServiceClientManagementMutationLimiter CreateLimiter(
        IAtomicFixedWindowCounterStore store,
        IOptions<ServiceClientManagementMutationLimiterOptions> options) =>
        CreateLimiter(
            store,
            options,
            new PrivacyHashingOptions(PrivacyKey, AllowDevelopmentKey: false));

    private static DistributedServiceClientManagementMutationLimiter CreateLimiter(
        IAtomicFixedWindowCounterStore store,
        IOptions<ServiceClientManagementMutationLimiterOptions> options,
        PrivacyHashingOptions privacyHashingOptions) =>
        new(
            store,
            privacyHashingOptions,
            options);

    private sealed class SharedFixedWindowCounterStore : IAtomicFixedWindowCounterStore
    {
        private readonly Dictionary<string, long> counts = new(StringComparer.Ordinal);
        private readonly List<string> callKeys = [];
        private readonly object sync = new();
        private int incrementCalls;

        public IReadOnlyCollection<string> Keys
        {
            get
            {
                lock (sync)
                {
                    return counts.Keys.ToArray();
                }
            }
        }

        public int IncrementCalls => Volatile.Read(ref incrementCalls);

        public IReadOnlyList<string> CallKeys
        {
            get
            {
                lock (sync)
                {
                    return callKeys.ToArray();
                }
            }
        }

        public IReadOnlyDictionary<string, long> Counts
        {
            get
            {
                lock (sync)
                {
                    return new Dictionary<string, long>(counts, StringComparer.Ordinal);
                }
            }
        }

        public ValueTask<long> IncrementAsync(
            string key,
            TimeSpan window,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref incrementCalls);
            lock (sync)
            {
                callKeys.Add(key);
                counts.TryGetValue(key, out var current);
                current++;
                counts[key] = current;
                return ValueTask.FromResult(current);
            }
        }
    }

    private sealed class ThrowingFixedWindowCounterStore(Exception failure) : IAtomicFixedWindowCounterStore
    {
        public ValueTask<long> IncrementAsync(
            string key,
            TimeSpan window,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromException<long>(failure);
    }

    private sealed class ConstantFixedWindowCounterStore(long value) : IAtomicFixedWindowCounterStore
    {
        public ValueTask<long> IncrementAsync(
            string key,
            TimeSpan window,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(value);
    }

    private sealed class ThrowOnCallFixedWindowCounterStore(int failureCall, Exception failure)
        : IAtomicFixedWindowCounterStore
    {
        private int calls;

        public ValueTask<long> IncrementAsync(
            string key,
            TimeSpan window,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Interlocked.Increment(ref calls) == failureCall
                ? ValueTask.FromException<long>(failure)
                : ValueTask.FromResult(1L);
        }
    }
}
