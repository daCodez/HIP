using HIP.Application.Reporting;
using HIP.Application.ServiceClients;
using HIP.Infrastructure;
using HIP.Infrastructure.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace HIP.Tests.ServiceClients;

[TestFixture]
public sealed class ServiceClientAuthenticationAttemptLimiterTests
{
    private const string PrivacyKey = "test-service-client-attempt-limiter-privacy-key";
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);

    [Test]
    public async Task Shared_instances_allow_the_exact_client_boundary_then_reject()
    {
        var store = new SharedFixedWindowCounterStore();
        var options = Options.Create(new ServiceClientAuthenticationAttemptLimiterOptions
        {
            Window = Window,
            SourceAttemptLimit = 10,
            SourceAndClientAttemptLimit = 2
        });
        var firstInstance = CreateLimiter(store, options);
        var secondInstance = CreateLimiter(store, options);

        var first = await firstInstance.TryAcquireAsync("203.0.113.11", "hipc_v1_client-a");
        var second = await secondInstance.TryAcquireAsync("203.0.113.11", "hipc_v1_client-a");
        var rejected = await firstInstance.TryAcquireAsync("203.0.113.11", "hipc_v1_client-a");

        Assert.That(new[] { first, second, rejected }, Is.EqualTo(new[] { true, true, false }));
    }

    [Test]
    public async Task Rotating_apparent_client_ids_cannot_bypass_the_source_ceiling()
    {
        var store = new SharedFixedWindowCounterStore();
        var options = Options.Create(new ServiceClientAuthenticationAttemptLimiterOptions
        {
            Window = Window,
            SourceAttemptLimit = 3,
            SourceAndClientAttemptLimit = 3
        });
        var firstInstance = CreateLimiter(store, options);
        var secondInstance = CreateLimiter(store, options);

        var results = new[]
        {
            await firstInstance.TryAcquireAsync("203.0.113.12", "hipc_v1_client-a"),
            await secondInstance.TryAcquireAsync("203.0.113.12", "hipc_v1_client-b"),
            await firstInstance.TryAcquireAsync("203.0.113.12", "hipc_v1_client-c"),
            await secondInstance.TryAcquireAsync("203.0.113.12", "hipc_v1_client-d")
        };

        Assert.That(results, Is.EqualTo(new[] { true, true, true, false }));
    }

    [Test]
    public async Task Apparent_client_budgets_are_partitioned_within_one_source_budget()
    {
        var store = new SharedFixedWindowCounterStore();
        var options = Options.Create(new ServiceClientAuthenticationAttemptLimiterOptions
        {
            Window = Window,
            SourceAttemptLimit = 10,
            SourceAndClientAttemptLimit = 1
        });
        var limiter = CreateLimiter(store, options);

        var firstClient = await limiter.TryAcquireAsync("203.0.113.13", "hipc_v1_client-a");
        var repeatedClient = await limiter.TryAcquireAsync("203.0.113.13", "hipc_v1_client-a");
        var secondClient = await limiter.TryAcquireAsync("203.0.113.13", "hipc_v1_client-b");

        Assert.That(new[] { firstClient, repeatedClient, secondClient },
            Is.EqualTo(new[] { true, false, true }));
    }

    [Test]
    public async Task First_increment_ttl_starts_a_new_window_after_expiry_without_wall_clock_alignment()
    {
        var clock = new ManualTimeProvider();
        var store = new SharedFixedWindowCounterStore(clock);
        var limiter = CreateLimiter(
            store,
            Options.Create(new ServiceClientAuthenticationAttemptLimiterOptions
            {
                Window = Window,
                SourceAttemptLimit = 1,
                SourceAndClientAttemptLimit = 1
            }));

        Assert.That(await limiter.TryAcquireAsync("203.0.113.14", "hipc_v1_client-a"), Is.True);
        clock.Advance(Window.Subtract(TimeSpan.FromMilliseconds(1)));
        Assert.That(await limiter.TryAcquireAsync("203.0.113.14", "hipc_v1_client-a"), Is.False);
        clock.Advance(TimeSpan.FromMilliseconds(1));
        Assert.That(await limiter.TryAcquireAsync("203.0.113.14", "hipc_v1_client-a"), Is.True);
    }

    [Test]
    public async Task Stored_keys_are_domain_separated_hmacs_and_never_expose_raw_identities()
    {
        const string source = "198.51.100.42";
        const string clientId = "hipc_v1_sensitive-client";
        var store = new SharedFixedWindowCounterStore();
        var limiter = CreateLimiter(store, Options.Create(ValidOptions()));

        Assert.That(await limiter.TryAcquireAsync(source, clientId), Is.True);

        Assert.Multiple(() =>
        {
            Assert.That(store.Keys, Has.Count.EqualTo(2));
            Assert.That(store.Keys, Has.All.Matches("^hip:v1:service-client-auth:(source|source-client):[0-9a-f]{64}$"));
            Assert.That(store.Keys.Any(key => key.Contains(source, StringComparison.Ordinal)), Is.False);
            Assert.That(store.Keys.Any(key => key.Contains(clientId, StringComparison.Ordinal)), Is.False);
            Assert.That(store.Keys, Is.Unique);
        });
    }

    [Test]
    public async Task Exact_identity_casing_produces_distinct_privacy_safe_partitions()
    {
        var store = new SharedFixedWindowCounterStore();
        var limiter = CreateLimiter(store, Options.Create(ValidOptions()));

        Assert.That(await limiter.TryAcquireAsync("SOURCE-A", "hipc_v1_Client-A"), Is.True);
        Assert.That(await limiter.TryAcquireAsync("source-a", "hipc_v1_client-a"), Is.True);

        Assert.That(store.Keys, Has.Count.EqualTo(4));
    }

    [Test]
    public async Task Rolling_privacy_key_rotation_shares_the_legacy_budget_with_old_instances()
    {
        const string oldKey = "service-client-auth-limiter-old-key";
        const string newKey = "service-client-auth-limiter-new-key";
        var store = new SharedFixedWindowCounterStore();
        var options = Options.Create(new ServiceClientAuthenticationAttemptLimiterOptions
        {
            Window = Window,
            SourceAttemptLimit = 20,
            SourceAndClientAttemptLimit = 2
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

        var oldAttempt = await oldInstance.TryAcquireAsync("203.0.113.191", "hipc_v1_client-a");
        var rotatingAttempt = await rotatingInstance.TryAcquireAsync("203.0.113.191", "hipc_v1_client-a");
        var rejectedByOldInstance = await oldInstance.TryAcquireAsync(
            "203.0.113.191",
            "hipc_v1_client-a");

        Assert.Multiple(() =>
        {
            Assert.That(oldAttempt, Is.True);
            Assert.That(rotatingAttempt, Is.True);
            Assert.That(rejectedByOldInstance, Is.False);
            Assert.That(store.Keys, Has.Count.EqualTo(4));
            Assert.That(store.IncrementCalls, Is.EqualTo(8));
        });
    }

    [Test]
    public async Task Rotation_candidates_are_current_first_exact_deduplicated_and_privacy_safe()
    {
        const string oldKey = "service-client-auth-limiter-order-old-key";
        const string newKey = "service-client-auth-limiter-order-new-key";
        const string source = "203.0.113.192";
        const string clientId = "hipc_v1_sensitive-rotation-client";
        var options = Options.Create(ValidOptions());
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

        Assert.That(await newOnly.TryAcquireAsync(source, clientId), Is.True);
        Assert.That(await oldOnly.TryAcquireAsync(source, clientId), Is.True);
        Assert.That(await rotating.TryAcquireAsync(source, clientId), Is.True);

        Assert.Multiple(() =>
        {
            Assert.That(rotatingStore.CallKeys, Is.EqualTo(new[]
            {
                newOnlyStore.CallKeys[0],
                oldOnlyStore.CallKeys[0],
                newOnlyStore.CallKeys[1],
                oldOnlyStore.CallKeys[1]
            }));
            Assert.That(rotatingStore.Keys, Has.Count.EqualTo(4));
            Assert.That(string.Join("|", rotatingStore.Keys), Does.Not.Contain(source));
            Assert.That(string.Join("|", rotatingStore.Keys), Does.Not.Contain(clientId));
        });
    }

    [Test]
    public async Task Rejected_attempt_still_counts_every_rotation_candidate_before_returning()
    {
        var store = new SharedFixedWindowCounterStore();
        var limiter = CreateLimiter(
            store,
            Options.Create(new ServiceClientAuthenticationAttemptLimiterOptions
            {
                Window = Window,
                SourceAttemptLimit = 10,
                SourceAndClientAttemptLimit = 1
            }),
            new PrivacyHashingOptions(
                "service-client-auth-limiter-reject-current-key",
                AllowDevelopmentKey: false,
                LegacyKeys: ["service-client-auth-limiter-reject-legacy-key"]));

        Assert.That(await limiter.TryAcquireAsync("203.0.113.193", "hipc_v1_client-a"), Is.True);
        Assert.That(await limiter.TryAcquireAsync("203.0.113.193", "hipc_v1_client-a"), Is.False);

        Assert.Multiple(() =>
        {
            Assert.That(store.IncrementCalls, Is.EqualTo(8));
            Assert.That(store.Counts.Values, Has.All.EqualTo(2L));
        });
    }

    [Test]
    public void Legacy_counter_failure_and_unsafe_key_rings_fail_closed()
    {
        var failure = new InvalidOperationException("Legacy counter unavailable.");
        var failingLimiter = CreateLimiter(
            new ThrowOnCallFixedWindowCounterStore(2, failure),
            Options.Create(ValidOptions()),
            new PrivacyHashingOptions(
                "service-client-auth-limiter-failure-current-key",
                AllowDevelopmentKey: false,
                LegacyKeys: ["service-client-auth-limiter-failure-legacy-key"]));
        var tooManyLegacyKeys = Enumerable.Range(0, PrivacyHashingOptions.MaximumLegacyKeyCount + 1)
            .Select(index => $"service-client-auth-limiter-legacy-key-{index:D2}")
            .ToArray();

        var thrown = Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await failingLimiter.TryAcquireAsync("203.0.113.194", "hipc_v1_client-a"));

        Assert.Multiple(() =>
        {
            Assert.That(thrown, Is.SameAs(failure));
            Assert.Throws<InvalidOperationException>(() => CreateLimiter(
                new SharedFixedWindowCounterStore(),
                Options.Create(ValidOptions()),
                new PrivacyHashingOptions(
                    "service-client-auth-limiter-current-key",
                    AllowDevelopmentKey: false,
                    LegacyKeys: tooManyLegacyKeys)));
            Assert.Throws<InvalidOperationException>(() => CreateLimiter(
                new SharedFixedWindowCounterStore(),
                Options.Create(ValidOptions()),
                new PrivacyHashingOptions(
                    "service-client-auth-limiter-current-key",
                    AllowDevelopmentKey: false,
                    LegacyKeys: [Sha256PrivacyHashingService.DevelopmentOnlyKey])));
        });
    }

    [TestCase(null, "hipc_v1_client-a")]
    [TestCase("", "hipc_v1_client-a")]
    [TestCase(" ", "hipc_v1_client-a")]
    [TestCase("203.0.113.15\n", "hipc_v1_client-a")]
    [TestCase("203.0.113.15", null)]
    [TestCase("203.0.113.15", "")]
    [TestCase("203.0.113.15", " ")]
    [TestCase("203.0.113.15", "hipc_v1_client-a\t")]
    public void Invalid_identities_are_rejected_before_distributed_state_access(
        string? source,
        string? apparentClientId)
    {
        var store = new SharedFixedWindowCounterStore();
        var limiter = CreateLimiter(store, Options.Create(ValidOptions()));

        Assert.That(
            async () => await limiter.TryAcquireAsync(source!, apparentClientId!),
            Throws.InstanceOf<ArgumentException>());
        Assert.That(store.IncrementCalls, Is.Zero);
    }

    [Test]
    public void Overlong_identities_are_rejected_before_distributed_state_access()
    {
        var store = new SharedFixedWindowCounterStore();
        var limiter = CreateLimiter(store, Options.Create(ValidOptions()));

        Assert.Multiple(() =>
        {
            Assert.ThrowsAsync<ArgumentException>(async () =>
                await limiter.TryAcquireAsync(
                    new string('s', ServiceClientAuthenticationAttemptLimiterOptions.MaximumSourceIdentityUtf8Bytes + 1),
                    "hipc_v1_client-a"));
            Assert.ThrowsAsync<ArgumentException>(async () =>
                await limiter.TryAcquireAsync(
                    "203.0.113.16",
                    new string('c', ServiceClientAuthenticationAttemptLimiterOptions.MaximumApparentClientIdUtf8Bytes + 1)));
        });
        Assert.That(store.IncrementCalls, Is.Zero);
    }

    [Test]
    public void Invalid_options_are_rejected_before_distributed_state_access()
    {
        var store = new SharedFixedWindowCounterStore();
        var invalidOptions = new[]
        {
            new ServiceClientAuthenticationAttemptLimiterOptions
            {
                Window = TimeSpan.Zero,
                SourceAttemptLimit = 10,
                SourceAndClientAttemptLimit = 2
            },
            new ServiceClientAuthenticationAttemptLimiterOptions
            {
                Window = Window,
                SourceAttemptLimit = 0,
                SourceAndClientAttemptLimit = 1
            },
            new ServiceClientAuthenticationAttemptLimiterOptions
            {
                Window = Window,
                SourceAttemptLimit = 2,
                SourceAndClientAttemptLimit = 3
            }
        };

        foreach (var candidate in invalidOptions)
        {
            Assert.Throws<OptionsValidationException>(() =>
                CreateLimiter(store, Options.Create(candidate)));
        }

        Assert.That(store.IncrementCalls, Is.Zero);
    }

    [Test]
    public void Development_privacy_key_is_rejected_when_the_host_disallows_it()
    {
        var store = new SharedFixedWindowCounterStore();

        Assert.Throws<InvalidOperationException>(() =>
            new DistributedServiceClientAuthenticationAttemptLimiter(
                store,
                new PrivacyHashingOptions(
                    Sha256PrivacyHashingService.DevelopmentOnlyKey,
                    AllowDevelopmentKey: false),
                Options.Create(ValidOptions())));
        Assert.That(store.IncrementCalls, Is.Zero);
    }

    [Test]
    public void Caller_cancellation_is_propagated_before_distributed_state_access()
    {
        var store = new SharedFixedWindowCounterStore();
        var limiter = CreateLimiter(store, Options.Create(ValidOptions()));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await limiter.TryAcquireAsync(
                "203.0.113.17",
                "hipc_v1_client-a",
                cancellation.Token));
        Assert.That(store.IncrementCalls, Is.Zero);
    }

    [Test]
    public async Task Caller_cancellation_interrupts_distributed_state_access()
    {
        var store = new BlockingFixedWindowCounterStore();
        var limiter = CreateLimiter(store, Options.Create(ValidOptions()));
        using var cancellation = new CancellationTokenSource();

        var attempt = limiter.TryAcquireAsync(
            "203.0.113.171",
            "hipc_v1_client-a",
            cancellation.Token).AsTask();
        await store.Entered.WaitAsync(TimeSpan.FromSeconds(2));
        cancellation.Cancel();

        Assert.That(
            async () => await attempt,
            Throws.InstanceOf<OperationCanceledException>());
    }

    [Test]
    public void Distributed_backend_failure_is_propagated_without_process_local_fallback()
    {
        var failure = new InvalidOperationException("Distributed authentication limiter unavailable.");
        var store = new ThrowingFixedWindowCounterStore(failure);
        var limiter = CreateLimiter(store, Options.Create(ValidOptions()));

        var thrown = Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await limiter.TryAcquireAsync("203.0.113.18", "hipc_v1_client-a"));

        Assert.That(thrown, Is.SameAs(failure));
    }

    [Test]
    public void Redis_counter_uses_one_atomic_increment_and_first_expiry_script()
    {
        var source = File.ReadAllText(Path.Combine(
            RepositoryRoot(),
            "src",
            "HIP.Infrastructure",
            "Security",
            "RedisAtomicFixedWindowCounterStore.cs"));

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Contain("redis.call('INCR', KEYS[1])"));
            Assert.That(source, Does.Contain("if current == 1 then"));
            Assert.That(source, Does.Contain("redis.call('PEXPIRE', KEYS[1], ARGV[1])"));
            Assert.That(source, Does.Contain("ScriptEvaluateAsync"));
            Assert.That(source, Does.Contain("WaitAsync(cancellationToken)"));
            Assert.That(source, Does.Not.Contain("StringIncrementAsync"));
            Assert.That(source, Does.Not.Contain("KeyExpireAsync"));
            Assert.That(source, Does.Not.Contain("TimeProvider"));
            Assert.That(source, Does.Not.Contain("DateTime"));
        });
    }

    [Test]
    public void Infrastructure_registers_distributed_service_client_attempt_limiting()
    {
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:HipDatabase"] = "Host=localhost;Database=hip_tests;Username=hip",
                ["ConnectionStrings:redis"] = "localhost:6379,abortConnect=false",
                ["HipInfrastructure:DatabaseProvider"] = "PostgreSQL"
            })
            .Build();

        services.AddHipInfrastructure(configuration);

        Assert.Multiple(() =>
        {
            Assert.That(
                services.Single(descriptor => descriptor.ServiceType == typeof(IAtomicFixedWindowCounterStore)).ImplementationType,
                Is.EqualTo(typeof(RedisAtomicFixedWindowCounterStore)));
            Assert.That(
                services.Single(descriptor => descriptor.ServiceType == typeof(IServiceClientAuthenticationAttemptLimiter)).ImplementationType,
                Is.EqualTo(typeof(DistributedServiceClientAuthenticationAttemptLimiter)));
        });
    }

    [Test]
    public void Conservative_defaults_are_bounded_and_valid()
    {
        var options = new ServiceClientAuthenticationAttemptLimiterOptions();

        Assert.Multiple(() =>
        {
            Assert.That(options.Window, Is.EqualTo(TimeSpan.FromMinutes(1)));
            Assert.That(options.SourceAttemptLimit, Is.EqualTo(120));
            Assert.That(options.SourceAndClientAttemptLimit, Is.EqualTo(30));
            Assert.That(options.Validate(), Is.Null);
        });
    }

    private static DistributedServiceClientAuthenticationAttemptLimiter CreateLimiter(
        IAtomicFixedWindowCounterStore store,
        IOptions<ServiceClientAuthenticationAttemptLimiterOptions> options) =>
        CreateLimiter(
            store,
            options,
            new PrivacyHashingOptions(PrivacyKey, AllowDevelopmentKey: false));

    private static DistributedServiceClientAuthenticationAttemptLimiter CreateLimiter(
        IAtomicFixedWindowCounterStore store,
        IOptions<ServiceClientAuthenticationAttemptLimiterOptions> options,
        PrivacyHashingOptions privacyHashingOptions) =>
        new(
            store,
            privacyHashingOptions,
            options);

    private static ServiceClientAuthenticationAttemptLimiterOptions ValidOptions() =>
        new()
        {
            Window = Window,
            SourceAttemptLimit = 20,
            SourceAndClientAttemptLimit = 5
        };

    private sealed class SharedFixedWindowCounterStore(TimeProvider? timeProvider = null)
        : IAtomicFixedWindowCounterStore
    {
        private readonly Dictionary<string, CounterEntry> counters = new(StringComparer.Ordinal);
        private readonly object sync = new();
        private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

        public int IncrementCalls { get; private set; }

        public IReadOnlyCollection<string> Keys
        {
            get
            {
                lock (sync)
                {
                    return counters.Keys.ToArray();
                }
            }
        }

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
                    return counters.ToDictionary(
                        pair => pair.Key,
                        pair => pair.Value.Count,
                        StringComparer.Ordinal);
                }
            }
        }

        public ValueTask<long> IncrementAsync(
            string key,
            TimeSpan window,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (sync)
            {
                IncrementCalls++;
                callKeys.Add(key);
                var now = clock.GetUtcNow();
                if (!counters.TryGetValue(key, out var current) || current.ExpiresAt <= now)
                {
                    counters[key] = new CounterEntry(1, now.Add(window));
                    return ValueTask.FromResult(1L);
                }

                var next = current with { Count = current.Count + 1 };
                counters[key] = next;
                return ValueTask.FromResult(next.Count);
            }
        }

        private sealed record CounterEntry(long Count, DateTimeOffset ExpiresAt);

        private readonly List<string> callKeys = [];
    }

    private sealed class ThrowingFixedWindowCounterStore(Exception failure)
        : IAtomicFixedWindowCounterStore
    {
        public ValueTask<long> IncrementAsync(
            string key,
            TimeSpan window,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromException<long>(failure);
    }

    private sealed class BlockingFixedWindowCounterStore : IAtomicFixedWindowCounterStore
    {
        private readonly TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task Entered => entered.Task;

        public async ValueTask<long> IncrementAsync(
            string key,
            TimeSpan window,
            CancellationToken cancellationToken = default)
        {
            entered.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 1;
        }
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

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset utcNow = new(2026, 7, 20, 0, 0, 37, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => utcNow;

        public void Advance(TimeSpan duration) => utcNow = utcNow.Add(duration);
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate repository root.");
    }
}
