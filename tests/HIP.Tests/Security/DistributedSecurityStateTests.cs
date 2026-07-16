using HIP.Application.Security;
using HIP.Infrastructure.Security;

namespace HIP.Tests.Security;

public sealed class DistributedSecurityStateTests
{
    [Test]
    public async Task Duplicate_guard_accepts_exactly_one_concurrent_submission_across_instances()
    {
        var store = new TestAtomicExpiryStore();
        var firstInstance = new RedisDuplicateSubmissionGuard(store);
        var secondInstance = new RedisDuplicateSubmissionGuard(store);

        var attempts = Enumerable.Range(0, 100)
            .Select(index => (index & 1) == 0 ? firstInstance : secondInstance)
            .Select(guard => guard.TryAcceptAsync(
                "public-feedback",
                ["domain", "vote"],
                TimeSpan.FromMinutes(1)).AsTask());

        var results = await Task.WhenAll(attempts);

        Assert.That(results.Count(accepted => accepted), Is.EqualTo(1));
    }

    [Test]
    public async Task Replay_nonce_is_rejected_across_instances_until_expiry()
    {
        var timeProvider = new ManualTimeProvider();
        var store = new TestAtomicExpiryStore(timeProvider);
        var firstInstance = new RedisReplayNonceStore(store);
        var secondInstance = new RedisReplayNonceStore(store);

        var first = await firstInstance.TryReserveAsync(
            "issuer-1",
            "nonce-1",
            TimeSpan.FromMinutes(5));
        var replay = await secondInstance.TryReserveAsync(
            "issuer-1",
            "nonce-1",
            TimeSpan.FromMinutes(5));
        timeProvider.Advance(TimeSpan.FromMinutes(5));
        var afterExpiry = await secondInstance.TryReserveAsync(
            "issuer-1",
            "nonce-1",
            TimeSpan.FromMinutes(5));

        Assert.Multiple(() =>
        {
            Assert.That(first, Is.True);
            Assert.That(replay, Is.False);
            Assert.That(afterExpiry, Is.True);
        });
    }

    [Test]
    public async Task Replay_nonce_values_remain_case_sensitive()
    {
        var store = new TestAtomicExpiryStore();
        var nonceStore = new RedisReplayNonceStore(store);

        var first = await nonceStore.TryReserveAsync("issuer-1", "Nonce-A", TimeSpan.FromMinutes(5));
        var differentCase = await nonceStore.TryReserveAsync("issuer-1", "nonce-a", TimeSpan.FromMinutes(5));

        Assert.Multiple(() =>
        {
            Assert.That(first, Is.True);
            Assert.That(differentCase, Is.True);
        });
    }

    [Test]
    public void Fingerprints_are_unambiguous_when_untrusted_parts_contain_delimiters()
    {
        var first = SecurityStateKey.Fingerprint("duplicate", "scope", ["a|b", "c"]);
        var second = SecurityStateKey.Fingerprint("duplicate", "scope", ["a", "b|c"]);

        Assert.That(first, Is.Not.EqualTo(second));
    }

    [Test]
    public void Distributed_state_failure_is_not_replaced_with_process_local_acceptance()
    {
        var guard = new RedisDuplicateSubmissionGuard(new ThrowingAtomicExpiryStore());

        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await guard.TryAcceptAsync("public-feedback", ["domain"], TimeSpan.FromMinutes(1)));
    }

    [Test]
    public void Redis_atomic_store_uses_create_if_absent_with_expiry()
    {
        var root = RepositoryRoot();
        var source = File.ReadAllText(Path.Combine(
            root,
            "src",
            "HIP.Infrastructure",
            "Security",
            "RedisAtomicExpiryStore.cs"));

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Contain("StringSetAsync"));
            Assert.That(source, Does.Contain("expiry: timeToLive"));
            Assert.That(source, Does.Contain("when: When.NotExists"));
        });
    }

    private sealed class TestAtomicExpiryStore(TimeProvider? timeProvider = null) : IAtomicExpiryStore
    {
        private readonly Dictionary<string, DateTimeOffset> entries = new(StringComparer.Ordinal);
        private readonly object sync = new();
        private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

        public ValueTask<bool> TryCreateAsync(
            string key,
            TimeSpan timeToLive,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (sync)
            {
                var now = clock.GetUtcNow();
                if (entries.TryGetValue(key, out var expiresAt) && expiresAt > now)
                {
                    return ValueTask.FromResult(false);
                }

                entries[key] = now.Add(timeToLive);
                return ValueTask.FromResult(true);
            }
        }
    }

    private sealed class ThrowingAtomicExpiryStore : IAtomicExpiryStore
    {
        public ValueTask<bool> TryCreateAsync(
            string key,
            TimeSpan timeToLive,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromException<bool>(new InvalidOperationException("Distributed state unavailable."));
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset utcNow = new(2026, 7, 16, 0, 0, 0, TimeSpan.Zero);

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
