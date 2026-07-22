using System.Text.Json;
using HIP.Application.Security;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;

namespace HIP.Tests.Security;

public sealed class HipReplayProtectionServiceTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 7, 18, 16, 0, 0, TimeSpan.Zero);

    [Test]
    public void Policy_rejects_an_unrepresentable_replay_retention_window()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            _ = new HipReplayProtectionPolicy(TimeSpan.FromTicks(1), TimeSpan.MaxValue));
    }

    [Test]
    public void Precancelled_requests_propagate_without_reserving_state()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var messageStore = new RecordingMessageStore();
        var nonceStore = new RecordingNonceStore();
        var service = CreateService(messageStore, nonceStore);

        Assert.ThrowsAsync<OperationCanceledException>(() => service.ValidateAndReserveAsync(
            Envelope(Now, Now.AddMinutes(5)),
            cancellation.Token));
        Assert.Multiple(() =>
        {
            Assert.That(messageStore.CallCount, Is.Zero);
            Assert.That(nonceStore.CallCount, Is.Zero);
        });
    }

    [Test]
    public async Task Expired_envelopes_fail_before_state_reservation()
    {
        var messageStore = new RecordingMessageStore();
        var nonceStore = new RecordingNonceStore();
        var service = CreateService(messageStore, nonceStore);

        var result = await service.ValidateAndReserveAsync(
            Envelope(Now.AddMinutes(-5), Now),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(HipReplayProtectionStatus.Expired));
            Assert.That(result.IsAccepted, Is.False);
            Assert.That(messageStore.CallCount, Is.Zero);
            Assert.That(nonceStore.CallCount, Is.Zero);
        });
    }

    [TestCase(-301)]
    [TestCase(301)]
    public async Task Issuance_outside_the_inclusive_tolerance_fails_before_reservation(int secondsFromNow)
    {
        var messageStore = new RecordingMessageStore();
        var nonceStore = new RecordingNonceStore();
        var service = CreateService(messageStore, nonceStore);
        var issuedAt = Now.AddSeconds(secondsFromNow);
        var expiresAt = secondsFromNow < 0 ? Now.AddMinutes(1) : issuedAt.AddMinutes(1);

        var result = await service.ValidateAndReserveAsync(
            Envelope(issuedAt, expiresAt),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(HipReplayProtectionStatus.TimestampOutsideTolerance));
            Assert.That(messageStore.CallCount, Is.Zero);
            Assert.That(nonceStore.CallCount, Is.Zero);
        });
    }

    [TestCase(-300)]
    [TestCase(300)]
    public async Task Issuance_at_the_tolerance_boundary_is_accepted(int secondsFromNow)
    {
        var service = CreateService(
            policy: new HipReplayProtectionPolicy(
                TimeSpan.FromMinutes(5),
                TimeSpan.FromMinutes(10)));
        var issuedAt = Now.AddSeconds(secondsFromNow);
        var expiresAt = secondsFromNow < 0 ? Now.AddMinutes(1) : issuedAt.AddMinutes(1);

        var result = await service.ValidateAndReserveAsync(
            Envelope(issuedAt, expiresAt),
            CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(HipReplayProtectionStatus.Accepted));
    }

    [Test]
    public async Task Validity_window_above_policy_fails_before_reservation()
    {
        var messageStore = new RecordingMessageStore();
        var nonceStore = new RecordingNonceStore();
        var service = CreateService(messageStore, nonceStore);

        var result = await service.ValidateAndReserveAsync(
            Envelope(Now, Now.AddMinutes(5).AddMilliseconds(1)),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(HipReplayProtectionStatus.ValidityWindowExceeded));
            Assert.That(messageStore.CallCount, Is.Zero);
            Assert.That(nonceStore.CallCount, Is.Zero);
        });
    }

    [Test]
    public async Task Duplicate_message_id_stops_before_nonce_reservation()
    {
        var messageStore = new RecordingMessageStore(result: false);
        var nonceStore = new RecordingNonceStore();
        var service = CreateService(messageStore, nonceStore);

        var result = await service.ValidateAndReserveAsync(
            Envelope(Now, Now.AddMinutes(5)),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(HipReplayProtectionStatus.DuplicateMessageId));
            Assert.That(messageStore.CallCount, Is.EqualTo(1));
            Assert.That(nonceStore.CallCount, Is.Zero);
        });
    }

    [Test]
    public async Task Duplicate_nonce_is_typed_after_message_reservation()
    {
        var messageStore = new RecordingMessageStore();
        var nonceStore = new RecordingNonceStore(result: false);
        var service = CreateService(messageStore, nonceStore);

        var result = await service.ValidateAndReserveAsync(
            Envelope(Now, Now.AddMinutes(5)),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(HipReplayProtectionStatus.DuplicateNonce));
            Assert.That(messageStore.CallCount, Is.EqualTo(1));
            Assert.That(nonceStore.CallCount, Is.EqualTo(1));
        });
    }

    [TestCase(true)]
    [TestCase(false)]
    public async Task State_store_failures_return_fail_closed_status(bool failMessageStore)
    {
        var messageStore = new RecordingMessageStore(throwOnCall: failMessageStore);
        var nonceStore = new RecordingNonceStore(throwOnCall: !failMessageStore);
        var service = CreateService(messageStore, nonceStore);

        var result = await service.ValidateAndReserveAsync(
            Envelope(Now, Now.AddMinutes(5)),
            CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(HipReplayProtectionStatus.StateUnavailable));
    }

    [Test]
    public async Task Accepted_reservations_use_issuer_scope_and_complete_cross_node_retention_window()
    {
        var messageStore = new RecordingMessageStore();
        var nonceStore = new RecordingNonceStore();
        var service = CreateService(messageStore, nonceStore);

        var result = await service.ValidateAndReserveAsync(
            Envelope(Now.AddMinutes(-1), Now.AddMinutes(4)),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsAccepted, Is.True);
            Assert.That(messageStore.Issuer, Is.EqualTo("hip:domain:issuer.example"));
            Assert.That(messageStore.Identifier, Is.EqualTo("message-1"));
            Assert.That(messageStore.ValidityWindow, Is.EqualTo(TimeSpan.FromMinutes(10)));
            Assert.That(nonceStore.Issuer, Is.EqualTo("hip:domain:issuer.example"));
            Assert.That(nonceStore.Identifier, Is.EqualTo("AAECAwQFBgcICQoLDA0ODw"));
            Assert.That(nonceStore.ValidityWindow, Is.EqualTo(TimeSpan.FromMinutes(10)));
        });
    }

    [Test]
    public async Task Shared_replay_state_outlives_clock_skew_between_accepting_nodes()
    {
        var stateClock = new ManualTimeProvider(Now);
        var fastClock = new ManualTimeProvider(Now.AddMinutes(4).AddSeconds(59));
        var slowClock = new ManualTimeProvider(Now.AddMinutes(-4).AddSeconds(-59));
        var messageStore = new InMemoryReplayMessageIdStore(stateClock);
        var nonceStore = new InMemoryReplayNonceStore(stateClock);
        var policy = new HipReplayProtectionPolicy(TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
        var fastNode = CreateService(messageStore, nonceStore, policy, fastClock);
        var slowNode = CreateService(messageStore, nonceStore, policy, slowClock);
        var envelope = Envelope(Now, Now.AddMinutes(5));

        var first = await fastNode.ValidateAndReserveAsync(envelope, CancellationToken.None);
        stateClock.Advance(TimeSpan.FromSeconds(2));
        slowClock.Advance(TimeSpan.FromSeconds(2));
        var replay = await slowNode.ValidateAndReserveAsync(envelope, CancellationToken.None);

        Assert.That(first.Status, Is.EqualTo(HipReplayProtectionStatus.Accepted));
        Assert.That(replay.Status, Is.EqualTo(HipReplayProtectionStatus.DuplicateMessageId));
    }

    [Test]
    public async Task Envelope_that_expires_during_state_reservation_is_not_accepted()
    {
        var clock = new ManualTimeProvider(Now);
        var messageStore = new RecordingMessageStore();
        var nonceStore = new AdvancingNonceStore(clock, TimeSpan.FromSeconds(2));
        var service = CreateService(messageStore, nonceStore, timeProvider: clock);

        var result = await service.ValidateAndReserveAsync(
            Envelope(Now, Now.AddSeconds(1)),
            CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(HipReplayProtectionStatus.Expired));
        Assert.That(messageStore.CallCount, Is.EqualTo(1));
        Assert.That(nonceStore.CallCount, Is.EqualTo(1));
    }

    [Test]
    public async Task Message_identifiers_are_case_sensitive_and_issuer_scoped()
    {
        var clock = new ManualTimeProvider(Now);
        var store = new InMemoryReplayMessageIdStore(clock);

        var first = await store.TryReserveAsync("issuer-a", "Message-A", TimeSpan.FromMinutes(1));
        var duplicate = await store.TryReserveAsync("issuer-a", "Message-A", TimeSpan.FromMinutes(1));
        var differentCase = await store.TryReserveAsync("issuer-a", "message-a", TimeSpan.FromMinutes(1));
        var differentIssuer = await store.TryReserveAsync("issuer-b", "Message-A", TimeSpan.FromMinutes(1));

        Assert.That(new[] { first, duplicate, differentCase, differentIssuer },
            Is.EqualTo(new[] { true, false, true, true }));
    }

    private static HipReplayProtectionService CreateService(
        IReplayMessageIdStore? messageStore = null,
        IReplayNonceStore? nonceStore = null,
        HipReplayProtectionPolicy? policy = null,
        TimeProvider? timeProvider = null) =>
        new(
            messageStore ?? new RecordingMessageStore(),
            nonceStore ?? new RecordingNonceStore(),
            policy ?? HipReplayProtectionPolicy.Default,
            timeProvider ?? new ManualTimeProvider(Now));

    private static HipProtocolEnvelope Envelope(DateTimeOffset issuedAt, DateTimeOffset expiresAt) =>
        new(
            HipProtocolVersion.Current,
            "message-1",
            "AAECAwQFBgcICQoLDA0ODw",
            new HipProtocolIssuer("hip:domain:issuer.example"),
            new HipProtocolSubject(IdentitySubjectType.Website, "example.com"),
            HipContentDigest.FromPrefixedString($"sha256:{new string('a', 64)}"),
            new HipProtocolClaims(new Dictionary<string, JsonElement>
            {
                ["source"] = JsonDocument.Parse("\"test\"").RootElement.Clone()
            }),
            new HipProtocolSignature(
                HipProtocolSignature.OriginAndIntegrityScope,
                "key-1",
                "algorithm",
                SignatureAlgorithmFamily.Unknown,
                HipProtocolSignature.Rfc8785Canonicalization,
                "signature"),
            issuedAt,
            expiresAt);

    private sealed class RecordingMessageStore(
        bool result = true,
        bool throwOnCall = false) : IReplayMessageIdStore
    {
        public int CallCount { get; private set; }
        public string? Issuer { get; private set; }
        public string? Identifier { get; private set; }
        public TimeSpan? ValidityWindow { get; private set; }

        public ValueTask<bool> TryReserveAsync(
            string issuer,
            string messageId,
            TimeSpan validityWindow,
            CancellationToken cancellationToken = default)
        {
            CallCount++;
            Issuer = issuer;
            Identifier = messageId;
            ValidityWindow = validityWindow;
            if (throwOnCall)
            {
                throw new InvalidOperationException("Replay message state unavailable.");
            }

            return ValueTask.FromResult(result);
        }
    }

    private sealed class RecordingNonceStore(
        bool result = true,
        bool throwOnCall = false) : IReplayNonceStore
    {
        public int CallCount { get; private set; }
        public string? Issuer { get; private set; }
        public string? Identifier { get; private set; }
        public TimeSpan? ValidityWindow { get; private set; }

        public ValueTask<bool> TryReserveAsync(
            string issuer,
            string nonce,
            TimeSpan validityWindow,
            CancellationToken cancellationToken = default)
        {
            CallCount++;
            Issuer = issuer;
            Identifier = nonce;
            ValidityWindow = validityWindow;
            if (throwOnCall)
            {
                throw new InvalidOperationException("Replay nonce state unavailable.");
            }

            return ValueTask.FromResult(result);
        }
    }

    private sealed class AdvancingNonceStore(
        ManualTimeProvider clock,
        TimeSpan delay) : IReplayNonceStore
    {
        public int CallCount { get; private set; }

        public ValueTask<bool> TryReserveAsync(
            string issuer,
            string nonce,
            TimeSpan validityWindow,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            clock.Advance(delay);
            return ValueTask.FromResult(true);
        }
    }

    private sealed class ManualTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset current = now;

        public override DateTimeOffset GetUtcNow() => current;

        public void Advance(TimeSpan elapsed) => current = current.Add(elapsed);
    }
}
