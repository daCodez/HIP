using HIP.Protocol.Canonicalization;
using HIP.Protocol.Contracts;
using HIP.Protocol.Security.Abstractions;
using HIP.Protocol.Security.Options;
using HIP.Protocol.Security.Services;
using HIP.Protocol.Validation;

namespace HIP.Protocol.Benchmarks.Data;

public sealed class DeterministicInputs
{
    private readonly object _nonceLock = new();
    private readonly Dictionary<int, string> _payloadCache = new();
    private long _nonceCounter = 1000;

    public HipCanonicalSerializer Canonical { get; } = new();
    public Sha256PayloadHasher Hasher { get; } = new();
    public HmacHipSigner HmacSigner { get; }
    public HipReceiptSecurityService ReceiptService { get; }
    public HipChallengeService ChallengeService { get; }

    public DateTimeOffset FixedUtc { get; } = new(2026, 3, 6, 21, 0, 0, TimeSpan.Zero);

    public DeterministicInputs()
    {
        HmacSigner = new HmacHipSigner(new Dictionary<string, string>
        {
            ["key-sender"] = "sender-secret-123",
            ["key-receiver"] = "receiver-secret-456",
            ["hip-http-verifier"] = "verifier-secret-456"
        });

        ReceiptService = new HipReceiptSecurityService(Canonical, new HipReceiptValidator(), HmacSigner, HmacSigner);
        ChallengeService = new HipChallengeService(HmacSigner, HmacSigner);
    }

    public HipEnvelopeSecurityService BuildEnvelopeService(bool replayEnabled, bool includeBinaryVersion = false)
    {
        IHipReplayGuard replay = replayEnabled
            ? new InMemoryReplayGuard(new HipSecurityOptions { AllowedClockSkewSeconds = 300, ReplayWindowSeconds = 600 })
            : new ReplayDisabledGuard();

        var versions = includeBinaryVersion
            ? new[] { HipProtocolVersions.V1, HipProtocolVersions.V1Binary }
            : new[] { HipProtocolVersions.V1 };

        return new HipEnvelopeSecurityService(
            Canonical,
            new HipEnvelopeValidator(),
            HmacSigner,
            HmacSigner,
            replay,
            new HipTimestampPolicy(new HipSecurityOptions { AllowedClockSkewSeconds = 300, ReplayWindowSeconds = 600 }),
            new NoopRevocationChecker(),
            new HIP.Protocol.Versioning.HipVersionPolicy(versions));
    }

    public string PayloadOfSize(int bytes)
    {
        if (bytes <= 0) return string.Empty;

        lock (_payloadCache)
        {
            if (_payloadCache.TryGetValue(bytes, out var cached))
            {
                return cached;
            }

            var value = new string('A', bytes);
            _payloadCache[bytes] = value;
            return value;
        }
    }

    public HipMessageEnvelope CreateSignedEnvelope(int payloadBytes, bool withDeviceId = false, string? hipVersion = null)
    {
        var payload = PayloadOfSize(payloadBytes);
        var envelope = new HipMessageEnvelope(
            HipVersion: hipVersion ?? HipProtocolVersions.V1,
            MessageType: "ProtectedHttpRequest",
            SenderHipId: "key-sender",
            ReceiverHipId: "key-receiver",
            TimestampUtc: FixedUtc,
            Nonce: NextNonce(),
            PayloadHash: Hasher.ComputePayloadHash(payload),
            Signature: string.Empty,
            CorrelationId: $"corr-{payloadBytes}-{_nonceCounter}",
            DeviceId: withDeviceId ? "device-01" : null);

        if (Canonical is IHipCanonicalBufferSerializer bufferCanonical)
        {
            var canonicalBuffer = new System.Buffers.ArrayBufferWriter<byte>(512);
            bufferCanonical.WriteCanonicalEnvelope(envelope, canonicalBuffer);
            var sigFast = HmacSigner.SignBytes(canonicalBuffer.WrittenSpan, "key-sender");
            return envelope with { Signature = sigFast };
        }

        var canonical = Canonical.CanonicalizeEnvelope(envelope);
        var sig = HmacSigner.Sign(canonical, "key-sender");
        return envelope with { Signature = sig };
    }

    public HipTrustReceipt CreateUnsignedReceipt(HipMessageEnvelope envelope)
        => new(
            ReceiptId: Guid.NewGuid().ToString("N"),
            HipVersion: HipProtocolVersions.V1,
            InteractionType: envelope.MessageType,
            SenderHipId: envelope.SenderHipId,
            ReceiverHipId: envelope.ReceiverHipId,
            TimestampUtc: FixedUtc,
            MessageHash: envelope.PayloadHash,
            DeviceId: envelope.DeviceId,
            Checks: ["signature", "nonce", "timestamp"],
            Decision: HipDecision.Allow,
            AppliedPolicyIds: ["policy-allow"],
            ReputationSnapshot: 80,
            ReceiptSignature: string.Empty);

    private string NextNonce()
    {
        lock (_nonceLock)
        {
            _nonceCounter++;
            return $"nonce-{_nonceCounter}";
        }
    }

    private sealed class ReplayDisabledGuard : IHipReplayGuard
    {
        public Task<bool> IsReplayAsync(string senderHipId, string nonce, DateTimeOffset timestampUtc, CancellationToken ct = default)
            => Task.FromResult(false);
    }
}
