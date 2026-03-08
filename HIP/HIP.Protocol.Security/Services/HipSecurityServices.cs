using System.Buffers;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using HIP.Protocol.Canonicalization;
using HIP.Protocol.Contracts;
using HIP.Protocol.Security.Abstractions;
using HIP.Protocol.Security.Options;
using HIP.Protocol.Validation;
using HIP.Protocol.Versioning;
using NSec.Cryptography;

namespace HIP.Protocol.Security.Services;

public sealed class HmacHipSigner(IDictionary<string, string> keys) : IHipSigner, IHipSignatureVerifier, IHipKeyResolver
{
    private readonly Dictionary<string, byte[]> _keys = keys.ToDictionary(
        kv => kv.Key,
        kv => Encoding.UTF8.GetBytes(kv.Value),
        StringComparer.Ordinal);

    public string Sign(string canonicalPayload, string keyId)
    {
        var payloadBytes = GetUtf8Bytes(canonicalPayload, out var rented);
        try
        {
            return SignBytes(payloadBytes, keyId);
        }
        finally
        {
            ReturnIfRented(rented);
        }
    }

    public string SignBytes(ReadOnlySpan<byte> payloadBytes, string keyId)
    {
        if (!_keys.TryGetValue(keyId, out var secret)) throw new InvalidOperationException($"Unknown key id: {keyId}");
        var sig = HMACSHA256.HashData(secret, payloadBytes);
        return ToLowerHex(sig);
    }

    public bool Verify(string canonicalPayload, string signature, string keyId)
    {
        var payloadBytes = GetUtf8Bytes(canonicalPayload, out var rented);
        try
        {
            return VerifyBytes(payloadBytes, signature, keyId);
        }
        finally
        {
            ReturnIfRented(rented);
        }
    }

    public bool VerifyBytes(ReadOnlySpan<byte> payloadBytes, string signature, string keyId)
    {
        if (!_keys.TryGetValue(keyId, out var secret)) return false;
        if (signature is null || signature.Length != 64) return false;

        Span<byte> provided = stackalloc byte[32];
        if (!TryDecodeLowerHex(signature, provided))
        {
            return false;
        }

        var computed = HMACSHA256.HashData(secret, payloadBytes);
        return CryptographicOperations.FixedTimeEquals(computed, provided);
    }

    public bool KeyExists(string keyId) => _keys.ContainsKey(keyId);

    private static ReadOnlySpan<byte> GetUtf8Bytes(string value, out byte[]? rented)
    {
        rented = null;
        if (string.IsNullOrEmpty(value))
        {
            return ReadOnlySpan<byte>.Empty;
        }

        var byteCount = Encoding.UTF8.GetByteCount(value);
        rented = ArrayPool<byte>.Shared.Rent(byteCount);
        var written = Encoding.UTF8.GetBytes(value, rented);
        return rented.AsSpan(0, written);
    }

    private static void ReturnIfRented(byte[]? rented)
    {
        if (rented is not null)
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private static string ToLowerHex(byte[] data)
    {
        return string.Create(data.Length * 2, data, static (span, bytes) =>
        {
            const string hex = "0123456789abcdef";
            for (var i = 0; i < bytes.Length; i++)
            {
                var b = bytes[i];
                span[i * 2] = hex[b >> 4];
                span[(i * 2) + 1] = hex[b & 0x0F];
            }
        });
    }

    private static bool TryDecodeLowerHex(string hex, Span<byte> destination)
    {
        if (hex.Length != destination.Length * 2) return false;

        for (var i = 0; i < destination.Length; i++)
        {
            var hi = HexValue(hex[i * 2]);
            var lo = HexValue(hex[(i * 2) + 1]);
            if (hi < 0 || lo < 0) return false;
            destination[i] = (byte)((hi << 4) | lo);
        }

        return true;
    }

    private static int HexValue(char c)
        => c switch
        {
            >= '0' and <= '9' => c - '0',
            >= 'a' and <= 'f' => c - 'a' + 10,
            >= 'A' and <= 'F' => c - 'A' + 10,
            _ => -1
        };
}

public sealed class InMemoryHipKeyStore(IEnumerable<HipSigningKey> keys) : IHipKeyStore
{
    private readonly Dictionary<string, HipSigningKey> _keys = keys.ToDictionary(x => x.KeyId, x => x, StringComparer.Ordinal);

    public bool TryGet(string keyId, out HipSigningKey key)
        => _keys.TryGetValue(keyId, out key!);
}

public sealed class EcdsaP256AlgorithmProvider : IHipAlgorithmProvider
{
    public string Algorithm => "ECDSA_P256_SHA256";

    public string Sign(string canonicalPayload, HipSigningKey key)
    {
        if (key.KeyMaterial is not ECDsa ecdsa)
            throw new InvalidOperationException("ECDSA key material is required for ECDSA_P256_SHA256.");

        var bytes = Encoding.UTF8.GetBytes(canonicalPayload);
        var signature = ecdsa.SignData(bytes, HashAlgorithmName.SHA256);
        return Convert.ToBase64String(signature);
    }

    public bool Verify(string canonicalPayload, string signature, HipSigningKey key)
    {
        if (key.KeyMaterial is not ECDsa ecdsa) return false;
        byte[] sig;
        try
        {
            sig = Convert.FromBase64String(signature);
        }
        catch
        {
            return false;
        }

        var bytes = Encoding.UTF8.GetBytes(canonicalPayload);
        return ecdsa.VerifyData(bytes, sig, HashAlgorithmName.SHA256);
    }
}

public sealed class Ed25519AlgorithmProvider : IHipAlgorithmProvider
{
    public string Algorithm => "ED25519";

    public string Sign(string canonicalPayload, HipSigningKey key)
    {
        if (key.KeyMaterial is not Ed25519KeyMaterial material)
            throw new InvalidOperationException("Ed25519 key material is required for ED25519.");

        var bytes = Encoding.UTF8.GetBytes(canonicalPayload);
        var signature = SignatureAlgorithm.Ed25519.Sign(material.PrivateKey, bytes);
        return Convert.ToBase64String(signature);
    }

    public bool Verify(string canonicalPayload, string signature, HipSigningKey key)
    {
        if (key.KeyMaterial is not Ed25519KeyMaterial material) return false;

        byte[] sig;
        try
        {
            sig = Convert.FromBase64String(signature);
        }
        catch
        {
            return false;
        }

        var bytes = Encoding.UTF8.GetBytes(canonicalPayload);
        return SignatureAlgorithm.Ed25519.Verify(material.PublicKey, bytes, sig);
    }
}

public sealed record Ed25519KeyMaterial(Key PrivateKey, PublicKey PublicKey)
{
    public static Ed25519KeyMaterial Generate()
    {
        var algorithm = SignatureAlgorithm.Ed25519;
        var privateKey = Key.Create(algorithm, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        return new Ed25519KeyMaterial(privateKey, privateKey.PublicKey);
    }

    public static Ed25519KeyMaterial FromRawPrivateKey(byte[] rawPrivateKey)
    {
        var algorithm = SignatureAlgorithm.Ed25519;
        var privateKey = Key.Import(algorithm, rawPrivateKey, KeyBlobFormat.RawPrivateKey, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        return new Ed25519KeyMaterial(privateKey, privateKey.PublicKey);
    }

    public static Ed25519KeyMaterial FromRawKeyPair(byte[] rawPrivateKey, byte[] rawPublicKey)
    {
        var algorithm = SignatureAlgorithm.Ed25519;
        var privateKey = Key.Import(algorithm, rawPrivateKey, KeyBlobFormat.RawPrivateKey, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var publicKey = PublicKey.Import(algorithm, rawPublicKey, KeyBlobFormat.RawPublicKey);
        return new Ed25519KeyMaterial(privateKey, publicKey);
    }

    public byte[] ExportRawPrivateKey() => PrivateKey.Export(KeyBlobFormat.RawPrivateKey);
    public byte[] ExportRawPublicKey() => PublicKey.Export(KeyBlobFormat.RawPublicKey);
}

public sealed class AlgorithmRouterSigner(
    IHipKeyStore keyStore,
    IEnumerable<IHipAlgorithmProvider> providers) : IHipSigner, IHipSignatureVerifier, IHipKeyResolver
{
    private readonly Dictionary<string, IHipAlgorithmProvider> _providers = providers.ToDictionary(x => x.Algorithm, x => x, StringComparer.OrdinalIgnoreCase);

    public string Sign(string canonicalPayload, string keyId)
    {
        if (!keyStore.TryGet(keyId, out var key)) throw new InvalidOperationException($"Unknown key id: {keyId}");
        if (!_providers.TryGetValue(key.Algorithm, out var provider)) throw new InvalidOperationException($"Unsupported algorithm: {key.Algorithm}");
        return provider.Sign(canonicalPayload, key);
    }

    public bool Verify(string canonicalPayload, string signature, string keyId)
    {
        if (!keyStore.TryGet(keyId, out var key)) return false;
        if (!_providers.TryGetValue(key.Algorithm, out var provider)) return false;
        return provider.Verify(canonicalPayload, signature, key);
    }

    public bool KeyExists(string keyId) => keyStore.TryGet(keyId, out _);
}

public sealed class HipKeyLifecycleValidator : IHipKeyLifecycleValidator
{
    public HipError? Validate(HipSigningKey key, DateTimeOffset atUtc, string? correlationId)
    {
        if (key.Revoked)
        {
            return new HipError(HipErrorCode.KeyRevoked, "Key revoked.", correlationId, key.ReplacedByKeyId);
        }

        if (key.NotBeforeUtc.HasValue && atUtc < key.NotBeforeUtc.Value)
        {
            return new HipError(HipErrorCode.PolicyViolation, "Key not yet active.", correlationId);
        }

        if (key.NotAfterUtc.HasValue && atUtc > key.NotAfterUtc.Value)
        {
            return new HipError(HipErrorCode.KeyRevoked, "Key validity expired.", correlationId, key.ReplacedByKeyId);
        }

        return null;
    }
}

public sealed class HipTimestampPolicy(HipSecurityOptions options) : IHipTimestampPolicy
{
    public bool IsWithinAllowedSkew(DateTimeOffset timestampUtc, DateTimeOffset nowUtc)
        => Math.Abs((nowUtc - timestampUtc).TotalSeconds) <= options.AllowedClockSkewSeconds;
}

public sealed class InMemoryReplayGuard(HipSecurityOptions options) : IHipReplayGuard
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _nonces = new(StringComparer.Ordinal);
    private int _checkCount;

    public Task<bool> IsReplayAsync(string senderHipId, string nonce, DateTimeOffset timestampUtc, CancellationToken ct = default)
    {
        MaybeCleanupExpired(DateTimeOffset.UtcNow);

        var key = string.Concat(senderHipId, ":", nonce);
        var expiry = timestampUtc.AddSeconds(options.ReplayWindowSeconds);
        var added = _nonces.TryAdd(key, expiry);
        return Task.FromResult(!added);
    }

    private void MaybeCleanupExpired(DateTimeOffset nowUtc)
    {
        // Avoid full dictionary scans on every verification call.
        if (Interlocked.Increment(ref _checkCount) % 256 != 0)
        {
            return;
        }

        foreach (var item in _nonces)
        {
            if (item.Value < nowUtc)
            {
                _nonces.TryRemove(item.Key, out _);
            }
        }
    }
}

public sealed class NoopRevocationChecker : IHipRevocationChecker
{
    public bool IsRevoked(string keyId) => false;
}

public sealed class HipEnvelopeSecurityService(
    IHipCanonicalSerializer canonical,
    IHipEnvelopeValidator validator,
    IHipSignatureVerifier verifier,
    IHipKeyResolver keyResolver,
    IHipReplayGuard replayGuard,
    IHipTimestampPolicy timestampPolicy,
    IHipRevocationChecker revocationChecker,
    IHipVersionPolicy? versionPolicy = null,
    IHipKeyStore? keyStore = null,
    IHipKeyLifecycleValidator? keyLifecycleValidator = null)
{
    public async Task<HipVerificationOutcome> VerifyAsync(HipMessageEnvelope envelope, string keyId, CancellationToken ct = default)
    {
        var validation = validator.Validate(envelope);
        if (!validation.IsValid)
        {
            return new HipVerificationOutcome(false, new HipError(HipErrorCode.InvalidEnvelope, validation.Errors[0].Message, envelope.CorrelationId));
        }

        if (!(versionPolicy?.IsSupported(envelope.HipVersion) ?? string.Equals(envelope.HipVersion, HipProtocolVersions.V1, StringComparison.OrdinalIgnoreCase)))
        {
            return new HipVerificationOutcome(false, new HipError(HipErrorCode.UnsupportedVersion, "Unsupported HIP version.", envelope.CorrelationId));
        }

        if (!timestampPolicy.IsWithinAllowedSkew(envelope.TimestampUtc, DateTimeOffset.UtcNow))
        {
            return new HipVerificationOutcome(false, new HipError(HipErrorCode.TimestampExpired, "Timestamp outside allowed skew.", envelope.CorrelationId));
        }

        if (await replayGuard.IsReplayAsync(envelope.SenderHipId, envelope.Nonce, envelope.TimestampUtc, ct))
        {
            return new HipVerificationOutcome(false, new HipError(HipErrorCode.ReplayDetected, "Nonce already used.", envelope.CorrelationId));
        }

        if (!keyResolver.KeyExists(keyId))
        {
            return new HipVerificationOutcome(false, new HipError(HipErrorCode.UnknownIdentity, "Unknown key identity.", envelope.CorrelationId));
        }

        if (revocationChecker.IsRevoked(keyId))
        {
            return new HipVerificationOutcome(false, new HipError(HipErrorCode.KeyRevoked, "Key revoked.", envelope.CorrelationId));
        }

        if (keyStore is not null && keyLifecycleValidator is not null && keyStore.TryGet(keyId, out var key))
        {
            var keyError = keyLifecycleValidator.Validate(key, envelope.TimestampUtc, envelope.CorrelationId);
            if (keyError is not null)
            {
                return new HipVerificationOutcome(false, keyError);
            }
        }

        if (canonical is IHipCanonicalBufferSerializer bufferCanonical
            && verifier is HmacHipSigner hmacVerifier)
        {
            var canonicalBuffer = new ArrayBufferWriter<byte>(512);
            bufferCanonical.WriteCanonicalEnvelope(envelope, canonicalBuffer);
            var okFast = hmacVerifier.VerifyBytes(canonicalBuffer.WrittenSpan, envelope.Signature, keyId);
            return okFast
                ? new HipVerificationOutcome(true)
                : new HipVerificationOutcome(false, new HipError(HipErrorCode.InvalidSignature, "Invalid signature.", envelope.CorrelationId));
        }

        var canonicalPayload = canonical.CanonicalizeEnvelope(envelope);
        var ok = verifier.Verify(canonicalPayload, envelope.Signature, keyId);
        return ok
            ? new HipVerificationOutcome(true)
            : new HipVerificationOutcome(false, new HipError(HipErrorCode.InvalidSignature, "Invalid signature.", envelope.CorrelationId));
    }
}

public sealed class HipReceiptSecurityService(
    IHipCanonicalSerializer canonical,
    IHipReceiptValidator validator,
    IHipSigner signer,
    IHipSignatureVerifier verifier,
    IHipVersionPolicy? versionPolicy = null)
{
    public HipTrustReceipt Issue(HipTrustReceipt unsignedReceipt, string keyId)
    {
        var valid = validator.Validate(unsignedReceipt, requireSignature: false);
        if (!valid.IsValid) throw new InvalidOperationException(valid.Errors[0].Message);

        if (canonical is IHipCanonicalBufferSerializer bufferCanonical
            && signer is HmacHipSigner hmacSigner)
        {
            var canonicalBuffer = new ArrayBufferWriter<byte>(384);
            bufferCanonical.WriteCanonicalReceipt(unsignedReceipt, canonicalBuffer);
            var signatureFast = hmacSigner.SignBytes(canonicalBuffer.WrittenSpan, keyId);
            return unsignedReceipt with { ReceiptSignature = signatureFast };
        }

        var canonicalPayload = canonical.CanonicalizeReceipt(unsignedReceipt);
        var signature = signer.Sign(canonicalPayload, keyId);
        return unsignedReceipt with { ReceiptSignature = signature };
    }

    public HipVerificationOutcome Verify(HipTrustReceipt receipt, string keyId)
    {
        var valid = validator.Validate(receipt);
        if (!valid.IsValid)
        {
            return new HipVerificationOutcome(false, new HipError(HipErrorCode.InvalidEnvelope, valid.Errors[0].Message, null));
        }

        if (!(versionPolicy?.IsSupported(receipt.HipVersion) ?? string.Equals(receipt.HipVersion, HipProtocolVersions.V1, StringComparison.OrdinalIgnoreCase)))
        {
            return new HipVerificationOutcome(false, new HipError(HipErrorCode.UnsupportedVersion, "Unsupported receipt version.", null));
        }

        if (canonical is IHipCanonicalBufferSerializer bufferCanonical
            && verifier is HmacHipSigner hmacVerifier)
        {
            var canonicalBuffer = new ArrayBufferWriter<byte>(384);
            bufferCanonical.WriteCanonicalReceipt(receipt, canonicalBuffer);
            var okFast = hmacVerifier.VerifyBytes(canonicalBuffer.WrittenSpan, receipt.ReceiptSignature, keyId);
            return okFast
                ? new HipVerificationOutcome(true)
                : new HipVerificationOutcome(false, new HipError(HipErrorCode.InvalidSignature, "Invalid receipt signature.", null));
        }

        var canonicalPayload = canonical.CanonicalizeReceipt(receipt);
        var ok = verifier.Verify(canonicalPayload, receipt.ReceiptSignature, keyId);
        return ok
            ? new HipVerificationOutcome(true)
            : new HipVerificationOutcome(false, new HipError(HipErrorCode.InvalidSignature, "Invalid receipt signature.", null));
    }
}

public sealed class HipChallengeService(IHipSigner signer, IHipSignatureVerifier verifier)
{
    public HipChallenge CreateChallenge(string senderHipId, string verifierHipId)
        => new(HipProtocolVersions.V1, Guid.NewGuid().ToString("N"), senderHipId, verifierHipId, Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5));

    public HipProof CreateProof(HipChallenge challenge, string senderHipId, string keyId)
    {
        var payload = $"{challenge.ChallengeId}|{senderHipId}|{challenge.Nonce}|{challenge.ExpiresUtc.UtcDateTime:O}";
        var sig = signer.Sign(payload, keyId);
        return new HipProof(HipProtocolVersions.V1, challenge.ChallengeId, senderHipId, sig, DateTimeOffset.UtcNow);
    }

    public bool VerifyProof(HipChallenge challenge, HipProof proof, string keyId)
    {
        if (proof.HipVersion != HipProtocolVersions.V1) return false;
        if (proof.ChallengeId != challenge.ChallengeId) return false;
        if (DateTimeOffset.UtcNow > challenge.ExpiresUtc) return false;

        var payload = $"{challenge.ChallengeId}|{proof.SenderHipId}|{challenge.Nonce}|{challenge.ExpiresUtc.UtcDateTime:O}";
        return verifier.Verify(payload, proof.Signature, keyId);
    }
}
