using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace HIP.Application.Protocol;

/// <summary>
/// Canonicalizes provider-specific public-key material and computes its stable HIP fingerprint.
/// </summary>
/// <remarks>
/// This is an additive companion to <see cref="IHipSignatureProvider"/> so existing signature
/// providers do not silently acquire a fingerprint implementation that hashes raw display text.
/// </remarks>
public interface IHipPublicKeyFingerprintProvider
{
    /// <summary>Computes a canonical, algorithm-bound fingerprint for public verification material.</summary>
    string ComputePublicKeyFingerprint(string publicKey);
}

/// <summary>
/// Resolves the exact algorithm provider and computes trusted public-key fingerprints for lifecycle policy.
/// </summary>
public interface IHipPublicKeyFingerprintService
{
    /// <summary>Computes a canonical fingerprint using the provider registered for <paramref name="algorithm"/>.</summary>
    string ComputePublicKeyFingerprint(string algorithm, string publicKey);
}

/// <summary>
/// Selects a canonical fingerprint provider by exact protocol algorithm identifier without fallback.
/// </summary>
public sealed class HipPublicKeyFingerprintService : IHipPublicKeyFingerprintService
{
    private readonly IReadOnlyDictionary<string, IHipSignatureProvider> providers;

    /// <summary>Builds the resolver from the signature providers registered for the current host.</summary>
    public HipPublicKeyFingerprintService(IEnumerable<IHipSignatureProvider> providers)
    {
        ArgumentNullException.ThrowIfNull(providers);
        var registered = new Dictionary<string, IHipSignatureProvider>(StringComparer.Ordinal);
        foreach (var provider in providers)
        {
            ArgumentNullException.ThrowIfNull(provider);
            var algorithm = provider.Capabilities?.Algorithm;
            ArgumentException.ThrowIfNullOrWhiteSpace(algorithm);
            if (!registered.TryAdd(algorithm, provider))
            {
                throw new InvalidOperationException(
                    $"Multiple HIP signature providers registered algorithm '{algorithm}'.");
            }
        }

        this.providers = registered;
    }

    /// <inheritdoc />
    public string ComputePublicKeyFingerprint(string algorithm, string publicKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithm);
        ArgumentException.ThrowIfNullOrWhiteSpace(publicKey);
        if (!providers.TryGetValue(algorithm, out var provider))
        {
            throw new NotSupportedException(
                $"No HIP signature provider is registered for algorithm '{algorithm}'.");
        }

        if (provider is not IHipPublicKeyFingerprintProvider fingerprintProvider)
        {
            throw new NotSupportedException(
                $"HIP signature provider '{algorithm}' does not expose canonical public-key fingerprinting.");
        }

        if (!provider.Capabilities.IsAvailable)
        {
            throw new InvalidOperationException(
                $"HIP signature provider '{algorithm}' is unavailable in the current runtime.");
        }

        return fingerprintProvider.ComputePublicKeyFingerprint(publicKey);
    }
}

/// <summary>Creates unambiguous, algorithm-bound fingerprints from provider-canonical key bytes.</summary>
internal static class HipPublicKeyFingerprint
{
    private static readonly byte[] Context = "HIP-PUBLIC-KEY-FINGERPRINT-V1"u8.ToArray();

    /// <summary>
    /// Hashes a length-delimited algorithm identifier and canonical provider encoding using SHA-256.
    /// </summary>
    public static string ComputeSha256(string algorithm, ReadOnlySpan<byte> canonicalPublicKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithm);
        if (canonicalPublicKey.IsEmpty)
        {
            throw new ArgumentException("Canonical public-key bytes are required.", nameof(canonicalPublicKey));
        }

        var algorithmBytes = Encoding.UTF8.GetBytes(algorithm);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Context);
        AppendLengthDelimited(hash, algorithmBytes);
        AppendLengthDelimited(hash, canonicalPublicKey);
        var digest = hash.GetHashAndReset();
        return $"sha256:{Convert.ToBase64String(digest).TrimEnd('=').Replace('+', '-').Replace('/', '_')}";
    }

    private static void AppendLengthDelimited(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(length, value.Length);
        hash.AppendData(length);
        hash.AppendData(value);
    }
}
