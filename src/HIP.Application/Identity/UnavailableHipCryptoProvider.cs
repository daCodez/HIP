using HIP.Application.Protocol;
using HIP.Domain.Identity;

namespace HIP.Application.Identity;

/// <summary>
/// Fail-closed identity crypto boundary used when production managed-key custody is not configured.
/// It can be resolved safely so read-only identity and certificate pages remain available.
/// </summary>
public sealed class UnavailableHipCryptoProvider : IHipCryptoProvider
{
    public const string Algorithm = "Managed-Identity-Key-Custody-Unavailable";

    /// <inheritdoc />
    public SignatureProviderCapabilities Capabilities { get; } = new(
        Algorithm,
        SignatureAlgorithmFamily.Unknown,
        SignatureProviderOperations.None,
        IsAvailable: false,
        IsDevelopmentOnly: false);

    /// <inheritdoc />
    public HipKeyPair GenerateKeyPair() => throw Unavailable();

    /// <inheritdoc />
    public string HashContent(string content) => throw Unavailable();

    /// <inheritdoc />
    public string SignHash(string contentHash, string privateKey) => throw Unavailable();

    /// <inheritdoc />
    public bool VerifySignature(string contentHash, string signatureValue, string publicKey) => throw Unavailable();

    /// <inheritdoc />
    public string ComputePublicKeyFingerprint(string publicKey) => throw Unavailable();

    private static PlatformNotSupportedException Unavailable() => new(
        "Managed production identity-key custody is not configured.");
}
