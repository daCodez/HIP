namespace HIP.Application.Protocol;

/// <summary>
/// Public, verification-only description of one HIP signature algorithm. Algorithm-family values are protocol text
/// rather than implementation enums so verification clients do not depend on HIP's hosted domain model.
/// </summary>
public sealed record HipSignatureVerificationCapabilities(
    string Algorithm,
    string AlgorithmFamily,
    bool IsAvailable)
{
    /// <summary>A valid signature establishes integrity and signer evidence, never safety or reputation.</summary>
    public bool EstablishesSafetyOrReputation => false;
}

/// <summary>
/// Public verification-only cryptographic boundary. Implementations receive public verification material and never
/// private keys, signing authority, certificate authority access, trust scores, or provider-selection policy.
/// </summary>
public interface IHipSignatureVerificationProvider
{
    /// <summary>Gets the provider's public verification capabilities.</summary>
    HipSignatureVerificationCapabilities VerificationCapabilities { get; }

    /// <summary>Verifies a signature over an already computed content hash using public key material.</summary>
    bool VerifySignature(string contentHash, string signatureValue, string publicKey);
}

/// <summary>Computes an algorithm-bound fingerprint from public verification material.</summary>
public interface IHipPublicKeyFingerprintProvider
{
    /// <summary>Computes a canonical fingerprint for public verification material.</summary>
    string ComputePublicKeyFingerprint(string publicKey);
}
