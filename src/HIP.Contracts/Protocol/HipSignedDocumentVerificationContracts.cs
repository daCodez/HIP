namespace HIP.Application.Protocol;

/// <summary>Fail-closed result for the public signed-document verification boundary.</summary>
public enum HipSignedDocumentVerificationStatus
{
    /// <summary>No verification outcome was supplied.</summary>
    Unspecified = 0,
    /// <summary>The signature and authoritative issuer state were verified.</summary>
    Verified,
    /// <summary>The authoritative issuer could not be found.</summary>
    IssuerNotFound,
    /// <summary>The authoritative issuer is not verified.</summary>
    IssuerNotVerified,
    /// <summary>The authoritative issuer is suspended.</summary>
    IssuerSuspended,
    /// <summary>The authoritative issuer is revoked.</summary>
    IssuerRevoked,
    /// <summary>The document issuer does not match the authoritative binding.</summary>
    IssuerBindingMismatch,
    /// <summary>The requested public verification key could not be found.</summary>
    KeyNotFound,
    /// <summary>The key was not valid when the document was issued.</summary>
    KeyNotValidAtIssuedTime,
    /// <summary>The public verification key is revoked.</summary>
    KeyRevoked,
    /// <summary>The signature metadata does not match the authoritative key metadata.</summary>
    SignatureMetadataMismatch,
    /// <summary>The required verification provider is unavailable.</summary>
    ProviderUnavailable,
    /// <summary>The signature is invalid.</summary>
    InvalidSignature,
    /// <summary>Authoritative verification state could not be obtained safely.</summary>
    VerificationStateUnavailable
}

/// <summary>
/// Dependency-free public input for verifying one canonical signed document. Algorithm-family metadata is protocol
/// text so callers do not depend on HIP's hosted domain model.
/// </summary>
public sealed record HipSignedDocumentVerificationInput(
    string IssuerId,
    string KeyId,
    string Algorithm,
    string AlgorithmFamily,
    string Canonicalization,
    string SignatureValue,
    DateTimeOffset IssuedAtUtc,
    ReadOnlyMemory<byte> SigningPayloadJson);

/// <summary>Public verification outcome that never equates origin evidence with safety or reputation.</summary>
public sealed record HipSignedDocumentVerificationResult(
    HipSignedDocumentVerificationStatus Status,
    string? VerifiedIssuerId = null,
    string? VerifiedKeyId = null)
{
    /// <summary>Gets whether the result is verified.</summary>
    public bool IsVerified => Status == HipSignedDocumentVerificationStatus.Verified;

    /// <summary>Always false because signature evidence does not establish safety or reputation.</summary>
    public bool EstablishesSafetyOrReputation => false;
}

/// <summary>
/// Public signed-document verification service. Implementations may consult authoritative public identity and key
/// state but must not expose repositories, private keys, signing operations, trust scores, or certificate authority.
/// </summary>
public interface IHipSignedDocumentVerificationService
{
    /// <summary>Verifies one signed document against authoritative public state.</summary>
    Task<HipSignedDocumentVerificationResult> VerifyAsync(
        HipSignedDocumentVerificationInput input,
        CancellationToken cancellationToken);
}
