namespace HIP.Application.Protocol;

/// <summary>Fail-closed result for the public signed-document verification boundary.</summary>
public enum HipSignedDocumentVerificationStatus
{
    Unspecified = 0,
    Verified,
    IssuerNotFound,
    IssuerNotVerified,
    IssuerSuspended,
    IssuerRevoked,
    IssuerBindingMismatch,
    KeyNotFound,
    KeyNotValidAtIssuedTime,
    KeyRevoked,
    SignatureMetadataMismatch,
    ProviderUnavailable,
    InvalidSignature,
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
    public bool IsVerified => Status == HipSignedDocumentVerificationStatus.Verified;

    public bool EstablishesSafetyOrReputation => false;
}

/// <summary>
/// Public signed-document verification service. Implementations may consult authoritative public identity and key
/// state but must not expose repositories, private keys, signing operations, trust scores, or certificate authority.
/// </summary>
public interface IHipSignedDocumentVerificationService
{
    Task<HipSignedDocumentVerificationResult> VerifyAsync(
        HipSignedDocumentVerificationInput input,
        CancellationToken cancellationToken);
}
