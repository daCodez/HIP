namespace HIP.Domain.Identity;

public sealed record SignatureMetadata(
    string KeyId,
    SignatureAlgorithmFamily AlgorithmFamily,
    VerificationStatus VerificationStatus,
    DateTimeOffset SignedAt,
    string IntegrityExplanation);
