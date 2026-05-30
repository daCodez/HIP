namespace HIP.Domain.Identity;

public sealed record SignatureVerificationResult(
    bool IsValid,
    string IdentityId,
    VerificationStatus IdentityVerificationStatus,
    string SignedIdentityStatus,
    string SignerReputationStatus,
    string FinalRiskStatus,
    string Reason,
    DateTimeOffset CheckedAtUtc);
