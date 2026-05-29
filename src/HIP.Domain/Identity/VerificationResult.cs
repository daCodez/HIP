namespace HIP.Domain.Identity;

public sealed record VerificationResult(
    bool IsValid,
    string IdentityId,
    VerificationStatus VerificationStatus,
    string Reason,
    DateTimeOffset CheckedAtUtc);
