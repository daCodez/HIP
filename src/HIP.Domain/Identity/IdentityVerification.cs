namespace HIP.Domain.Identity;

public sealed record IdentityVerification(
    VerificationMethod Method,
    VerificationStatus Status,
    DateTimeOffset CheckedAt,
    string Explanation);
