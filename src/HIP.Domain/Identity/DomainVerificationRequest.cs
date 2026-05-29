namespace HIP.Domain.Identity;

public sealed record DomainVerificationRequest(
    string Domain,
    VerificationMethod Method,
    string Token,
    VerificationStatus Status,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? VerifiedAtUtc);
