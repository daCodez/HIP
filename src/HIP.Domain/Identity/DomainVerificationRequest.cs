namespace HIP.Domain.Identity;

public sealed record DomainVerificationRequest(
    string Domain,
    VerificationMethod Method,
    string Token,
    VerificationStatus Status,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? VerifiedAtUtc,
    DateTimeOffset? ExpiresAtUtc = null,
    DateTimeOffset? LastCheckedAtUtc = null,
    string? LastCheckMessage = null,
    DateTimeOffset? RevokedAtUtc = null,
    int ChallengeVersion = 1);
