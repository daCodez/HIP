namespace HIP.Domain.Identity;


/// <summary>Privacy-safe outcome of an explicit owner verification attempt.</summary>
public enum DomainVerificationAttemptOutcome
{
    Pending,
    Failed,
    Succeeded
}
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
    int ChallengeVersion = 1,
    int VerificationAttemptCount = 0,
    DateTimeOffset? ConsumedAtUtc = null,
    DomainVerificationAttemptOutcome? LastAttemptOutcome = null);
