namespace HIP.Domain.Identity;

public sealed record WebsiteIdentity(
    string Domain,
    string HipIdentityId,
    IReadOnlyCollection<SigningKey> PublicKeys,
    VerificationStatus VerificationStatus,
    VerificationMethod PreferredVerificationMethod,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? VerifiedAtUtc);
