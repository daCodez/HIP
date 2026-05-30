namespace HIP.Domain.Identity;

public sealed record HipWellKnownDocument(
    string Domain,
    string HipIdentityId,
    IReadOnlyCollection<SigningKey> PublicKeys,
    DateTimeOffset IssuedAtUtc);
