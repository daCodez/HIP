using HIP.Domain.Protocol;

namespace HIP.Domain.Identity;

public sealed record HipWellKnownDocument(
    string Domain,
    string HipIdentityId,
    IReadOnlyCollection<SigningKey> PublicKeys,
    DateTimeOffset IssuedAtUtc,
    string SchemaVersion = "1",
    string? VerificationChallenge = null,
    DateTimeOffset? ExpiresAtUtc = null,
    HipProtocolSignature? Signature = null);
