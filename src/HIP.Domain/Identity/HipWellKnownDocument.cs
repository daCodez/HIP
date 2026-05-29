namespace HIP.Domain.Identity;

public sealed record HipWellKnownDocument(
    string HipIdentityId,
    string Domain,
    string PublicKey,
    string KeyAlgorithm,
    DateTimeOffset SignedAtUtc,
    string Signature);
