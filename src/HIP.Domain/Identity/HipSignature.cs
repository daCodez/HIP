namespace HIP.Domain.Identity;

public sealed record HipSignature(
    string SignatureId,
    string IdentityId,
    string Algorithm,
    string ContentHash,
    string SignatureValue,
    DateTimeOffset SignedAtUtc,
    DateTimeOffset? ExpiresAtUtc);
