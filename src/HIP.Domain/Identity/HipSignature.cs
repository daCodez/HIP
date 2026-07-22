namespace HIP.Domain.Identity;

/// <summary>
/// Represents a HIP signature and the immutable managed key identifier required to verify it.
/// </summary>
/// <param name="SignatureId">Stable signature identifier.</param>
/// <param name="IdentityId">Identity that created the signature.</param>
/// <param name="Algorithm">Exact signature algorithm identifier.</param>
/// <param name="ContentHash">Hash covered by the signature.</param>
/// <param name="SignatureValue">Provider-specific signature value.</param>
/// <param name="SignedAtUtc">Time at which HIP created the signature.</param>
/// <param name="ExpiresAtUtc">Optional expiry time.</param>
/// <param name="KeyId">Immutable managed key identifier. Null is reserved for legacy data that must be migrated before verification.</param>
public sealed record HipSignature(
    string SignatureId,
    string IdentityId,
    string Algorithm,
    string ContentHash,
    string SignatureValue,
    DateTimeOffset SignedAtUtc,
    DateTimeOffset? ExpiresAtUtc,
    string? KeyId = null);
