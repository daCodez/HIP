namespace HIP.ApiService.Application.Abstractions;

/// <summary>
/// Provides key-material lookup and rotation policy for token/signature services.
/// </summary>
public interface IKeyRotationPolicy
{
    /// <summary>
    /// Returns the current active key material.
    /// </summary>
    /// <returns>Active key metadata and secret bytes.</returns>
    KeyMaterial Current();

    /// <summary>
    /// Attempts to resolve key material by key id.
    /// </summary>
    /// <param name="keyId">Key id to resolve.</param>
    /// <param name="key">Resolved key material when present.</param>
    /// <returns><see langword="true"/> when key was found; otherwise <see langword="false"/>.</returns>
    bool TryGet(string keyId, out KeyMaterial key);

    /// <summary>
    /// Rotates key material and returns rotation metadata.
    /// </summary>
    /// <param name="emergency">Whether this rotation is an emergency rotation.</param>
    /// <returns>Rotation result metadata.</returns>
    KeyRotationResult Rotate(bool emergency);

    /// <summary>
    /// Gets the minimum key version accepted for validation.
    /// </summary>
    int MinAcceptedVersion { get; }
}

/// <summary>
/// Key material used for signing and token operations.
/// </summary>
/// <param name="KeyId">Stable key identifier.</param>
/// <param name="Version">Monotonic key version.</param>
/// <param name="Secret">Raw key bytes.</param>
/// <param name="CreatedAtUtc">UTC key creation timestamp.</param>
public sealed record KeyMaterial(string KeyId, int Version, byte[] Secret, DateTimeOffset CreatedAtUtc);

/// <summary>
/// Result metadata for a key rotation operation.
/// </summary>
/// <param name="KeyId">Rotated key id.</param>
/// <param name="Version">New active version.</param>
/// <param name="Emergency">Whether rotation was marked emergency.</param>
/// <param name="RotatedAtUtc">UTC rotation timestamp.</param>
public sealed record KeyRotationResult(string KeyId, int Version, bool Emergency, DateTimeOffset RotatedAtUtc);
