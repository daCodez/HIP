using HIP.Domain.Audit;
using HIP.Domain.Identity;

namespace HIP.Application.Identity;

/// <summary>
/// Describes registration of the first managed signing key for a HIP identity.
/// </summary>
public sealed record RegisterSigningKeyRequest(
    string IdentityId,
    string KeyId,
    string Algorithm,
    string PublicKey,
    string ActorId,
    string Reason,
    DateTimeOffset TransitionAtUtc);

/// <summary>
/// Describes an atomic transition from an active signing key to its replacement.
/// </summary>
public sealed record RotateSigningKeyRequest(
    string IdentityId,
    string CurrentKeyId,
    long ExpectedVersion,
    string ReplacementKeyId,
    string Algorithm,
    string PublicKey,
    string ActorId,
    string Reason,
    DateTimeOffset TransitionAtUtc);

/// <summary>
/// Describes atomic revocation of a compromised active signing key and activation of its replacement.
/// </summary>
public sealed record EmergencyReplaceSigningKeyRequest(
    string IdentityId,
    string CompromisedKeyId,
    long ExpectedVersion,
    string ReplacementKeyId,
    string Algorithm,
    string PublicKey,
    string ActorId,
    string Reason,
    DateTimeOffset TransitionAtUtc);

/// <summary>
/// Describes an optimistic-concurrency-protected signing-key state change.
/// </summary>
public sealed record ChangeSigningKeyStateRequest(
    string IdentityId,
    string KeyId,
    long ExpectedVersion,
    string ActorId,
    string Reason,
    DateTimeOffset TransitionAtUtc);

/// <summary>
/// Captures both sides of a successful signing-key rotation and the resulting aggregate.
/// </summary>
public sealed record SigningKeyRotationResult(
    ManagedSigningKey PreviousKey,
    ManagedSigningKey ReplacementKey,
    SigningKeyRing KeyRing);

/// <summary>
/// Captures both sides of a successful emergency replacement and the resulting aggregate.
/// </summary>
public sealed record SigningKeyEmergencyReplacementResult(
    ManagedSigningKey CompromisedKey,
    ManagedSigningKey ReplacementKey,
    SigningKeyRing KeyRing);

/// <summary>
/// Coordinates signing-key lifecycle transitions and policy-enforced key resolution.
/// </summary>
public interface ISigningKeyLifecycleService
{
    /// <summary>Registers the initial active signing key for an identity.</summary>
    Task<SigningKeyRing> RegisterAsync(
        RegisterSigningKeyRequest request,
        CancellationToken cancellationToken);

    /// <summary>Atomically retires an active signing key from signing use and activates its replacement.</summary>
    Task<SigningKeyRotationResult> RotateAsync(
        RotateSigningKeyRequest request,
        CancellationToken cancellationToken);

    /// <summary>
    /// Atomically revokes a compromised active key and activates its replacement.
    /// </summary>
    Task<SigningKeyEmergencyReplacementResult> EmergencyReplaceAsync(
        EmergencyReplaceSigningKeyRequest request,
        CancellationToken cancellationToken);

    /// <summary>Marks a rotating key as retired while preserving historical verification use.</summary>
    Task<SigningKeyRing> RetireAsync(
        ChangeSigningKeyStateRequest request,
        CancellationToken cancellationToken);

    /// <summary>Revokes a key so it can no longer sign or verify historical signatures.</summary>
    Task<SigningKeyRing> RevokeAsync(
        ChangeSigningKeyStateRequest request,
        CancellationToken cancellationToken);

    /// <summary>Gets a key only when lifecycle policy permits creation of new signatures.</summary>
    Task<ManagedSigningKey> GetRequiredSigningKeyAsync(
        string identityId,
        string keyId,
        CancellationToken cancellationToken);

    /// <summary>Gets a key only when lifecycle policy permits historical signature verification.</summary>
    Task<ManagedSigningKey> GetRequiredHistoricalVerificationKeyAsync(
        string identityId,
        string keyId,
        CancellationToken cancellationToken);
}

/// <summary>
/// Carries one immutable key-ring update and every privacy-safe audit fact that must commit with it.
/// </summary>
public sealed class SigningKeyLifecycleTransitionBatch
{
    /// <summary>Initializes an atomic signing-key lifecycle persistence batch.</summary>
    public SigningKeyLifecycleTransitionBatch(
        SigningKeyRing keyRing,
        long expectedVersion,
        IReadOnlyCollection<AuditLogEntry> auditEntries)
    {
        ArgumentNullException.ThrowIfNull(keyRing);
        ArgumentNullException.ThrowIfNull(auditEntries);
        if (expectedVersion < 0 || expectedVersion == long.MaxValue || keyRing.Version != expectedVersion + 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expectedVersion),
                "A signing-key transition must advance its expected aggregate version by exactly one.");
        }

        var entries = auditEntries.ToArray();
        if (entries.Length is < 1 or > 8)
        {
            throw new ArgumentOutOfRangeException(
                nameof(auditEntries),
                "A signing-key transition requires between one and eight audit facts.");
        }
        if (entries.Any(entry =>
                entry is null ||
                !entry.Metadata.TryGetValue("identityId", out var auditIdentityId) ||
                !string.Equals(auditIdentityId, keyRing.IdentityId, StringComparison.Ordinal)))
        {
            throw new ArgumentException(
                "Every signing-key audit fact must be bound to the transition identity.",
                nameof(auditEntries));
        }
        if (entries.Select(entry => entry.AuditLogId).Distinct(StringComparer.Ordinal).Count() != entries.Length)
        {
            throw new ArgumentException("Signing-key audit fact identifiers must be unique.", nameof(auditEntries));
        }

        KeyRing = keyRing;
        ExpectedVersion = expectedVersion;
        AuditEntries = entries;
    }

    /// <summary>Gets the immutable post-transition key ring.</summary>
    public SigningKeyRing KeyRing { get; }

    /// <summary>Gets the aggregate version that must currently be stored.</summary>
    public long ExpectedVersion { get; }

    /// <summary>Gets the complete privacy-safe audit evidence set for the transition.</summary>
    public IReadOnlyCollection<AuditLogEntry> AuditEntries { get; }
}

/// <summary>
/// Persists immutable signing-key ring snapshots with compare-and-swap semantics.
/// </summary>
public interface ISigningKeyLifecycleRepository
{
    /// <summary>Gets the current key-ring snapshot for an identity, when one exists.</summary>
    Task<SigningKeyRing?> GetAsync(string identityId, CancellationToken cancellationToken);

    /// <summary>
    /// Atomically saves a transition and all of its audit facts only when the stored version matches.
    /// </summary>
    Task<bool> TrySaveAsync(
        SigningKeyLifecycleTransitionBatch transitionBatch,
        CancellationToken cancellationToken);
}

/// <summary>
/// Indicates that a signing-key lifecycle command was based on a stale aggregate version.
/// </summary>
public sealed class SigningKeyConcurrencyException : InvalidOperationException
{
    /// <summary>Initializes a stale signing-key aggregate error.</summary>
    public SigningKeyConcurrencyException(string identityId, long expectedVersion)
        : base($"Signing key update for identity '{identityId}' was stale at expected version {expectedVersion}.")
    {
        IdentityId = identityId;
        ExpectedVersion = expectedVersion;
    }

    /// <summary>Gets the identity whose key ring could not be updated.</summary>
    public string IdentityId { get; }

    /// <summary>Gets the aggregate version supplied by the rejected command.</summary>
    public long ExpectedVersion { get; }
}
