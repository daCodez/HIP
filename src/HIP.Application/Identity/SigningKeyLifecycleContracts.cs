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
/// Describes atomic creation of a HIP identity and its first managed signing key.
/// </summary>
public sealed record RegisterIdentitySigningKeyRequest(
    HipIdentity Identity,
    string KeyId,
    string ActorId,
    string Reason,
    DateTimeOffset TransitionAtUtc);

/// <summary>
/// Returns the canonical identity and key-ring snapshots committed by initial registration.
/// </summary>
public sealed record IdentitySigningKeyRegistrationResult(
    HipIdentity Identity,
    SigningKeyRing KeyRing,
    bool WasCreated = false);

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
    /// <summary>
    /// Atomically creates an identity, its first active key, and the required audit evidence.
    /// Exact retries return the canonical stored registration.
    /// </summary>
    Task<IdentitySigningKeyRegistrationResult> RegisterIdentityAsync(
        RegisterIdentitySigningKeyRequest request,
        CancellationToken cancellationToken);

    /// <summary>Registers the initial active signing key for an identity.</summary>
    Task<SigningKeyRing> RegisterAsync(
        RegisterSigningKeyRequest request,
        CancellationToken cancellationToken);

    /// <summary>
    /// Idempotently registers an initial key or returns the exact canonical-fingerprint match already retained.
    /// </summary>
    Task<SigningKeyRing> EnsureInitialKeyAsync(
        RegisterSigningKeyRequest request,
        CancellationToken cancellationToken);

    /// <summary>
    /// Returns the authoritative existing ring, or atomically creates the supplied fallback key when no ring exists.
    /// </summary>
    Task<SigningKeyRing> EnsureKeyRingAsync(
        RegisterSigningKeyRequest fallbackInitialKey,
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
/// Carries an identity and its complete version-one signing-key transition as one commit unit.
/// </summary>
public sealed class IdentitySigningKeyRegistrationBatch
{
    /// <summary>Initializes and validates one atomic initial-registration commit.</summary>
    public IdentitySigningKeyRegistrationBatch(
        HipIdentity identity,
        SigningKeyLifecycleTransitionBatch lifecycleTransition)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(lifecycleTransition);
        ArgumentException.ThrowIfNullOrWhiteSpace(identity.IdentityId);
        ArgumentException.ThrowIfNullOrWhiteSpace(identity.DisplayName);
        ArgumentException.ThrowIfNullOrWhiteSpace(identity.PublicKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(identity.KeyAlgorithm);
        ArgumentException.ThrowIfNullOrWhiteSpace(identity.ReputationTargetId);

        if (identity.CreatedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Identity creation time must be expressed in UTC.", nameof(identity));
        }

        var keyRing = lifecycleTransition.KeyRing;
        if (!string.Equals(identity.IdentityId, keyRing.IdentityId, StringComparison.Ordinal) ||
            lifecycleTransition.ExpectedVersion != 0 ||
            keyRing.Version != 1 ||
            keyRing.Keys.Count != 1)
        {
            throw new ArgumentException(
                "Initial identity registration requires a matching version-one signing-key ring.",
                nameof(lifecycleTransition));
        }

        var initialKey = keyRing.Keys[0];
        if (initialKey.Status != SigningKeyStatus.Active ||
            !string.Equals(initialKey.Algorithm, identity.KeyAlgorithm, StringComparison.Ordinal) ||
            !string.Equals(initialKey.PublicKey, identity.PublicKey, StringComparison.Ordinal) ||
            initialKey.ActivatedAtUtc != identity.CreatedAtUtc)
        {
            throw new ArgumentException(
                "The initial active signing key must match the identity's key material and creation time.",
                nameof(lifecycleTransition));
        }

        Identity = identity;
        LifecycleTransition = lifecycleTransition;
    }

    /// <summary>Gets the immutable identity to create.</summary>
    public HipIdentity Identity { get; }

    /// <summary>Gets the version-one ring and audit facts to create with the identity.</summary>
    public SigningKeyLifecycleTransitionBatch LifecycleTransition { get; }
}

/// <summary>
/// Persists immutable signing-key ring snapshots with compare-and-swap semantics.
/// </summary>
public interface ISigningKeyLifecycleRepository
{
    /// <summary>Gets an identity written through the atomic registration boundary, when present.</summary>
    Task<HipIdentity?> GetRegisteredIdentityAsync(
        string identityId,
        CancellationToken cancellationToken);

    /// <summary>Gets the current key-ring snapshot for an identity, when one exists.</summary>
    Task<SigningKeyRing?> GetAsync(string identityId, CancellationToken cancellationToken);

    /// <summary>
    /// Atomically creates an identity, its first signing-key ring, and every required audit fact.
    /// Returns false without mutation when any member already exists.
    /// </summary>
    Task<bool> TryRegisterIdentityAsync(
        IdentitySigningKeyRegistrationBatch registrationBatch,
        CancellationToken cancellationToken);

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

/// <summary>
/// Indicates that bootstrap found lifecycle metadata that does not identify the requested canonical key.
/// </summary>
public sealed class SigningKeyBootstrapMismatchException : InvalidOperationException
{
    /// <summary>Initializes a privacy-safe signing-key bootstrap mismatch.</summary>
    public SigningKeyBootstrapMismatchException(string identityId, string keyId)
        : base(
            $"Existing signing-key lifecycle metadata for identity '{identityId}' " +
            $"does not match bootstrap key '{keyId}'.")
    {
        IdentityId = identityId;
        KeyId = keyId;
    }

    /// <summary>Gets the identity whose existing lifecycle metadata did not match.</summary>
    public string IdentityId { get; }

    /// <summary>Gets the requested stable key identifier.</summary>
    public string KeyId { get; }
}

/// <summary>
/// Indicates that an identity identifier is already bound to different registration facts.
/// </summary>
public sealed class IdentitySigningKeyRegistrationConflictException : InvalidOperationException
{
    /// <summary>Initializes a privacy-safe initial-registration conflict.</summary>
    public IdentitySigningKeyRegistrationConflictException(string identityId, string keyId)
        : base($"Identity '{identityId}' cannot be registered with initial signing key '{keyId}' because conflicting registration state already exists.")
    {
        IdentityId = identityId;
        KeyId = keyId;
    }

    /// <summary>Gets the conflicting identity identifier.</summary>
    public string IdentityId { get; }

    /// <summary>Gets the requested initial key identifier.</summary>
    public string KeyId { get; }
}

/// <summary>
/// Indicates that storage contains only one side of the required identity and key-ring commit.
/// </summary>
public sealed class IdentitySigningKeyRegistrationInconsistencyException : InvalidOperationException
{
    /// <summary>Initializes a privacy-safe partial-registration error.</summary>
    public IdentitySigningKeyRegistrationInconsistencyException(
        string identityId,
        bool identityExists,
        bool keyRingExists)
        : base($"Identity '{identityId}' has inconsistent initial registration state and cannot be repaired automatically.")
    {
        IdentityId = identityId;
        IdentityExists = identityExists;
        KeyRingExists = keyRingExists;
    }

    /// <summary>Gets the affected identity identifier.</summary>
    public string IdentityId { get; }

    /// <summary>Gets whether the identity side of the atomic registration exists.</summary>
    public bool IdentityExists { get; }

    /// <summary>Gets whether the signing-key-ring side of the atomic registration exists.</summary>
    public bool KeyRingExists { get; }
}
