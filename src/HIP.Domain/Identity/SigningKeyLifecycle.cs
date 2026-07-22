using System.Collections.ObjectModel;
using System.Text.Json.Serialization;

namespace HIP.Domain.Identity;

/// <summary>
/// Describes whether a managed signing key may sign new content or verify historical content.
/// </summary>
public enum SigningKeyStatus
{
    /// <summary>The key may create signatures and verify signatures.</summary>
    Active,

    /// <summary>The key has a replacement and may only verify historical signatures.</summary>
    Retiring,

    /// <summary>The planned overlap period ended, but historical verification remains allowed.</summary>
    Retired,

    /// <summary>The key is untrusted and may neither sign nor verify signatures.</summary>
    Revoked
}

/// <summary>
/// Represents immutable public lifecycle metadata for a managed HIP signing key.
/// </summary>
public sealed class ManagedSigningKey
{
    [JsonConstructor]
    private ManagedSigningKey(
        string keyId,
        string algorithm,
        string publicKey,
        SigningKeyStatus status,
        string? replacementKeyId,
        DateTimeOffset activatedAtUtc,
        DateTimeOffset statusChangedAtUtc,
        DateTimeOffset? retiringAtUtc,
        DateTimeOffset? retiredAtUtc,
        DateTimeOffset? revokedAtUtc,
        long version)
    {
        var normalizedKeyId = SigningKeyLifecycleValidation.NormalizeKeyId(keyId, nameof(keyId));
        var normalizedReplacementKeyId = replacementKeyId is null
            ? null
            : SigningKeyLifecycleValidation.NormalizeKeyId(replacementKeyId, nameof(replacementKeyId));
        var normalizedAlgorithm = SigningKeyLifecycleValidation.NormalizeAlgorithm(algorithm, nameof(algorithm));
        var normalizedPublicKey = SigningKeyLifecycleValidation.NormalizePublicKey(publicKey, nameof(publicKey));

        ValidatePersistedState(
            normalizedKeyId,
            status,
            normalizedReplacementKeyId,
            activatedAtUtc,
            statusChangedAtUtc,
            retiringAtUtc,
            retiredAtUtc,
            revokedAtUtc,
            version);

        KeyId = normalizedKeyId;
        Algorithm = normalizedAlgorithm;
        PublicKey = normalizedPublicKey;
        Status = status;
        ReplacementKeyId = normalizedReplacementKeyId;
        ActivatedAtUtc = activatedAtUtc;
        StatusChangedAtUtc = statusChangedAtUtc;
        RetiringAtUtc = retiringAtUtc;
        RetiredAtUtc = retiredAtUtc;
        RevokedAtUtc = revokedAtUtc;
        Version = version;
    }

    /// <summary>Gets the stable identifier carried by signatures created with this key.</summary>
    public string KeyId { get; }

    /// <summary>Gets the cryptographic algorithm identifier.</summary>
    public string Algorithm { get; }

    /// <summary>Gets the public verification material. Private key material is never represented here.</summary>
    public string PublicKey { get; }

    /// <summary>Gets the current lifecycle status.</summary>
    public SigningKeyStatus Status { get; }

    /// <summary>Gets the replacement key identifier recorded during rotation, when present.</summary>
    public string? ReplacementKeyId { get; }

    /// <summary>Gets when the key first became active.</summary>
    public DateTimeOffset ActivatedAtUtc { get; }

    /// <summary>Gets when the most recent lifecycle transition occurred.</summary>
    public DateTimeOffset StatusChangedAtUtc { get; }

    /// <summary>Gets when the key entered the retiring state.</summary>
    public DateTimeOffset? RetiringAtUtc { get; }

    /// <summary>Gets when the planned retirement completed.</summary>
    public DateTimeOffset? RetiredAtUtc { get; }

    /// <summary>Gets when the key was revoked.</summary>
    public DateTimeOffset? RevokedAtUtc { get; }

    /// <summary>Gets the monotonic version of this key's lifecycle metadata.</summary>
    public long Version { get; }

    /// <summary>Gets whether policy permits this key to create new signatures.</summary>
    public bool CanCreateSignature => Status == SigningKeyStatus.Active;

    /// <summary>Gets whether policy permits this key to verify an existing signature.</summary>
    public bool CanVerifyHistoricalSignature => Status != SigningKeyStatus.Revoked;

    /// <summary>
    /// Determines whether a signature's trusted creation time falls inside this key's signing window.
    /// Revoked keys fail closed regardless of the supplied time.
    /// </summary>
    public bool CanVerifySignatureIssuedAt(DateTimeOffset issuedAtUtc)
    {
        SigningKeyLifecycleValidation.EnsureUtc(issuedAtUtc, nameof(issuedAtUtc));
        if (Status == SigningKeyStatus.Revoked || issuedAtUtc < ActivatedAtUtc)
        {
            return false;
        }

        if (RetiringAtUtc is null)
        {
            return Status == SigningKeyStatus.Active;
        }

        // The cutoff is exclusive: the old key stops signing at the instant rotation begins.
        return issuedAtUtc < RetiringAtUtc.Value;
    }

    /// <summary>Creates lifecycle metadata for a newly activated key.</summary>
    public static ManagedSigningKey CreateActive(
        string keyId,
        string algorithm,
        string publicKey,
        DateTimeOffset activatedAtUtc)
    {
        var normalizedKeyId = SigningKeyLifecycleValidation.NormalizeKeyId(keyId, nameof(keyId));
        var normalizedAlgorithm = SigningKeyLifecycleValidation.NormalizeAlgorithm(algorithm, nameof(algorithm));
        var normalizedPublicKey = SigningKeyLifecycleValidation.NormalizePublicKey(publicKey, nameof(publicKey));
        SigningKeyLifecycleValidation.EnsureUtc(activatedAtUtc, nameof(activatedAtUtc));

        return new ManagedSigningKey(
            normalizedKeyId,
            normalizedAlgorithm,
            normalizedPublicKey,
            SigningKeyStatus.Active,
            replacementKeyId: null,
            activatedAtUtc,
            activatedAtUtc,
            retiringAtUtc: null,
            retiredAtUtc: null,
            revokedAtUtc: null,
            version: 1);
    }

    /// <summary>Stops signing with this key and records the active replacement.</summary>
    public ManagedSigningKey BeginRotation(string replacementKeyId, DateTimeOffset transitionAtUtc)
    {
        EnsureStatus(SigningKeyStatus.Active, "begin rotation");
        var normalizedReplacementKeyId = SigningKeyLifecycleValidation.NormalizeKeyId(
            replacementKeyId,
            nameof(replacementKeyId));

        if (string.Equals(KeyId, normalizedReplacementKeyId, StringComparison.Ordinal))
        {
            throw new ArgumentException("A signing key cannot replace itself.", nameof(replacementKeyId));
        }

        EnsureOrderedUtc(transitionAtUtc, nameof(transitionAtUtc));

        return new ManagedSigningKey(
            KeyId,
            Algorithm,
            PublicKey,
            SigningKeyStatus.Retiring,
            normalizedReplacementKeyId,
            ActivatedAtUtc,
            transitionAtUtc,
            transitionAtUtc,
            RetiredAtUtc,
            RevokedAtUtc,
            NextVersion());
    }

    /// <summary>Completes the planned retirement of a rotating key.</summary>
    public ManagedSigningKey Retire(DateTimeOffset transitionAtUtc)
    {
        EnsureStatus(SigningKeyStatus.Retiring, "retire");
        EnsureOrderedUtc(transitionAtUtc, nameof(transitionAtUtc));

        return new ManagedSigningKey(
            KeyId,
            Algorithm,
            PublicKey,
            SigningKeyStatus.Retired,
            ReplacementKeyId,
            ActivatedAtUtc,
            transitionAtUtc,
            RetiringAtUtc,
            transitionAtUtc,
            RevokedAtUtc,
            NextVersion());
    }

    /// <summary>
    /// Revokes a non-active key immediately. Active keys require an atomic emergency replacement.
    /// </summary>
    public ManagedSigningKey Revoke(DateTimeOffset transitionAtUtc)
    {
        if (Status == SigningKeyStatus.Active)
        {
            throw new InvalidOperationException(
                $"Active signing key '{KeyId}' must be replaced atomically when revoked.");
        }

        if (Status == SigningKeyStatus.Revoked)
        {
            throw new InvalidOperationException($"Signing key '{KeyId}' is already revoked.");
        }

        EnsureOrderedUtc(transitionAtUtc, nameof(transitionAtUtc));

        return new ManagedSigningKey(
            KeyId,
            Algorithm,
            PublicKey,
            SigningKeyStatus.Revoked,
            ReplacementKeyId,
            ActivatedAtUtc,
            transitionAtUtc,
            RetiringAtUtc,
            RetiredAtUtc,
            transitionAtUtc,
            NextVersion());
    }

    /// <summary>
    /// Revokes an active compromised key while recording the replacement activated by the same aggregate transition.
    /// </summary>
    public ManagedSigningKey RevokeWithReplacement(
        string replacementKeyId,
        DateTimeOffset transitionAtUtc)
    {
        EnsureStatus(SigningKeyStatus.Active, "replace and revoke");
        var normalizedReplacementKeyId = SigningKeyLifecycleValidation.NormalizeKeyId(
            replacementKeyId,
            nameof(replacementKeyId));
        if (string.Equals(KeyId, normalizedReplacementKeyId, StringComparison.Ordinal))
        {
            throw new ArgumentException("A signing key cannot replace itself.", nameof(replacementKeyId));
        }

        EnsureOrderedUtc(transitionAtUtc, nameof(transitionAtUtc));

        return new ManagedSigningKey(
            KeyId,
            Algorithm,
            PublicKey,
            SigningKeyStatus.Revoked,
            normalizedReplacementKeyId,
            ActivatedAtUtc,
            transitionAtUtc,
            retiringAtUtc: null,
            retiredAtUtc: null,
            revokedAtUtc: transitionAtUtc,
            NextVersion());
    }

    private void EnsureStatus(SigningKeyStatus expectedStatus, string transition)
    {
        if (Status != expectedStatus)
        {
            throw new InvalidOperationException(
                $"Cannot {transition} signing key '{KeyId}' while it is {Status}.");
        }
    }

    private void EnsureOrderedUtc(DateTimeOffset transitionAtUtc, string parameterName)
    {
        SigningKeyLifecycleValidation.EnsureUtc(transitionAtUtc, parameterName);
        if (transitionAtUtc < StatusChangedAtUtc)
        {
            throw new ArgumentOutOfRangeException(
                parameterName,
                transitionAtUtc,
                "A lifecycle transition cannot precede the current key state.");
        }
    }

    private long NextVersion()
    {
        try
        {
            return checked(Version + 1);
        }
        catch (OverflowException exception)
        {
            throw new InvalidOperationException($"Signing key '{KeyId}' exhausted its lifecycle version.", exception);
        }
    }

    private static void ValidatePersistedState(
        string keyId,
        SigningKeyStatus status,
        string? replacementKeyId,
        DateTimeOffset activatedAtUtc,
        DateTimeOffset statusChangedAtUtc,
        DateTimeOffset? retiringAtUtc,
        DateTimeOffset? retiredAtUtc,
        DateTimeOffset? revokedAtUtc,
        long version)
    {
        SigningKeyLifecycleValidation.EnsureUtc(activatedAtUtc, nameof(activatedAtUtc));
        SigningKeyLifecycleValidation.EnsureUtc(statusChangedAtUtc, nameof(statusChangedAtUtc));
        SigningKeyLifecycleValidation.EnsureOptionalUtc(retiringAtUtc, nameof(retiringAtUtc));
        SigningKeyLifecycleValidation.EnsureOptionalUtc(retiredAtUtc, nameof(retiredAtUtc));
        SigningKeyLifecycleValidation.EnsureOptionalUtc(revokedAtUtc, nameof(revokedAtUtc));

        if (version < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(version), "Signing key versions must be positive.");
        }

        if (statusChangedAtUtc < activatedAtUtc ||
            retiringAtUtc < activatedAtUtc ||
            retiredAtUtc < retiringAtUtc ||
            revokedAtUtc < (retiredAtUtc ?? retiringAtUtc ?? activatedAtUtc) ||
            retiringAtUtc > statusChangedAtUtc ||
            retiredAtUtc > statusChangedAtUtc ||
            revokedAtUtc > statusChangedAtUtc)
        {
            throw new ArgumentException("Signing key lifecycle timestamps are not chronologically valid.");
        }

        if (replacementKeyId is not null &&
            string.Equals(keyId, replacementKeyId, StringComparison.Ordinal))
        {
            throw new ArgumentException("A signing key cannot replace itself.", nameof(replacementKeyId));
        }

        var stateIsValid = status switch
        {
            SigningKeyStatus.Active =>
                replacementKeyId is null &&
                retiringAtUtc is null &&
                retiredAtUtc is null &&
                revokedAtUtc is null &&
                statusChangedAtUtc == activatedAtUtc,
            SigningKeyStatus.Retiring =>
                replacementKeyId is not null &&
                retiringAtUtc == statusChangedAtUtc &&
                retiredAtUtc is null &&
                revokedAtUtc is null,
            SigningKeyStatus.Retired =>
                replacementKeyId is not null &&
                retiringAtUtc is not null &&
                retiredAtUtc == statusChangedAtUtc &&
                revokedAtUtc is null,
            SigningKeyStatus.Revoked =>
                revokedAtUtc == statusChangedAtUtc &&
                IsValidRevokedHistory(replacementKeyId, retiringAtUtc, retiredAtUtc),
            _ => false
        };

        if (!stateIsValid)
        {
            throw new ArgumentException($"Signing key '{keyId}' has inconsistent {status} lifecycle metadata.");
        }
    }

    private static bool IsValidRevokedHistory(
        string? replacementKeyId,
        DateTimeOffset? retiringAtUtc,
        DateTimeOffset? retiredAtUtc)
    {
        if (replacementKeyId is null)
        {
            return retiringAtUtc is null && retiredAtUtc is null;
        }

        return retiringAtUtc is null
            ? retiredAtUtc is null
            : retiredAtUtc is null || retiredAtUtc >= retiringAtUtc;
    }
}

/// <summary>
/// Represents the immutable, versioned signing-key lifecycle aggregate for one HIP identity.
/// </summary>
public sealed class SigningKeyRing
{
    private const int MaximumKeyCount = 64;
    private readonly ReadOnlyCollection<ManagedSigningKey> _keys;

    [JsonConstructor]
    private SigningKeyRing(string identityId, long version, IReadOnlyList<ManagedSigningKey> keys)
    {
        ArgumentNullException.ThrowIfNull(keys);
        var normalizedIdentityId = SigningKeyLifecycleValidation.NormalizeIdentityId(identityId, nameof(identityId));
        var keySnapshot = keys.ToArray();
        ValidatePersistedKeySet(normalizedIdentityId, version, keySnapshot);

        IdentityId = normalizedIdentityId;
        Version = version;
        _keys = Array.AsReadOnly(keySnapshot);
    }

    private static void ValidatePersistedKeySet(
        string identityId,
        long version,
        IReadOnlyCollection<ManagedSigningKey> keys)
    {
        if (version < 0 || (keys.Count == 0 && version != 0) || (keys.Count > 0 && version == 0))
        {
            throw new ArgumentOutOfRangeException(
                nameof(version),
                "A signing-key ring version must match whether the aggregate contains key history.");
        }

        if (keys.Count > MaximumKeyCount)
        {
            throw new ArgumentOutOfRangeException(
                nameof(keys),
                $"Identity '{identityId}' cannot retain more than {MaximumKeyCount} managed signing keys.");
        }

        var keyIds = keys.Select(key => key.KeyId).ToHashSet(StringComparer.Ordinal);
        var publicKeys = keys.Select(key => key.PublicKey).ToHashSet(StringComparer.Ordinal);
        var activeKeyCount = keys.Count(key => key.Status == SigningKeyStatus.Active);
        if (keyIds.Count != keys.Count ||
            publicKeys.Count != keys.Count ||
            (keys.Count > 0 && activeKeyCount != 1))
        {
            throw new ArgumentException(
                "A non-empty signing-key ring must contain one active key and cannot reuse identifiers or public keys.",
                nameof(keys));
        }

        if (keys.Any(key =>
                key.ReplacementKeyId is not null &&
                !keyIds.Contains(key.ReplacementKeyId)))
        {
            throw new ArgumentException("Every replacement key reference must exist in the same signing-key ring.", nameof(keys));
        }
    }

    /// <summary>Gets the HIP identity governed by this key ring.</summary>
    public string IdentityId { get; }

    /// <summary>Gets the monotonic aggregate version used for optimistic concurrency.</summary>
    public long Version { get; }

    /// <summary>Gets the complete public lifecycle history retained by the aggregate.</summary>
    public IReadOnlyList<ManagedSigningKey> Keys => _keys;

    /// <summary>Creates an empty signing-key ring for an identity.</summary>
    public static SigningKeyRing Create(string identityId)
    {
        return new SigningKeyRing(
            SigningKeyLifecycleValidation.NormalizeIdentityId(identityId, nameof(identityId)),
            version: 0,
            Array.Empty<ManagedSigningKey>());
    }

    /// <summary>Registers the first active key for the identity.</summary>
    public SigningKeyRing RegisterActiveKey(
        string keyId,
        string algorithm,
        string publicKey,
        DateTimeOffset activatedAtUtc)
    {
        if (_keys.Count != 0)
        {
            throw new InvalidOperationException($"Identity '{IdentityId}' already has a managed signing key.");
        }

        return WithKeys([ManagedSigningKey.CreateActive(keyId, algorithm, publicKey, activatedAtUtc)]);
    }

    /// <summary>
    /// Atomically removes an active key from signing use and activates its unique replacement.
    /// </summary>
    public SigningKeyRing Rotate(
        string currentKeyId,
        string replacementKeyId,
        string algorithm,
        string publicKey,
        DateTimeOffset transitionAtUtc)
    {
        EnsureCanAddKey(replacementKeyId, publicKey);
        var current = GetRequiredKey(currentKeyId);
        var retiring = current.BeginRotation(replacementKeyId, transitionAtUtc);
        var replacement = ManagedSigningKey.CreateActive(
            replacementKeyId,
            algorithm,
            publicKey,
            transitionAtUtc);

        var nextKeys = new ManagedSigningKey[_keys.Count + 1];
        for (var index = 0; index < _keys.Count; index++)
        {
            nextKeys[index] = ReferenceEquals(_keys[index], current) ? retiring : _keys[index];
        }

        nextKeys[^1] = replacement;
        return WithKeys(nextKeys);
    }

    /// <summary>
    /// Atomically revokes a compromised active key and activates a unique replacement.
    /// </summary>
    public SigningKeyRing ReplaceCompromised(
        string compromisedKeyId,
        string replacementKeyId,
        string algorithm,
        string publicKey,
        DateTimeOffset transitionAtUtc)
    {
        EnsureCanAddKey(replacementKeyId, publicKey);
        var current = GetRequiredKey(compromisedKeyId);
        var revoked = current.RevokeWithReplacement(replacementKeyId, transitionAtUtc);
        var replacement = ManagedSigningKey.CreateActive(
            replacementKeyId,
            algorithm,
            publicKey,
            transitionAtUtc);

        var nextKeys = new ManagedSigningKey[_keys.Count + 1];
        for (var index = 0; index < _keys.Count; index++)
        {
            nextKeys[index] = ReferenceEquals(_keys[index], current) ? revoked : _keys[index];
        }

        nextKeys[^1] = replacement;
        return WithKeys(nextKeys);
    }

    /// <summary>Completes retirement of a rotating key while retaining verification metadata.</summary>
    public SigningKeyRing Retire(string keyId, DateTimeOffset transitionAtUtc)
    {
        var current = GetRequiredKey(keyId);
        return Replace(current, current.Retire(transitionAtUtc));
    }

    /// <summary>Revokes a key so it cannot sign or verify historical signatures.</summary>
    public SigningKeyRing Revoke(string keyId, DateTimeOffset transitionAtUtc)
    {
        var current = GetRequiredKey(keyId);
        return Replace(current, current.Revoke(transitionAtUtc));
    }

    /// <summary>Gets an existing key by its exact, stable identifier.</summary>
    public ManagedSigningKey GetRequiredKey(string keyId)
    {
        var normalizedKeyId = SigningKeyLifecycleValidation.NormalizeKeyId(keyId, nameof(keyId));
        foreach (var key in _keys)
        {
            if (string.Equals(key.KeyId, normalizedKeyId, StringComparison.Ordinal))
            {
                return key;
            }
        }

        throw new KeyNotFoundException(
            $"Signing key '{normalizedKeyId}' was not found for identity '{IdentityId}'.");
    }

    private SigningKeyRing Replace(ManagedSigningKey current, ManagedSigningKey replacement)
    {
        var nextKeys = new ManagedSigningKey[_keys.Count];
        for (var index = 0; index < _keys.Count; index++)
        {
            nextKeys[index] = ReferenceEquals(_keys[index], current) ? replacement : _keys[index];
        }

        return WithKeys(nextKeys);
    }

    private void EnsureCanAddKey(string keyId, string publicKey)
    {
        if (_keys.Count >= MaximumKeyCount)
        {
            throw new InvalidOperationException(
                $"Identity '{IdentityId}' cannot retain more than {MaximumKeyCount} managed signing keys.");
        }

        var normalizedKeyId = SigningKeyLifecycleValidation.NormalizeKeyId(keyId, nameof(keyId));
        var normalizedPublicKey = SigningKeyLifecycleValidation.NormalizePublicKey(publicKey, nameof(publicKey));
        if (_keys.Any(key => string.Equals(key.KeyId, normalizedKeyId, StringComparison.Ordinal)))
        {
            throw new InvalidOperationException(
                $"Signing key '{normalizedKeyId}' already exists for identity '{IdentityId}'.");
        }

        if (_keys.Any(key => string.Equals(key.PublicKey, normalizedPublicKey, StringComparison.Ordinal)))
        {
            throw new InvalidOperationException(
                $"Signing key material has already been used for identity '{IdentityId}'.");
        }
    }

    private SigningKeyRing WithKeys(IEnumerable<ManagedSigningKey> keys)
    {
        try
        {
            return new SigningKeyRing(IdentityId, checked(Version + 1), keys.ToArray());
        }
        catch (OverflowException exception)
        {
            throw new InvalidOperationException(
                $"Signing key ring for identity '{IdentityId}' exhausted its aggregate version.",
                exception);
        }
    }
}

/// <summary>Defines public size limits shared by signing-key lifecycle boundaries.</summary>
public static class SigningKeyLifecycleLimits
{
    /// <summary>Maximum persistence-safe length of a HIP identity identifier.</summary>
    public const int MaximumIdentityIdLength = 220;

    /// <summary>Maximum key identifier length allowed by HIP protocol signatures.</summary>
    public const int MaximumKeyIdLength = 128;
}

internal static class SigningKeyLifecycleValidation
{
    private const int MaximumAlgorithmLength = 128;
    private const int MaximumPublicKeyLength = 65_536;

    public static string NormalizeIdentityId(string value, string parameterName) =>
        NormalizeBounded(
            value,
            SigningKeyLifecycleLimits.MaximumIdentityIdLength,
            parameterName,
            "Identity identifier");

    public static string NormalizeKeyId(string value, string parameterName) =>
        NormalizeBounded(
            value,
            SigningKeyLifecycleLimits.MaximumKeyIdLength,
            parameterName,
            "Key identifier");

    public static string NormalizeAlgorithm(string value, string parameterName) =>
        NormalizeBounded(value, MaximumAlgorithmLength, parameterName, "Algorithm identifier");

    public static string NormalizePublicKey(string value, string parameterName) =>
        NormalizeBounded(value, MaximumPublicKeyLength, parameterName, "Public key");

    public static void EnsureUtc(DateTimeOffset value, string parameterName)
    {
        if (value.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Lifecycle timestamps must use the UTC offset.", parameterName);
        }
    }

    public static void EnsureOptionalUtc(DateTimeOffset? value, string parameterName)
    {
        if (value is not null)
        {
            EnsureUtc(value.Value, parameterName);
        }
    }

    private static string NormalizeBounded(
        string value,
        int maximumLength,
        string parameterName,
        string displayName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        var normalized = value.Trim();
        if (normalized.Length > maximumLength)
        {
            throw new ArgumentOutOfRangeException(
                parameterName,
                $"{displayName} cannot exceed {maximumLength} characters.");
        }

        return normalized;
    }
}
