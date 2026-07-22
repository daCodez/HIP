using HIP.Application.Review;
using HIP.Application.Protocol;
using HIP.Domain.Audit;
using HIP.Domain.Identity;
using HIP.Domain.Review;

namespace HIP.Application.Identity;

/// <summary>
/// Applies signing-key lifecycle policy through versioned aggregate updates and privacy-safe audit evidence.
/// </summary>
public sealed class SigningKeyLifecycleService(
    ISigningKeyLifecycleRepository repository,
    IAuditLogService auditLogService,
    IHipPublicKeyFingerprintService publicKeyFingerprintService) : ISigningKeyLifecycleService
{
    private const int MaximumActorIdLength = 256;
    private const int MaximumReasonLength = 1_024;

    /// <inheritdoc />
    public async Task<IdentitySigningKeyRegistrationResult> RegisterIdentityAsync(
        RegisterIdentitySigningKeyRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Identity);
        ValidateEvidence(request.ActorId, request.Reason);

        var identity = request.Identity;
        var publicKeyFingerprint = publicKeyFingerprintService.ComputePublicKeyFingerprint(
            identity.KeyAlgorithm,
            identity.PublicKey);
        var keyRing = SigningKeyRing.Create(identity.IdentityId)
            .RegisterActiveKey(
                request.KeyId,
                identity.KeyAlgorithm,
                identity.PublicKey,
                publicKeyFingerprint,
                request.TransitionAtUtc);
        var auditEntry = CreateAudit(
            request.ActorId,
            request.Reason,
            request.TransitionAtUtc,
            keyRing,
            keyRing.GetRequiredKey(request.KeyId),
            fromStatus: "Unregistered",
            action: "IdentityAndSigningKeyRegistered",
            AuditSeverity.Medium);
        var lifecycleTransition = new SigningKeyLifecycleTransitionBatch(
            keyRing,
            expectedVersion: 0,
            [auditEntry]);
        var registrationBatch = new IdentitySigningKeyRegistrationBatch(identity, lifecycleTransition);

        try
        {
            if (await repository.TryRegisterIdentityAsync(registrationBatch, cancellationToken)
                    .ConfigureAwait(false))
            {
                return new IdentitySigningKeyRegistrationResult(identity, keyRing);
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            var committed = await ReconcileInitialRegistrationAsync(
                    identity,
                    keyRing,
                    cancellationToken)
                .ConfigureAwait(false);
            if (committed is not null)
            {
                return committed;
            }

            throw;
        }

        return await ReconcileInitialRegistrationAsync(identity, keyRing, cancellationToken)
                   .ConfigureAwait(false) ??
               throw new IdentitySigningKeyRegistrationConflictException(
                   identity.IdentityId,
                   request.KeyId);
    }

    /// <inheritdoc />
    public async Task<SigningKeyRing> RegisterAsync(
        RegisterSigningKeyRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateEvidence(request.ActorId, request.Reason);

        var publicKeyFingerprint = publicKeyFingerprintService.ComputePublicKeyFingerprint(
            request.Algorithm,
            request.PublicKey);
        var keyRing = SigningKeyRing.Create(request.IdentityId)
            .RegisterActiveKey(
                request.KeyId,
                request.Algorithm,
                request.PublicKey,
                publicKeyFingerprint,
                request.TransitionAtUtc);

        var auditEntry = CreateAudit(
            request.ActorId,
            request.Reason,
            request.TransitionAtUtc,
            keyRing,
            keyRing.GetRequiredKey(request.KeyId),
            fromStatus: "Unregistered",
            action: "SigningKeyActivated",
            AuditSeverity.Medium);
        await SaveRequiredAsync(keyRing, expectedVersion: 0, [auditEntry], cancellationToken)
            .ConfigureAwait(false);
        return keyRing;
    }

    /// <inheritdoc />
    public async Task<SigningKeyRing> EnsureInitialKeyAsync(
        RegisterSigningKeyRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateEvidence(request.ActorId, request.Reason);

        var publicKeyFingerprint = publicKeyFingerprintService.ComputePublicKeyFingerprint(
            request.Algorithm,
            request.PublicKey);
        var requestedRing = SigningKeyRing.Create(request.IdentityId)
            .RegisterActiveKey(
                request.KeyId,
                request.Algorithm,
                request.PublicKey,
                publicKeyFingerprint,
                request.TransitionAtUtc);

        var existingRing = await repository.GetAsync(
                requestedRing.IdentityId,
                cancellationToken)
            .ConfigureAwait(false);
        if (existingRing is not null)
        {
            return EnsureBootstrapMatch(existingRing, requestedRing);
        }

        var auditEntry = CreateAudit(
            request.ActorId,
            request.Reason,
            request.TransitionAtUtc,
            requestedRing,
            requestedRing.GetRequiredKey(request.KeyId),
            fromStatus: "Unregistered",
            action: "SigningKeyActivated",
            AuditSeverity.Medium);
        var transitionBatch = new SigningKeyLifecycleTransitionBatch(
            requestedRing,
            expectedVersion: 0,
            [auditEntry]);
        if (await repository.TrySaveAsync(transitionBatch, cancellationToken)
                .ConfigureAwait(false))
        {
            return requestedRing;
        }

        var concurrentWinner = await repository.GetAsync(
                requestedRing.IdentityId,
                cancellationToken)
            .ConfigureAwait(false);
        return concurrentWinner is null
            ? throw new SigningKeyConcurrencyException(requestedRing.IdentityId, expectedVersion: 0)
            : EnsureBootstrapMatch(concurrentWinner, requestedRing);
    }

    /// <inheritdoc />
    public async Task<SigningKeyRing> EnsureKeyRingAsync(
        RegisterSigningKeyRequest fallbackInitialKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fallbackInitialKey);
        ValidateEvidence(fallbackInitialKey.ActorId, fallbackInitialKey.Reason);

        var existingRing = await repository.GetAsync(
                fallbackInitialKey.IdentityId,
                cancellationToken)
            .ConfigureAwait(false);
        if (existingRing is not null)
        {
            return EnsureIdentityBinding(existingRing, fallbackInitialKey);
        }

        try
        {
            return await EnsureInitialKeyAsync(fallbackInitialKey, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (SigningKeyBootstrapMismatchException)
        {
            // A different authoritative registration may win after the missing-ring read.
            // Read-through never rewrites or reactivates that winner.
            var concurrentWinner = await repository.GetAsync(
                    fallbackInitialKey.IdentityId,
                    cancellationToken)
                .ConfigureAwait(false);
            if (concurrentWinner is not null)
            {
                return EnsureIdentityBinding(concurrentWinner, fallbackInitialKey);
            }

            throw;
        }
    }

    /// <inheritdoc />
    public async Task<SigningKeyRotationResult> RotateAsync(
        RotateSigningKeyRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateEvidence(request.ActorId, request.Reason);

        var currentRing = await GetRequiredRingAsync(request.IdentityId, cancellationToken)
            .ConfigureAwait(false);
        EnsureExpectedVersion(currentRing, request.ExpectedVersion);

        var previousStatus = currentRing.GetRequiredKey(request.CurrentKeyId).Status;
        var publicKeyFingerprint = publicKeyFingerprintService.ComputePublicKeyFingerprint(
            request.Algorithm,
            request.PublicKey);
        var updatedRing = currentRing.Rotate(
            request.CurrentKeyId,
            request.ReplacementKeyId,
            request.Algorithm,
            request.PublicKey,
            publicKeyFingerprint,
            request.TransitionAtUtc);

        var previousKey = updatedRing.GetRequiredKey(request.CurrentKeyId);
        var replacementKey = updatedRing.GetRequiredKey(request.ReplacementKeyId);
        var previousAudit = CreateAudit(
            request.ActorId,
            request.Reason,
            request.TransitionAtUtc,
            updatedRing,
            previousKey,
            previousStatus.ToString(),
            "SigningKeyRotationStarted",
            AuditSeverity.Medium);
        var replacementAudit = CreateAudit(
            request.ActorId,
            request.Reason,
            request.TransitionAtUtc,
            updatedRing,
            replacementKey,
            fromStatus: "Unregistered",
            action: "SigningKeyActivated",
            AuditSeverity.Medium);

        await SaveRequiredAsync(
                updatedRing, request.ExpectedVersion, [previousAudit, replacementAudit], cancellationToken)
            .ConfigureAwait(false);

        return new SigningKeyRotationResult(previousKey, replacementKey, updatedRing);
    }

    /// <inheritdoc />
    public async Task<SigningKeyEmergencyReplacementResult> EmergencyReplaceAsync(
        EmergencyReplaceSigningKeyRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateEvidence(request.ActorId, request.Reason);

        var currentRing = await GetRequiredRingAsync(request.IdentityId, cancellationToken)
            .ConfigureAwait(false);
        EnsureExpectedVersion(currentRing, request.ExpectedVersion);

        var previousStatus = currentRing.GetRequiredKey(request.CompromisedKeyId).Status;
        var publicKeyFingerprint = publicKeyFingerprintService.ComputePublicKeyFingerprint(
            request.Algorithm,
            request.PublicKey);
        var updatedRing = currentRing.ReplaceCompromised(
            request.CompromisedKeyId,
            request.ReplacementKeyId,
            request.Algorithm,
            request.PublicKey,
            publicKeyFingerprint,
            request.TransitionAtUtc);

        var compromisedKey = updatedRing.GetRequiredKey(request.CompromisedKeyId);
        var replacementKey = updatedRing.GetRequiredKey(request.ReplacementKeyId);
        var compromisedAudit = CreateAudit(
            request.ActorId,
            request.Reason,
            request.TransitionAtUtc,
            updatedRing,
            compromisedKey,
            previousStatus.ToString(),
            "SigningKeyEmergencyRevoked",
            AuditSeverity.Critical);
        var replacementAudit = CreateAudit(
            request.ActorId,
            request.Reason,
            request.TransitionAtUtc,
            updatedRing,
            replacementKey,
            fromStatus: "Unregistered",
            action: "SigningKeyEmergencyReplacementActivated",
            AuditSeverity.Critical);

        await SaveRequiredAsync(
                updatedRing, request.ExpectedVersion, [compromisedAudit, replacementAudit], cancellationToken)
            .ConfigureAwait(false);

        return new SigningKeyEmergencyReplacementResult(
            compromisedKey,
            replacementKey,
            updatedRing);
    }

    /// <inheritdoc />
    public Task<SigningKeyRing> RetireAsync(
        ChangeSigningKeyStateRequest request,
        CancellationToken cancellationToken) =>
        ChangeStateAsync(request, static (ring, keyId, atUtc) => ring.Retire(keyId, atUtc),
            "SigningKeyRetired", AuditSeverity.Low, cancellationToken);

    /// <inheritdoc />
    public Task<SigningKeyRing> RevokeAsync(
        ChangeSigningKeyStateRequest request,
        CancellationToken cancellationToken) =>
        ChangeStateAsync(request, static (ring, keyId, atUtc) => ring.Revoke(keyId, atUtc),
            "SigningKeyRevoked", AuditSeverity.High, cancellationToken);

    /// <inheritdoc />
    public async Task<ManagedSigningKey> GetRequiredSigningKeyAsync(
        string identityId,
        string keyId,
        CancellationToken cancellationToken)
    {
        var key = (await GetRequiredRingAsync(identityId, cancellationToken).ConfigureAwait(false))
            .GetRequiredKey(keyId);
        if (!key.CanCreateSignature)
        {
            throw new InvalidOperationException(
                $"Signing key '{key.KeyId}' is not active and cannot create signatures.");
        }

        return key;
    }

    /// <inheritdoc />
    public async Task<ManagedSigningKey> GetRequiredHistoricalVerificationKeyAsync(
        string identityId,
        string keyId,
        CancellationToken cancellationToken)
    {
        var key = (await GetRequiredRingAsync(identityId, cancellationToken).ConfigureAwait(false))
            .GetRequiredKey(keyId);
        if (!key.CanVerifyHistoricalSignature)
        {
            throw new InvalidOperationException(
                $"Signing key '{key.KeyId}' is revoked and cannot verify historical signatures.");
        }

        return key;
    }

    private async Task<SigningKeyRing> ChangeStateAsync(
        ChangeSigningKeyStateRequest request,
        Func<SigningKeyRing, string, DateTimeOffset, SigningKeyRing> transition,
        string action,
        AuditSeverity severity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateEvidence(request.ActorId, request.Reason);

        var currentRing = await GetRequiredRingAsync(request.IdentityId, cancellationToken)
            .ConfigureAwait(false);
        EnsureExpectedVersion(currentRing, request.ExpectedVersion);
        var previousStatus = currentRing.GetRequiredKey(request.KeyId).Status;
        var updatedRing = transition(currentRing, request.KeyId, request.TransitionAtUtc);

        var auditEntry = CreateAudit(
            request.ActorId,
            request.Reason,
            request.TransitionAtUtc,
            updatedRing,
            updatedRing.GetRequiredKey(request.KeyId),
            previousStatus.ToString(),
            action,
            severity);
        await SaveRequiredAsync(updatedRing, request.ExpectedVersion, [auditEntry], cancellationToken)
            .ConfigureAwait(false);
        return updatedRing;
    }

    private static SigningKeyRing EnsureBootstrapMatch(
        SigningKeyRing existingRing,
        SigningKeyRing requestedRing)
    {
        var requestedKey = requestedRing.Keys.Single();
        var existingKey = existingRing.Keys.SingleOrDefault(key =>
            string.Equals(key.KeyId, requestedKey.KeyId, StringComparison.Ordinal));

        if (string.Equals(
                existingRing.IdentityId,
                requestedRing.IdentityId,
                StringComparison.Ordinal) &&
            existingKey is not null &&
            string.Equals(
                existingKey.Algorithm,
                requestedKey.Algorithm,
                StringComparison.Ordinal) &&
            string.Equals(
                existingKey.PublicKeyFingerprint,
                requestedKey.PublicKeyFingerprint,
                StringComparison.Ordinal))
        {
            return existingRing;
        }

        throw new SigningKeyBootstrapMismatchException(existingRing.IdentityId, requestedKey.KeyId);
    }

    private SigningKeyRing EnsureIdentityBinding(
        SigningKeyRing existingRing,
        RegisterSigningKeyRequest fallbackInitialKey)
    {
        var identityPublicKeyFingerprint = publicKeyFingerprintService.ComputePublicKeyFingerprint(
            fallbackInitialKey.Algorithm,
            fallbackInitialKey.PublicKey);
        if (string.Equals(
                existingRing.IdentityId,
                fallbackInitialKey.IdentityId,
                StringComparison.Ordinal) &&
            existingRing.Keys.Any(key =>
                string.Equals(key.Algorithm, fallbackInitialKey.Algorithm, StringComparison.Ordinal) &&
                string.Equals(
                    key.PublicKeyFingerprint,
                    identityPublicKeyFingerprint,
                    StringComparison.Ordinal)))
        {
            return existingRing;
        }

        throw new SigningKeyBootstrapMismatchException(
            existingRing.IdentityId,
            fallbackInitialKey.KeyId);
    }

    private async Task<IdentitySigningKeyRegistrationResult?> ReconcileInitialRegistrationAsync(
        HipIdentity requestedIdentity,
        SigningKeyRing requestedRing,
        CancellationToken cancellationToken)
    {
        var storedIdentity = await repository.GetRegisteredIdentityAsync(
                requestedIdentity.IdentityId,
                cancellationToken)
            .ConfigureAwait(false);
        var storedRing = await repository.GetAsync(
                requestedIdentity.IdentityId,
                cancellationToken)
            .ConfigureAwait(false);

        if (storedIdentity is null && storedRing is null)
        {
            return null;
        }

        if (storedIdentity is null || storedRing is null)
        {
            throw new IdentitySigningKeyRegistrationInconsistencyException(
                requestedIdentity.IdentityId,
                identityExists: storedIdentity is not null,
                keyRingExists: storedRing is not null);
        }

        var requestedKey = requestedRing.Keys.Single();
        var storedKey = storedRing.Keys.SingleOrDefault(key =>
            string.Equals(key.KeyId, requestedKey.KeyId, StringComparison.Ordinal));
        var storedIdentityFingerprint = publicKeyFingerprintService.ComputePublicKeyFingerprint(
            storedIdentity.KeyAlgorithm,
            storedIdentity.PublicKey);
        if (!IdentityMatches(
                storedIdentity,
                requestedIdentity,
                storedIdentityFingerprint,
                requestedKey.PublicKeyFingerprint) ||
            !string.Equals(storedRing.IdentityId, requestedRing.IdentityId, StringComparison.Ordinal) ||
            storedKey is null ||
            !string.Equals(storedKey.Algorithm, requestedKey.Algorithm, StringComparison.Ordinal) ||
            !string.Equals(
                storedKey.PublicKeyFingerprint,
                requestedKey.PublicKeyFingerprint,
                StringComparison.Ordinal) ||
            storedKey.ActivatedAtUtc != requestedKey.ActivatedAtUtc)
        {
            throw new IdentitySigningKeyRegistrationConflictException(
                requestedIdentity.IdentityId,
                requestedKey.KeyId);
        }

        return new IdentitySigningKeyRegistrationResult(storedIdentity, storedRing);
    }

    private static bool IdentityMatches(
        HipIdentity stored,
        HipIdentity requested,
        string storedPublicKeyFingerprint,
        string requestedPublicKeyFingerprint) =>
        string.Equals(stored.IdentityId, requested.IdentityId, StringComparison.Ordinal) &&
        stored.IdentityType == requested.IdentityType &&
        string.Equals(stored.DisplayName, requested.DisplayName, StringComparison.Ordinal) &&
        string.Equals(stored.KeyAlgorithm, requested.KeyAlgorithm, StringComparison.Ordinal) &&
        string.Equals(storedPublicKeyFingerprint, requestedPublicKeyFingerprint, StringComparison.Ordinal) &&
        stored.VerificationStatus == requested.VerificationStatus &&
        stored.CreatedAtUtc == requested.CreatedAtUtc &&
        string.Equals(stored.ReputationTargetId, requested.ReputationTargetId, StringComparison.Ordinal);

    private async Task<SigningKeyRing> GetRequiredRingAsync(
        string identityId,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identityId);
        return await repository.GetAsync(identityId, cancellationToken).ConfigureAwait(false)
            ?? throw new KeyNotFoundException(
                $"Signing key ring for identity '{identityId}' was not found.");
    }

    private async Task SaveRequiredAsync(
        SigningKeyRing keyRing,
        long expectedVersion,
        IReadOnlyCollection<AuditLogEntry> auditEntries,
        CancellationToken cancellationToken)
    {
        var transitionBatch = new SigningKeyLifecycleTransitionBatch(
            keyRing, expectedVersion, auditEntries);
        if (!await repository.TrySaveAsync(transitionBatch, cancellationToken)
                .ConfigureAwait(false))
        {
            throw new SigningKeyConcurrencyException(keyRing.IdentityId, expectedVersion);
        }
    }

    private static void EnsureExpectedVersion(SigningKeyRing keyRing, long expectedVersion)
    {
        if (keyRing.Version != expectedVersion)
        {
            throw new SigningKeyConcurrencyException(keyRing.IdentityId, expectedVersion);
        }
    }

    private static void ValidateEvidence(string actorId, string reason)
    {
        ValidateBounded(actorId, nameof(actorId), MaximumActorIdLength);
        ValidateBounded(reason, nameof(reason), MaximumReasonLength);
    }

    private static void ValidateBounded(string value, string parameterName, int maximumLength)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length > maximumLength)
        {
            throw new ArgumentOutOfRangeException(
                parameterName,
                $"{parameterName} cannot exceed {maximumLength} characters.");
        }
    }

    private AuditLogEntry CreateAudit(
        string actorId,
        string reason,
        DateTimeOffset transitionAtUtc,
        SigningKeyRing keyRing,
        ManagedSigningKey key,
        string fromStatus,
        string action,
        AuditSeverity severity)
    {
        var metadata = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["identityId"] = keyRing.IdentityId,
            ["keyId"] = key.KeyId,
            ["algorithm"] = key.Algorithm,
            ["fromStatus"] = fromStatus,
            ["toStatus"] = key.Status.ToString(),
            ["aggregateVersion"] = keyRing.Version.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["transitionAtUtc"] = transitionAtUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
            ["reason"] = reason
        };
        if (key.ReplacementKeyId is not null)
        {
            metadata["replacementKeyId"] = key.ReplacementKeyId;
        }

        return auditLogService.CreateEntry(
            actorId,
            action,
            TargetType.DeviceKey,
            $"{keyRing.IdentityId}:{key.KeyId}",
            reason,
            severity,
            metadata);
    }
}
