using HIP.Application.Review;
using HIP.Domain.Audit;
using HIP.Domain.Identity;
using HIP.Domain.Review;

namespace HIP.Application.Identity;

/// <summary>
/// Applies signing-key lifecycle policy through versioned aggregate updates and privacy-safe audit evidence.
/// </summary>
public sealed class SigningKeyLifecycleService(
    ISigningKeyLifecycleRepository repository,
    IAuditLogService auditLogService) : ISigningKeyLifecycleService
{
    private const int MaximumActorIdLength = 256;
    private const int MaximumReasonLength = 1_024;

    /// <inheritdoc />
    public async Task<SigningKeyRing> RegisterAsync(
        RegisterSigningKeyRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateEvidence(request.ActorId, request.Reason);

        var keyRing = SigningKeyRing.Create(request.IdentityId)
            .RegisterActiveKey(
                request.KeyId,
                request.Algorithm,
                request.PublicKey,
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
        var updatedRing = currentRing.Rotate(
            request.CurrentKeyId,
            request.ReplacementKeyId,
            request.Algorithm,
            request.PublicKey,
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
        var updatedRing = currentRing.ReplaceCompromised(
            request.CompromisedKeyId,
            request.ReplacementKeyId,
            request.Algorithm,
            request.PublicKey,
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
