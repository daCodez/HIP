using HIP.Domain.Identity;

namespace HIP.Application.Identity;

/// <summary>
/// Provides the local-development identity flow while enforcing managed signing-key lifecycle policy.
/// </summary>
public sealed class HipIdentityService(
    IHipCryptoProvider cryptoProvider,
    IHipIdentityRepository identityRepository,
    ISigningKeyLifecycleService signingKeyLifecycleService) : IHipIdentityService
{
    /// <summary>Stable identifier assigned to the first managed signing key created with an identity.</summary>
    public const string InitialSigningKeyId = "default";

    /// <inheritdoc />
    public async Task<IdentityRegistrationResponse> RegisterAsync(IdentityRegistrationRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.DisplayName))
        {
            throw new ArgumentException("Display name is required.", nameof(request));
        }

        var keyPair = cryptoProvider.GenerateKeyPair();
        var targetId = string.IsNullOrWhiteSpace(request.ReputationTargetId) ? request.DisplayName.Trim().ToLowerInvariant() : request.ReputationTargetId.Trim().ToLowerInvariant();
        var createdAtUtc = DateTimeOffset.UtcNow;
        var identity = new HipIdentity(
            $"hip:{request.IdentityType.ToString().ToLowerInvariant()}:{Guid.NewGuid():N}",
            request.IdentityType,
            request.DisplayName.Trim(),
            keyPair.PublicKey,
            keyPair.Algorithm,
            VerificationStatus.Pending,
            createdAtUtc,
            targetId);

        var registration = await signingKeyLifecycleService.RegisterIdentityAsync(
            new RegisterIdentitySigningKeyRequest(
                identity,
                InitialSigningKeyId,
                "system:identity-registration",
                "Register the identity and its initial managed signing key atomically.",
                createdAtUtc),
            cancellationToken);
        return new IdentityRegistrationResponse(
            registration.Identity,
            keyPair.PrivateKey,
            "Development private key is returned only by DevelopmentHipCryptoProvider and is not production-safe.");
    }

    /// <inheritdoc />
    public async Task<HipSignature> SignAsync(SignContentRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var identity = await GetIdentity(request.IdentityId, cancellationToken);
        var keyId = DevelopmentKeyId(request.KeyId);
        await EnsureInitialKeyAsync(identity, cancellationToken);
        var managedKey = await signingKeyLifecycleService.GetRequiredSigningKeyAsync(
            identity.IdentityId,
            keyId,
            cancellationToken);
        EnsureProviderSupports(managedKey);
        var signature = cryptoProvider.SignHash(request.ContentHash, request.DevelopmentPrivateKey);
        if (!cryptoProvider.VerifySignature(request.ContentHash, signature, managedKey.PublicKey))
        {
            throw new ArgumentException(
                $"Development private key does not match managed signing key '{managedKey.KeyId}'.",
                nameof(request));
        }

        return new HipSignature(
            $"sig:{Guid.NewGuid():N}",
            identity.IdentityId,
            managedKey.Algorithm,
            request.ContentHash,
            signature,
            DateTimeOffset.UtcNow,
            request.ExpiresAtUtc,
            managedKey.KeyId);
    }

    /// <inheritdoc />
    public async Task<VerificationResult> VerifyAsync(VerifySignatureRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var identity = await GetIdentity(request.IdentityId, cancellationToken);
        var keyId = DevelopmentKeyId(request.KeyId);
        await EnsureInitialKeyAsync(identity, cancellationToken);
        ManagedSigningKey managedKey;
        try
        {
            managedKey = await signingKeyLifecycleService.GetRequiredHistoricalVerificationKeyAsync(
                identity.IdentityId,
                keyId,
                cancellationToken);
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or KeyNotFoundException)
        {
            return InvalidVerification(identity, exception.Message);
        }

        EnsureProviderSupports(managedKey);
        var policyReason = ActiveVerificationPolicyFailure(managedKey);
        if (policyReason is not null)
        {
            return InvalidVerification(identity, policyReason);
        }

        var valid = cryptoProvider.VerifySignature(request.ContentHash, request.SignatureValue, managedKey.PublicKey);
        var reason = valid
            ? $"Signature is valid for managed key {managedKey.KeyId}. HIP knows who signed this content and that the signed hash was not changed. Safety still depends on reputation and risk scoring."
            : "Signature is invalid for the supplied content hash or identity.";

        return new VerificationResult(valid, identity.IdentityId, identity.VerificationStatus, reason, DateTimeOffset.UtcNow);
    }

    private Task<SigningKeyRing> EnsureInitialKeyAsync(
        HipIdentity identity,
        CancellationToken cancellationToken) =>
        signingKeyLifecycleService.EnsureKeyRingAsync(
            new RegisterSigningKeyRequest(
                identity.IdentityId,
                InitialSigningKeyId,
                identity.KeyAlgorithm,
                identity.PublicKey,
                "system:legacy-identity-key-bootstrap",
                "Backfill managed signing-key lifecycle for an existing identity.",
                identity.CreatedAtUtc),
            cancellationToken);

    private async Task<HipIdentity> GetIdentity(string identityId, CancellationToken cancellationToken) =>
        await identityRepository.GetAsync(identityId, cancellationToken) ??
        throw new ArgumentException("HIP identity was not found.", nameof(identityId));

    private static string DevelopmentKeyId(string? keyId) =>
        string.IsNullOrWhiteSpace(keyId) ? InitialSigningKeyId : keyId.Trim();

    private void EnsureProviderSupports(ManagedSigningKey managedKey)
    {
        if (!string.Equals(cryptoProvider.Capabilities.Algorithm, managedKey.Algorithm, StringComparison.Ordinal))
        {
            throw new NotSupportedException(
                $"The development identity provider does not support managed key algorithm '{managedKey.Algorithm}'.");
        }
    }

    private static string? ActiveVerificationPolicyFailure(ManagedSigningKey managedKey) =>
        managedKey.Status == SigningKeyStatus.Active
            ? null
            : $"Managed key '{managedKey.KeyId}' is {managedKey.Status}; this legacy verification contract accepts only Active keys. " +
              "Retiring and Retired keys require cryptographically trusted envelope evidence, which this request cannot supply.";

    private static VerificationResult InvalidVerification(HipIdentity identity, string reason) =>
        new(
            false,
            identity.IdentityId,
            identity.VerificationStatus,
            $"Signing-key lifecycle policy rejected verification: {reason}",
            DateTimeOffset.UtcNow);
}
