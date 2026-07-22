using HIP.Domain.Identity;

namespace HIP.Application.Identity;

/// <summary>
/// Creates and verifies signatures only through immutable managed signing-key lifecycle records.
/// </summary>
public sealed class HipSignatureService(
    IHipCryptoProvider cryptoProvider,
    IHipIdentityRepository identityRepository,
    ISigningKeyLifecycleService signingKeyLifecycleService) : IHipSignatureService
{
    /// <inheritdoc />
    public async Task<HipSignature> SignAsync(HipSignatureRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var identity = await GetIdentity(request.IdentityId, cancellationToken);
        var keyId = RequireManagedKeyId(request.KeyId, nameof(request));
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
    public async Task<SignatureVerificationResult> VerifyAsync(HipSignatureVerificationRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var identity = await GetIdentity(request.IdentityId, cancellationToken);
        var keyId = RequireManagedKeyId(request.KeyId, nameof(request));
        await EnsureInitialKeyAsync(identity, cancellationToken);
        var reputation = string.IsNullOrWhiteSpace(request.SignerReputationStatus) ? "Unknown" : request.SignerReputationStatus.Trim();
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
            return PolicyRejected(identity, reputation, exception.Message);
        }

        EnsureProviderSupports(managedKey);
        var policyReason = ActiveVerificationPolicyFailure(managedKey);
        if (policyReason is not null)
        {
            return PolicyRejected(identity, reputation, policyReason);
        }

        var valid = cryptoProvider.VerifySignature(
            request.ContentHash,
            request.SignatureValue,
            managedKey.PublicKey);
        var finalRisk = valid && reputation.Equals("Low", StringComparison.OrdinalIgnoreCase) ? "Caution" :
            valid ? "DependsOnReputation" : "Unknown";
        var reason = valid
            ? $"Signature is valid for identity {identity.IdentityId} using managed key {managedKey.KeyId}. HIP knows who signed it and that the signed hash was not changed. This does not automatically mean safe; signer reputation is {reputation}."
            : "Signature is invalid for the supplied content hash or identity.";

        return new SignatureVerificationResult(
            valid,
            identity.IdentityId,
            identity.VerificationStatus,
            valid ? "Verified" : "Invalid",
            reputation,
            finalRisk,
            reason,
            DateTimeOffset.UtcNow);
    }

    /// <inheritdoc />
    public async Task<SigningKey> GetPublicKeyAsync(string identityId, CancellationToken cancellationToken)
    {
        var identity = await GetIdentity(identityId, cancellationToken);
        var keyRing = await EnsureInitialKeyAsync(identity, cancellationToken);
        var managedKey = keyRing.Keys.Single(key => key.Status == SigningKeyStatus.Active);
        return new SigningKey(managedKey.KeyId, managedKey.Algorithm, managedKey.PublicKey);
    }

    private Task<SigningKeyRing> EnsureInitialKeyAsync(
        HipIdentity identity,
        CancellationToken cancellationToken) =>
        signingKeyLifecycleService.EnsureKeyRingAsync(
            new RegisterSigningKeyRequest(
                identity.IdentityId,
                HipIdentityService.InitialSigningKeyId,
                identity.KeyAlgorithm,
                identity.PublicKey,
                "system:legacy-signature-key-bootstrap",
                "Backfill managed signing-key lifecycle for an existing identity.",
                identity.CreatedAtUtc),
            cancellationToken);

    private async Task<HipIdentity> GetIdentity(string identityId, CancellationToken cancellationToken) =>
        await identityRepository.GetAsync(identityId, cancellationToken) ??
        throw new ArgumentException("HIP identity was not found.", nameof(identityId));

    private void EnsureProviderSupports(ManagedSigningKey managedKey)
    {
        if (!string.Equals(cryptoProvider.Capabilities.Algorithm, managedKey.Algorithm, StringComparison.Ordinal))
        {
            throw new NotSupportedException(
                $"The legacy signature provider does not support managed key algorithm '{managedKey.Algorithm}'.");
        }
    }

    private static string RequireManagedKeyId(string? keyId, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(keyId))
        {
            throw new ArgumentException(
                "A managed signing key identifier is required. Legacy signatures without a key identifier must be migrated before verification.",
                parameterName);
        }

        return keyId.Trim();
    }

    private static string? ActiveVerificationPolicyFailure(ManagedSigningKey managedKey) =>
        managedKey.Status == SigningKeyStatus.Active
            ? null
            : $"Managed key '{managedKey.KeyId}' is {managedKey.Status}; this legacy verification contract accepts only Active keys. " +
              "Retiring and Retired keys require cryptographically trusted envelope evidence, which this request cannot supply.";

    private static SignatureVerificationResult PolicyRejected(
        HipIdentity identity,
        string reputation,
        string reason) =>
        new(
            false,
            identity.IdentityId,
            identity.VerificationStatus,
            "Invalid",
            reputation,
            "Unknown",
            $"Signing-key lifecycle policy rejected verification: {reason}",
            DateTimeOffset.UtcNow);
}
