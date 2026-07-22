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
        var reputation = string.IsNullOrWhiteSpace(request.SignerReputationStatus) ? "Unknown" : request.SignerReputationStatus.Trim();
        ManagedSigningKey managedKey;
        try
        {
            managedKey = await signingKeyLifecycleService.GetRequiredHistoricalVerificationKeyAsync(
                identity.IdentityId,
                keyId,
                cancellationToken);
        }
        catch (InvalidOperationException exception)
        {
            return PolicyRejected(identity, reputation, exception.Message);
        }

        EnsureProviderSupports(managedKey);
        var policyReason = HistoricalPolicyFailure(managedKey, request.TrustedSignedAtUtc);
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
        var managedKey = await signingKeyLifecycleService.GetRequiredHistoricalVerificationKeyAsync(
            identity.IdentityId,
            HipIdentityService.InitialSigningKeyId,
            cancellationToken);
        return new SigningKey(managedKey.KeyId, managedKey.Algorithm, managedKey.PublicKey);
    }

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

    private static string? HistoricalPolicyFailure(
        ManagedSigningKey managedKey,
        DateTimeOffset? trustedSignedAtUtc)
    {
        if (trustedSignedAtUtc is not null)
        {
            return managedKey.CanVerifySignatureIssuedAt(trustedSignedAtUtc.Value)
                ? null
                : $"Trusted signing time is outside the signing window for managed key '{managedKey.KeyId}'.";
        }

        return managedKey.Status == SigningKeyStatus.Active
            ? null
            : $"Managed key '{managedKey.KeyId}' is {managedKey.Status}; a trusted signing time is required for historical verification.";
    }

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
