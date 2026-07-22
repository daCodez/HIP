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

        await identityRepository.SaveAsync(identity, cancellationToken);
        await signingKeyLifecycleService.RegisterAsync(
            new RegisterSigningKeyRequest(
                identity.IdentityId,
                InitialSigningKeyId,
                keyPair.Algorithm,
                keyPair.PublicKey,
                "system:identity-registration",
                "Register the identity's initial managed signing key.",
                createdAtUtc),
            cancellationToken);
        return new IdentityRegistrationResponse(
            identity,
            keyPair.PrivateKey,
            "Development private key is returned only by DevelopmentHipCryptoProvider and is not production-safe.");
    }

    /// <inheritdoc />
    public async Task<HipSignature> SignAsync(SignContentRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var identity = await GetIdentity(request.IdentityId, cancellationToken);
        var managedKey = await signingKeyLifecycleService.GetRequiredSigningKeyAsync(
            identity.IdentityId,
            DevelopmentKeyId(request.KeyId),
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
        ManagedSigningKey managedKey;
        try
        {
            managedKey = await signingKeyLifecycleService.GetRequiredHistoricalVerificationKeyAsync(
                identity.IdentityId,
                DevelopmentKeyId(request.KeyId),
                cancellationToken);
        }
        catch (InvalidOperationException exception)
        {
            return InvalidVerification(identity, exception.Message);
        }

        EnsureProviderSupports(managedKey);
        var policyReason = HistoricalPolicyFailure(managedKey, request.TrustedSignedAtUtc);
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

    private static VerificationResult InvalidVerification(HipIdentity identity, string reason) =>
        new(
            false,
            identity.IdentityId,
            identity.VerificationStatus,
            $"Signing-key lifecycle policy rejected verification: {reason}",
            DateTimeOffset.UtcNow);
}
