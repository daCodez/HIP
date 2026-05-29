using HIP.Domain.Identity;

namespace HIP.Application.Identity;

public sealed class HipIdentityService(
    IHipCryptoProvider cryptoProvider,
    IHipIdentityRepository identityRepository) : IHipIdentityService
{
    public async Task<IdentityRegistrationResponse> RegisterAsync(IdentityRegistrationRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.DisplayName))
        {
            throw new ArgumentException("Display name is required.", nameof(request));
        }

        var keyPair = cryptoProvider.GenerateKeyPair();
        var targetId = string.IsNullOrWhiteSpace(request.ReputationTargetId) ? request.DisplayName.Trim().ToLowerInvariant() : request.ReputationTargetId.Trim().ToLowerInvariant();
        var identity = new HipIdentity(
            $"hip:{request.IdentityType.ToString().ToLowerInvariant()}:{Guid.NewGuid():N}",
            request.IdentityType,
            request.DisplayName.Trim(),
            keyPair.PublicKey,
            keyPair.Algorithm,
            VerificationStatus.Pending,
            DateTimeOffset.UtcNow,
            targetId);

        await identityRepository.SaveAsync(identity, cancellationToken);
        return new IdentityRegistrationResponse(
            identity,
            keyPair.PrivateKey,
            "Development private key is returned only by DevelopmentHipCryptoProvider and is not production-safe.");
    }

    public async Task<HipSignature> SignAsync(SignContentRequest request, CancellationToken cancellationToken)
    {
        var identity = await GetIdentity(request.IdentityId, cancellationToken);
        var signature = cryptoProvider.SignHash(request.ContentHash, request.DevelopmentPrivateKey);

        return new HipSignature(
            $"sig:{Guid.NewGuid():N}",
            identity.IdentityId,
            identity.KeyAlgorithm,
            request.ContentHash,
            signature,
            DateTimeOffset.UtcNow,
            request.ExpiresAtUtc);
    }

    public async Task<VerificationResult> VerifyAsync(VerifySignatureRequest request, CancellationToken cancellationToken)
    {
        var identity = await GetIdentity(request.IdentityId, cancellationToken);
        var valid = cryptoProvider.VerifySignature(request.ContentHash, request.SignatureValue, identity.PublicKey);
        var reason = valid
            ? "Signature is valid. HIP knows who signed this content and that the signed hash was not changed. Safety still depends on reputation and risk scoring."
            : "Signature is invalid for the supplied content hash or identity.";

        return new VerificationResult(valid, identity.IdentityId, identity.VerificationStatus, reason, DateTimeOffset.UtcNow);
    }

    private async Task<HipIdentity> GetIdentity(string identityId, CancellationToken cancellationToken) =>
        await identityRepository.GetAsync(identityId, cancellationToken) ??
        throw new ArgumentException("HIP identity was not found.", nameof(identityId));
}
