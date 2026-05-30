using HIP.Domain.Identity;

namespace HIP.Application.Identity;

public sealed class HipSignatureService(
    IHipCryptoProvider cryptoProvider,
    IHipIdentityRepository identityRepository) : IHipSignatureService
{
    public async Task<HipSignature> SignAsync(HipSignatureRequest request, CancellationToken cancellationToken)
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

    public async Task<SignatureVerificationResult> VerifyAsync(HipSignatureVerificationRequest request, CancellationToken cancellationToken)
    {
        var identity = await GetIdentity(request.IdentityId, cancellationToken);
        var valid = cryptoProvider.VerifySignature(request.ContentHash, request.SignatureValue, identity.PublicKey);
        var reputation = string.IsNullOrWhiteSpace(request.SignerReputationStatus) ? "Unknown" : request.SignerReputationStatus.Trim();
        var finalRisk = valid && reputation.Equals("Low", StringComparison.OrdinalIgnoreCase) ? "Caution" :
            valid ? "DependsOnReputation" : "Unknown";
        var reason = valid
            ? $"Signature is valid for identity {identity.IdentityId}. HIP knows who signed it and that the signed hash was not changed. This does not automatically mean safe; signer reputation is {reputation}."
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

    public async Task<SigningKey> GetPublicKeyAsync(string identityId, CancellationToken cancellationToken)
    {
        var identity = await GetIdentity(identityId, cancellationToken);
        return new SigningKey("default", identity.KeyAlgorithm, identity.PublicKey);
    }

    private async Task<HipIdentity> GetIdentity(string identityId, CancellationToken cancellationToken) =>
        await identityRepository.GetAsync(identityId, cancellationToken) ??
        throw new ArgumentException("HIP identity was not found.", nameof(identityId));
}
