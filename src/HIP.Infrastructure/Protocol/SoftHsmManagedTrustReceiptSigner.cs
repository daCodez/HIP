using System.Security.Cryptography;
using System.Text;
using HIP.Application.Identity;
using HIP.Application.Protocol;
using HIP.Domain.Identity;

namespace HIP.Infrastructure.Protocol;

/// <summary>
/// Adapts HIP's managed signing boundary to a software PKCS #11 token and maintains only public lifecycle state.
/// </summary>
internal sealed class SoftHsmManagedTrustReceiptSigner(
    SoftHsmManagedSignerIdentityOptions identityOptions,
    ISoftHsmPkcs11Client softHsm,
    MlDsa65SignatureProvider verifier,
    ISigningKeyLifecycleService lifecycleService,
    ISigningKeyLifecycleRepository repository,
    TimeProvider timeProvider) : IManagedTrustReceiptSigner
{
    private readonly SoftHsmManagedSignerIdentityOptions identity = identityOptions;
    private readonly ISoftHsmPkcs11Client token = softHsm;
    private readonly MlDsa65SignatureProvider signatureVerifier = verifier;
    private readonly ISigningKeyLifecycleService lifecycle = lifecycleService;
    private readonly ISigningKeyLifecycleRepository keyRepository = repository;
    private readonly TimeProvider clock = timeProvider;
    private readonly SemaphoreSlim lifecycleLock = new(1, 1);

    public async Task<HipManagedTrustReceiptSigningKey> GetSigningKeyAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var tokenKey = await token.GetSigningKeyAsync(cancellationToken).ConfigureAwait(false);
        _ = signatureVerifier.ComputePublicKeyFingerprint(tokenKey.PublicKeyPem);

        await lifecycleLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLifecycleStateAsync(tokenKey.PublicKeyPem, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            lifecycleLock.Release();
        }

        return SigningKey();
    }

    public async Task<string> SignHashAsync(
        HipManagedTrustReceiptSigningKey signingKey,
        string contentHash,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(contentHash);
        cancellationToken.ThrowIfCancellationRequested();
        if (signingKey != SigningKey())
        {
            throw new InvalidOperationException("The requested signing key does not match the configured SoftHSM authority.");
        }

        var durableKey = await lifecycle.GetRequiredSigningKeyAsync(
                identity.IssuerId,
                identity.KeyId,
                cancellationToken)
            .ConfigureAwait(false);
        var tokenKey = await token.GetSigningKeyAsync(cancellationToken).ConfigureAwait(false);
        if (!durableKey.CanCreateSignature ||
            !string.Equals(durableKey.Algorithm, MlDsa65SignatureProvider.Algorithm, StringComparison.Ordinal) ||
            !string.Equals(durableKey.PublicKey, tokenKey.PublicKeyPem, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("HIP durable key state does not match the active SoftHSM key.");
        }

        byte[] data;
        try
        {
            data = new UTF8Encoding(false, true).GetBytes(contentHash);
        }
        catch (EncoderFallbackException exception)
        {
            throw new ArgumentException("The content hash must contain valid Unicode data.", nameof(contentHash), exception);
        }

        var signatureBytes = await token.SignAsync(data, cancellationToken).ConfigureAwait(false);
        var signature = Convert.ToBase64String(signatureBytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        if (!signatureVerifier.VerifySignature(contentHash, signature, tokenKey.PublicKeyPem))
        {
            throw new CryptographicException("SoftHSM returned an ML-DSA-65 signature that HIP could not verify.");
        }

        return signature;
    }

    private async Task EnsureLifecycleStateAsync(string publicKey, CancellationToken cancellationToken)
    {
        var registeredIdentity = await keyRepository.GetRegisteredIdentityAsync(identity.IssuerId, cancellationToken)
            .ConfigureAwait(false);
        var ring = await keyRepository.GetAsync(identity.IssuerId, cancellationToken).ConfigureAwait(false);
        var now = clock.GetUtcNow().ToUniversalTime();

        if (registeredIdentity is null && ring is null)
        {
            var authority = new HipIdentity(
                identity.IssuerId,
                IdentitySubjectType.Organization,
                identity.DisplayName,
                publicKey,
                MlDsa65SignatureProvider.Algorithm,
                VerificationStatus.Verified,
                now,
                "hip-softhsm-pkcs11");
            await lifecycle.RegisterIdentityAsync(
                    new RegisterIdentitySigningKeyRequest(
                        authority,
                        identity.KeyId,
                        identity.ActorId,
                        "Register the configured SoftHSM public signing authority.",
                        now),
                    cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        if (registeredIdentity is null || ring is null)
        {
            throw new IdentitySigningKeyRegistrationInconsistencyException(
                identity.IssuerId,
                identityExists: registeredIdentity is not null,
                keyRingExists: ring is not null);
        }

        if (registeredIdentity.VerificationStatus != VerificationStatus.Verified)
        {
            throw new InvalidOperationException("The configured SoftHSM signing authority identity is not verified.");
        }

        var configuredKey = ring.Keys.SingleOrDefault(key =>
            string.Equals(key.KeyId, identity.KeyId, StringComparison.Ordinal));
        if (configuredKey is not null)
        {
            if (!configuredKey.CanCreateSignature ||
                !string.Equals(configuredKey.Algorithm, MlDsa65SignatureProvider.Algorithm, StringComparison.Ordinal) ||
                !string.Equals(configuredKey.PublicKey, publicKey, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("The configured SoftHSM key does not match active HIP lifecycle state.");
            }

            return;
        }

        var activeKey = ring.Keys.SingleOrDefault(key => key.CanCreateSignature)
            ?? throw new InvalidOperationException("The SoftHSM signing authority has no active key to rotate.");
        await lifecycle.RotateAsync(
                new RotateSigningKeyRequest(
                    identity.IssuerId,
                    activeKey.KeyId,
                    ring.Version,
                    identity.KeyId,
                    MlDsa65SignatureProvider.Algorithm,
                    publicKey,
                    identity.ActorId,
                    "Rotate to the explicitly configured SoftHSM signing key.",
                    now),
                cancellationToken)
            .ConfigureAwait(false);
    }

    private HipManagedTrustReceiptSigningKey SigningKey() => new(
        identity.IssuerId,
        identity.KeyId,
        MlDsa65SignatureProvider.Algorithm,
        SignatureAlgorithmFamily.PostQuantum);
}

/// <summary>Explicit identity metadata for the configured SoftHSM authority.</summary>
public sealed record SoftHsmManagedSignerIdentityOptions(
    string IssuerId,
    string KeyId,
    string DisplayName,
    string ActorId);
