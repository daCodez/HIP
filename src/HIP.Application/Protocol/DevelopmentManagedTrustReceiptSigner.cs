using System.Security.Cryptography;
using System.Text;
using HIP.Application.Identity;
using HIP.Domain.Identity;

namespace HIP.Application.Protocol;

/// <summary>
/// Development-only process key material. Private material never enters persistence or a public contract.
/// </summary>
internal sealed class DevelopmentManagedTrustReceiptSigningMaterial
{
    public const string DefaultIssuerId = "hip:development:certificate-authority";
    public const string DefaultActorId = "system:development-signing-authority";

    private DevelopmentManagedTrustReceiptSigningMaterial(
        HipKeyPair keyPair,
        string keyId,
        string issuerId,
        string actorId)
    {
        KeyPair = keyPair;
        KeyId = keyId;
        IssuerId = issuerId;
        ActorId = actorId;
    }

    public HipKeyPair KeyPair { get; }

    public string KeyId { get; }

    /// <summary>Development-only issuer identity isolated to one local service role.</summary>
    public string IssuerId { get; }

    /// <summary>Development-only audit actor isolated to one local service role.</summary>
    public string ActorId { get; }

    public SemaphoreSlim LifecycleLock { get; } = new(1, 1);

    public static DevelopmentManagedTrustReceiptSigningMaterial Create(string? authorityScope = null)
    {
        var scope = NormalizeAuthorityScope(authorityScope);
        var provider = new DevelopmentHipCryptoProvider(
            new DevelopmentHipCryptoProviderOptions(AllowDevelopmentProvider: true));
        var keyPair = provider.GenerateKeyPair();
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(keyPair.PublicKey));
        var keyId = $"development-{Convert.ToHexString(digest).ToLowerInvariant()[..24]}";
        var issuerId = scope.Length == 0
            ? DefaultIssuerId
            : $"hip:development:{scope}-certificate-authority";
        var actorId = scope.Length == 0
            ? DefaultActorId
            : $"system:development-{scope}-signing-authority";
        return new DevelopmentManagedTrustReceiptSigningMaterial(
            keyPair,
            keyId,
            issuerId,
            actorId);
    }

    private static string NormalizeAuthorityScope(string? value)
    {
        if (value is null)
        {
            return string.Empty;
        }

        var scope = value.Trim().ToLowerInvariant();
        if (scope.Length is < 1 or > 32 ||
            scope[0] == '-' ||
            scope[^1] == '-' ||
            scope.Any(character =>
                !(character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-')))
        {
            throw new ArgumentException(
                "Development signing authority scope must be a bounded lowercase token.",
                nameof(value));
        }

        return scope;
    }
}

/// <summary>
/// Development-only managed signer. It persists public lifecycle state and rotates after process restart,
/// while keeping private material confined to this process.
/// </summary>
internal sealed class DevelopmentManagedTrustReceiptSigner(
    DevelopmentManagedTrustReceiptSigningMaterial material,
    DevelopmentHipCryptoProvider cryptoProvider,
    ISigningKeyLifecycleService lifecycleService,
    ISigningKeyLifecycleRepository repository,
    TimeProvider timeProvider) : IManagedTrustReceiptSigner
{
    private readonly DevelopmentManagedTrustReceiptSigningMaterial signingMaterial = material;
    private readonly DevelopmentHipCryptoProvider crypto = cryptoProvider;
    private readonly ISigningKeyLifecycleService lifecycle = lifecycleService;
    private readonly ISigningKeyLifecycleRepository keyRepository = repository;
    private readonly TimeProvider clock = timeProvider;

    public async Task<HipManagedTrustReceiptSigningKey> GetSigningKeyAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await signingMaterial.LifecycleLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var now = clock.GetUtcNow().ToUniversalTime();
            var identity = await keyRepository.GetRegisteredIdentityAsync(
                    signingMaterial.IssuerId,
                    cancellationToken)
                .ConfigureAwait(false);
            var ring = await keyRepository.GetAsync(
                    signingMaterial.IssuerId,
                    cancellationToken)
                .ConfigureAwait(false);

            if (identity is null && ring is null)
            {
                await RegisterAsync(now, cancellationToken).ConfigureAwait(false);
                return SigningKey();
            }

            if (identity is null || ring is null)
            {
                throw new IdentitySigningKeyRegistrationInconsistencyException(
                    signingMaterial.IssuerId,
                    identityExists: identity is not null,
                    keyRingExists: ring is not null);
            }

            EnsureVerifiedIdentity(identity);
            var processKey = ring.Keys.SingleOrDefault(IsProcessKey);
            if (processKey is not null)
            {
                if (!processKey.CanCreateSignature)
                {
                    throw new InvalidOperationException(
                        "The development signing process key is no longer active.");
                }

                return SigningKey();
            }

            var activeKey = ring.Keys.SingleOrDefault(key => key.CanCreateSignature)
                ?? throw new InvalidOperationException(
                    "The development signing authority has no active key to rotate.");
            await lifecycle.RotateAsync(
                    new RotateSigningKeyRequest(
                        ring.IdentityId,
                        activeKey.KeyId,
                        ring.Version,
                        signingMaterial.KeyId,
                        signingMaterial.KeyPair.Algorithm,
                        signingMaterial.KeyPair.PublicKey,
                        signingMaterial.ActorId,
                        "Rotate the process-confined development signing key after host startup.",
                        now),
                    cancellationToken)
                .ConfigureAwait(false);
            return SigningKey();
        }
        finally
        {
            signingMaterial.LifecycleLock.Release();
        }
    }

    public async Task<string> SignHashAsync(
        HipManagedTrustReceiptSigningKey signingKey,
        string contentHash,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(contentHash);
        cancellationToken.ThrowIfCancellationRequested();

        var expected = SigningKey();
        if (signingKey != expected)
        {
            throw new InvalidOperationException(
                "The requested signing key does not match the active development signing authority.");
        }

        var managedKey = await lifecycle.GetRequiredSigningKeyAsync(
                expected.IssuerId,
                expected.KeyId,
                cancellationToken)
            .ConfigureAwait(false);
        if (!IsProcessKey(managedKey))
        {
            throw new InvalidOperationException(
                "Durable signing-key state does not match the process-confined development key.");
        }

        return crypto.SignHash(contentHash, signingMaterial.KeyPair.PrivateKey);
    }

    private async Task RegisterAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        var identity = new HipIdentity(
            signingMaterial.IssuerId,
            IdentitySubjectType.Organization,
            "HIP Development Signing Authority",
            signingMaterial.KeyPair.PublicKey,
            signingMaterial.KeyPair.Algorithm,
            VerificationStatus.Verified,
            now,
            "hip-development-certificate-authority");
        await lifecycle.RegisterIdentityAsync(
                new RegisterIdentitySigningKeyRequest(
                    identity,
                    signingMaterial.KeyId,
                    signingMaterial.ActorId,
                    "Register the process-confined development signing authority.",
                    now),
                cancellationToken)
            .ConfigureAwait(false);
    }

    private bool IsProcessKey(ManagedSigningKey key) =>
        string.Equals(key.KeyId, signingMaterial.KeyId, StringComparison.Ordinal) &&
        string.Equals(key.Algorithm, signingMaterial.KeyPair.Algorithm, StringComparison.Ordinal) &&
        string.Equals(key.PublicKey, signingMaterial.KeyPair.PublicKey, StringComparison.Ordinal);

    private void EnsureVerifiedIdentity(HipIdentity identity)
    {
        if (!string.Equals(
                identity.IdentityId,
                signingMaterial.IssuerId,
                StringComparison.Ordinal) ||
            identity.VerificationStatus != VerificationStatus.Verified)
        {
            throw new InvalidOperationException(
                "The development signing authority identity is not verified.");
        }
    }

    private HipManagedTrustReceiptSigningKey SigningKey() =>
        new(
            signingMaterial.IssuerId,
            signingMaterial.KeyId,
            signingMaterial.KeyPair.Algorithm,
            crypto.Capabilities.AlgorithmFamily);
}
