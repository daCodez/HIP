using System.Security.Cryptography;
using System.Text.Json;
using HIP.Application.Identity;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;

namespace HIP.Application.Protocol;

/// <summary>Fail-closed result for the reusable identity, key, provider, and signature boundary.</summary>
public enum HipSignedDocumentVerificationStatus
{
    Unspecified = 0,
    Verified,
    IssuerNotFound,
    IssuerNotVerified,
    IssuerSuspended,
    IssuerRevoked,
    IssuerBindingMismatch,
    KeyNotFound,
    KeyNotValidAtIssuedTime,
    KeyRevoked,
    SignatureMetadataMismatch,
    ProviderUnavailable,
    InvalidSignature,
    VerificationStateUnavailable
}

/// <summary>Inputs shared by HIP envelopes and other versioned signed documents.</summary>
public sealed record HipSignedDocumentVerificationRequest(
    string IssuerId,
    string KeyId,
    string Algorithm,
    SignatureAlgorithmFamily AlgorithmFamily,
    string Canonicalization,
    string SignatureValue,
    DateTimeOffset IssuedAtUtc,
    ReadOnlyMemory<byte> SigningPayloadJson);

/// <summary>Internal verification result that never equates origin evidence with safety.</summary>
public sealed record HipSignedDocumentVerificationResult(
    HipSignedDocumentVerificationStatus Status,
    string? VerifiedIssuerId = null,
    string? VerifiedKeyId = null)
{
    public bool IsVerified => Status == HipSignedDocumentVerificationStatus.Verified;

    public bool EstablishesSafetyOrReputation => false;
}

/// <summary>Verifies canonical signed-document evidence against authoritative identity and key state.</summary>
public interface IHipSignedDocumentVerifier
{
    Task<HipSignedDocumentVerificationResult> VerifyAsync(
        HipSignedDocumentVerificationRequest request,
        CancellationToken cancellationToken);
}

/// <summary>
/// Reusable cryptographic verification core. Provider selection is always derived from the managed key,
/// never from caller-supplied signature metadata.
/// </summary>
public sealed class HipSignedDocumentVerifier(
    ISigningKeyLifecycleRepository signingKeyRepository,
    IHipSignatureProviderFactory signatureProviderFactory,
    SignatureProviderRuntimePolicy runtimePolicy,
    ICanonicalJsonService canonicalJsonService) : IHipSignedDocumentVerifier
{
    private readonly ISigningKeyLifecycleRepository keyRepository =
        signingKeyRepository ?? throw new ArgumentNullException(nameof(signingKeyRepository));
    private readonly IHipSignatureProviderFactory providerFactory =
        signatureProviderFactory ?? throw new ArgumentNullException(nameof(signatureProviderFactory));
    private readonly SignatureProviderRuntimePolicy providerPolicy =
        runtimePolicy ?? throw new ArgumentNullException(nameof(runtimePolicy));
    private readonly ICanonicalJsonService canonicalizer =
        canonicalJsonService ?? throw new ArgumentNullException(nameof(canonicalJsonService));

    public async Task<HipSignedDocumentVerificationResult> VerifyAsync(
        HipSignedDocumentVerificationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        var initialState = await ReadStateAsync(
                request.IssuerId,
                request.KeyId,
                request.IssuedAtUtc,
                cancellationToken)
            .ConfigureAwait(false);
        if (!initialState.Result.IsVerified)
        {
            return initialState.Result;
        }

        var managedKey = initialState.Key!;
        IHipSignatureProvider provider;
        SignatureProviderCapabilities capabilities;
        try
        {
            // The authoritative lifecycle algorithm is the only provider-selection input.
            provider = providerFactory.GetRequiredProvider(
                managedKey.Algorithm,
                SignatureProviderOperations.Verify,
                providerPolicy);
            capabilities = provider.Capabilities;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Result(HipSignedDocumentVerificationStatus.ProviderUnavailable);
        }

        if (!string.Equals(request.Algorithm, managedKey.Algorithm, StringComparison.Ordinal) ||
            !string.Equals(capabilities.Algorithm, managedKey.Algorithm, StringComparison.Ordinal) ||
            request.AlgorithmFamily != capabilities.AlgorithmFamily ||
            !string.Equals(
                request.Canonicalization,
                HipProtocolSignature.Rfc8785Canonicalization,
                StringComparison.Ordinal))
        {
            return Result(HipSignedDocumentVerificationStatus.SignatureMetadataMismatch);
        }

        string signedHash;
        try
        {
            var canonicalPayload = canonicalizer.Canonicalize(request.SigningPayloadJson.Span);
            if (canonicalPayload is null)
            {
                return Result(HipSignedDocumentVerificationStatus.VerificationStateUnavailable);
            }

            signedHash = $"sha256:{Convert.ToHexString(SHA256.HashData(canonicalPayload)).ToLowerInvariant()}";
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or JsonException)
        {
            return Result(HipSignedDocumentVerificationStatus.InvalidSignature);
        }
        catch (Exception)
        {
            return Result(HipSignedDocumentVerificationStatus.VerificationStateUnavailable);
        }

        bool signatureIsValid;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            signatureIsValid = provider.VerifySignature(
                signedHash,
                request.SignatureValue,
                managedKey.PublicKey);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or CryptographicException)
        {
            return Result(HipSignedDocumentVerificationStatus.InvalidSignature);
        }
        catch (Exception)
        {
            return Result(HipSignedDocumentVerificationStatus.ProviderUnavailable);
        }

        if (!signatureIsValid)
        {
            return Result(HipSignedDocumentVerificationStatus.InvalidSignature);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var refreshedState = await ReadStateAsync(
                request.IssuerId,
                request.KeyId,
                request.IssuedAtUtc,
                cancellationToken)
            .ConfigureAwait(false);
        if (!refreshedState.Result.IsVerified)
        {
            return refreshedState.Result;
        }

        var refreshedKey = refreshedState.Key!;
        if (!string.Equals(refreshedKey.Algorithm, managedKey.Algorithm, StringComparison.Ordinal) ||
            !string.Equals(refreshedKey.PublicKey, managedKey.PublicKey, StringComparison.Ordinal) ||
            !string.Equals(refreshedKey.PublicKeyFingerprint, managedKey.PublicKeyFingerprint, StringComparison.Ordinal))
        {
            return Result(HipSignedDocumentVerificationStatus.VerificationStateUnavailable);
        }

        return new HipSignedDocumentVerificationResult(
            HipSignedDocumentVerificationStatus.Verified,
            refreshedState.Identity!.IdentityId,
            refreshedKey.KeyId);
    }

    private async Task<StateRead> ReadStateAsync(
        string issuerId,
        string keyId,
        DateTimeOffset issuedAtUtc,
        CancellationToken cancellationToken)
    {
        HipIdentity? identity;
        SigningKeyRing? keyRing;
        try
        {
            identity = await keyRepository.GetRegisteredIdentityAsync(issuerId, cancellationToken)
                .ConfigureAwait(false);
            keyRing = identity is null
                ? null
                : await keyRepository.GetAsync(issuerId, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return StateRead.Failure(HipSignedDocumentVerificationStatus.VerificationStateUnavailable);
        }

        if (identity is null)
        {
            return StateRead.Failure(HipSignedDocumentVerificationStatus.IssuerNotFound);
        }

        if (!string.Equals(identity.IdentityId, issuerId, StringComparison.Ordinal))
        {
            return StateRead.Failure(HipSignedDocumentVerificationStatus.IssuerBindingMismatch);
        }

        var issuerStatus = identity.VerificationStatus switch
        {
            VerificationStatus.Verified => HipSignedDocumentVerificationStatus.Verified,
            VerificationStatus.Suspended => HipSignedDocumentVerificationStatus.IssuerSuspended,
            VerificationStatus.Revoked => HipSignedDocumentVerificationStatus.IssuerRevoked,
            _ => HipSignedDocumentVerificationStatus.IssuerNotVerified
        };
        if (issuerStatus != HipSignedDocumentVerificationStatus.Verified)
        {
            return StateRead.Failure(issuerStatus);
        }

        if (keyRing is null || !string.Equals(keyRing.IdentityId, issuerId, StringComparison.Ordinal))
        {
            return StateRead.Failure(keyRing is null
                ? HipSignedDocumentVerificationStatus.KeyNotFound
                : HipSignedDocumentVerificationStatus.IssuerBindingMismatch);
        }

        ManagedSigningKey? key = null;
        foreach (var candidate in keyRing.Keys)
        {
            if (!string.Equals(candidate.KeyId, keyId, StringComparison.Ordinal))
            {
                continue;
            }

            if (key is not null)
            {
                return StateRead.Failure(HipSignedDocumentVerificationStatus.VerificationStateUnavailable);
            }

            key = candidate;
        }
        if (key is null)
        {
            return StateRead.Failure(HipSignedDocumentVerificationStatus.KeyNotFound);
        }

        if (key.Status == SigningKeyStatus.Revoked)
        {
            return StateRead.Failure(HipSignedDocumentVerificationStatus.KeyRevoked);
        }

        if (!key.CanVerifySignatureIssuedAt(issuedAtUtc))
        {
            return StateRead.Failure(HipSignedDocumentVerificationStatus.KeyNotValidAtIssuedTime);
        }

        return new StateRead(
            new HipSignedDocumentVerificationResult(
                HipSignedDocumentVerificationStatus.Verified,
                identity.IdentityId,
                key.KeyId),
            identity,
            key);
    }

    private static HipSignedDocumentVerificationResult Result(HipSignedDocumentVerificationStatus status) => new(status);

    private sealed record StateRead(
        HipSignedDocumentVerificationResult Result,
        HipIdentity? Identity,
        ManagedSigningKey? Key)
    {
        public static StateRead Failure(HipSignedDocumentVerificationStatus status) =>
            new(new HipSignedDocumentVerificationResult(status), null, null);
    }
}
