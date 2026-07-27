using System.Security.Cryptography;
using HIP.Application.Protocol;
using HIP.Domain.Protocol;

namespace HIP.Application.PublicLookup;

/// <summary>Signs only server-derived public badge fields and verifies managed key state before release.</summary>
public sealed class HipLiveBadgeSigningService(
    IManagedTrustReceiptSigner managedSigner,
    ICanonicalJsonService canonicalJsonService,
    IHipSignedDocumentVerifier signedDocumentVerifier,
    HipTrustReceiptIssuerPolicy issuerPolicy,
    HipLiveBadgePolicy policy,
    TimeProvider timeProvider) : IHipLiveBadgeSigningService
{
    private const string UnsignedPlaceholder = "unsigned-placeholder";
    private readonly IManagedTrustReceiptSigner signer =
        managedSigner ?? throw new ArgumentNullException(nameof(managedSigner));
    private readonly ICanonicalJsonService canonicalizer =
        canonicalJsonService ?? throw new ArgumentNullException(nameof(canonicalJsonService));
    private readonly IHipSignedDocumentVerifier verifier =
        signedDocumentVerifier ?? throw new ArgumentNullException(nameof(signedDocumentVerifier));
    private readonly HipTrustReceiptIssuerPolicy authorizedIssuers =
        issuerPolicy ?? throw new ArgumentNullException(nameof(issuerPolicy));
    private readonly HipLiveBadgePolicy badgePolicy = policy ?? throw new ArgumentNullException(nameof(policy));
    private readonly TimeProvider clock = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    public async Task<HipLiveBadgeSigningResult> SignAsync(
        HipLiveBadgeSigningRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        HipManagedTrustReceiptSigningKey signingKey;
        try
        {
            signingKey = await signer.GetSigningKeyAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Result(HipLiveBadgeSignatureStatus.SignerUnavailable);
        }

        if (!authorizedIssuers.IsAuthorized(signingKey.IssuerId, signingKey.KeyId))
        {
            return Result(HipLiveBadgeSignatureStatus.SignerNotAuthorized);
        }

        HipLiveBadgeDocument document;
        try
        {
            var issuedAtUtc = ProtocolTimestamp(clock.GetUtcNow());
            var lastCheckedUtc = ProtocolTimestamp(request.LastCheckedUtc);
            if (lastCheckedUtc > issuedAtUtc)
            {
                lastCheckedUtc = issuedAtUtc;
            }

            var payload = new HipLiveBadgePayload(
                HipLiveBadgePayload.LiveBadgeDocumentType,
                HipProtocolVersion.CurrentValue,
                DomainInputValidator.ValidateAndNormalize(request.Domain),
                request.Score,
                request.Status,
                request.VerifiedDomain,
                request.IdentityVerificationStatus,
                request.VerifiedMeaning,
                lastCheckedUtc,
                issuedAtUtc,
                issuedAtUtc + badgePolicy.ValidityPeriod,
                request.Certificate,
                request.DisplayScore,
                request.ScorePresentation,
                request.EvidenceCoverage,
                request.EvidenceConfidence);
            var issuer = new HipProtocolIssuer(signingKey.IssuerId);
            var unsignedSignature = Signature(signingKey, UnsignedPlaceholder);
            var unsignedDocument = new HipLiveBadgeDocument(payload, issuer, unsignedSignature);
            var canonicalPayload = canonicalizer.Canonicalize(HipLiveBadgeSigningPayload.Create(unsignedDocument));
            var signingHash = $"sha256:{Convert.ToHexString(SHA256.HashData(canonicalPayload)).ToLowerInvariant()}";
            var signatureValue = await signer.SignHashAsync(signingKey, signingHash, cancellationToken)
                .ConfigureAwait(false);
            document = new HipLiveBadgeDocument(payload, issuer, Signature(signingKey, signatureValue));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Result(HipLiveBadgeSignatureStatus.SignerUnavailable);
        }

        HipSignedDocumentVerificationResult verified;
        try
        {
            verified = await verifier.VerifyAsync(
                    VerificationRequest(document),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Result(HipLiveBadgeSignatureStatus.VerificationStateUnavailable);
        }

        var status = HipLiveBadgeVerificationService.Map(verified.Status);
        return status == HipLiveBadgeSignatureStatus.Verified
            ? new HipLiveBadgeSigningResult(status, document)
            : Result(status);
    }

    internal static HipSignedDocumentVerificationRequest VerificationRequest(HipLiveBadgeDocument document) =>
        new(
            document.Issuer.Id,
            document.Signature.KeyId,
            document.Signature.Algorithm,
            document.Signature.AlgorithmFamily,
            document.Signature.Canonicalization,
            document.Signature.Value,
            document.Payload.IssuedAtUtc,
            HipLiveBadgeSigningPayload.Create(document));

    private static HipProtocolSignature Signature(
        HipManagedTrustReceiptSigningKey signingKey,
        string signatureValue) =>
        new(
            HipProtocolSignature.OriginAndIntegrityScope,
            signingKey.KeyId,
            signingKey.Algorithm,
            signingKey.AlgorithmFamily,
            HipProtocolSignature.Rfc8785Canonicalization,
            signatureValue);

    private static DateTimeOffset ProtocolTimestamp(DateTimeOffset value)
    {
        var utc = value.ToUniversalTime();
        return new DateTimeOffset(
            utc.Ticks - (utc.Ticks % TimeSpan.TicksPerMillisecond),
            TimeSpan.Zero);
    }

    private static HipLiveBadgeSigningResult Result(HipLiveBadgeSignatureStatus status) => new(status);
}

/// <summary>Verifies badge lifetime, issuer authorization, managed lifecycle state, and signature integrity.</summary>
public sealed class HipLiveBadgeVerificationService(
    IHipSignedDocumentVerifier signedDocumentVerifier,
    HipTrustReceiptIssuerPolicy issuerPolicy,
    HipLiveBadgePolicy policy,
    TimeProvider timeProvider) : IHipLiveBadgeVerificationService
{
    private readonly IHipSignedDocumentVerifier verifier =
        signedDocumentVerifier ?? throw new ArgumentNullException(nameof(signedDocumentVerifier));
    private readonly HipTrustReceiptIssuerPolicy authorizedIssuers =
        issuerPolicy ?? throw new ArgumentNullException(nameof(issuerPolicy));
    private readonly HipLiveBadgePolicy badgePolicy = policy ?? throw new ArgumentNullException(nameof(policy));
    private readonly TimeProvider clock = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    public async Task<HipLiveBadgeVerificationResult> VerifyAsync(
        HipLiveBadgeDocument document,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (document?.Payload is null || document.Issuer is null || document.Signature is null)
        {
            return new HipLiveBadgeVerificationResult(HipLiveBadgeSignatureStatus.Malformed);
        }

        var now = clock.GetUtcNow();
        if (document.Payload.ExpiresAtUtc <= now)
        {
            return new HipLiveBadgeVerificationResult(HipLiveBadgeSignatureStatus.Expired);
        }

        if (document.Payload.IssuedAtUtc > now &&
            document.Payload.IssuedAtUtc - now > badgePolicy.AllowedClockSkew)
        {
            return new HipLiveBadgeVerificationResult(HipLiveBadgeSignatureStatus.TimestampOutsideTolerance);
        }

        if (document.Payload.ExpiresAtUtc - document.Payload.IssuedAtUtc > badgePolicy.ValidityPeriod)
        {
            return new HipLiveBadgeVerificationResult(HipLiveBadgeSignatureStatus.ValidityWindowExceeded);
        }

        if (!authorizedIssuers.IsAuthorized(document.Issuer.Id, document.Signature.KeyId))
        {
            return new HipLiveBadgeVerificationResult(HipLiveBadgeSignatureStatus.SignerNotAuthorized);
        }

        try
        {
            var result = await verifier.VerifyAsync(
                    HipLiveBadgeSigningService.VerificationRequest(document),
                    cancellationToken)
                .ConfigureAwait(false);
            return new HipLiveBadgeVerificationResult(Map(result.Status));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return new HipLiveBadgeVerificationResult(HipLiveBadgeSignatureStatus.VerificationStateUnavailable);
        }
    }

    internal static HipLiveBadgeSignatureStatus Map(HipSignedDocumentVerificationStatus status) => status switch
    {
        HipSignedDocumentVerificationStatus.Verified => HipLiveBadgeSignatureStatus.Verified,
        HipSignedDocumentVerificationStatus.IssuerNotFound => HipLiveBadgeSignatureStatus.IssuerNotFound,
        HipSignedDocumentVerificationStatus.IssuerNotVerified => HipLiveBadgeSignatureStatus.IssuerNotVerified,
        HipSignedDocumentVerificationStatus.IssuerSuspended => HipLiveBadgeSignatureStatus.IssuerSuspended,
        HipSignedDocumentVerificationStatus.IssuerRevoked => HipLiveBadgeSignatureStatus.IssuerRevoked,
        HipSignedDocumentVerificationStatus.IssuerBindingMismatch => HipLiveBadgeSignatureStatus.IssuerBindingMismatch,
        HipSignedDocumentVerificationStatus.KeyNotFound => HipLiveBadgeSignatureStatus.KeyNotFound,
        HipSignedDocumentVerificationStatus.KeyNotValidAtIssuedTime => HipLiveBadgeSignatureStatus.KeyNotValidAtIssuedTime,
        HipSignedDocumentVerificationStatus.KeyRevoked => HipLiveBadgeSignatureStatus.KeyRevoked,
        HipSignedDocumentVerificationStatus.SignatureMetadataMismatch => HipLiveBadgeSignatureStatus.SignatureMetadataMismatch,
        HipSignedDocumentVerificationStatus.ProviderUnavailable => HipLiveBadgeSignatureStatus.ProviderUnavailable,
        HipSignedDocumentVerificationStatus.InvalidSignature => HipLiveBadgeSignatureStatus.InvalidSignature,
        _ => HipLiveBadgeSignatureStatus.VerificationStateUnavailable
    };
}
