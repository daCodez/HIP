using System.Text.Json;
using HIP.Domain.Protocol;

namespace HIP.Application.Protocol;

/// <summary>Strictly parses and verifies a signed HIP trust receipt without consuming replay state.</summary>
public sealed class HipTrustReceiptVerificationService(
    IHipSignedDocumentVerifier signedDocumentVerifier,
    HipTrustReceiptIssuerPolicy issuerPolicy,
    HipTrustReceiptPolicy policy,
    TimeProvider timeProvider) : IHipTrustReceiptVerificationService
{
    private readonly IHipSignedDocumentVerifier documentVerifier =
        signedDocumentVerifier ?? throw new ArgumentNullException(nameof(signedDocumentVerifier));
    private readonly HipTrustReceiptIssuerPolicy authorizedIssuers =
        issuerPolicy ?? throw new ArgumentNullException(nameof(issuerPolicy));
    private readonly HipTrustReceiptPolicy receiptPolicy = policy ?? throw new ArgumentNullException(nameof(policy));
    private readonly TimeProvider clock = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    public async Task<HipTrustReceiptVerificationResult> VerifyAsync(
        ReadOnlyMemory<byte> utf8Receipt,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        HipTrustReceipt receipt;
        try
        {
            receipt = HipTrustReceiptJson.Deserialize(utf8Receipt.Span);
        }
        catch (JsonException exception) when (Contains<HipTrustReceiptDocumentTypeException>(exception))
        {
            return Result(HipTrustReceiptVerificationStatus.WrongDocumentType);
        }
        catch (JsonException exception) when (Contains<NotSupportedException>(exception))
        {
            return Result(HipTrustReceiptVerificationStatus.UnsupportedVersion);
        }
        catch (JsonException)
        {
            return Result(HipTrustReceiptVerificationStatus.MalformedReceipt);
        }

        if (!receipt.Version.IsSupported)
        {
            return Result(HipTrustReceiptVerificationStatus.UnsupportedVersion);
        }

        var now = clock.GetUtcNow();
        if (receipt.ExpiresAtUtc <= now)
        {
            return Result(HipTrustReceiptVerificationStatus.Expired);
        }

        if (receipt.IssuedAtUtc > now && receipt.IssuedAtUtc - now > receiptPolicy.AllowedClockSkew)
        {
            return Result(HipTrustReceiptVerificationStatus.TimestampOutsideTolerance);
        }

        if (receipt.ExpiresAtUtc - receipt.IssuedAtUtc > receiptPolicy.ValidityPeriod)
        {
            return Result(HipTrustReceiptVerificationStatus.ValidityWindowExceeded);
        }

        if (!authorizedIssuers.IsAuthorized(receipt.Issuer.Id, receipt.Signature.KeyId))
        {
            return Result(HipTrustReceiptVerificationStatus.IssuerNotAuthorized);
        }

        HipSignedDocumentVerificationResult signatureResult;
        try
        {
            signatureResult = await documentVerifier.VerifyAsync(
                    new HipSignedDocumentVerificationRequest(
                        receipt.Issuer.Id,
                        receipt.Signature.KeyId,
                        receipt.Signature.Algorithm,
                        receipt.Signature.AlgorithmFamily,
                        receipt.Signature.Canonicalization,
                        receipt.Signature.Value,
                        receipt.IssuedAtUtc,
                        HipTrustReceiptSigningPayload.Create(receipt)),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Result(HipTrustReceiptVerificationStatus.VerificationStateUnavailable);
        }

        if (!signatureResult.IsVerified)
        {
            return Result(Map(signatureResult.Status));
        }

        return new HipTrustReceiptVerificationResult(
            HipTrustReceiptVerificationStatus.Verified,
            receipt,
            signatureResult.VerifiedIssuerId,
            signatureResult.VerifiedKeyId);
    }

    private static HipTrustReceiptVerificationStatus Map(HipSignedDocumentVerificationStatus status) => status switch
    {
        HipSignedDocumentVerificationStatus.IssuerNotFound => HipTrustReceiptVerificationStatus.IssuerNotFound,
        HipSignedDocumentVerificationStatus.IssuerNotVerified => HipTrustReceiptVerificationStatus.IssuerNotVerified,
        HipSignedDocumentVerificationStatus.IssuerSuspended => HipTrustReceiptVerificationStatus.IssuerSuspended,
        HipSignedDocumentVerificationStatus.IssuerRevoked => HipTrustReceiptVerificationStatus.IssuerRevoked,
        HipSignedDocumentVerificationStatus.IssuerBindingMismatch => HipTrustReceiptVerificationStatus.IssuerBindingMismatch,
        HipSignedDocumentVerificationStatus.KeyNotFound => HipTrustReceiptVerificationStatus.KeyNotFound,
        HipSignedDocumentVerificationStatus.KeyNotValidAtIssuedTime => HipTrustReceiptVerificationStatus.KeyNotValidAtIssuedTime,
        HipSignedDocumentVerificationStatus.KeyRevoked => HipTrustReceiptVerificationStatus.KeyRevoked,
        HipSignedDocumentVerificationStatus.SignatureMetadataMismatch => HipTrustReceiptVerificationStatus.SignatureMetadataMismatch,
        HipSignedDocumentVerificationStatus.ProviderUnavailable => HipTrustReceiptVerificationStatus.ProviderUnavailable,
        HipSignedDocumentVerificationStatus.InvalidSignature => HipTrustReceiptVerificationStatus.InvalidSignature,
        _ => HipTrustReceiptVerificationStatus.VerificationStateUnavailable
    };

    private static bool Contains<TException>(Exception exception)
        where TException : Exception
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current is TException)
            {
                return true;
            }
        }

        return false;
    }

    private static HipTrustReceiptVerificationResult Result(HipTrustReceiptVerificationStatus status) => new(status);
}
