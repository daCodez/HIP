using System.Text.Json;
using HIP.Application.Security;
using HIP.Domain.Protocol;

namespace HIP.Application.Protocol;

/// <summary>Typed fail-closed result for one raw HIP envelope.</summary>
public enum HipEnvelopeVerificationStatus
{
    Unspecified = 0,
    Accepted,
    MalformedEnvelope,
    UnsupportedVersion,
    Expired,
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
    TimestampOutsideTolerance,
    ValidityWindowExceeded,
    DuplicateMessageId,
    DuplicateNonce,
    ReplayStateUnavailable,
    VerificationStateUnavailable
}

/// <summary>Public-safe envelope decision. Valid origin evidence is not a safety or reputation verdict.</summary>
public sealed record HipEnvelopeVerificationResult(
    HipEnvelopeVerificationStatus Status,
    string? VerifiedIssuerId = null,
    string? VerifiedKeyId = null)
{
    public bool IsAccepted => Status == HipEnvelopeVerificationStatus.Accepted;

    public bool EstablishesSafetyOrReputation => false;
}

public interface IHipEnvelopeVerificationService
{
    Task<HipEnvelopeVerificationResult> VerifyAsync(
        ReadOnlyMemory<byte> utf8Envelope,
        CancellationToken cancellationToken);
}

/// <summary>Strictly parses, verifies, rechecks, and replay-protects one version-one HIP envelope.</summary>
public sealed class HipEnvelopeVerificationService(
    IHipSignedDocumentVerifier signedDocumentVerifier,
    IHipReplayProtectionService replayProtectionService,
    TimeProvider timeProvider) : IHipEnvelopeVerificationService
{
    private readonly IHipSignedDocumentVerifier documentVerifier =
        signedDocumentVerifier ?? throw new ArgumentNullException(nameof(signedDocumentVerifier));
    private readonly IHipReplayProtectionService replayProtection =
        replayProtectionService ?? throw new ArgumentNullException(nameof(replayProtectionService));
    private readonly TimeProvider clock = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    public async Task<HipEnvelopeVerificationResult> VerifyAsync(
        ReadOnlyMemory<byte> utf8Envelope,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        HipProtocolEnvelope envelope;
        try
        {
            envelope = HipProtocolEnvelopeJson.Deserialize(utf8Envelope.Span);
        }
        catch (JsonException exception) when (ContainsUnsupportedVersion(exception))
        {
            return Result(HipEnvelopeVerificationStatus.UnsupportedVersion);
        }
        catch (JsonException)
        {
            return Result(HipEnvelopeVerificationStatus.MalformedEnvelope);
        }

        if (!envelope.Version.IsSupported)
        {
            return Result(HipEnvelopeVerificationStatus.UnsupportedVersion);
        }

        if (envelope.ExpiresAtUtc <= clock.GetUtcNow())
        {
            return Result(HipEnvelopeVerificationStatus.Expired);
        }

        var signatureResult = await documentVerifier.VerifyAsync(
                new HipSignedDocumentVerificationRequest(
                    envelope.Issuer.Id,
                    envelope.Signature.KeyId,
                    envelope.Signature.Algorithm,
                    envelope.Signature.AlgorithmFamily,
                    envelope.Signature.Canonicalization,
                    envelope.Signature.Value,
                    envelope.IssuedAtUtc,
                    HipProtocolEnvelopeSigningPayload.Create(envelope)),
                cancellationToken)
            .ConfigureAwait(false);
        if (!signatureResult.IsVerified)
        {
            return Result(Map(signatureResult.Status));
        }

        HipReplayProtectionResult replayResult;
        try
        {
            replayResult = await replayProtection.ValidateAndReserveAsync(envelope, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Result(HipEnvelopeVerificationStatus.ReplayStateUnavailable);
        }

        var mappedReplayStatus = replayResult.Status switch
        {
            HipReplayProtectionStatus.Accepted => HipEnvelopeVerificationStatus.Accepted,
            HipReplayProtectionStatus.Expired => HipEnvelopeVerificationStatus.Expired,
            HipReplayProtectionStatus.TimestampOutsideTolerance => HipEnvelopeVerificationStatus.TimestampOutsideTolerance,
            HipReplayProtectionStatus.ValidityWindowExceeded => HipEnvelopeVerificationStatus.ValidityWindowExceeded,
            HipReplayProtectionStatus.DuplicateMessageId => HipEnvelopeVerificationStatus.DuplicateMessageId,
            HipReplayProtectionStatus.DuplicateNonce => HipEnvelopeVerificationStatus.DuplicateNonce,
            _ => HipEnvelopeVerificationStatus.ReplayStateUnavailable
        };
        return mappedReplayStatus == HipEnvelopeVerificationStatus.Accepted
            ? new HipEnvelopeVerificationResult(
                mappedReplayStatus,
                signatureResult.VerifiedIssuerId,
                signatureResult.VerifiedKeyId)
            : Result(mappedReplayStatus);
    }

    private static HipEnvelopeVerificationStatus Map(HipSignedDocumentVerificationStatus status) => status switch
    {
        HipSignedDocumentVerificationStatus.IssuerNotFound => HipEnvelopeVerificationStatus.IssuerNotFound,
        HipSignedDocumentVerificationStatus.IssuerNotVerified => HipEnvelopeVerificationStatus.IssuerNotVerified,
        HipSignedDocumentVerificationStatus.IssuerSuspended => HipEnvelopeVerificationStatus.IssuerSuspended,
        HipSignedDocumentVerificationStatus.IssuerRevoked => HipEnvelopeVerificationStatus.IssuerRevoked,
        HipSignedDocumentVerificationStatus.IssuerBindingMismatch => HipEnvelopeVerificationStatus.IssuerBindingMismatch,
        HipSignedDocumentVerificationStatus.KeyNotFound => HipEnvelopeVerificationStatus.KeyNotFound,
        HipSignedDocumentVerificationStatus.KeyNotValidAtIssuedTime => HipEnvelopeVerificationStatus.KeyNotValidAtIssuedTime,
        HipSignedDocumentVerificationStatus.KeyRevoked => HipEnvelopeVerificationStatus.KeyRevoked,
        HipSignedDocumentVerificationStatus.SignatureMetadataMismatch => HipEnvelopeVerificationStatus.SignatureMetadataMismatch,
        HipSignedDocumentVerificationStatus.ProviderUnavailable => HipEnvelopeVerificationStatus.ProviderUnavailable,
        HipSignedDocumentVerificationStatus.InvalidSignature => HipEnvelopeVerificationStatus.InvalidSignature,
        _ => HipEnvelopeVerificationStatus.VerificationStateUnavailable
    };

    private static bool ContainsUnsupportedVersion(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current is NotSupportedException)
            {
                return true;
            }
        }

        return false;
    }

    private static HipEnvelopeVerificationResult Result(HipEnvelopeVerificationStatus status) => new(status);
}
