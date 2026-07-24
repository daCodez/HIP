using HIP.Application.PublicLookup;
using HIP.Application.Protocol;
using HIP.Domain.Certificates;
using HIP.Domain.Protocol;

namespace HIP.Application.Certificates;

/// <summary>Public lookup outcome that does not reveal private enrollment existence details.</summary>
public enum PublicDomainCertificateLookupStatus
{
    Found,
    NotFound,
    Unavailable
}

/// <summary>Authoritative signature verification state for a public certificate response.</summary>
public enum PublicDomainCertificateSignatureStatus
{
    Verified,
    Invalid,
    Unavailable
}

/// <summary>Time-window status evaluated independently from the immutable signed payload.</summary>
public enum PublicDomainCertificateValidityStatus
{
    Current,
    NotYetValid,
    Expired
}

/// <summary>Privacy-safe machine-readable certificate verification response.</summary>
public sealed record PublicDomainCertificateResponse(
    string SchemaVersion,
    SignedDomainTrustCertificate SignedCertificate,
    DomainCertificateStatus CurrentStatus,
    PublicDomainCertificateSignatureStatus SignatureStatus,
    PublicDomainCertificateValidityStatus ValidityStatus,
    bool IsActive,
    DateTimeOffset CheckedAtUtc,
    string RevocationStatusUrl,
    string PublicCertificateUrl);

/// <summary>Public lookup result with no private owner or audit-actor data.</summary>
public sealed record PublicDomainCertificateLookupResult(
    PublicDomainCertificateLookupStatus Status,
    PublicDomainCertificateResponse? Certificate = null);

/// <summary>Retrieves and independently verifies public HIP Domain Trust Certificates.</summary>
public interface IPublicDomainCertificateService
{
    /// <summary>Gets one certificate by public identifier and verifies it against current key state.</summary>
    Task<PublicDomainCertificateLookupResult> GetByIdAsync(
        string certificateId,
        CancellationToken cancellationToken);

    /// <summary>Gets the current public certificate for one exact canonical domain.</summary>
    Task<PublicDomainCertificateLookupResult> GetByDomainAsync(
        string domain,
        CancellationToken cancellationToken) =>
        Task.FromResult(new PublicDomainCertificateLookupResult(
            PublicDomainCertificateLookupStatus.NotFound));
}

/// <summary>Builds fail-closed public certificate responses from durable signed records.</summary>
public sealed class PublicDomainCertificateService(
    IDomainCertificateRepository certificateRepository,
    IHipSignedDocumentVerifier signedDocumentVerifier,
    TimeProvider timeProvider) : IPublicDomainCertificateService
{
    public const string SchemaVersion = "hip-domain-certificate-verification-v1";
    private static readonly TimeSpan MaximumClockSkew = TimeSpan.FromMinutes(5);
    private readonly IDomainCertificateRepository repository =
        certificateRepository ?? throw new ArgumentNullException(nameof(certificateRepository));
    private readonly IHipSignedDocumentVerifier verifier =
        signedDocumentVerifier ?? throw new ArgumentNullException(nameof(signedDocumentVerifier));
    private readonly TimeProvider clock = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    /// <inheritdoc />
    public async Task<PublicDomainCertificateLookupResult> GetByIdAsync(
        string certificateId,
        CancellationToken cancellationToken)
    {
        ValidateCertificateId(certificateId);
        HipStoredDomainCertificate? stored;
        try
        {
            stored = await repository.GetByIdAsync(certificateId, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return new PublicDomainCertificateLookupResult(
                PublicDomainCertificateLookupStatus.Unavailable);
        }

        if (stored is null)
        {
            return new PublicDomainCertificateLookupResult(
                PublicDomainCertificateLookupStatus.NotFound);
        }

        var certificate = stored.Certificate;
        var now = clock.GetUtcNow();
        var validity = Validity(certificate.Payload, now);
        var signatureStatus = await VerifyAsync(certificate, cancellationToken).ConfigureAwait(false);
        var effectiveStatus = validity == PublicDomainCertificateValidityStatus.Expired &&
                              stored.CurrentStatus == DomainCertificateStatus.Active
            ? DomainCertificateStatus.Expired
            : stored.CurrentStatus;
        var isActive = signatureStatus == PublicDomainCertificateSignatureStatus.Verified &&
                       validity == PublicDomainCertificateValidityStatus.Current &&
                       effectiveStatus == DomainCertificateStatus.Active;
        return new PublicDomainCertificateLookupResult(
            PublicDomainCertificateLookupStatus.Found,
            new PublicDomainCertificateResponse(
                SchemaVersion,
                certificate,
                effectiveStatus,
                signatureStatus,
                validity,
                isActive,
                now,
                certificate.Payload.RevocationStatusUrl,
                certificate.Payload.PublicCertificateUrl));
    }
    /// <inheritdoc />
    public async Task<PublicDomainCertificateLookupResult> GetByDomainAsync(
        string domain,
        CancellationToken cancellationToken)
    {
        var normalizedDomain = DomainInputValidator.ValidateAndNormalize(domain);
        HipStoredDomainCertificate? stored;
        try
        {
            stored = await repository.GetCurrentByDomainAsync(normalizedDomain, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return new PublicDomainCertificateLookupResult(
                PublicDomainCertificateLookupStatus.Unavailable);
        }

        if (stored is null)
        {
            return new PublicDomainCertificateLookupResult(
                PublicDomainCertificateLookupStatus.NotFound);
        }

        var certificate = stored.Certificate;
        var now = clock.GetUtcNow();
        var validity = Validity(certificate.Payload, now);
        var signatureStatus = await VerifyAsync(certificate, cancellationToken).ConfigureAwait(false);
        var effectiveStatus = validity == PublicDomainCertificateValidityStatus.Expired &&
                              stored.CurrentStatus == DomainCertificateStatus.Active
            ? DomainCertificateStatus.Expired
            : stored.CurrentStatus;
        var isActive = signatureStatus == PublicDomainCertificateSignatureStatus.Verified &&
                       validity == PublicDomainCertificateValidityStatus.Current &&
                       effectiveStatus == DomainCertificateStatus.Active;
        return new PublicDomainCertificateLookupResult(
            PublicDomainCertificateLookupStatus.Found,
            new PublicDomainCertificateResponse(
                SchemaVersion,
                certificate,
                effectiveStatus,
                signatureStatus,
                validity,
                isActive,
                now,
                certificate.Payload.RevocationStatusUrl,
                certificate.Payload.PublicCertificateUrl));
    }

    private async Task<PublicDomainCertificateSignatureStatus> VerifyAsync(
        SignedDomainTrustCertificate certificate,
        CancellationToken cancellationToken)
    {
        try
        {
            var signature = certificate.Signature;
            var result = await verifier.VerifyAsync(
                    new HipSignedDocumentVerificationRequest(
                        signature.AuthorityId,
                        signature.KeyId,
                        signature.Algorithm,
                        signature.AlgorithmFamily,
                        signature.Canonicalization,
                        signature.Value,
                        certificate.Payload.IssuedAtUtc,
                        DomainTrustCertificateJson.SigningPayload(certificate.Payload)),
                    cancellationToken)
                .ConfigureAwait(false);
            return result.IsVerified
                ? PublicDomainCertificateSignatureStatus.Verified
                : PublicDomainCertificateSignatureStatus.Invalid;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return PublicDomainCertificateSignatureStatus.Unavailable;
        }
    }

    private static PublicDomainCertificateValidityStatus Validity(
        DomainTrustCertificatePayload payload,
        DateTimeOffset now)
    {
        if (payload.ExpiresAtUtc <= payload.IssuedAtUtc || payload.ExpiresAtUtc <= now)
        {
            return PublicDomainCertificateValidityStatus.Expired;
        }

        return payload.IssuedAtUtc > now.Add(MaximumClockSkew)
            ? PublicDomainCertificateValidityStatus.NotYetValid
            : PublicDomainCertificateValidityStatus.Current;
    }

    private static void ValidateCertificateId(string certificateId)
    {
        if (string.IsNullOrWhiteSpace(certificateId) ||
            certificateId.Length > 128 ||
            certificateId.Any(character =>
                !(char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.' or ':')))
        {
            throw new ArgumentException("Certificate identifier is invalid.", nameof(certificateId));
        }
    }
}
