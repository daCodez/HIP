using HIP.Application.Certificates;
using HIP.Domain.Certificates;

namespace HIP.Application.PublicLookup;

public sealed class TrustBadgeService(
    IPublicDomainLookupService lookupService,
    IHipLiveBadgeSigningService? signingService = null,
    IPublicDomainCertificateService? certificateService = null) : ITrustBadgeService
{
    public async Task<PublicBadgeResponse> GetDomainBadgeAsync(string domain, CancellationToken cancellationToken)
    {
        var lookup = await lookupService.LookupDomainAsync(domain, cancellationToken);
        var certificateLookup = certificateService is null
            ? new PublicDomainCertificateLookupResult(PublicDomainCertificateLookupStatus.NotFound)
            : await certificateService.GetByDomainAsync(lookup.Domain, cancellationToken);
        var certificate = CertificateState(lookup.Domain, certificateLookup);
        var variant = certificate is null
            ? "unknown"
            : certificate.IsActive
                ? certificate.Level.ToString().ToLowerInvariant()
                : certificate.Status.ToString().ToLowerInvariant();
        var label = certificate is null
            ? "HIP Certificate Unavailable"
            : certificate.IsActive
                ? $"HIP {certificate.Level}"
                : $"HIP {certificate.Status}";
        var verifiedMeaning = certificate is null
            ? "No active HIP Domain Trust Certificate was verified for this domain."
            : Meaning(certificate.Level);
        var signingResult = signingService is null
            ? new HipLiveBadgeSigningResult(HipLiveBadgeSignatureStatus.SignerUnavailable)
            : await signingService.SignAsync(
                new HipLiveBadgeSigningRequest(
                    lookup.Domain,
                    lookup.FinalHipScore,
                    lookup.Status,
                    lookup.VerificationStatus == "Verified",
                    lookup.IdentityVerificationStatus,
                    verifiedMeaning,
                    lookup.LastCheckedUtc,
                    certificate),
                cancellationToken);

        var publicUrl = certificate?.PublicCertificateUrl ?? lookup.PublicLookupUrl;
        return new PublicBadgeResponse(
            lookup.Domain,
            lookup.FinalHipScore,
            lookup.Status,
            lookup.VerificationStatus == "Verified",
            lookup.LastCheckedUtc,
            publicUrl,
            publicUrl,
            $"{label} - Certificate: {certificate?.Status.ToString() ?? "NotIssued"} - Score: {lookup.FinalHipScore}/100 - Risk: {lookup.Status}. A certificate does not automatically mean safe.",
            variant,
            lookup.IdentityVerificationStatus,
            lookup.SignatureValid,
            verifiedMeaning,
            signingResult.Document?.Signature.Value,
            signingResult.Document,
            signingResult.Status.ToString(),
            signingResult.IsVerified,
            certificate);
    }

    private static HipLiveBadgeCertificateState? CertificateState(
        string domain,
        PublicDomainCertificateLookupResult lookup)
    {
        if (lookup.Status != PublicDomainCertificateLookupStatus.Found ||
            lookup.Certificate is not { } certificate ||
            !string.Equals(certificate.SignedCertificate.Payload.Domain, domain, StringComparison.Ordinal))
        {
            return null;
        }

        var payload = certificate.SignedCertificate.Payload;
        return new HipLiveBadgeCertificateState(
            payload.CertificateId,
            payload.Domain,
            payload.Level,
            certificate.CurrentStatus,
            certificate.SignatureStatus,
            payload.ExpiresAtUtc,
            certificate.PublicCertificateUrl,
            certificate.IsActive);
    }

    private static string Meaning(DomainCertificateLevel level) => level switch
    {
        DomainCertificateLevel.Registered => "Domain control has been verified by HIP. This does not mean the site is safe.",
        DomainCertificateLevel.Verified => "This domain completed HIP identity and baseline security verification.",
        DomainCertificateLevel.Monitored => "This domain is verified and continuously monitored by HIP.",
        _ => "HIP could not verify a current certificate level for this domain."
    };
}
