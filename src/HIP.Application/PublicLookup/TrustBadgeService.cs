namespace HIP.Application.PublicLookup;

public sealed class TrustBadgeService(
    IPublicDomainLookupService lookupService,
    IHipLiveBadgeSigningService? signingService = null) : ITrustBadgeService
{
    public async Task<PublicBadgeResponse> GetDomainBadgeAsync(string domain, CancellationToken cancellationToken)
    {
        var lookup = await lookupService.LookupDomainAsync(domain, cancellationToken);
        var variant = lookup.Status.ToString().ToLowerInvariant();
        var label = lookup.VerificationStatus == "Verified" ? "HIP Verified" : "HIP Warning";
        var verifiedMeaning = "Verified means the domain identity is known; the score and status show current trust level.";
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
                    lookup.LastCheckedUtc),
                cancellationToken);

        return new PublicBadgeResponse(
            lookup.Domain,
            lookup.FinalHipScore,
            lookup.Status,
            lookup.VerificationStatus == "Verified",
            lookup.LastCheckedUtc,
            lookup.PublicLookupUrl,
            lookup.PublicLookupUrl,
            $"{label} - Score: {lookup.FinalHipScore}/100 - Status: {lookup.Status}. Verified identity does not automatically mean safe.",
            variant,
            lookup.IdentityVerificationStatus,
            lookup.SignatureValid,
            verifiedMeaning,
            signingResult.Document?.Signature.Value,
            signingResult.Document,
            signingResult.Status.ToString(),
            signingResult.IsVerified);
    }
}
