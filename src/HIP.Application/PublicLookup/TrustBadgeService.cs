namespace HIP.Application.PublicLookup;

public sealed class TrustBadgeService(IPublicDomainLookupService lookupService) : ITrustBadgeService
{
    public async Task<PublicBadgeResponse> GetDomainBadgeAsync(string domain, CancellationToken cancellationToken)
    {
        var lookup = await lookupService.LookupDomainAsync(domain, cancellationToken);
        var variant = lookup.Status.ToString().ToLowerInvariant();
        var label = lookup.VerificationStatus == "Verified" ? "HIP Verified" : "HIP Warning";

        return new PublicBadgeResponse(
            lookup.Domain,
            lookup.FinalHipScore,
            lookup.Status,
            lookup.VerificationStatus == "Verified",
            lookup.LastCheckedUtc,
            lookup.PublicLookupUrl,
            $"{label} - Score: {lookup.FinalHipScore}/100 - Status: {lookup.Status}",
            variant,
            lookup.IdentityVerificationStatus,
            lookup.SignatureValid,
            null);
    }
}
