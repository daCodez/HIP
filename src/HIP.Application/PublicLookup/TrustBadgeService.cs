namespace HIP.Application.PublicLookup;

public sealed class TrustBadgeService(IPublicDomainLookupService lookupService) : ITrustBadgeService
{
    public async Task<PublicBadgeResponse> GetDomainBadgeAsync(string domain, CancellationToken cancellationToken)
    {
        var lookup = await lookupService.LookupDomainAsync(domain, cancellationToken);
        var variant = lookup.Status.ToString().ToLowerInvariant();

        return new PublicBadgeResponse(
            lookup.Domain,
            lookup.FinalHipScore,
            lookup.Status,
            lookup.VerificationStatus == "Verified",
            lookup.LastCheckedUtc,
            $"/api/public/lookup/domain/{lookup.Domain}",
            $"HIP {lookup.Status} - Score: {lookup.FinalHipScore}/100",
            variant);
    }
}
