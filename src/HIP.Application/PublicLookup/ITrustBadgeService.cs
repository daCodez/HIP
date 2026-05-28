namespace HIP.Application.PublicLookup;

public interface ITrustBadgeService
{
    Task<PublicBadgeResponse> GetDomainBadgeAsync(string domain, CancellationToken cancellationToken);
}
