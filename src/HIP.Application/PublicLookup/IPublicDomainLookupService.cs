namespace HIP.Application.PublicLookup;

public interface IPublicDomainLookupService
{
    Task<PublicDomainLookupResponse> LookupDomainAsync(string domain, CancellationToken cancellationToken);
}
