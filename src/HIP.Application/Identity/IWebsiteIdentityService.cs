using HIP.Domain.Identity;

namespace HIP.Application.Identity;

public interface IWebsiteIdentityService
{
    Task<WebsiteIdentityRegistrationResponse> RegisterAsync(WebsiteIdentityRegistrationRequest request, CancellationToken cancellationToken);

    Task<WebsiteIdentity> VerifyAsync(WebsiteVerificationRequest request, CancellationToken cancellationToken);

    Task<WebsiteIdentity?> GetAsync(string domain, CancellationToken cancellationToken);

    Task<HipWellKnownDocument> BuildWellKnownDocumentAsync(string domain, CancellationToken cancellationToken);
}
