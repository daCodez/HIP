using HIP.Domain.Identity;

namespace HIP.Application.Identity;

public interface IWebsiteIdentityService
{
    Task<WebsiteIdentityRegistrationResponse> RegisterAsync(WebsiteIdentityRegistrationRequest request, CancellationToken cancellationToken);

    Task<WebsiteIdentity> VerifyAsync(WebsiteVerificationRequest request, CancellationToken cancellationToken);

    Task<WebsiteIdentity?> GetAsync(string domain, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<WebsiteIdentity>> ListAsync(CancellationToken cancellationToken);

    Task<WebsiteIdentity> RetryVerificationAsync(
        string domain,
        string actorId,
        string actorRole,
        CancellationToken cancellationToken);

    Task<WebsiteIdentity> RevokeVerificationAsync(
        string domain,
        string reason,
        string actorId,
        string actorRole,
        CancellationToken cancellationToken);

    Task<HipWellKnownDocument> BuildWellKnownDocumentAsync(string domain, CancellationToken cancellationToken);
}
