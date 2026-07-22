using HIP.Domain.Identity;

namespace HIP.Application.Identity;

public interface IWebsiteIdentityService
{
    Task<WebsiteIdentityRegistrationResponse> RegisterAsync(WebsiteIdentityRegistrationRequest request, CancellationToken cancellationToken);

    Task<WebsiteIdentityRegistrationResponse> RegisterAsync(
        WebsiteIdentityRegistrationRequest request,
        string actorId,
        string actorRole,
        CancellationToken cancellationToken);

    Task<WebsiteIdentity> VerifyAsync(WebsiteVerificationRequest request, CancellationToken cancellationToken);

    Task<WebsiteIdentity> VerifyAsync(
        WebsiteVerificationRequest request,
        string actorId,
        string actorRole,
        CancellationToken cancellationToken);

    Task<WebsiteIdentity?> GetAsync(string domain, CancellationToken cancellationToken);

    Task<WebsiteIdentity?> GetAsync(
        string domain,
        string actorId,
        string actorRole,
        CancellationToken cancellationToken);

    Task<IReadOnlyCollection<WebsiteIdentity>> ListAsync(CancellationToken cancellationToken);

    Task<IReadOnlyCollection<WebsiteIdentity>> ListAsync(
        string actorId,
        string actorRole,
        CancellationToken cancellationToken);

    Task<WebsiteIdentity> RetryVerificationAsync(
        string domain,
        string actorId,
        string actorRole,
        CancellationToken cancellationToken);

    Task<WebsiteIdentityRegistrationResponse> RenewExpiredVerificationAsync(
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

    Task<HipWellKnownDocument> BuildWellKnownDocumentAsync(
        string domain,
        string actorId,
        string actorRole,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException("Owner-bound well-known document generation is not implemented.");
}
