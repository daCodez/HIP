using HIP.Domain.Identity;

namespace HIP.Application.Identity;

public interface IDomainVerificationService
{
    Task<DomainVerificationRequest> StartAsync(string domain, VerificationMethod method, CancellationToken cancellationToken);

    Task<DomainVerificationRequest> VerifyAsync(string domain, VerificationMethod method, string token, CancellationToken cancellationToken);
}
