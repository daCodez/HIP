using HIP.Domain.Identity;

namespace HIP.Application.Identity;

public interface IHipIdentityService
{
    Task<IdentityRegistrationResponse> RegisterAsync(IdentityRegistrationRequest request, CancellationToken cancellationToken);

    Task<HipSignature> SignAsync(SignContentRequest request, CancellationToken cancellationToken);

    Task<VerificationResult> VerifyAsync(VerifySignatureRequest request, CancellationToken cancellationToken);
}
