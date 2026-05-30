using HIP.Domain.Identity;

namespace HIP.Application.Identity;

public interface IHipSignatureService
{
    Task<HipSignature> SignAsync(HipSignatureRequest request, CancellationToken cancellationToken);

    Task<SignatureVerificationResult> VerifyAsync(HipSignatureVerificationRequest request, CancellationToken cancellationToken);

    Task<SigningKey> GetPublicKeyAsync(string identityId, CancellationToken cancellationToken);
}
