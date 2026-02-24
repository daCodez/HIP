using HIP.ApiService.Application.Contracts;

namespace HIP.ApiService.Application.Abstractions;

public interface IMessageSignatureService
{
    Task<SignMessageResultDto> SignAsync(SignMessageRequestDto request, CancellationToken cancellationToken);
    Task<VerifyMessageResultDto> VerifyAsync(SignedMessageDto message, CancellationToken cancellationToken);
    Task<VerifyMessageResultDto> VerifyReadOnlyAsync(SignedMessageDto message, CancellationToken cancellationToken);
}
