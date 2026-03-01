using HIP.ApiService.Application.Contracts;

namespace HIP.ApiService.Application.Abstractions;

/// <summary>
/// Signs and verifies HIP message envelopes.
/// </summary>
public interface IMessageSignatureService
{
    /// <summary>
    /// Signs a message payload and returns a signed message contract.
    /// </summary>
    /// <param name="request">Unsigned sign request.</param>
    /// <param name="cancellationToken">Cancellation token for crypto and storage operations.</param>
    /// <returns>Sign result including signed payload when successful.</returns>
    Task<SignMessageResultDto> SignAsync(SignMessageRequestDto request, CancellationToken cancellationToken);

    /// <summary>
    /// Verifies a signed message with full side effects (replay tracking, counters, reputation impact).
    /// </summary>
    /// <param name="message">Signed message to verify.</param>
    /// <param name="cancellationToken">Cancellation token for verification operations.</param>
    /// <returns>Verification result.</returns>
    Task<VerifyMessageResultDto> VerifyAsync(SignedMessageDto message, CancellationToken cancellationToken);

    /// <summary>
    /// Verifies a signed message in read-only mode without side effects.
    /// </summary>
    /// <param name="message">Signed message to verify.</param>
    /// <param name="cancellationToken">Cancellation token for verification operations.</param>
    /// <returns>Verification result.</returns>
    Task<VerifyMessageResultDto> VerifyReadOnlyAsync(SignedMessageDto message, CancellationToken cancellationToken);
}
