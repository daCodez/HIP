namespace HIP.ApiService.Application.Abstractions;

/// <summary>
/// Tracks message ids to prevent replay of signed messages/envelopes.
/// </summary>
public interface IReplayProtectionService
{
    /// <summary>
    /// Attempts to consume a message id for an identity.
    /// </summary>
    /// <param name="messageId">Message id/nonce to consume.</param>
    /// <param name="identityId">Identity id associated with the message.</param>
    /// <param name="cancellationToken">Cancellation token for storage access.</param>
    /// <returns><see langword="true"/> when the id is new; <see langword="false"/> when replayed.</returns>
    Task<bool> TryConsumeAsync(string messageId, string identityId, CancellationToken cancellationToken);
}
