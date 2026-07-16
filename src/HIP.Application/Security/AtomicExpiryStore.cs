namespace HIP.Application.Security;

/// <summary>
/// Provides atomic create-if-absent state with automatic expiry for distributed security decisions.
/// </summary>
public interface IAtomicExpiryStore
{
    /// <summary>
    /// Creates a key only when no unexpired value already exists.
    /// </summary>
    ValueTask<bool> TryCreateAsync(
        string key,
        TimeSpan timeToLive,
        CancellationToken cancellationToken = default);
}
