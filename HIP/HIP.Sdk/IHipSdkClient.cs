using HIP.Sdk.Models;

namespace HIP.Sdk;

/// <summary>
/// Defines the minimal HIP SDK read surface used by callers that need status,
/// identity lookups, and reputation lookups.
/// </summary>
public interface IHipSdkClient
{
    /// <summary>
    /// Fetches service health/status metadata from <c>/api/status</c>.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for the outbound HTTP request.</param>
    /// <returns>Structured status payload returned by the HIP API.</returns>
    Task<StatusResponse> GetStatusAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Fetches identity metadata from <c>/api/identity/{id}</c>.
    /// </summary>
    /// <param name="id">Identity identifier to resolve.</param>
    /// <param name="cancellationToken">Cancellation token for the outbound HTTP request.</param>
    /// <returns>
    /// Identity payload when found; <see langword="null"/> when the API returns <c>404 Not Found</c>.
    /// </returns>
    Task<IdentityDto?> GetIdentityAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Fetches reputation data from <c>/api/reputation/{identityId}</c>.
    /// </summary>
    /// <param name="identityId">Identity identifier whose reputation should be returned.</param>
    /// <param name="cancellationToken">Cancellation token for the outbound HTTP request.</param>
    /// <returns>
    /// Reputation payload when found; <see langword="null"/> when the API returns <c>404 Not Found</c>.
    /// </returns>
    Task<ReputationDto?> GetReputationAsync(string identityId, CancellationToken cancellationToken = default);
}
