using HIP.ApiService.Application.Contracts;

namespace HIP.ApiService.Application.Abstractions;

/// <summary>
/// Provides identity lookup capabilities for API handlers and policies.
/// </summary>
public interface IIdentityService
{
    /// <summary>
    /// Retrieves identity details by identifier.
    /// </summary>
    /// <param name="id">Identity id to resolve.</param>
    /// <param name="cancellationToken">Cancellation token for the lookup operation.</param>
    /// <returns>The identity payload if found; otherwise <see langword="null"/>.</returns>
    Task<IdentityDto?> GetByIdAsync(string id, CancellationToken cancellationToken);
}
