using HIP.Application.Identity;
using HIP.Application.PublicLookup;
using HIP.Domain.Identity;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>
/// Persists domain verification challenges in the encrypted HIP record store.
/// </summary>
public sealed class EfDomainVerificationRequestRepository(HipRecordStore store) : IDomainVerificationRequestRepository
{
    private const string Partition = "domain-verification-request";

    /// <summary>
    /// Saves a domain verification challenge without logging or exposing its token.
    /// </summary>
    /// <param name="request">Verification challenge to save.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>The saved verification challenge.</returns>
    public async Task<DomainVerificationRequest> SaveAsync(DomainVerificationRequest request, CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(request.Domain);
        var safeRequest = request with { Domain = normalized };
        await store.SaveAsync(Partition, Key(normalized, request.Method), safeRequest, cancellationToken);
        return safeRequest;
    }

    /// <summary>
    /// Gets a stored verification challenge by domain and method.
    /// </summary>
    /// <param name="domain">Domain being verified.</param>
    /// <param name="method">Verification method used by the challenge.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>The stored challenge, or null when verification has not started.</returns>
    public Task<DomainVerificationRequest?> GetAsync(string domain, VerificationMethod method, CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        return store.GetAsync<DomainVerificationRequest>(Partition, Key(normalized, method), cancellationToken);
    }

    /// <summary>
    /// Creates a stable storage key for a domain and verification method.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="method">Verification method.</param>
    /// <returns>Storage key for the challenge.</returns>
    private static string Key(string domain, VerificationMethod method) => $"{method}:{domain}";
}
