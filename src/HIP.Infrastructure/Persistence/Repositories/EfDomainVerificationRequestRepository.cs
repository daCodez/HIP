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
    /// Atomically creates a normalized domain verification challenge without replacing an existing token.
    /// </summary>
    /// <param name="request">Verification challenge to create.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>True when this request created the challenge; false when the normalized key already exists.</returns>
    public Task<bool> TryCreateAsync(
        DomainVerificationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var normalized = DomainInputValidator.ValidateAndNormalize(request.Domain);
        var safeRequest = request with { Domain = normalized };
        return store.TrySaveVersionedAsync(
            Partition,
            Key(normalized, request.Method),
            safeRequest,
            expectedVersion: 0,
            newVersion: 1,
            cancellationToken);
    }

    /// <inheritdoc />
    public async Task<bool> TryUpdateAsync(
        DomainVerificationRequest expected,
        DomainVerificationRequest updated,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(updated);
        var normalized = DomainInputValidator.ValidateAndNormalize(expected.Domain);
        var normalizedUpdated = DomainInputValidator.ValidateAndNormalize(updated.Domain);
        var renewal = IsRenewal(expected, updated);
        if (!string.Equals(normalized, normalizedUpdated, StringComparison.Ordinal) ||
            expected.Method != updated.Method ||
            (!renewal &&
             (!string.Equals(expected.Token, updated.Token, StringComparison.Ordinal) ||
              expected.CreatedAtUtc != updated.CreatedAtUtc ||
              expected.ExpiresAtUtc != updated.ExpiresAtUtc ||
              expected.ChallengeVersion != updated.ChallengeVersion)))
        {
            throw new ArgumentException(
                "Domain verification updates cannot change the domain, method, token, or request time.",
                nameof(updated));
        }

        var id = Key(normalized, expected.Method);
        var stored = await store.GetEncryptedVersionedAsync<DomainVerificationRequest>(
                Partition,
                id,
                cancellationToken)
            .ConfigureAwait(false);
        if (stored is null || !Equals(stored.Value.Record, expected with { Domain = normalized }))
        {
            return false;
        }

        return await store.TryUpdateVersionedAsync(
                Partition,
                id,
                updated with { Domain = normalized },
                stored.Value.AggregateVersion,
                stored.Value.AggregateVersion + 1,
                cancellationToken)
            .ConfigureAwait(false);
    }

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

    private static bool IsRenewal(DomainVerificationRequest expected, DomainVerificationRequest updated) =>
        expected.Status == VerificationStatus.Expired &&
        updated.Status == VerificationStatus.Pending &&
        !string.Equals(expected.Token, updated.Token, StringComparison.Ordinal) &&
        updated.CreatedAtUtc > expected.CreatedAtUtc &&
        updated.ExpiresAtUtc > updated.CreatedAtUtc &&
        updated.ChallengeVersion == expected.ChallengeVersion + 1;
}
