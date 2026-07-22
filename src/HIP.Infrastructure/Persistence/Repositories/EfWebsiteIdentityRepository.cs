using HIP.Application.Identity;
using HIP.Application.PublicLookup;
using HIP.Domain.Identity;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>
/// Persists registered website identities in the encrypted HIP record store.
/// </summary>
public sealed class EfWebsiteIdentityRepository(HipRecordStore store) : IWebsiteIdentityRepository
{
    private const string Partition = "website-identity";

    /// <summary>
    /// Atomically creates a normalized website identity without replacing an existing registration.
    /// </summary>
    /// <param name="websiteIdentity">Website identity to create.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>True when this request created the registration; false when the normalized domain already exists.</returns>
    public Task<bool> TryCreateAsync(
        WebsiteIdentity websiteIdentity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(websiteIdentity);
        var normalized = DomainInputValidator.ValidateAndNormalize(websiteIdentity.Domain);
        var safeIdentity = websiteIdentity with { Domain = normalized };
        return store.TrySaveVersionedAsync(
            Partition,
            normalized,
            safeIdentity,
            expectedVersion: 0,
            newVersion: 1,
            cancellationToken);
    }

    /// <inheritdoc />
    public async Task<bool> TryUpdateAsync(
        WebsiteIdentity expected,
        WebsiteIdentity updated,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(updated);
        var normalized = DomainInputValidator.ValidateAndNormalize(expected.Domain);
        var normalizedUpdated = DomainInputValidator.ValidateAndNormalize(updated.Domain);
        if (!string.Equals(normalized, normalizedUpdated, StringComparison.Ordinal) ||
            !ImmutableRegistrationMatches(expected, updated))
        {
            throw new ArgumentException(
                "Website status updates cannot change the registered identity, key material, method, or creation time.",
                nameof(updated));
        }

        var stored = await store.GetEncryptedVersionedAsync<WebsiteIdentity>(
                Partition,
                normalized,
                cancellationToken)
            .ConfigureAwait(false);
        if (stored is null || !SnapshotsMatch(stored.Value.Record, expected))
        {
            return false;
        }

        return await store.TryUpdateVersionedAsync(
                Partition,
                normalized,
                updated with { Domain = normalized },
                stored.Value.AggregateVersion,
                stored.Value.AggregateVersion + 1,
                cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Saves a website identity and normalizes the domain used as the lookup key.
    /// </summary>
    /// <param name="websiteIdentity">Website identity to save.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>The saved website identity.</returns>
    public async Task<WebsiteIdentity> SaveAsync(WebsiteIdentity websiteIdentity, CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(websiteIdentity.Domain);
        var safeIdentity = websiteIdentity with { Domain = normalized };
        await store.SaveAsync(Partition, normalized, safeIdentity, cancellationToken);
        return safeIdentity;
    }

    /// <summary>
    /// Gets a website identity by domain.
    /// </summary>
    /// <param name="domain">Domain to look up.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>The stored website identity, or null when it has not been registered.</returns>
    public Task<WebsiteIdentity?> GetAsync(string domain, CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        return store.GetAsync<WebsiteIdentity>(Partition, normalized, cancellationToken);
    }

    /// <summary>
    /// Lists all persisted website identities without exposing verification challenge tokens.
    /// </summary>
    public Task<IReadOnlyCollection<WebsiteIdentity>> ListAsync(CancellationToken cancellationToken) =>
        store.ListAsync<WebsiteIdentity>(Partition, cancellationToken);

    private static bool ImmutableRegistrationMatches(WebsiteIdentity left, WebsiteIdentity right) =>
        string.Equals(left.HipIdentityId, right.HipIdentityId, StringComparison.Ordinal) &&
        left.PreferredVerificationMethod == right.PreferredVerificationMethod &&
        left.CreatedAtUtc == right.CreatedAtUtc &&
        SigningKeysMatch(left.PublicKeys, right.PublicKeys);

    private static bool SnapshotsMatch(WebsiteIdentity left, WebsiteIdentity right) =>
        string.Equals(left.Domain, DomainInputValidator.ValidateAndNormalize(right.Domain), StringComparison.Ordinal) &&
        ImmutableRegistrationMatches(left, right) &&
        left.VerificationStatus == right.VerificationStatus &&
        left.VerifiedAtUtc == right.VerifiedAtUtc &&
        left.LastCheckedAtUtc == right.LastCheckedAtUtc &&
        string.Equals(left.LastCheckMessage, right.LastCheckMessage, StringComparison.Ordinal) &&
        left.RevokedAtUtc == right.RevokedAtUtc;

    private static bool SigningKeysMatch(
        IReadOnlyCollection<SigningKey> left,
        IReadOnlyCollection<SigningKey> right) =>
        left.Count == right.Count &&
        left.Zip(right).All(pair =>
            string.Equals(pair.First.KeyId, pair.Second.KeyId, StringComparison.Ordinal) &&
            string.Equals(pair.First.Algorithm, pair.Second.Algorithm, StringComparison.Ordinal) &&
            string.Equals(pair.First.PublicKey, pair.Second.PublicKey, StringComparison.Ordinal));
}
