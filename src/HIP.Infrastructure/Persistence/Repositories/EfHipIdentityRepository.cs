using HIP.Application.Identity;
using HIP.Domain.Identity;

namespace HIP.Infrastructure.Persistence.Repositories;

public sealed class EfHipIdentityRepository(HipRecordStore store) : IHipIdentityRepository
{
    private const string Partition = "identity";

    public Task<HipIdentity> SaveAsync(HipIdentity identity, CancellationToken cancellationToken) =>
        Save(identity, cancellationToken);

    public Task<HipIdentity?> GetAsync(string identityId, CancellationToken cancellationToken) =>
        store.GetAsync<HipIdentity>(Partition, identityId, cancellationToken);

    public async Task<bool> TryUpdateAsync(
        HipIdentity expected,
        HipIdentity updated,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(updated);
        if (!ImmutableFieldsMatch(expected, updated))
        {
            throw new ArgumentException(
                "HIP verification-status updates cannot change canonical identity fields.",
                nameof(updated));
        }

        var stored = await store.GetVersionedAsync<HipIdentity>(Partition, expected.IdentityId, cancellationToken)
            .ConfigureAwait(false);
        if (stored is null || stored.Value.Record != expected)
        {
            return false;
        }

        return await store.TryUpdateVersionedAsync(
                Partition,
                expected.IdentityId,
                updated,
                stored.Value.AggregateVersion,
                stored.Value.AggregateVersion + 1,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static bool ImmutableFieldsMatch(HipIdentity expected, HipIdentity updated) =>
        string.Equals(expected.IdentityId, updated.IdentityId, StringComparison.Ordinal) &&
        expected.IdentityType == updated.IdentityType &&
        string.Equals(expected.DisplayName, updated.DisplayName, StringComparison.Ordinal) &&
        string.Equals(expected.PublicKey, updated.PublicKey, StringComparison.Ordinal) &&
        string.Equals(expected.KeyAlgorithm, updated.KeyAlgorithm, StringComparison.Ordinal) &&
        expected.CreatedAtUtc == updated.CreatedAtUtc &&
        string.Equals(expected.ReputationTargetId, updated.ReputationTargetId, StringComparison.Ordinal);

    private async Task<HipIdentity> Save(HipIdentity identity, CancellationToken cancellationToken)
    {
        await store.SaveAsync(Partition, identity.IdentityId, identity, cancellationToken);
        return identity;
    }
}
