using HIP.Application.Safety;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>Encrypted create-only persistence for privacy-safe safety-flow decisions.</summary>
public sealed class EfSafetyDecisionRepository(HipRecordStore store) : ISafetyDecisionRepository
{
    private const string Partition = "safety-decision";

    public async Task AddAsync(SafetyDecisionRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (!record.DecisionId.StartsWith("safety-decision:", StringComparison.Ordinal) ||
            record.DecisionId.Length != 48 ||
            !record.UrlHash.StartsWith("sha256:", StringComparison.Ordinal) ||
            !record.DomainHash.StartsWith("sha256:", StringComparison.Ordinal) ||
            record.RecordedAtUtc == default ||
            !Enum.IsDefined(record.Action) ||
            !Enum.IsDefined(record.RiskLevel))
        {
            throw new ArgumentException("Safety decision persistence contract is invalid.", nameof(record));
        }

        var created = await store.TrySaveVersionedAsync(
            Partition,
            record.DecisionId,
            record,
            expectedVersion: 0,
            newVersion: 1,
            cancellationToken);
        if (!created)
        {
            throw new InvalidOperationException("The immutable safety decision already exists.");
        }
    }
}
