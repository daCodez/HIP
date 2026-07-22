using HIP.Application.Ai;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>Encrypted create-only persistence for immutable AI rule drafts.</summary>
public sealed class EfAiRuleDraftRepository(HipRecordStore store) : IAiRuleDraftRepository
{
    private const string Partition = "ai-rule-draft";

    public async Task<bool> TryCreateAsync(AiRuleDraft draft, CancellationToken cancellationToken)
    {
        AiRuleDraftContract.Validate(draft);
        return await store.TrySaveVersionedAsync(
            Partition, draft.DraftId, draft, expectedVersion: 0, newVersion: 1, cancellationToken);
    }

    public async Task<AiRuleDraft?> GetAsync(string draftId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(draftId) || draftId.Length > 48 || draftId.Any(char.IsControl)) return null;
        var stored = await store.GetVersionedAsync<AiRuleDraft>(Partition, draftId, cancellationToken);
        if (stored is null || stored.Value.Record is null) return null;
        AiRuleDraftContract.Validate(stored.Value.Record);
        return stored.Value.AggregateVersion == stored.Value.Record.Version
            ? stored.Value.Record
            : throw new InvalidOperationException("AI rule draft version is inconsistent.");
    }

    public async Task<IReadOnlyCollection<AiRuleDraft>> ListAsync(CancellationToken cancellationToken)
    {
        var drafts = await store.ListAsync<AiRuleDraft>(Partition, cancellationToken);
        foreach (var draft in drafts) AiRuleDraftContract.Validate(draft);
        return drafts.OrderByDescending(draft => draft.CreatedAtUtc).ToArray();
    }
}
