using HIP.Application.SelfHealing;

namespace HIP.Infrastructure.Persistence.Repositories;

public sealed class EfGeneratedRuleCandidateRepository(HipRecordStore store) : IGeneratedRuleCandidateRepository
{
    private const string Partition = "generated-rule-candidate";

    public Task SaveAsync(GeneratedRuleCandidate candidate, CancellationToken cancellationToken) =>
        store.SaveAsync(Partition, candidate.CandidateId, candidate, cancellationToken);

    public Task<GeneratedRuleCandidate?> GetAsync(string candidateId, CancellationToken cancellationToken) =>
        store.GetAsync<GeneratedRuleCandidate>(Partition, candidateId, cancellationToken);

    public Task<IReadOnlyCollection<GeneratedRuleCandidate>> ListAsync(CancellationToken cancellationToken) =>
        store.ListAsync<GeneratedRuleCandidate>(Partition, cancellationToken);
}
