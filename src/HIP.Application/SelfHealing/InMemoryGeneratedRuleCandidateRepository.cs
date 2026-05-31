using System.Collections.Concurrent;

namespace HIP.Application.SelfHealing;

public sealed class InMemoryGeneratedRuleCandidateRepository : IGeneratedRuleCandidateRepository
{
    private readonly ConcurrentDictionary<string, GeneratedRuleCandidate> _candidates = new(StringComparer.OrdinalIgnoreCase);

    public Task SaveAsync(GeneratedRuleCandidate candidate, CancellationToken cancellationToken)
    {
        _candidates[candidate.CandidateId] = candidate;
        return Task.CompletedTask;
    }

    public Task<GeneratedRuleCandidate?> GetAsync(string candidateId, CancellationToken cancellationToken)
    {
        _candidates.TryGetValue(candidateId, out var candidate);
        return Task.FromResult(candidate);
    }

    public Task<IReadOnlyCollection<GeneratedRuleCandidate>> ListAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyCollection<GeneratedRuleCandidate>>(
            _candidates.Values
                .OrderByDescending(candidate => candidate.CreatedAtUtc)
                .ToArray());
}
