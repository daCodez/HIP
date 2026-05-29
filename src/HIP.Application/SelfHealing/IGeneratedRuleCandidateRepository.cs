namespace HIP.Application.SelfHealing;

public interface IGeneratedRuleCandidateRepository
{
    Task SaveAsync(GeneratedRuleCandidate candidate, CancellationToken cancellationToken);

    Task<GeneratedRuleCandidate?> GetAsync(string candidateId, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<GeneratedRuleCandidate>> ListAsync(CancellationToken cancellationToken);
}
