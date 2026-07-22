using HIP.Domain.Rules;

namespace HIP.Application.Rules;

public interface IRuleRepository
{
    Task<TrustRule> SaveAsync(TrustRule rule, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<TrustRule>> ListAsync(CancellationToken cancellationToken);

    Task<TrustRule?> GetByIdAsync(string ruleId, CancellationToken cancellationToken);

    /// <summary>Lists immutable saved versions of one rule, newest first.</summary>
    Task<IReadOnlyCollection<TrustRule>> ListVersionsAsync(string ruleId, CancellationToken cancellationToken);
}
