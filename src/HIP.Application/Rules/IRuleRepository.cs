using HIP.Domain.Rules;

namespace HIP.Application.Rules;

public interface IRuleRepository
{
    Task<TrustRule> SaveAsync(TrustRule rule, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<TrustRule>> ListAsync(CancellationToken cancellationToken);

    Task<TrustRule?> GetByIdAsync(string ruleId, CancellationToken cancellationToken);
}
