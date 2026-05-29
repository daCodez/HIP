using HIP.Application.Rules;
using HIP.Domain.Rules;

namespace HIP.Infrastructure.Persistence.Repositories;

public sealed class EfRuleRepository(HipRecordStore store) : IRuleRepository
{
    private const string Partition = "rule";

    public async Task<TrustRule> SaveAsync(TrustRule rule, CancellationToken cancellationToken)
    {
        await store.SaveAsync(Partition, rule.RuleId, rule, cancellationToken);
        return rule;
    }

    public Task<IReadOnlyCollection<TrustRule>> ListAsync(CancellationToken cancellationToken) =>
        store.ListAsync<TrustRule>(Partition, cancellationToken);
}
