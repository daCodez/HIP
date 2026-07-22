using HIP.Application.Rules;
using HIP.Application.Simulation;
using HIP.Domain.Rules;

namespace HIP.Infrastructure.Persistence.Repositories;

public sealed class EfRuleRepository(HipRecordStore store) : IRuleRepository
{
    private const string Partition = "rule";
    private const string VersionPartition = "rule-version";

    public async Task<TrustRule> SaveAsync(TrustRule rule, CancellationToken cancellationToken)
    {
        var versionId = VersionId(rule.RuleId, rule.Version);
        var existingVersion = await store.GetAsync<TrustRule>(VersionPartition, versionId, cancellationToken);
        if (existingVersion is not null &&
            RuleDefinitionFingerprint.Compute(existingVersion) != RuleDefinitionFingerprint.Compute(rule))
        {
            throw new InvalidOperationException("A saved rule version is immutable.");
        }

        await store.SaveAsync(VersionPartition, versionId, rule, cancellationToken);
        await store.SaveAsync(Partition, rule.RuleId, rule, cancellationToken);
        return rule;
    }

    public Task<IReadOnlyCollection<TrustRule>> ListAsync(CancellationToken cancellationToken) =>
        store.ListAsync<TrustRule>(Partition, cancellationToken);

    public Task<TrustRule?> GetByIdAsync(string ruleId, CancellationToken cancellationToken) =>
        store.GetAsync<TrustRule>(Partition, ruleId, cancellationToken);

    public async Task<IReadOnlyCollection<TrustRule>> ListVersionsAsync(string ruleId, CancellationToken cancellationToken) =>
        (await store.ListAsync<TrustRule>(VersionPartition, cancellationToken))
            .Where(rule => rule.RuleId.Equals(ruleId, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(rule => rule.Version)
            .ToArray();

    private static string VersionId(string ruleId, int version) => $"{ruleId}:v{version}";
}
