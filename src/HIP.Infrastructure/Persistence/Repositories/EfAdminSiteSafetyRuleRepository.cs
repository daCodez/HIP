using HIP.Application.SiteSafety;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>
/// Persists admin-managed Site Safety rules using HIP's generic JSON record store.
/// </summary>
public sealed class EfAdminSiteSafetyRuleRepository(HipRecordStore store) : IAdminSiteSafetyRuleRepository
{
    private const string RulePartition = "site-safety-admin-rule";
    private const string VersionPartitionPrefix = "site-safety-admin-rule-version";

    /// <inheritdoc />
    public async Task<AdminSiteSafetyRule> SaveAsync(AdminSiteSafetyRule rule, CancellationToken cancellationToken)
    {
        await store.SaveAsync(RulePartition, rule.RuleId, rule, cancellationToken);
        return rule;
    }

    /// <inheritdoc />
    public Task<IReadOnlyCollection<AdminSiteSafetyRule>> ListAsync(CancellationToken cancellationToken) =>
        store.ListAsync<AdminSiteSafetyRule>(RulePartition, cancellationToken);

    /// <inheritdoc />
    public Task<AdminSiteSafetyRule?> GetByIdAsync(string ruleId, CancellationToken cancellationToken) =>
        store.GetAsync<AdminSiteSafetyRule>(RulePartition, ruleId, cancellationToken);

    /// <inheritdoc />
    public Task SaveVersionAsync(AdminSiteSafetyRule rule, CancellationToken cancellationToken) =>
        store.SaveAsync(VersionPartition(rule.RuleId), rule.Version.ToString("D6"), rule, cancellationToken);

    /// <inheritdoc />
    public async Task<AdminSiteSafetyRule?> GetPreviousVersionAsync(string ruleId, CancellationToken cancellationToken)
    {
        var versions = await store.ListAsync<AdminSiteSafetyRule>(VersionPartition(ruleId), cancellationToken);
        return versions.OrderByDescending(rule => rule.Version).FirstOrDefault();
    }

    /// <summary>
    /// Builds the per-rule version partition.
    /// </summary>
    private static string VersionPartition(string ruleId) =>
        $"{VersionPartitionPrefix}:{ruleId}";
}
