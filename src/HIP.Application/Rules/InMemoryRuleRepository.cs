using System.Collections.Concurrent;
using HIP.Domain.Rules;

namespace HIP.Application.Rules;

public sealed class InMemoryRuleRepository : IRuleRepository
{
    private readonly ConcurrentDictionary<string, TrustRule> _rules = new(StringComparer.OrdinalIgnoreCase);

    public Task<TrustRule> SaveAsync(TrustRule rule, CancellationToken cancellationToken)
    {
        var ruleId = string.IsNullOrWhiteSpace(rule.RuleId)
            ? Slug(rule.Name)
            : rule.RuleId;

        var version = Math.Max(rule.Version, 1);
        var requiresApproval = rule.RequiresApproval || RuleValidationConstants.IsHighImpact(rule);
        var approvalStatus = requiresApproval && rule.ApprovalStatus == ApprovalStatus.NotRequired
            ? ApprovalStatus.Pending
            : rule.ApprovalStatus;

        var saved = rule with
        {
            RuleId = ruleId,
            Version = version,
            RequiresApproval = requiresApproval,
            ApprovalStatus = approvalStatus
        };

        _rules[saved.RuleId] = saved;
        return Task.FromResult(saved);
    }

    public Task<IReadOnlyCollection<TrustRule>> ListAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyCollection<TrustRule>>(_rules.Values.OrderBy(rule => rule.Name).ToArray());

    public Task<TrustRule?> GetByIdAsync(string ruleId, CancellationToken cancellationToken)
    {
        _rules.TryGetValue(ruleId, out var rule);
        return Task.FromResult(rule);
    }

    private static string Slug(string value)
    {
        var chars = value.Trim().ToLowerInvariant()
            .Select(character => char.IsLetterOrDigit(character) ? character : '-')
            .ToArray();

        return string.Join('-', new string(chars).Split('-', StringSplitOptions.RemoveEmptyEntries));
    }
}
