using System.Collections.Concurrent;
using HIP.Application.Simulation;
using HIP.Domain.Rules;

namespace HIP.Application.Rules;

public sealed class InMemoryRuleRepository : IRuleRepository
{
    private readonly ConcurrentDictionary<string, TrustRule> _rules = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<int, TrustRule>> _versions = new(StringComparer.OrdinalIgnoreCase);

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

        var versions = _versions.GetOrAdd(saved.RuleId, _ => new ConcurrentDictionary<int, TrustRule>());
        if (!versions.TryAdd(saved.Version, saved) &&
            RuleDefinitionFingerprint.Compute(versions[saved.Version]) != RuleDefinitionFingerprint.Compute(saved))
        {
            throw new InvalidOperationException("A saved rule version is immutable.");
        }
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

    public Task<IReadOnlyCollection<TrustRule>> ListVersionsAsync(string ruleId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<IReadOnlyCollection<TrustRule>>(
            _versions.TryGetValue(ruleId, out var versions)
                ? versions.Values.OrderByDescending(rule => rule.Version).ToArray()
                : []);
    }

    private static string Slug(string value)
    {
        var chars = value.Trim().ToLowerInvariant()
            .Select(character => char.IsLetterOrDigit(character) ? character : '-')
            .ToArray();

        return string.Join('-', new string(chars).Split('-', StringSplitOptions.RemoveEmptyEntries));
    }
}
