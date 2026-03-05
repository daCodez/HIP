using HIP.ApiService.Infrastructure.Plugins;
using Microsoft.Extensions.Options;

namespace HIP.ApiService.Features.Admin;

internal sealed class PolicyRuleStore
{
    private readonly object _gate = new();
    private readonly List<PolicyRuleEntry> _rules;

    public PolicyRuleStore(IConfiguration configuration, IOptions<PolicyPackOptions> optionsAccessor)
    {
        var options = optionsAccessor.Value;
        var enabled = configuration.GetSection("HIP:Plugins:Enabled").Get<string[]>() ?? [];
        var strictEnabled = enabled.Contains("core.policy.strict", StringComparer.OrdinalIgnoreCase);

        _rules =
        [
            new("POL-001", "Require MFA", "Login", "mfa == false", "Challenge", "High", true),
            new("POL-002", "Untrusted device challenge", "Device", "deviceTrusted == false", "Challenge", "Medium", true),
            new("POL-003", "Replay attempt block", "Token", "replayDetected == true", "Block", "Critical", true),
            new("POL-004", "Token expiration block", "Token", "tokenExpired == true", "Block", "High", true),
            new("POL-005", "Low reputation restriction", "Reputation", $"reputation < {options.LowRiskRequiredScore}", "Warn", "Medium", true),
            new("POL-006", "Very low reputation quarantine", "Reputation", $"reputation < {Math.Max(1, options.LowRiskRequiredScore / 2)}", "Quarantine", "Critical", true),
            new("POL-007", "Phishing domain block", "Messaging", "domainFlagged == true", "Block", "Critical", true),
            new("POL-008", "Spam rate limit", "Messaging", "messagesSent > 50 in 5m", "RateLimit", "Medium", true),
            new("POL-009", "Suspicious IP alert", "Login", "ipRisk == high", "Alert", "Warning", true),
            new("POL-010", "Impossible travel block", "Login", "loginCountry changed && time < 2h", strictEnabled ? "Block" : "Challenge", strictEnabled ? "Critical" : "High", true)
        ];
    }

    public IReadOnlyList<PolicyRuleEntry> GetAll()
    {
        lock (_gate)
        {
            return _rules.Select(x => x with { }).ToList();
        }
    }

    public void Upsert(PolicyRuleEntry entry)
    {
        lock (_gate)
        {
            var ix = _rules.FindIndex(x => x.RuleId.Equals(entry.RuleId, StringComparison.OrdinalIgnoreCase));
            if (ix >= 0) _rules[ix] = entry;
            else _rules.Add(entry);
        }
    }
}

internal sealed record PolicyRuleEntry(
    string RuleId,
    string Name,
    string Category,
    string Condition,
    string Action,
    string Severity,
    bool Enabled);
