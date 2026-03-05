namespace HIP.ApiService.Features.Admin;

internal sealed class AuthzPolicyStore
{
    private readonly object _gate = new();
    private readonly List<AuthzPolicyEntry> _rules =
    [
        new("AUTHZ-001", "Support can view audit logs", "Support", "audit", "read", "Allow", true),
        new("AUTHZ-002", "Support cannot export audit logs", "Support", "audit", "export", "Deny", true),
        new("AUTHZ-003", "Analyst can view reputation", "Analyst", "reputation", "read", "Allow", true),
        new("AUTHZ-004", "Analyst cannot disable security policies", "Analyst", "policy", "disable", "Deny", true),
        new("AUTHZ-005", "Admin full policy management", "Admin", "policy", "manage", "Allow", true)
    ];

    public IReadOnlyList<AuthzPolicyEntry> GetAll()
    {
        lock (_gate)
        {
            return _rules.Select(x => x with { }).ToList();
        }
    }
}

internal sealed record AuthzPolicyEntry(
    string RuleId,
    string Name,
    string Role,
    string Resource,
    string Action,
    string Decision,
    bool Enabled);
