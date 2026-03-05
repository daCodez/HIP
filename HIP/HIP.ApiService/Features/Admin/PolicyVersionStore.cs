namespace HIP.ApiService.Features.Admin;

internal sealed class PolicyVersionStore
{
    private readonly object _gate = new();
    private readonly List<PolicyVersionSnapshot> _versions = [];
    private string _activeVersionId;
    private string? _previousActiveVersionId;

    public PolicyVersionStore(PolicyRuleStore rules)
    {
        var seedId = "POLVER-001";
        var seed = new PolicyVersionSnapshot(
            seedId,
            "Initial policy pack",
            "Active",
            DateTimeOffset.UtcNow,
            "system",
            "seed",
            null,
            rules.GetAll().Select(x => x with { }).ToList());

        _versions.Add(seed);
        _activeVersionId = seedId;
    }

    public IReadOnlyList<PolicyVersionSnapshot> List() { lock (_gate) return _versions.Select(v => v.Clone()).OrderByDescending(v => v.CreatedUtc).ToList(); }
    public PolicyVersionSnapshot? Get(string id) { lock (_gate) return _versions.FirstOrDefault(x => x.VersionId == id)?.Clone(); }

    public IReadOnlyList<PolicyRuleEntry> GetEditableRules()
    {
        lock (_gate)
        {
            var draft = _versions.FirstOrDefault(v => v.Status == "Draft");
            var source = draft ?? _versions.First(v => v.VersionId == _activeVersionId);
            return source.Rules.Select(x => x with { }).ToList();
        }
    }

    public PolicyVersionSnapshot CreateDraft(string actor, string reason)
    {
        lock (_gate)
        {
            var existingDraft = _versions.FirstOrDefault(v => v.Status == "Draft");
            if (existingDraft is not null) return existingDraft.Clone();

            var active = _versions.First(v => v.VersionId == _activeVersionId);
            var id = $"POLVER-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}";
            var draft = new PolicyVersionSnapshot(id, $"Draft {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm}", "Draft", DateTimeOffset.UtcNow, actor, reason, null, active.Rules.Select(x => x with { }).ToList());
            _versions.Add(draft);
            return draft.Clone();
        }
    }

    public (PolicyVersionSnapshot Version, string DraftId) UpsertRule(PolicyRuleEntry rule, string actor, string reason)
    {
        lock (_gate)
        {
            var draft = _versions.FirstOrDefault(v => v.Status == "Draft") ?? CreateDraft(actor, reason);
            var inList = _versions.First(v => v.VersionId == draft.VersionId);
            var ix = inList.Rules.FindIndex(r => string.Equals(r.RuleId, rule.RuleId, StringComparison.OrdinalIgnoreCase));
            if (ix >= 0) inList.Rules[ix] = rule;
            else inList.Rules.Add(rule);
            return (inList.Clone(), inList.VersionId);
        }
    }

    public PolicyVersionSnapshot Activate(string versionId, string actor, string reason, string? approvedBy)
    {
        lock (_gate)
        {
            var target = _versions.First(v => v.VersionId == versionId);
            var active = _versions.First(v => v.VersionId == _activeVersionId);
            active.Status = "Archived";

            _previousActiveVersionId = _activeVersionId;
            _activeVersionId = target.VersionId;

            target.Status = "Active";
            target.ActivatedUtc = DateTimeOffset.UtcNow;
            target.Actor = actor;
            target.Reason = reason;
            target.ApprovedBy = approvedBy;

            return target.Clone();
        }
    }

    public PolicyVersionSnapshot Rollback(string actor, string reason)
    {
        lock (_gate)
        {
            if (string.IsNullOrWhiteSpace(_previousActiveVersionId)) throw new InvalidOperationException("No previous active version to roll back to.");
            return Activate(_previousActiveVersionId, actor, reason, approvedBy: actor);
        }
    }

    public object PreviewImpact(string versionId)
    {
        lock (_gate)
        {
            var target = _versions.First(v => v.VersionId == versionId);
            var active = _versions.First(v => v.VersionId == _activeVersionId);

            static (int Block, int Challenge, int Warn) Buckets(IEnumerable<PolicyRuleEntry> rules) => (
                rules.Count(x => string.Equals(x.Action, "Block", StringComparison.OrdinalIgnoreCase)),
                rules.Count(x => string.Equals(x.Action, "Challenge", StringComparison.OrdinalIgnoreCase)),
                rules.Count(x => string.Equals(x.Action, "Warn", StringComparison.OrdinalIgnoreCase) || string.Equals(x.Action, "Restrict", StringComparison.OrdinalIgnoreCase))
            );

            var a = Buckets(active.Rules);
            var t = Buckets(target.Rules);
            return new
            {
                activeVersionId = active.VersionId,
                targetVersionId = target.VersionId,
                ifActivated = new { block = t.Block, challenge = t.Challenge, warn = t.Warn },
                delta = new { block = t.Block - a.Block, challenge = t.Challenge - a.Challenge, warn = t.Warn - a.Warn }
            };
        }
    }

    public object Diff(string versionId, string? against)
    {
        lock (_gate)
        {
            var target = _versions.First(v => v.VersionId == versionId);
            var baselineId = string.IsNullOrWhiteSpace(against) || string.Equals(against, "active", StringComparison.OrdinalIgnoreCase)
                ? _activeVersionId
                : against;
            var baseline = _versions.First(v => v.VersionId == baselineId);

            var b = baseline.Rules.ToDictionary(x => x.RuleId, x => x);
            var t = target.Rules.ToDictionary(x => x.RuleId, x => x);

            var added = t.Keys.Except(b.Keys).Select(id => t[id]);
            var removed = b.Keys.Except(t.Keys).Select(id => b[id]);
            var changed = t.Keys.Intersect(b.Keys)
                .Where(id => !Equals(t[id], b[id]))
                .Select(id => new { ruleId = id, before = b[id], after = t[id] });

            return new { baseline = baseline.VersionId, target = target.VersionId, added, removed, changed };
        }
    }
}

internal sealed class PolicyVersionSnapshot
{
    public string VersionId { get; set; }
    public string Name { get; set; }
    public string Status { get; set; }
    public DateTimeOffset CreatedUtc { get; set; }
    public DateTimeOffset? ActivatedUtc { get; set; }
    public string Actor { get; set; }
    public string Reason { get; set; }
    public string? ApprovedBy { get; set; }
    public List<PolicyRuleEntry> Rules { get; set; }

    public PolicyVersionSnapshot(string versionId, string name, string status, DateTimeOffset createdUtc, string actor, string reason, string? approvedBy, List<PolicyRuleEntry> rules)
    {
        VersionId = versionId;
        Name = name;
        Status = status;
        CreatedUtc = createdUtc;
        Actor = actor;
        Reason = reason;
        ApprovedBy = approvedBy;
        Rules = rules;
    }

    public PolicyVersionSnapshot Clone() => new(VersionId, Name, Status, CreatedUtc, Actor, Reason, ApprovedBy, Rules.Select(x => x with { }).ToList()) { ActivatedUtc = ActivatedUtc };
}
