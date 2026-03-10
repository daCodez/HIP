using System.Text.Json;

namespace HIP.ApiService.Features.Admin;

internal sealed class PolicyVersionStore
{
    private readonly object _gate = new();
    private readonly List<PolicyVersionSnapshot> _versions = [];
    private readonly string _storePath;
    private readonly ILogger<PolicyVersionStore> _logger;
    private string _activeVersionId = string.Empty;
    private string? _previousActiveVersionId;

    public PolicyVersionStore(PolicyRuleStore rules, IConfiguration configuration, IWebHostEnvironment env, ILogger<PolicyVersionStore> logger)
    {
        _logger = logger;
        _storePath = configuration["HIP:Policy:VersionStorePath"]
            ?? Path.Combine(env.ContentRootPath, "Policy", "policy-versions.store.json");

        if (TryLoadPersistedState())
        {
            return;
        }

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
        SavePersistedStateUnsafe();
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
            SavePersistedStateUnsafe();
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
            SavePersistedStateUnsafe();
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

            SavePersistedStateUnsafe();
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

    private bool TryLoadPersistedState()
    {
        try
        {
            if (!File.Exists(_storePath))
            {
                return false;
            }

            var json = File.ReadAllText(_storePath);
            var state = JsonSerializer.Deserialize<PolicyVersionStoreState>(json);
            if (state is null || state.Versions.Count == 0 || string.IsNullOrWhiteSpace(state.ActiveVersionId))
            {
                return false;
            }

            _versions.Clear();
            _versions.AddRange(state.Versions.Select(v => v.Clone()));
            _activeVersionId = state.ActiveVersionId;
            _previousActiveVersionId = state.PreviousActiveVersionId;
            _logger.LogInformation("Loaded persisted policy version store from {Path} with {Count} versions", _storePath, _versions.Count);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load persisted policy version store from {Path}. Falling back to seed.", _storePath);
            return false;
        }
    }

    private void SavePersistedStateUnsafe()
    {
        try
        {
            var dir = Path.GetDirectoryName(_storePath);
            if (!string.IsNullOrWhiteSpace(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var state = new PolicyVersionStoreState
            {
                ActiveVersionId = _activeVersionId,
                PreviousActiveVersionId = _previousActiveVersionId,
                Versions = _versions.Select(v => v.Clone()).ToList()
            };

            var json = JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_storePath, json);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to persist policy version store to {Path}", _storePath);
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

internal sealed class PolicyVersionStoreState
{
    public string ActiveVersionId { get; set; } = string.Empty;
    public string? PreviousActiveVersionId { get; set; }
    public List<PolicyVersionSnapshot> Versions { get; set; } = [];
}
