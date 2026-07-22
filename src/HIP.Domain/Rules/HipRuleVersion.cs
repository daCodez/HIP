namespace HIP.Domain.Rules;

using System.Text.Json;

/// <summary>Lifecycle state of one immutable rule version.</summary>
public enum HipRuleStatus { Draft, PendingApproval, Approved, Active, Disabled, Archived }

/// <summary>Runtime behavior of a rule version.</summary>
public enum HipRuleMode { Disabled, Watch, Active }

/// <summary>Maximum operational impact of a rule version.</summary>
public enum HipRuleImpactLevel { Low, Medium, High, Critical }

/// <summary>Origin of a rule definition; origin never grants approval authority.</summary>
public enum HipRuleCreatorType { Human, Imported, AiSuggested }

/// <summary>Approval policy derived from rule impact.</summary>
public enum HipRuleApprovalRequirement { None, OnePerson, TwoPerson, ManualTwoPerson }

/// <summary>One immutable authorized approval without credentials or display-name data.</summary>
public sealed record HipRuleApproval(string ApprovalId, string ApproverId, DateTimeOffset ApprovedAtUtc);

/// <summary>JSON-first condition shape; HIP-0402 owns the typed field/operator catalog.</summary>
public sealed record HipRuleCondition(string Field, string Operator, string ExpectedValueJson);

/// <summary>JSON-first action shape; action validation remains bounded and allow-listed by the application.</summary>
public sealed record HipRuleAction(string ActionType, string ParametersJson);

/// <summary>Explicit rollback target or known disabled fallback for one rule version.</summary>
public sealed record HipRuleRollback(
    string? TargetVersionId,
    bool UseDisabledFallback,
    bool TestRequired,
    DateTimeOffset? TestedAtUtc,
    string? TestedBy);

/// <summary>
/// Version-one domain schema for an immutable rule version. It contains lifecycle metadata only;
/// evaluation, persistence, UI, and provider concerns remain outside the domain.
/// </summary>
public sealed class HipRuleVersion
{
    public const string CurrentSchemaVersion = "hip-rule/1";
    public const int MaximumConditions = 32;
    public const int MaximumActions = 16;

    public HipRuleVersion(
        string schemaVersion,
        string ruleId,
        string versionId,
        int version,
        string name,
        string description,
        HipRuleStatus status,
        HipRuleMode mode,
        HipRuleImpactLevel impactLevel,
        HipRuleCreatorType creatorType,
        string createdBy,
        DateTimeOffset createdAtUtc,
        IReadOnlyCollection<HipRuleCondition> conditions,
        IReadOnlyCollection<HipRuleAction> actions,
        bool simulationRequired,
        HipRuleApprovalRequirement approvalRequirement,
        IReadOnlyCollection<HipRuleApproval> approvals,
        DateTimeOffset? effectiveFromUtc,
        DateTimeOffset? expiresAtUtc,
        string? previousVersionId,
        HipRuleRollback rollback)
    {
        SchemaVersion = Required(schemaVersion, nameof(schemaVersion), 32);
        if (!string.Equals(SchemaVersion, CurrentSchemaVersion, StringComparison.Ordinal))
        {
            throw new ArgumentException("Unsupported HIP rule schema version.", nameof(schemaVersion));
        }

        RuleId = Identifier(ruleId, nameof(ruleId));
        VersionId = Identifier(versionId, nameof(versionId));
        if (version < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(version));
        }
        if (version == 1 && previousVersionId is not null || version > 1 && previousVersionId is null)
        {
            throw new ArgumentException("Rule version lineage must identify exactly one prior version after version one.", nameof(previousVersionId));
        }

        Version = version;
        Name = Required(name, nameof(name), 160);
        Description = Required(description, nameof(description), 2_000);
        ValidateEnum(status, nameof(status));
        ValidateEnum(mode, nameof(mode));
        ValidateEnum(impactLevel, nameof(impactLevel));
        ValidateEnum(creatorType, nameof(creatorType));
        ValidateEnum(approvalRequirement, nameof(approvalRequirement));
        Status = status;
        Mode = mode;
        if (status is HipRuleStatus.Disabled or HipRuleStatus.Archived && mode is not HipRuleMode.Disabled ||
            status is not HipRuleStatus.Active && mode is HipRuleMode.Active ||
            status is HipRuleStatus.Active && mode is HipRuleMode.Disabled)
        {
            throw new ArgumentException("Rule lifecycle status and runtime mode are inconsistent.", nameof(mode));
        }
        ImpactLevel = impactLevel;
        CreatorType = creatorType;
        CreatedBy = Identifier(createdBy, nameof(createdBy));
        CreatedAtUtc = createdAtUtc;
        PreviousVersionId = previousVersionId is null ? null : Identifier(previousVersionId, nameof(previousVersionId));

        ArgumentNullException.ThrowIfNull(conditions);
        ArgumentNullException.ThrowIfNull(actions);
        ArgumentNullException.ThrowIfNull(approvals);
        ArgumentNullException.ThrowIfNull(rollback);
        if (conditions.Count is < 1 or > MaximumConditions || conditions.Any(item => item is null))
        {
            throw new ArgumentOutOfRangeException(nameof(conditions));
        }
        if (actions.Count is < 1 or > MaximumActions || actions.Any(item => item is null))
        {
            throw new ArgumentOutOfRangeException(nameof(actions));
        }
        if (approvals.Count > 4 || approvals.Any(item => item is null))
        {
            throw new ArgumentOutOfRangeException(nameof(approvals));
        }

        Conditions = Array.AsReadOnly(conditions.Select(ValidateCondition).ToArray());
        Actions = Array.AsReadOnly(actions.Select(ValidateAction).ToArray());
        SimulationRequired = simulationRequired;
        ApprovalRequirement = approvalRequirement;
        ValidateApprovalPolicy(impactLevel, approvalRequirement);

        var normalizedApprovals = approvals.Select(approval => new HipRuleApproval(
            Identifier(approval.ApprovalId, nameof(approvals)),
            Identifier(approval.ApproverId, nameof(approvals)),
            approval.ApprovedAtUtc)).ToArray();
        if (normalizedApprovals.Select(item => item.ApprovalId).Distinct(StringComparer.OrdinalIgnoreCase).Count() != normalizedApprovals.Length ||
            normalizedApprovals.Select(item => item.ApproverId).Distinct(StringComparer.OrdinalIgnoreCase).Count() != normalizedApprovals.Length ||
            normalizedApprovals.Any(item =>
                string.Equals(item.ApproverId, CreatedBy, StringComparison.OrdinalIgnoreCase) ||
                item.ApprovedAtUtc < CreatedAtUtc))
        {
            throw new ArgumentException("Rule approvals must be unique, independent from the creator, and no earlier than creation.", nameof(approvals));
        }
        Approvals = Array.AsReadOnly(normalizedApprovals);

        if (effectiveFromUtc < createdAtUtc || expiresAtUtc <= (effectiveFromUtc ?? createdAtUtc))
        {
            throw new ArgumentException("Rule effective and expiry times are out of order.", nameof(effectiveFromUtc));
        }
        if (status is HipRuleStatus.Active && effectiveFromUtc is null)
        {
            throw new ArgumentException("An active rule version requires an effective time.", nameof(effectiveFromUtc));
        }
        EffectiveFromUtc = effectiveFromUtc;
        ExpiresAtUtc = expiresAtUtc;

        var rollbackTarget = rollback.TargetVersionId is null ? null : Identifier(rollback.TargetVersionId, nameof(rollback));
        if ((rollbackTarget is null) == !rollback.UseDisabledFallback ||
            rollback.TestedAtUtc is null != (rollback.TestedBy is null) ||
            string.Equals(rollbackTarget, VersionId, StringComparison.Ordinal))
        {
            throw new ArgumentException("Rollback must identify one target and complete test metadata as a pair.", nameof(rollback));
        }
        if (rollback.TestedAtUtc < createdAtUtc)
        {
            throw new ArgumentException("Rollback testing cannot predate rule creation.", nameof(rollback));
        }
        Rollback = new HipRuleRollback(
            rollbackTarget,
            rollback.UseDisabledFallback,
            rollback.TestRequired,
            rollback.TestedAtUtc,
            rollback.TestedBy is null ? null : Identifier(rollback.TestedBy, nameof(rollback)));
    }

    public string SchemaVersion { get; }
    public string RuleId { get; }
    public string VersionId { get; }
    public int Version { get; }
    public string Name { get; }
    public string Description { get; }
    public HipRuleStatus Status { get; }
    public HipRuleMode Mode { get; }
    public HipRuleImpactLevel ImpactLevel { get; }
    public HipRuleCreatorType CreatorType { get; }
    public string CreatedBy { get; }
    public DateTimeOffset CreatedAtUtc { get; }
    public IReadOnlyCollection<HipRuleCondition> Conditions { get; }
    public IReadOnlyCollection<HipRuleAction> Actions { get; }
    public bool SimulationRequired { get; }
    public HipRuleApprovalRequirement ApprovalRequirement { get; }
    public IReadOnlyCollection<HipRuleApproval> Approvals { get; }
    public DateTimeOffset? EffectiveFromUtc { get; }
    public DateTimeOffset? ExpiresAtUtc { get; }
    public string? PreviousVersionId { get; }
    public HipRuleRollback Rollback { get; }

    private static HipRuleCondition ValidateCondition(HipRuleCondition value) => new(
        Identifier(value.Field, nameof(value.Field)),
        Identifier(value.Operator, nameof(value.Operator)),
        Json(value.ExpectedValueJson, nameof(value.ExpectedValueJson), 4_096));

    private static HipRuleAction ValidateAction(HipRuleAction value) => new(
        Identifier(value.ActionType, nameof(value.ActionType)),
        Json(value.ParametersJson, nameof(value.ParametersJson), 8_192));

    private static string Json(string value, string parameterName, int maximumLength)
    {
        var normalized = Required(value, parameterName, maximumLength);
        try
        {
            using var _ = JsonDocument.Parse(normalized, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 32
            });
            return normalized;
        }
        catch (JsonException exception)
        {
            throw new ArgumentException("Rule JSON must be valid and bounded.", parameterName, exception);
        }
    }

    private static void ValidateApprovalPolicy(HipRuleImpactLevel impact, HipRuleApprovalRequirement requirement)
    {
        var expected = impact switch
        {
            HipRuleImpactLevel.Low => HipRuleApprovalRequirement.None,
            HipRuleImpactLevel.Medium => HipRuleApprovalRequirement.OnePerson,
            HipRuleImpactLevel.High => HipRuleApprovalRequirement.TwoPerson,
            HipRuleImpactLevel.Critical => HipRuleApprovalRequirement.ManualTwoPerson,
            _ => throw new ArgumentOutOfRangeException(nameof(impact))
        };
        if (requirement != expected)
        {
            throw new ArgumentException("Rule approval policy does not match its impact level.", nameof(requirement));
        }
    }

    private static string Identifier(string value, string parameterName) => Required(value, parameterName, 160, allowSpaces: false);

    private static string Required(string value, string parameterName, int maximumLength, bool allowSpaces = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        var normalized = value.Trim();
        if (normalized.Length > maximumLength || normalized.Any(char.IsControl) ||
            !allowSpaces && normalized.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("Rule text is outside privacy-safe schema bounds.", parameterName);
        }
        return normalized;
    }

    private static void ValidateEnum<T>(T value, string parameterName) where T : struct, Enum
    {
        if (!Enum.IsDefined(value))
        {
            throw new ArgumentOutOfRangeException(parameterName);
        }
    }
}
