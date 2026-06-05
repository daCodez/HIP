using System.Collections.Concurrent;
using System.Text.Json;
using FluentValidation;

namespace HIP.Application.SiteSafety;

/// <summary>
/// Lifecycle status for admin-managed Site Safety rules.
/// </summary>
public enum AdminSiteSafetyRuleStatus
{
    Draft,
    PendingApproval,
    Approved,
    Active,
    Disabled,
    Archived
}

/// <summary>
/// Execution mode for admin-managed Site Safety rules.
/// </summary>
public enum AdminSiteSafetyRuleMode
{
    Simulation,
    WatchOnly,
    Enforced
}

/// <summary>
/// Target scope for admin-managed Site Safety rules.
/// </summary>
public enum AdminSiteSafetyRuleTargetType
{
    Domain,
    Page,
    PageContent,
    ProviderEvidence
}

/// <summary>
/// Safe operators supported by admin-managed Site Safety rules.
/// </summary>
public enum AdminSiteSafetyRuleOperator
{
    Equals,
    NotEquals,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    Contains,
    ContainsAny,
    StartsWith,
    EndsWith,
    InList
}

/// <summary>
/// Admin rule condition using only allow-listed fields and safe operators.
/// </summary>
/// <param name="Field">Allow-listed field name.</param>
/// <param name="Operator">Safe operator.</param>
/// <param name="Value">JSON value used for comparison.</param>
public sealed record AdminSiteSafetyRuleCondition(
    string Field,
    AdminSiteSafetyRuleOperator Operator,
    JsonElement Value);

/// <summary>
/// Safe effects supported by admin-managed Site Safety rules.
/// </summary>
public sealed record AdminSiteSafetyRuleEffects(
    int IncreaseMalwareRisk = 0,
    int IncreasePhishingRisk = 0,
    int IncreaseRedirectRisk = 0,
    int IncreaseScriptRisk = 0,
    int IncreaseDownloadRisk = 0,
    int IncreaseFormRisk = 0,
    int IncreaseReputationRisk = 0,
    int DecreaseDomainTrust = 0,
    int DecreasePageTrust = 0,
    int DecreaseContentTrust = 0,
    string? AddReason = null,
    string? AddWarning = null,
    string? AddPositiveSignal = null,
    string? AddNegativeSignal = null,
    SiteSafetyScanStatus? SetStatusOverride = null,
    int LowerConfidence = 0,
    bool SendToAdminReview = false);

/// <summary>
/// Structured admin-managed Site Safety rule.
/// </summary>
public sealed record AdminSiteSafetyRule(
    string RuleId,
    string Name,
    string Description,
    AdminSiteSafetyRuleTargetType TargetType,
    IReadOnlyCollection<AdminSiteSafetyRuleCondition> Conditions,
    AdminSiteSafetyRuleEffects Effects,
    SiteSafetyRuleSeverity Severity,
    SiteSafetyEvidenceQuality EvidenceQuality,
    AdminSiteSafetyRuleStatus Status,
    AdminSiteSafetyRuleMode Mode,
    string CreatedBy,
    DateTimeOffset CreatedAtUtc,
    string? ApprovedBy,
    DateTimeOffset? ApprovedAtUtc,
    int Version,
    string? PreviousVersionId,
    bool IsRollbackAvailable,
    string? UpdatedBy = null,
    DateTimeOffset? UpdatedAtUtc = null);

/// <summary>
/// Privacy-safe input facts used when simulating an admin Site Safety rule without sending page text.
/// </summary>
public sealed record AdminSiteSafetyRuleSimulationInput(
    string Url = "https://example.com",
    string? Domain = null,
    string? Tld = null,
    bool HasHttps = true,
    int RedirectCount = 0,
    int ShortenedLinkCount = 0,
    int ObfuscatedLinkCount = 0,
    int ExternalScriptCount = 0,
    int InlineScriptCount = 0,
    int SuspiciousScriptPatternCount = 0,
    int ExecutableDownloadCount = 0,
    int ArchiveDownloadCount = 0,
    bool HasLoginForm = false,
    bool HasPasswordField = false,
    bool HasPaymentField = false,
    int KnownAbuseReports = 0,
    int? DomainReputationScore = null,
    int? PageReputationScore = null,
    IReadOnlyCollection<string>? MatchedRiskTerms = null,
    bool TrustDataAvailable = false);

/// <summary>
/// Structured simulation output used by APIs and admins before a rule can enforce.
/// </summary>
public sealed record AdminSiteSafetyRuleSimulationResult(
    string RuleId,
    bool Matched,
    IReadOnlyCollection<string> MatchedConditions,
    int MatchedCount,
    int RiskImpact,
    int TrustImpact,
    SiteSafetyScanStatus? StatusImpact,
    IReadOnlyCollection<string> ReasonsAdded,
    IReadOnlyCollection<string> WarningsCreated,
    int ConfidenceImpact,
    bool SendsToAdminReview,
    bool ApprovalRequired,
    AdminSiteSafetyRuleMode RecommendedMode,
    string Recommendation);

/// <summary>
/// Actor request used by admin endpoints that change rule lifecycle state.
/// </summary>
public sealed record AdminSiteSafetyRuleActionRequest(string ActorId = "dev-admin");

/// <summary>
/// Repository for persisted admin-managed Site Safety rules.
/// </summary>
public interface IAdminSiteSafetyRuleRepository
{
    /// <summary>Saves a rule.</summary>
    Task<AdminSiteSafetyRule> SaveAsync(AdminSiteSafetyRule rule, CancellationToken cancellationToken);

    /// <summary>Lists all rules.</summary>
    Task<IReadOnlyCollection<AdminSiteSafetyRule>> ListAsync(CancellationToken cancellationToken);

    /// <summary>Gets a rule by ID.</summary>
    Task<AdminSiteSafetyRule?> GetByIdAsync(string ruleId, CancellationToken cancellationToken);

    /// <summary>Saves a previous rule version for rollback.</summary>
    Task SaveVersionAsync(AdminSiteSafetyRule rule, CancellationToken cancellationToken);

    /// <summary>Gets the most recent previous version for rollback.</summary>
    Task<AdminSiteSafetyRule?> GetPreviousVersionAsync(string ruleId, CancellationToken cancellationToken);
}

/// <summary>
/// In-memory admin Site Safety rule repository used by tests and development fallback.
/// </summary>
public sealed class InMemoryAdminSiteSafetyRuleRepository : IAdminSiteSafetyRuleRepository
{
    private readonly ConcurrentDictionary<string, AdminSiteSafetyRule> rules = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, Stack<AdminSiteSafetyRule>> versions = new(StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc />
    public Task<AdminSiteSafetyRule> SaveAsync(AdminSiteSafetyRule rule, CancellationToken cancellationToken)
    {
        rules[rule.RuleId] = rule;
        return Task.FromResult(rule);
    }

    /// <inheritdoc />
    public Task<IReadOnlyCollection<AdminSiteSafetyRule>> ListAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyCollection<AdminSiteSafetyRule>>(rules.Values.OrderBy(rule => rule.Name).ToArray());

    /// <inheritdoc />
    public Task<AdminSiteSafetyRule?> GetByIdAsync(string ruleId, CancellationToken cancellationToken)
    {
        rules.TryGetValue(ruleId, out var rule);
        return Task.FromResult(rule);
    }

    /// <inheritdoc />
    public Task SaveVersionAsync(AdminSiteSafetyRule rule, CancellationToken cancellationToken)
    {
        var stack = versions.GetOrAdd(rule.RuleId, _ => new Stack<AdminSiteSafetyRule>());
        stack.Push(rule);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<AdminSiteSafetyRule?> GetPreviousVersionAsync(string ruleId, CancellationToken cancellationToken)
    {
        if (!versions.TryGetValue(ruleId, out var stack) || stack.Count == 0)
        {
            return Task.FromResult<AdminSiteSafetyRule?>(null);
        }

        return Task.FromResult<AdminSiteSafetyRule?>(stack.Pop());
    }
}

/// <summary>
/// Validates admin-managed Site Safety rules and enforces safety guardrails.
/// </summary>
public sealed class AdminSiteSafetyRuleValidator : AbstractValidator<AdminSiteSafetyRule>
{
    /// <summary>
    /// Allow-listed fields available to admin rules.
    /// </summary>
    public static readonly HashSet<string> SupportedFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "Domain",
        "Tld",
        "HasHttps",
        "RedirectCount",
        "ShortenedLinkCount",
        "ObfuscatedLinkCount",
        "ExternalScriptCount",
        "InlineScriptCount",
        "SuspiciousScriptPatternCount",
        "ExecutableDownloadCount",
        "ArchiveDownloadCount",
        "HasLoginForm",
        "HasPasswordField",
        "HasPaymentField",
        "KnownAbuseReports",
        "DomainReputationScore",
        "PageReputationScore",
        "MatchedRiskTerms",
        "ProviderEvidenceType",
        "ProviderEvidenceStatus"
    };

    private static readonly string[] PrivateFieldNames =
    [
        "PageText",
        "Password",
        "Token",
        "Cookie",
        "FormValue",
        "RawMessage",
        "PrivateMessage"
    ];

    /// <summary>
    /// Initializes validation rules.
    /// </summary>
    public AdminSiteSafetyRuleValidator()
    {
        RuleFor(rule => rule.Name).NotEmpty();
        RuleFor(rule => rule.TargetType).IsInEnum();
        RuleFor(rule => rule.Status).IsInEnum();
        RuleFor(rule => rule.Mode).IsInEnum();
        RuleFor(rule => rule.Severity).IsInEnum();
        RuleFor(rule => rule.EvidenceQuality).IsInEnum();
        RuleFor(rule => rule.Version).GreaterThanOrEqualTo(1);
        RuleFor(rule => rule.Conditions).NotEmpty();
        RuleForEach(rule => rule.Conditions).ChildRules(condition =>
        {
            condition.RuleFor(item => item.Field)
                .Must(field => SupportedFields.Contains(field))
                .WithMessage("Unsupported or private field.");
            condition.RuleFor(item => item.Field)
                .Must(field => !PrivateFieldNames.Any(privateName => field.Contains(privateName, StringComparison.OrdinalIgnoreCase)))
                .WithMessage("Private fields are not available to admin rules.");
            condition.RuleFor(item => item.Operator).IsInEnum();
            condition.RuleFor(item => item.Value.ValueKind).NotEqual(JsonValueKind.Undefined);
        });
        RuleFor(rule => rule)
            .Must(rule => !RuleText(rule).Contains("eval(", StringComparison.OrdinalIgnoreCase) &&
                          !RuleText(rule).Contains("=>", StringComparison.OrdinalIgnoreCase) &&
                          !RuleText(rule).Contains("function", StringComparison.OrdinalIgnoreCase) &&
                          !RuleText(rule).Contains("javascript:", StringComparison.OrdinalIgnoreCase) &&
                          !RuleText(rule).Contains("<script", StringComparison.OrdinalIgnoreCase) &&
                          !RuleText(rule).Contains("System.", StringComparison.OrdinalIgnoreCase))
            .WithMessage("Rules cannot execute raw code.");
        RuleFor(rule => rule)
            .Must(rule => rule.Mode != AdminSiteSafetyRuleMode.Enforced ||
                          rule.Status is AdminSiteSafetyRuleStatus.Approved or AdminSiteSafetyRuleStatus.Active)
            .WithMessage("Rules must pass simulation and approval before enforced mode.");
        RuleFor(rule => rule)
            .Must(rule => rule.Effects.SetStatusOverride != SiteSafetyScanStatus.Clean)
            .WithMessage("Admin rules cannot mark a site trusted or clean by themselves.");
        RuleFor(rule => rule)
            .Must(rule => rule.Effects.SetStatusOverride != SiteSafetyScanStatus.Dangerous ||
                          (rule.Severity is SiteSafetyRuleSeverity.High or SiteSafetyRuleSeverity.Critical &&
                           rule.Status is AdminSiteSafetyRuleStatus.Approved or AdminSiteSafetyRuleStatus.Active &&
                           !string.IsNullOrWhiteSpace(rule.ApprovedBy) &&
                           rule.ApprovedAtUtc is not null))
            .WithMessage("Dangerous overrides require high severity and approval.");
    }

    /// <summary>
    /// Serializes rule text for raw-code guardrails.
    /// </summary>
    private static string RuleText(AdminSiteSafetyRule rule) =>
        JsonSerializer.Serialize(rule);
}

/// <summary>
/// Service for creating, updating, and rolling back admin-managed Site Safety rules.
/// </summary>
public sealed class AdminSiteSafetyRuleService(
    IAdminSiteSafetyRuleRepository repository,
    IValidator<AdminSiteSafetyRule> validator)
{
    /// <summary>
    /// Creates a validated Draft rule.
    /// </summary>
    public async Task<AdminSiteSafetyRule> CreateAsync(AdminSiteSafetyRule rule, CancellationToken cancellationToken)
    {
        var draft = rule with
        {
            RuleId = string.IsNullOrWhiteSpace(rule.RuleId) ? Slug(rule.Name) : rule.RuleId,
            Status = AdminSiteSafetyRuleStatus.Draft,
            Mode = AdminSiteSafetyRuleMode.Simulation,
            Version = Math.Max(rule.Version, 1),
            CreatedAtUtc = rule.CreatedAtUtc == default ? DateTimeOffset.UtcNow : rule.CreatedAtUtc
        };

        await validator.ValidateAndThrowAsync(draft, cancellationToken);
        return await repository.SaveAsync(draft, cancellationToken);
    }

    /// <summary>
    /// Updates a rule and stores the previous version for rollback.
    /// </summary>
    public async Task<AdminSiteSafetyRule> UpdateAsync(AdminSiteSafetyRule rule, CancellationToken cancellationToken)
    {
        await validator.ValidateAndThrowAsync(rule, cancellationToken);
        var current = await repository.GetByIdAsync(rule.RuleId, cancellationToken);
        if (current is not null)
        {
            await repository.SaveVersionAsync(current, cancellationToken);
        }

        var updated = rule with
        {
            Version = Math.Max((current?.Version ?? 0) + 1, rule.Version),
            PreviousVersionId = current?.RuleId,
            IsRollbackAvailable = current is not null,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };
        return await repository.SaveAsync(updated, cancellationToken);
    }

    /// <summary>
    /// Runs a rule simulation against privacy-safe input facts before any enforced rollout.
    /// </summary>
    public AdminSiteSafetyRuleSimulationResult Simulate(AdminSiteSafetyRule rule, AdminSiteSafetyRuleSimulationInput input)
    {
        var validation = validator.Validate(rule with { Mode = AdminSiteSafetyRuleMode.Simulation });
        if (!validation.IsValid)
        {
            throw new ValidationException(validation.Errors);
        }

        return AdminSiteSafetyRuleEvaluator.Simulate(rule, ToRuleInput(input));
    }

    /// <summary>
    /// Approves a rule so it can later be activated after review.
    /// </summary>
    public async Task<AdminSiteSafetyRule> ApproveAsync(string ruleId, string approvedBy, CancellationToken cancellationToken)
    {
        var current = await RequireRuleAsync(ruleId, cancellationToken);
        var actor = string.IsNullOrWhiteSpace(approvedBy) ? "dev-admin" : approvedBy;
        return await UpdateAsync(current with
        {
            Status = AdminSiteSafetyRuleStatus.Approved,
            ApprovedBy = actor,
            ApprovedAtUtc = DateTimeOffset.UtcNow,
            UpdatedBy = actor
        }, cancellationToken);
    }

    /// <summary>
    /// Activates an approved rule in enforced mode.
    /// </summary>
    public async Task<AdminSiteSafetyRule> ActivateAsync(string ruleId, string actorId, CancellationToken cancellationToken)
    {
        var current = await RequireRuleAsync(ruleId, cancellationToken);
        var actor = string.IsNullOrWhiteSpace(actorId) ? "dev-admin" : actorId;
        return await UpdateAsync(current with
        {
            Status = AdminSiteSafetyRuleStatus.Active,
            Mode = AdminSiteSafetyRuleMode.Enforced,
            UpdatedBy = actor
        }, cancellationToken);
    }

    /// <summary>
    /// Disables a rule so it no longer participates in Site Safety scoring.
    /// </summary>
    public async Task<AdminSiteSafetyRule> DisableAsync(string ruleId, string actorId, CancellationToken cancellationToken)
    {
        var current = await RequireRuleAsync(ruleId, cancellationToken);
        var actor = string.IsNullOrWhiteSpace(actorId) ? "dev-admin" : actorId;
        return await UpdateAsync(current with
        {
            Status = AdminSiteSafetyRuleStatus.Disabled,
            Mode = AdminSiteSafetyRuleMode.Simulation,
            UpdatedBy = actor
        }, cancellationToken);
    }

    /// <summary>
    /// Restores the most recent stored previous version.
    /// </summary>
    public async Task<AdminSiteSafetyRule> RollbackAsync(string ruleId, CancellationToken cancellationToken)
    {
        var previous = await repository.GetPreviousVersionAsync(ruleId, cancellationToken) ??
                       throw new InvalidOperationException("No rollback version is available.");

        var restored = previous with { IsRollbackAvailable = false };
        return await repository.SaveAsync(restored, cancellationToken);
    }

    /// <summary>
    /// Creates a URL-safe rule ID.
    /// </summary>
    private static string Slug(string value) =>
        string.Join('-', value.Trim().ToLowerInvariant().Select(character => char.IsLetterOrDigit(character) ? character : '-')).Replace("--", "-", StringComparison.Ordinal).Trim('-');

    /// <summary>
    /// Loads a rule or fails with a clear application exception.
    /// </summary>
    private async Task<AdminSiteSafetyRule> RequireRuleAsync(string ruleId, CancellationToken cancellationToken) =>
        await repository.GetByIdAsync(ruleId, cancellationToken) ??
        throw new InvalidOperationException("Admin Site Safety rule was not found.");

    /// <summary>
    /// Converts admin-provided simulation facts into the same privacy-safe input used by the scanner.
    /// </summary>
    private static SiteSafetyRuleInput ToRuleInput(AdminSiteSafetyRuleSimulationInput input)
    {
        var url = Uri.TryCreate(input.Url, UriKind.Absolute, out var parsedUrl) ? parsedUrl : new Uri("https://example.com");
        var domain = input.Domain ?? url.Host;

        return new SiteSafetyRuleInput(
            url,
            domain,
            input.Tld ?? domain.Split('.').LastOrDefault() ?? string.Empty,
            input.HasHttps,
            Math.Max(0, input.RedirectCount),
            Math.Max(0, input.ShortenedLinkCount),
            Math.Max(0, input.ObfuscatedLinkCount),
            HasSuspiciousQueryShape: false,
            Math.Max(0, input.ExternalScriptCount),
            Math.Max(0, input.InlineScriptCount),
            Math.Max(0, input.SuspiciousScriptPatternCount),
            Math.Max(0, input.ExecutableDownloadCount),
            Math.Max(0, input.ArchiveDownloadCount),
            input.HasLoginForm,
            input.HasPasswordField,
            input.HasPaymentField,
            Math.Max(0, input.KnownAbuseReports),
            input.DomainReputationScore,
            input.PageReputationScore,
            input.MatchedRiskTerms ?? [],
            [],
            input.TrustDataAvailable);
    }
}

/// <summary>
/// Evaluates safe structured admin-managed Site Safety rules without executing arbitrary code.
/// </summary>
public static class AdminSiteSafetyRuleEvaluator
{
    /// <summary>
    /// Evaluates one admin rule against privacy-safe scan facts.
    /// </summary>
    /// <param name="rule">Validated admin rule.</param>
    /// <param name="input">Privacy-safe scanner input.</param>
    /// <returns>Matched results. Simulation and watch rules are marked so callers can avoid score enforcement.</returns>
    public static IReadOnlyCollection<SiteSafetyRuleResult> Evaluate(AdminSiteSafetyRule rule, SiteSafetyRuleInput input)
    {
        if (rule.Status is AdminSiteSafetyRuleStatus.Disabled or AdminSiteSafetyRuleStatus.Archived ||
            !rule.Conditions.All(condition => ConditionMatches(condition, input)))
        {
            return [];
        }

        var isSimulationOnly = rule.Mode is AdminSiteSafetyRuleMode.Simulation or AdminSiteSafetyRuleMode.WatchOnly;
        return BuildResults(rule, isSimulationOnly);
    }

    /// <summary>
    /// Simulates an admin rule and explains what would happen without enforcing score changes.
    /// </summary>
    public static AdminSiteSafetyRuleSimulationResult Simulate(AdminSiteSafetyRule rule, SiteSafetyRuleInput input)
    {
        var matchedConditions = rule.Conditions
            .Where(condition => ConditionMatches(condition, input))
            .Select(DescribeCondition)
            .ToArray();
        var matched = matchedConditions.Length == rule.Conditions.Count;
        var results = matched ? BuildResults(rule with { Mode = AdminSiteSafetyRuleMode.Simulation }, isSimulationOnly: true) : [];
        var riskImpact = results.Select(result => result.RiskImpact).DefaultIfEmpty(0).Max();
        var trustImpact = results.Sum(result => result.TrustImpact);
        var statusImpact = StrongestStatusOverride(results);
        var confidenceImpact = results.Select(result => result.ConfidencePenalty).DefaultIfEmpty(0).Max();
        var approvalRequired = RequiresApproval(rule);
        var recommendedMode = approvalRequired || riskImpact >= 40 || statusImpact is SiteSafetyScanStatus.HighRisk or SiteSafetyScanStatus.Dangerous
            ? AdminSiteSafetyRuleMode.WatchOnly
            : AdminSiteSafetyRuleMode.Enforced;

        return new AdminSiteSafetyRuleSimulationResult(
            rule.RuleId,
            matched,
            matchedConditions,
            matchedConditions.Length,
            riskImpact,
            trustImpact,
            statusImpact,
            results.Select(result => result.Reason).Distinct().ToArray(),
            results.Select(result => result.Warning).OfType<string>().Distinct().ToArray(),
            confidenceImpact,
            results.Any(result => result.SendToAdminReview),
            approvalRequired,
            recommendedMode,
            matched ? Recommendation(approvalRequired, recommendedMode) : "The rule did not match the simulation input.");
    }

    /// <summary>
    /// Evaluates a condition against an allow-listed rule input field.
    /// </summary>
    private static bool ConditionMatches(AdminSiteSafetyRuleCondition condition, SiteSafetyRuleInput input)
    {
        var actual = FieldValue(condition.Field, input);
        return condition.Operator switch
        {
            AdminSiteSafetyRuleOperator.Equals => EqualsValue(actual, condition.Value),
            AdminSiteSafetyRuleOperator.NotEquals => !EqualsValue(actual, condition.Value),
            AdminSiteSafetyRuleOperator.GreaterThan => CompareNumber(actual, condition.Value, value => value > 0),
            AdminSiteSafetyRuleOperator.GreaterThanOrEqual => CompareNumber(actual, condition.Value, value => value >= 0),
            AdminSiteSafetyRuleOperator.LessThan => CompareNumber(actual, condition.Value, value => value < 0),
            AdminSiteSafetyRuleOperator.LessThanOrEqual => CompareNumber(actual, condition.Value, value => value <= 0),
            AdminSiteSafetyRuleOperator.Contains => ContainsValue(actual, condition.Value),
            AdminSiteSafetyRuleOperator.ContainsAny => ContainsAnyValue(actual, condition.Value),
            AdminSiteSafetyRuleOperator.StartsWith => actual?.ToString()?.StartsWith(condition.Value.ToString(), StringComparison.OrdinalIgnoreCase) == true,
            AdminSiteSafetyRuleOperator.EndsWith => actual?.ToString()?.EndsWith(condition.Value.ToString(), StringComparison.OrdinalIgnoreCase) == true,
            AdminSiteSafetyRuleOperator.InList => InList(actual, condition.Value),
            _ => false
        };
    }

    /// <summary>
    /// Builds normalized rule results from structured admin effects.
    /// </summary>
    private static IReadOnlyCollection<SiteSafetyRuleResult> BuildResults(AdminSiteSafetyRule rule, bool isSimulationOnly)
    {
        var results = new List<SiteSafetyRuleResult>();
        AddRisk(results, rule, SiteSafetyRiskCategory.Malware, rule.Effects.IncreaseMalwareRisk, "Admin rule increased malware risk.", isSimulationOnly);
        AddRisk(results, rule, SiteSafetyRiskCategory.Phishing, rule.Effects.IncreasePhishingRisk, "Admin rule increased phishing risk.", isSimulationOnly);
        AddRisk(results, rule, SiteSafetyRiskCategory.Redirect, rule.Effects.IncreaseRedirectRisk, "Admin rule increased redirect risk.", isSimulationOnly);
        AddRisk(results, rule, SiteSafetyRiskCategory.Script, rule.Effects.IncreaseScriptRisk, "Admin rule increased script risk.", isSimulationOnly);
        AddRisk(results, rule, SiteSafetyRiskCategory.Download, rule.Effects.IncreaseDownloadRisk, "Admin rule increased download risk.", isSimulationOnly);
        AddRisk(results, rule, SiteSafetyRiskCategory.Form, rule.Effects.IncreaseFormRisk, "Admin rule increased form risk.", isSimulationOnly);
        AddRisk(results, rule, SiteSafetyRiskCategory.Reputation, rule.Effects.IncreaseReputationRisk + rule.Effects.DecreaseDomainTrust + rule.Effects.DecreasePageTrust + rule.Effects.DecreaseContentTrust, "Admin rule decreased trust.", isSimulationOnly);

        if (rule.Effects.AddReason is not null || rule.Effects.AddWarning is not null || rule.Effects.SetStatusOverride is not null || rule.Effects.LowerConfidence > 0 || rule.Effects.SendToAdminReview)
        {
            results.Add(new SiteSafetyRuleResult(
                rule.RuleId,
                rule.Name,
                rule.Description,
                SiteSafetyRuleSource.Admin,
                SiteSafetyRuleCollectionType.StatusRules,
                SiteSafetyRiskCategory.Confidence,
                0,
                0,
                rule.Effects.AddReason ?? "Admin-managed Site Safety rule matched.",
                rule.Effects.AddWarning,
                rule.Severity,
                rule.EvidenceQuality,
                rule.Effects.SetStatusOverride,
                rule.Effects.LowerConfidence,
                rule.Effects.SendToAdminReview,
                isSimulationOnly,
                rule.Effects.AddPositiveSignal,
                rule.Effects.AddNegativeSignal));
        }

        return results;
    }

    /// <summary>
    /// Adds a risk result when an effect has a positive risk impact.
    /// </summary>
    private static void AddRisk(ICollection<SiteSafetyRuleResult> results, AdminSiteSafetyRule rule, SiteSafetyRiskCategory category, int impact, string fallbackReason, bool isSimulationOnly)
    {
        if (impact <= 0)
        {
            return;
        }

        results.Add(new SiteSafetyRuleResult(
            rule.RuleId,
            rule.Name,
            rule.Description,
            SiteSafetyRuleSource.Admin,
            SiteSafetyRuleCollectionType.StatusRules,
            category,
            Math.Clamp(impact, 0, 100),
            0,
            rule.Effects.AddReason ?? fallbackReason,
            rule.Effects.AddWarning,
            rule.Severity,
            rule.EvidenceQuality,
            rule.Effects.SetStatusOverride,
            rule.Effects.LowerConfidence,
            rule.Effects.SendToAdminReview,
            isSimulationOnly,
            rule.Effects.AddPositiveSignal,
            rule.Effects.AddNegativeSignal));
    }

    /// <summary>
    /// Selects the strongest status override from simulated or enforced rule results.
    /// </summary>
    private static SiteSafetyScanStatus? StrongestStatusOverride(IEnumerable<SiteSafetyRuleResult> results)
    {
        var overrides = results.Select(result => result.StatusOverride).OfType<SiteSafetyScanStatus>().ToArray();
        if (overrides.Contains(SiteSafetyScanStatus.Dangerous))
        {
            return SiteSafetyScanStatus.Dangerous;
        }

        if (overrides.Contains(SiteSafetyScanStatus.HighRisk))
        {
            return SiteSafetyScanStatus.HighRisk;
        }

        return overrides.Contains(SiteSafetyScanStatus.Suspicious) ? SiteSafetyScanStatus.Suspicious : null;
    }

    /// <summary>
    /// Describes a matched condition without exposing private scan data.
    /// </summary>
    private static string DescribeCondition(AdminSiteSafetyRuleCondition condition) =>
        $"{condition.Field} {condition.Operator} {condition.Value}";

    /// <summary>
    /// Decides whether a simulated rule needs approval before enforcement.
    /// </summary>
    private static bool RequiresApproval(AdminSiteSafetyRule rule) =>
        rule.Severity is SiteSafetyRuleSeverity.High or SiteSafetyRuleSeverity.Critical ||
        rule.Mode == AdminSiteSafetyRuleMode.Enforced ||
        rule.Effects.SetStatusOverride is SiteSafetyScanStatus.HighRisk or SiteSafetyScanStatus.Dangerous ||
        rule.Effects.SendToAdminReview;

    /// <summary>
    /// Builds the plain-English recommendation admins see after simulation.
    /// </summary>
    private static string Recommendation(bool approvalRequired, AdminSiteSafetyRuleMode recommendedMode) =>
        approvalRequired
            ? "Simulation matched. Approval is required, and the rule should start in watch-only mode."
            : recommendedMode == AdminSiteSafetyRuleMode.Enforced
                ? "Simulation matched with low impact. The rule can be considered for enforced mode after review."
                : "Simulation matched. Start in watch-only mode before enforcement.";

    /// <summary>
    /// Gets a safe field value from the rule input.
    /// </summary>
    private static object? FieldValue(string field, SiteSafetyRuleInput input) => field switch
    {
        "Domain" => input.Domain,
        "Tld" => input.Tld,
        "HasHttps" => input.HasHttps,
        "RedirectCount" => input.RedirectCount,
        "ShortenedLinkCount" => input.ShortenedLinkCount,
        "ObfuscatedLinkCount" => input.ObfuscatedLinkCount,
        "ExternalScriptCount" => input.ExternalScriptCount,
        "InlineScriptCount" => input.InlineScriptCount,
        "SuspiciousScriptPatternCount" => input.SuspiciousScriptPatternCount,
        "ExecutableDownloadCount" => input.ExecutableDownloadCount,
        "ArchiveDownloadCount" => input.ArchiveDownloadCount,
        "HasLoginForm" => input.HasLoginForm,
        "HasPasswordField" => input.HasPasswordField,
        "HasPaymentField" => input.HasPaymentField,
        "KnownAbuseReports" => input.KnownAbuseReports,
        "DomainReputationScore" => input.DomainReputationScore,
        "PageReputationScore" => input.PageReputationScore,
        "MatchedRiskTerms" => input.MatchedRiskTerms,
        "ProviderEvidenceType" => input.ProviderEvidence.Select(item => item.ProviderType.ToString()).ToArray(),
        "ProviderEvidenceStatus" => input.ProviderEvidence.SelectMany(item => item.EvidenceItems).Select(item => item.Status.ToString()).ToArray(),
        _ => null
    };

    /// <summary>
    /// Compares scalar values without unsafe expression evaluation.
    /// </summary>
    private static bool EqualsValue(object? actual, JsonElement expected) =>
        actual switch
        {
            bool value => expected.ValueKind == JsonValueKind.True && value || expected.ValueKind == JsonValueKind.False && !value,
            int value => expected.TryGetInt32(out var expectedNumber) && value == expectedNumber,
            string value => string.Equals(value, expected.ToString(), StringComparison.OrdinalIgnoreCase),
            _ => string.Equals(actual?.ToString(), expected.ToString(), StringComparison.OrdinalIgnoreCase)
        };

    /// <summary>
    /// Compares numeric values with a caller-provided comparison predicate.
    /// </summary>
    private static bool CompareNumber(object? actual, JsonElement expected, Func<int, bool> comparison)
    {
        if (!expected.TryGetInt32(out var expectedNumber) || actual is not int actualNumber)
        {
            return false;
        }

        return comparison(actualNumber.CompareTo(expectedNumber));
    }

    /// <summary>
    /// Checks whether a scalar or collection contains a string value.
    /// </summary>
    private static bool ContainsValue(object? actual, JsonElement expected)
    {
        var expectedValue = expected.ToString();
        return actual switch
        {
            string value => value.Contains(expectedValue, StringComparison.OrdinalIgnoreCase),
            IEnumerable<string> values => values.Any(value => value.Contains(expectedValue, StringComparison.OrdinalIgnoreCase)),
            _ => false
        };
    }

    /// <summary>
    /// Checks whether a collection field contains at least one expected value.
    /// </summary>
    private static bool ContainsAnyValue(object? actual, JsonElement expected)
    {
        if (actual is not IEnumerable<string> values || expected.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        var actualValues = values.ToArray();
        return expected.EnumerateArray().Any(item => actualValues.Contains(item.ToString(), StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Checks whether the actual scalar value is listed in an expected array.
    /// </summary>
    private static bool InList(object? actual, JsonElement expected) =>
        expected.ValueKind == JsonValueKind.Array &&
        expected.EnumerateArray().Any(item => string.Equals(actual?.ToString(), item.ToString(), StringComparison.OrdinalIgnoreCase));
}
