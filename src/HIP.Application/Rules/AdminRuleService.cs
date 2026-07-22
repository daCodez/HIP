using FluentValidation;
using HIP.Application.Review;
using HIP.Domain.Audit;
using HIP.Domain.Review;
using HIP.Application.Simulation;
using HIP.Domain.Rules;

namespace HIP.Application.Rules;

public interface IAdminRuleService
{
    /// <summary>
    /// Saves a rule while binding protected workflow metadata to the authenticated administrator.
    /// </summary>
    Task<TrustRule> SaveAsync(TrustRule rule, string actorId, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<TrustRule>> ListAsync(CancellationToken cancellationToken);

    RuleSimulationResult Simulate(TrustRule rule, IReadOnlyCollection<RuleSimulationTestCase>? testCases);
}

public sealed class AdminRuleService(
    IValidator<TrustRule> validator,
    IRuleRepository repository,
    IRuleSimulationService simulationService,
    IAuditLogService auditLogService) : IAdminRuleService
{
    /// <inheritdoc />
    public async Task<TrustRule> SaveAsync(
        TrustRule rule,
        string actorId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentException.ThrowIfNullOrWhiteSpace(actorId);
        var actor = actorId.Trim();
        var current = string.IsNullOrWhiteSpace(rule.RuleId)
            ? null
            : await repository.GetByIdAsync(rule.RuleId, cancellationToken);
        var requiresApproval = rule.RequiresApproval || RuleValidationConstants.IsHighImpact(rule);
        var protectedRule = rule with
        {
            CreatedBy = current is null || string.IsNullOrWhiteSpace(current.CreatedBy) ? actor : current.CreatedBy,
            RequiresApproval = requiresApproval,
            ApprovalStatus = requiresApproval ? ApprovalStatus.Pending : ApprovalStatus.NotRequired,
            Version = current is null ? 1 : checked(current.Version + 1)
        };

        var validation = await validator.ValidateAsync(protectedRule, cancellationToken);
        if (!validation.IsValid)
        {
            throw new ValidationException(validation.Errors);
        }

        var saved = await repository.SaveAsync(protectedRule, cancellationToken);
        auditLogService.Write(
            actor,
            "Rule changed",
            TargetType.Rule,
            saved.RuleId,
            $"Rule '{saved.Name}' saved with mode {saved.Mode} and severity {saved.Severity}.",
            AuditSeverity.Medium,
            afterMetadata: new Dictionary<string, string>
            {
                ["enabled"] = saved.Enabled.ToString(),
                ["mode"] = saved.Mode.ToString(),
                ["severity"] = saved.Severity.ToString(),
                ["version"] = saved.Version.ToString()
            });

        return saved;
    }

    public Task<IReadOnlyCollection<TrustRule>> ListAsync(CancellationToken cancellationToken) =>
        repository.ListAsync(cancellationToken);

    public RuleSimulationResult Simulate(TrustRule rule, IReadOnlyCollection<RuleSimulationTestCase>? testCases)
    {
        validator.ValidateAndThrow(rule);
        return simulationService.Simulate(rule, testCases is { Count: > 0 } ? testCases : DefaultTestCases());
    }

    public static IReadOnlyCollection<RuleSimulationTestCase> DefaultTestCases() =>
        RuleSimulationSeedData.DefaultCases();
}
