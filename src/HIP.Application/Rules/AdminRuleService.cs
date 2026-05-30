using FluentValidation;
using HIP.Application.Review;
using HIP.Domain.Audit;
using HIP.Domain.Review;
using HIP.Application.Simulation;
using HIP.Domain.Rules;

namespace HIP.Application.Rules;

public interface IAdminRuleService
{
    Task<TrustRule> SaveAsync(TrustRule rule, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<TrustRule>> ListAsync(CancellationToken cancellationToken);

    RuleSimulationResult Simulate(TrustRule rule, IReadOnlyCollection<RuleSimulationTestCase>? testCases);
}

public sealed class AdminRuleService(
    IValidator<TrustRule> validator,
    IRuleRepository repository,
    IRuleSimulationService simulationService,
    IAuditLogService auditLogService) : IAdminRuleService
{
    public async Task<TrustRule> SaveAsync(TrustRule rule, CancellationToken cancellationToken)
    {
        var validation = await validator.ValidateAsync(rule, cancellationToken);
        if (!validation.IsValid)
        {
            throw new ValidationException(validation.Errors);
        }

        var saved = await repository.SaveAsync(rule, cancellationToken);
        auditLogService.Write(
            "admin-rule-service",
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
