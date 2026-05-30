using FluentValidation;
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
    IRuleSimulationService simulationService) : IAdminRuleService
{
    public async Task<TrustRule> SaveAsync(TrustRule rule, CancellationToken cancellationToken)
    {
        var validation = await validator.ValidateAsync(rule, cancellationToken);
        if (!validation.IsValid)
        {
            throw new ValidationException(validation.Errors);
        }

        return await repository.SaveAsync(rule, cancellationToken);
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
