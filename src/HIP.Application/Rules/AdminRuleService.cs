using FluentValidation;
using HIP.Application.Simulation;
using HIP.Domain.Risk;
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
    [
        new("Safe old domain, no shortener", new FactSet(new Dictionary<string, object?> { ["domain.ageDays"] = 1200, ["url.usesShortener"] = false, ["url.isObfuscated"] = false, ["url.hasKnownRisk"] = false, ["sender.reputationScore"] = 85, ["identity.signatureValid"] = true }), false, null, null),
        new("New domain with shortener", new FactSet(new Dictionary<string, object?> { ["domain.ageDays"] = 8, ["url.usesShortener"] = true, ["url.isObfuscated"] = false, ["url.hasKnownRisk"] = false, ["sender.reputationScore"] = 55, ["identity.signatureValid"] = false }), true, RiskStatus.HighRisk, true),
        new("Obfuscated URL", new FactSet(new Dictionary<string, object?> { ["domain.ageDays"] = 90, ["url.usesShortener"] = false, ["url.isObfuscated"] = true, ["url.hasKnownRisk"] = false, ["sender.reputationScore"] = 60, ["identity.signatureValid"] = false }), false, null, null),
        new("Known risky URL", new FactSet(new Dictionary<string, object?> { ["domain.ageDays"] = 120, ["url.usesShortener"] = false, ["url.isObfuscated"] = false, ["url.hasKnownRisk"] = true, ["sender.reputationScore"] = 40, ["identity.signatureValid"] = false }), false, null, null),
        new("Low reputation sender", new FactSet(new Dictionary<string, object?> { ["domain.ageDays"] = 800, ["url.usesShortener"] = false, ["url.isObfuscated"] = false, ["url.hasKnownRisk"] = false, ["sender.reputationScore"] = 15, ["identity.signatureValid"] = false }), false, null, null),
        new("Valid signed identity", new FactSet(new Dictionary<string, object?> { ["domain.ageDays"] = 800, ["url.usesShortener"] = false, ["url.isObfuscated"] = false, ["url.hasKnownRisk"] = false, ["sender.reputationScore"] = 80, ["identity.signatureValid"] = true }), false, null, null),
        new("Invalid or missing signature", new FactSet(new Dictionary<string, object?> { ["domain.ageDays"] = 800, ["url.usesShortener"] = false, ["url.isObfuscated"] = false, ["url.hasKnownRisk"] = false, ["sender.reputationScore"] = 80, ["identity.signatureValid"] = false }), false, null, null)
    ];
}
