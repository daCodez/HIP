using HIP.Simulator.Core.Models;

namespace HIP.Simulator.Core.Interfaces;

public interface IScenarioLoader
{
    Task<IReadOnlyList<Scenario>> LoadAsync(string rootFolder, string? suite, string? scenarioId, CancellationToken ct = default);
    Task<IReadOnlyList<string>> ListSuitesAsync(string rootFolder, CancellationToken ct = default);
    Task<IReadOnlyList<(string Id, string Name, string Suite)>> ListScenariosAsync(string rootFolder, CancellationToken ct = default);
}

public interface IScenarioValidator
{
    IReadOnlyList<string> Validate(Scenario scenario);
}

public interface IEventGenerator
{
    IReadOnlyList<SecurityEvent> Generate(Scenario scenario, DateTimeOffset startedUtc);
}

public interface IEventInjector
{
    Task InjectAsync(SecurityEvent securityEvent, CancellationToken ct = default);
}

public interface IPolicyEvaluator
{
    Task<PolicyEvaluationResult> EvaluateAsync(Scenario scenario, IReadOnlyList<SecurityEvent> events, SimulationRunOptions options, CancellationToken ct = default);
}

public interface ISimulationExecutionTarget
{
    SimulationExecutionMode Mode { get; }
    Task<ScenarioResult> ExecuteAsync(Scenario scenario, SimulationRunOptions options, CancellationToken ct = default);
}

public interface ICoverageAnalyzer
{
    CoverageReport Analyze(IReadOnlyList<Scenario> scenarios, IReadOnlyList<ScenarioResult> results);
}

public interface IPolicySuggester
{
    PolicySuggestion Suggest(Scenario scenario, string gapReason);
}

public interface IReportWriter
{
    Task WriteAsync(SimulationRunResult result, SimulationRunOptions options, CancellationToken ct = default);
}

public interface ISimulationRunner
{
    Task<SimulationRunResult> RunAsync(SimulationRunOptions options, CancellationToken ct = default);
}

public interface IClock
{
    DateTimeOffset UtcNow { get; }
}
