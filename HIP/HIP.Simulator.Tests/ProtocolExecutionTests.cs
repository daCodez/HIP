using HIP.Simulator.Core.Extensions;
using HIP.Simulator.Core.Interfaces;
using HIP.Simulator.Core.Models;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace HIP.Simulator.Tests;

public class ProtocolExecutionTests
{
    private static string ScenarioRoot
        => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../HIP.Simulator.Cli/scenarios"));

    [Test]
    public async Task Runner_ShouldRouteProtocolMode_AndPassProtocolSuite()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHipSimulatorCore();

        using var provider = services.BuildServiceProvider();
        var runner = provider.GetRequiredService<ISimulationRunner>();

        var result = await runner.RunAsync(new SimulationRunOptions
        {
            InputFolder = ScenarioRoot,
            ReportFolder = Path.Combine(Path.GetTempPath(), "hip-sim-tests", Guid.NewGuid().ToString("N")),
            Suite = "protocol",
            ExecutionModeOverride = SimulationExecutionMode.Protocol
        });

        Assert.That(result.TotalScenarios, Is.GreaterThanOrEqualTo(5));
        Assert.That(result.Failed, Is.EqualTo(0));
        Assert.That(result.Scenarios.All(x => x.ExecutionMode == SimulationExecutionMode.Protocol), Is.True);
    }

    [Test]
    public async Task ProtocolSuite_ShouldIncludeReplayTimestampAndKeyLifecycleOutcomes()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHipSimulatorCore();

        using var provider = services.BuildServiceProvider();
        var runner = provider.GetRequiredService<ISimulationRunner>();

        var result = await runner.RunAsync(new SimulationRunOptions
        {
            InputFolder = ScenarioRoot,
            ReportFolder = Path.Combine(Path.GetTempPath(), "hip-sim-tests", Guid.NewGuid().ToString("N")),
            Suite = "protocol",
            ExecutionModeOverride = SimulationExecutionMode.Protocol
        });

        var replay = result.Scenarios.Single(x => x.ScenarioId == "protocol-replay-attempt-block");
        var skew = result.Scenarios.Single(x => x.ScenarioId == "protocol-timestamp-skew-block");
        var revoked = result.Scenarios.Single(x => x.ScenarioId == "protocol-key-revoked-block");
        var replaced = result.Scenarios.Single(x => x.ScenarioId == "protocol-key-replaced-block");

        Assert.Multiple(() =>
        {
            Assert.That(replay.Passed, Is.True);
            Assert.That(replay.FinalAction, Is.EqualTo("Block"));
            Assert.That(replay.FinalSeverity, Is.EqualTo("Critical"));

            Assert.That(skew.Passed, Is.True);
            Assert.That(skew.FinalAction, Is.EqualTo("Block"));
            Assert.That(skew.FinalSeverity, Is.EqualTo("High"));

            Assert.That(revoked.Passed, Is.True);
            Assert.That(revoked.FinalAction, Is.EqualTo("Block"));
            Assert.That(revoked.FinalSeverity, Is.EqualTo("Critical"));

            Assert.That(replaced.Passed, Is.True);
            Assert.That(replaced.FinalAction, Is.EqualTo("Block"));
            Assert.That(replaced.FinalSeverity, Is.EqualTo("Critical"));
        });
    }
}
