using System.Text.Json;
using HIP.Simulator.Core.Models;
using HIP.Simulator.Core.Services;
using NUnit.Framework;

namespace HIP.Simulator.Tests;

public class SimulatorCoreTests
{
    [Test]
    public void ScenarioValidator_ShouldFlagMissingActor()
    {
        var validator = new ScenarioValidator();
        var scenario = BuildScenario("missing-actor", "login.attempt", actorId: "", expectedAction: "Challenge", expectedSeverity: "High", shouldBeCovered: true);

        var issues = validator.Validate(scenario);

        Assert.That(issues.Count > 0, Is.EqualTo(true));
    }

    [Test]
    public async Task Precedence_ShouldPreferLockOverChallenge()
    {
        var eval = new HipPolicyEvaluatorAdapter(new Microsoft.Extensions.Logging.Abstractions.NullLogger<HipPolicyEvaluatorAdapter>());
        var scenario = BuildScenario("brute-force-lock", "login.failed", payloadJson: "{\"failedAttempts\":12,\"ipRisk\":\"medium\",\"mfa\":false}", expectedAction: "Lock", expectedSeverity: "Critical", shouldBeCovered: true);
        var events = new EventGenerator().Generate(scenario, DateTimeOffset.UtcNow);

        var result = await eval.EvaluateAsync(scenario, events, new SimulationRunOptions());

        Assert.That(result.FinalAction, Is.EqualTo("Lock"));
    }

    [Test]
    public async Task UncoveredEvent_ShouldBeDetected()
    {
        var eval = new HipPolicyEvaluatorAdapter(new Microsoft.Extensions.Logging.Abstractions.NullLogger<HipPolicyEvaluatorAdapter>());
        var scenario = BuildScenario("unknown", "unknown_event_type", payloadJson: "{\"x\":1}", expectedAction: "LogOnly", expectedSeverity: "Info", shouldBeCovered: false);
        var events = new EventGenerator().Generate(scenario, DateTimeOffset.UtcNow);

        var result = await eval.EvaluateAsync(scenario, events, new SimulationRunOptions());

        Assert.That(result.IsCovered, Is.EqualTo(false));
    }

    [Test]
    public void PolicySuggestion_ShouldContainTemplateFields()
    {
        var suggester = new PolicySuggester();
        var scenario = BuildScenario("oauth-consent", "oauth_consent_grant", payloadJson: "{\"scope\":\"mail.read\"}", expectedAction: "LogOnly", expectedSeverity: "Info", shouldBeCovered: false);

        var suggestion = suggester.Suggest(scenario, "No rule matched");

        Assert.That(suggestion.RuleName.StartsWith("Sim.oauth-consent"), Is.EqualTo(true));
        Assert.That(suggestion.ToTemplate().Contains("Signals needed"), Is.EqualTo(true));
    }

    [Test]
    public void CoverageAnalyzer_ShouldComputeCounts()
    {
        var analyzer = new CoverageAnalyzer();
        var scenario = BuildScenario("s1", "login.attempt", expectedAction: "Challenge", expectedSeverity: "High", shouldBeCovered: true);
        var results = new[]
        {
            new ScenarioResult("s1", true, true, true, "Challenge", "High", ["Require MFA"], [], [new RuleTraceEntry("Require MFA", true, "Challenge", "High", "MFA required")], [], SimulationExecutionMode.Application, null)
        };

        var report = analyzer.Analyze([scenario], results);

        Assert.That(report.EventCoverage.Count, Is.EqualTo(1));
        Assert.That(report.RuleCoverage.First().RuleName, Is.EqualTo("Require MFA"));
    }

    [Test]
    public async Task MultiStepScenario_BruteForce_ShouldLock()
    {
        var eval = new HipPolicyEvaluatorAdapter(new Microsoft.Extensions.Logging.Abstractions.NullLogger<HipPolicyEvaluatorAdapter>());
        var steps = new[]
        {
            BuildStep(0, "login.failed", "u1", "{\"failedAttempts\":5}"),
            BuildStep(30, "login.failed", "u1", "{\"failedAttempts\":11}")
        };
        var scenario = new Scenario("multi-brute", "multi brute", "", "authentication", [], steps, [],
            new ExpectedOutcome(["Brute force lock"], "Lock", "Critical"), true, true);

        var events = new EventGenerator().Generate(scenario, DateTimeOffset.UtcNow);
        var result = await eval.EvaluateAsync(scenario, events, new SimulationRunOptions());

        Assert.That(result.FinalAction, Is.EqualTo("Lock"));
    }

    [Test]
    public async Task ImpossibleTravel_ShouldBlock()
    {
        var eval = new HipPolicyEvaluatorAdapter(new Microsoft.Extensions.Logging.Abstractions.NullLogger<HipPolicyEvaluatorAdapter>());
        var scenario = BuildScenario("impossible-travel", "login.attempt", payloadJson: "{\"impossibleTravel\":true}", expectedAction: "Block", expectedSeverity: "Critical", shouldBeCovered: true);
        var result = await eval.EvaluateAsync(scenario, new EventGenerator().Generate(scenario, DateTimeOffset.UtcNow), new SimulationRunOptions());

        Assert.That(result.FinalAction, Is.EqualTo("Block"));
    }

    [Test]
    public void InvalidEventScenario_ShouldFailValidation()
    {
        var validator = new ScenarioValidator();
        var scenario = BuildScenario("invalid", "", payloadJson: "null", expectedAction: "Warn", expectedSeverity: "Medium", shouldBeCovered: false);

        var issues = validator.Validate(scenario);

        Assert.That(issues.Count > 0, Is.EqualTo(true));
    }

    [Test]
    public void ProtocolModeWithoutProtocolSteps_ShouldFailValidation()
    {
        var validator = new ScenarioValidator();
        var scenario = new Scenario("p1", "protocol", "", "protocol", [], [], [], new ExpectedOutcome([], "Allow", "Info"), true, true, SimulationExecutionMode.Protocol);

        var issues = validator.Validate(scenario);

        Assert.That(issues.Any(x => x.Contains("protocol mode requires at least one protocolSteps entry")), Is.True);
    }

    private static Scenario BuildScenario(string id, string eventType, string actorId = "user-1", string payloadJson = "{}", string expectedAction = "LogOnly", string expectedSeverity = "Info", bool shouldBeCovered = false)
    {
        var steps = new[] { BuildStep(0, eventType, actorId, payloadJson) };
        return new Scenario(id, id, "", "test", [], steps, [], new ExpectedOutcome([], expectedAction, expectedSeverity), shouldBeCovered, true);
    }

    private static ScenarioStep BuildStep(int offset, string eventType, string actorId, string payloadJson)
    {
        using var doc = JsonDocument.Parse(payloadJson);
        return new ScenarioStep(offset, eventType, actorId, null, doc.RootElement.Clone());
    }
}
