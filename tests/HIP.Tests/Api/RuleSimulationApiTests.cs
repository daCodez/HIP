using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HIP.Domain.Rules;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HIP.Tests.Api;

public sealed class RuleSimulationApiTests
{
    [Test]
    public async Task Rule_simulate_route_runs_seed_cases()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/rules/simulate", new { RuleId = "new-domain-shortener-high-risk" });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.GetProperty("simulationId").GetString(), Is.Not.Empty);
        Assert.That(json.RootElement.GetProperty("confidenceScore").GetDecimal(), Is.InRange(0m, 1m));
        Assert.That(json.RootElement.GetProperty("recommendedAction").GetString(), Is.Not.Empty);
        Assert.That(json.RootElement.GetProperty("recommendedMode").GetString(), Is.EqualTo("watch"));
    }

    [Test]
    public async Task Rule_simulation_can_be_retrieved_by_id()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var simulate = await client.PostAsJsonAsync("/api/v1/rules/simulate", new { RuleId = "new-domain-shortener-high-risk" });
        var json = await JsonDocument.ParseAsync(await simulate.Content.ReadAsStreamAsync());
        var simulationId = json.RootElement.GetProperty("simulationId").GetString();

        var response = await client.GetAsync($"/api/v1/rules/simulations/{simulationId}");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var retrieved = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(retrieved.RootElement.GetProperty("simulationId").GetString(), Is.EqualTo(simulationId));
    }

    [Test]
    public async Task Failed_simulation_response_includes_failed_cases()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var rule = RuleWithFalsePositive();
        var response = await client.PostAsJsonAsync("/api/v1/rules/simulate", new
        {
            Rule = rule,
            TestCases = new[]
            {
                new
                {
                    Name = "safe old domain",
                    InputFacts = new { Values = new Dictionary<string, object?> { ["domain.ageDays"] = 1200, ["url.usesShortener"] = false } },
                    ExpectedMatch = false,
                    ExpectedRiskLevel = (string?)null,
                    ExpectedSafetyPageRouting = (bool?)null
                }
            }
        });

        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.GetProperty("passed").GetBoolean(), Is.False);
        Assert.That(json.RootElement.GetProperty("failedCases").GetArrayLength(), Is.GreaterThan(0));
        Assert.That(json.RootElement.GetProperty("recommendedAction").GetString(), Does.Contain("Do not auto-enable"));
    }

    private static TrustRule RuleWithFalsePositive() =>
        new(
            "broad-domain-age-rule",
            "Broad Domain Age Rule",
            "Intentionally broad rule for API simulation test.",
            true,
            RuleMode.Active,
            RuleSeverity.Low,
            [new RuleCondition("domain.ageDays", RuleOperator.GreaterThan, JsonSerializer.SerializeToElement(1))],
            [new RuleAction(RuleActionType.AddReason, JsonSerializer.SerializeToElement("Broad match."))],
            false,
            true,
            "test",
            "simulation api test",
            ApprovalStatus.NotRequired,
            0m,
            1);
}
