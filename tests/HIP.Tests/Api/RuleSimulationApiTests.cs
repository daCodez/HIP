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
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = AdminClient(factory);

        var response = await client.PostAsJsonAsync("/api/v1/rules/simulate", new { RuleId = "new-domain-shortener-high-risk" });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.GetProperty("simulationId").GetString(), Is.Not.Empty);
        Assert.That(json.RootElement.GetProperty("confidenceScore").GetDecimal(), Is.InRange(0m, 1m));
        Assert.That(json.RootElement.GetProperty("recommendedAction").GetString(), Is.Not.Empty);
        Assert.That(json.RootElement.GetProperty("recommendedMode").GetString(), Is.EqualTo("watch"));
        Assert.That(json.RootElement.GetProperty("ruleVersion").GetInt32(), Is.GreaterThanOrEqualTo(1));
        Assert.That(json.RootElement.GetProperty("fixtureSetId").GetString(), Does.Match("^fixtures:[0-9a-f]{64}$"));
        Assert.That(json.RootElement.GetProperty("totalTestCases").GetInt32(), Is.GreaterThanOrEqualTo(10));
        Assert.That(json.RootElement.GetProperty("completedAtUtc").GetDateTimeOffset(),
            Is.GreaterThanOrEqualTo(json.RootElement.GetProperty("startedAtUtc").GetDateTimeOffset()));
    }

    [Test]
    public async Task Rule_simulation_can_be_retrieved_by_id()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = AdminClient(factory);

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
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = AdminClient(factory);

        var rule = RuleWithFalsePositive();
        var response = await client.PostAsJsonAsync("/api/v1/rules/simulate", new
        {
            Rule = rule,
            TestCases = new[]
            {
                new
                {
                    Name = "safe old domain",
                    InputFacts = new { Values = new Dictionary<string, object?>
                    {
                        ["domain.ageDays"] = 1200,
                        ["domain.name"] = "fixture-value-must-not-leave-api.example",
                        ["url.usesShortener"] = false
                    } },
                    ExpectedMatch = false,
                    ExpectedRiskLevel = (string?)null,
                    ExpectedSafetyPageRouting = (bool?)null
                }
            }
        });

        var responseText = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(responseText);
        Assert.That(json.RootElement.GetProperty("passed").GetBoolean(), Is.False);
        Assert.That(json.RootElement.GetProperty("failedCases").GetArrayLength(), Is.GreaterThan(0));
        Assert.That(json.RootElement.GetProperty("recommendedAction").GetString(), Does.Contain("Do not auto-enable"));
        Assert.That(responseText, Does.Not.Contain("fixture-value-must-not-leave-api.example"));
    }

    [Test]
    public async Task Anonymous_callers_cannot_read_simulation_results()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync($"/api/v1/rules/simulations/simulation:{new string('a', 32)}");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task High_impact_approval_workflow_requires_two_actor_bound_approvals_without_exposing_identities()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var requester = AdminClient(factory, "approval-requester");
        var simulationResponse = await requester.PostAsJsonAsync(
            "/api/v1/rules/simulate",
            new { RuleId = "new-domain-shortener-high-risk" });
        var simulationJson = JsonDocument.Parse(await simulationResponse.Content.ReadAsStringAsync());
        var simulationId = simulationJson.RootElement.GetProperty("simulationId").GetString();

        var requestResponse = await requester.PostAsJsonAsync(
            "/api/v1/rules/new-domain-shortener-high-risk/approval-workflows",
            new { SimulationId = simulationId });
        var requestedText = await requestResponse.Content.ReadAsStringAsync();
        var requested = JsonDocument.Parse(requestedText);
        var workflowId = requested.RootElement.GetProperty("workflowId").GetString();

        using var firstApprover = AdminClient(factory, "independent-approver-1");
        using var secondApprover = AdminClient(factory, "independent-approver-2");
        var first = await firstApprover.PostAsync(
            $"/api/v1/rules/approval-workflows/{workflowId}/approvals",
            content: null);
        var second = await secondApprover.PostAsync(
            $"/api/v1/rules/approval-workflows/{workflowId}/approvals",
            content: null);
        var completedText = await second.Content.ReadAsStringAsync();
        var completed = JsonDocument.Parse(completedText);
        using var deployer = AdminClient(factory, "independent-deployer");
        var activation = await deployer.PostAsJsonAsync(
            $"/api/v1/rules/approval-workflows/{workflowId}/activate",
            new { Reason = "Focused API activation test." });
        var activated = JsonDocument.Parse(await activation.Content.ReadAsStringAsync());
        var rollback = await deployer.PostAsJsonAsync(
            "/api/v1/rules/deployments/new-domain-shortener-high-risk/rollback",
            new
            {
                ExpectedVersion = activated.RootElement.GetProperty("version").GetInt64(),
                Reason = "Focused API rollback test."
            });
        var rolledBackText = await rollback.Content.ReadAsStringAsync();
        var rolledBack = JsonDocument.Parse(rolledBackText);
        var evaluation = await deployer.PostAsJsonAsync(
            "/api/v1/rules/evaluate",
            new RuleEvaluationApiRequest(
                null,
                new HIP.Application.Rules.RuleScanContext(
                    "https://bit.ly/example",
                    "new-example.com",
                    5,
                    true,
                    false,
                    1,
                    50,
                    50,
                    20)));
        var evaluated = JsonDocument.Parse(await evaluation.Content.ReadAsStringAsync());

        Assert.Multiple(() =>
        {
            Assert.That(requestResponse.StatusCode, Is.EqualTo(HttpStatusCode.Created));
            Assert.That(requested.RootElement.GetProperty("requiredApprovalCount").GetInt32(), Is.EqualTo(2));
            Assert.That(first.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(second.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(completed.RootElement.GetProperty("approvalCount").GetInt32(), Is.EqualTo(2));
            Assert.That(completed.RootElement.GetProperty("canActivate").GetBoolean(), Is.True);
            Assert.That(activation.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(activated.RootElement.GetProperty("status").GetString(), Is.EqualTo("Watch"));
            Assert.That(activated.RootElement.GetProperty("useDisabledRollback").GetBoolean(), Is.True);
            Assert.That(rollback.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(rolledBack.RootElement.GetProperty("status").GetString(), Is.EqualTo("Disabled"));
            Assert.That(rolledBack.RootElement.GetProperty("rollbackAvailable").GetBoolean(), Is.False);
            Assert.That(evaluation.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(evaluated.RootElement.GetProperty("matchedRules").GetArrayLength(), Is.Zero);
            Assert.That(completedText, Does.Not.Contain("independent-approver"));
            Assert.That(requestedText, Does.Not.Contain("system"));
            Assert.That(rolledBackText, Does.Not.Contain("independent-deployer"));
            Assert.That(rolledBackText, Does.Not.Contain("Focused API"));
        });
    }

    private static HttpClient AdminClient(
        HipWebApplicationFactory<Program> factory,
        string actor = "rule-simulation-api-test")
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", "Admin");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", actor);
        return client;
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
