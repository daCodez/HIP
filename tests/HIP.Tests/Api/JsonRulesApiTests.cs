using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HIP.Application.Rules;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HIP.Tests.Api;

public sealed class JsonRulesApiTests
{
    [Test]
    public async Task Rules_list_route_returns_sample_json_rule()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/rules");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.GetArrayLength(), Is.GreaterThan(0));
        Assert.That(json.RootElement[0].GetProperty("ruleId").GetString(), Is.EqualTo("new-domain-shortener-high-risk"));
    }

    [Test]
    public async Task Rule_by_id_route_returns_rule()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/rules/new-domain-shortener-high-risk");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.GetProperty("name").GetString(), Is.EqualTo("New Domain With Shortened URL"));
    }

    [Test]
    public async Task Rule_evaluate_route_returns_watch_mode_results()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/rules/evaluate", new RuleEvaluationApiRequest(
            null,
            new RuleScanContext(
                "https://bit.ly/example",
                "new-example.com",
                12,
                true,
                false,
                1,
                55,
                35,
                20)));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.GetProperty("matchedRules").GetArrayLength(), Is.EqualTo(1));
        Assert.That(json.RootElement.GetProperty("watchModeResults").GetArrayLength(), Is.EqualTo(1));
        Assert.That(json.RootElement.GetProperty("enforcementResults").GetArrayLength(), Is.EqualTo(0));
    }
}
