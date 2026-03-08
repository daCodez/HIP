using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class PolicyVersionEndpointsTests
{
    [Test]
    public async Task PolicyVersion_Workflow_CreateDraft_Upsert_List_AndDiff()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var createDraft = await client.PostAsync(
            "/api/admin/policy/versions/draft",
            new StringContent("{\"actor\":\"tester\",\"reason\":\"branch-test\"}", Encoding.UTF8, "application/json"));
        Assert.That(createDraft.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var draftDoc = JsonDocument.Parse(await createDraft.Content.ReadAsStringAsync());
        var draftId = draftDoc.RootElement.GetProperty("versionId").GetString();
        Assert.That(draftId, Is.Not.Null.And.Not.Empty);

        var upsertBody = """
        {
          "ruleId": "POL-BRANCH-001",
          "name": "Branch coverage rule",
          "category": "Messaging",
          "condition": "domainFlagged == true",
          "action": "Block",
          "severity": "Critical",
          "enabled": true,
          "actor": "tester",
          "reason": "add test rule"
        }
        """;

        var upsert = await client.PostAsync(
            "/api/admin/policy",
            new StringContent(upsertBody, Encoding.UTF8, "application/json"));
        Assert.That(upsert.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var rules = await client.GetFromJsonAsync<List<PolicyRuleDto>>("/api/admin/policy");
        Assert.That(rules, Is.Not.Null);
        Assert.That(rules!.Any(r => r.RuleId == "POL-BRANCH-001"), Is.True);

        var versions = await client.GetFromJsonAsync<List<PolicyVersionDto>>("/api/admin/policy/versions");
        Assert.That(versions, Is.Not.Null);
        Assert.That(versions!.Any(v => v.Status == "Draft"), Is.True);

        var impactRes = await client.GetAsync($"/api/admin/policy/versions/{Uri.EscapeDataString(draftId!)}/impact");
        Assert.That(impactRes.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var diffRes = await client.GetAsync($"/api/admin/policy/versions/{Uri.EscapeDataString(draftId!)}/diff?against=active");
        Assert.That(diffRes.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var diffJson = JsonDocument.Parse(await diffRes.Content.ReadAsStringAsync());
        Assert.That(diffJson.RootElement.TryGetProperty("added", out _), Is.True);
    }

    [Test]
    public async Task PolicyVersion_Workflow_Activate_ThenRollback()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var createDraft = await client.PostAsync(
            "/api/admin/policy/versions/draft",
            new StringContent("{\"actor\":\"tester\",\"reason\":\"activate-path\"}", Encoding.UTF8, "application/json"));
        var draftDoc = JsonDocument.Parse(await createDraft.Content.ReadAsStringAsync());
        var draftId = draftDoc.RootElement.GetProperty("versionId").GetString()!;

        var activate = await client.PostAsync(
            $"/api/admin/policy/versions/{Uri.EscapeDataString(draftId)}/activate",
            new StringContent("{\"actor\":\"tester\",\"reason\":\"activate\",\"approvedBy\":\"lead\"}", Encoding.UTF8, "application/json"));
        Assert.That(activate.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var rollback = await client.PostAsync(
            "/api/admin/policy/versions/rollback",
            new StringContent("{\"actor\":\"tester\",\"reason\":\"rollback\"}", Encoding.UTF8, "application/json"));
        Assert.That(rollback.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var versions = await client.GetFromJsonAsync<List<PolicyVersionDto>>("/api/admin/policy/versions");
        Assert.That(versions, Is.Not.Null);
        Assert.That(versions!.Count(v => v.Status == "Active"), Is.EqualTo(1));
        Assert.That(versions!.Any(v => v.Status == "Archived"), Is.True);
    }

    [Test]
    public async Task PolicyAiDraft_InfersTokenCategory_ForReplayPrompt()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var res = await client.PostAsync(
            "/api/admin/policy/ai-draft",
            new StringContent("{\"prompt\":\"block token replay attempts\"}", Encoding.UTF8, "application/json"));

        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var json = JsonDocument.Parse(await res.Content.ReadAsStringAsync());
        var category = json.RootElement.GetProperty("category").GetString();
        var action = json.RootElement.GetProperty("action").GetString();

        Assert.That(category, Is.EqualTo("Token"));
        Assert.That(action, Is.EqualTo("Block"));
    }

    private sealed record PolicyRuleDto(string RuleId, string Name, string Category, string Condition, string Action, string Severity, bool Enabled);
    private sealed record PolicyVersionDto(string VersionId, string Name, string Status, DateTimeOffset CreatedUtc, DateTimeOffset? ActivatedUtc, string Actor, string Reason, string? ApprovedBy, int RuleCount);
}
