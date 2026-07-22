using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HIP.Application.SiteSafety;
using HIP.Domain.Review;
using HIP.Web.Security;
using NUnit.Framework;

namespace HIP.Tests.Security;

[TestFixture]
public sealed class PrivilegedActionBindingTests
{
    private const string AuthenticatedActor = "authenticated-owner";

    [Test]
    public async Task Reputation_override_api_ignores_forged_request_and_decision_actors()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = CreateOwnerClient(factory);
        var requestId = $"override-{Guid.NewGuid():N}";
        var forgedApproval = new ApprovalRecord(
            "forged-approval",
            requestId,
            "forged-first-approver",
            DateTimeOffset.UtcNow,
            ApprovalDecision.Approved,
            "Forged caller-supplied approval.");
        var request = new ReputationOverrideRequest(
            requestId,
            TargetType.Domain,
            $"actor-binding-{Guid.NewGuid():N}.example",
            60,
            70,
            "Targeted actor-binding regression test.",
            "forged-requester",
            OverrideRequestStatus.Approved,
            1,
            [forgedApproval],
            DateTimeOffset.UtcNow.AddYears(-1),
            DateTimeOffset.UtcNow.AddYears(-1));

        var createResponse = await client.PostAsJsonAsync("/api/v1/admin/reputation-overrides/", request);
        var created = await ReadSuccessfulResponseAsync<ReputationOverrideRequest>(createResponse);

        Assert.Multiple(() =>
        {
            Assert.That(created.RequestedBy, Is.EqualTo(AuthenticatedActor));
            Assert.That(created.Approvals, Is.Empty);
            Assert.That(created.Status, Is.EqualTo(OverrideRequestStatus.Pending));
        });

        var firstApprovalResponse = await client.PostAsJsonAsync(
            $"/api/v1/admin/reputation-overrides/{created.OverrideRequestId}/approve",
            new { ActorId = "forged-second-approver", Reason = "Authenticated approval." });
        var firstApproval = await ReadSuccessfulResponseAsync<ReputationOverrideRequest>(firstApprovalResponse);

        Assert.That(firstApproval.Approvals, Has.Count.EqualTo(1));
        Assert.That(firstApproval.Approvals.Single().ApprovedBy, Is.EqualTo(AuthenticatedActor));

        var duplicateApprovalResponse = await client.PostAsJsonAsync(
            $"/api/v1/admin/reputation-overrides/{created.OverrideRequestId}/approve",
            new { ActorId = "forged-third-approver", Reason = "Attempted duplicate approval." });

        Assert.That(duplicateApprovalResponse.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        var requests = await client.GetFromJsonAsync<IReadOnlyCollection<ReputationOverrideRequest>>(
            "/api/v1/admin/reputation-overrides/");
        var stored = requests!.Single(item => item.OverrideRequestId == created.OverrideRequestId);
        Assert.That(stored.Approvals, Has.Count.EqualTo(1));
        Assert.That(stored.Approvals.Single().ApprovedBy, Is.EqualTo(AuthenticatedActor));
    }

    [Test]
    public async Task Admin_rule_api_ignores_forged_creation_and_approval_actors()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = CreateOwnerClient(factory);
        var ruleId = $"actor-binding-{Guid.NewGuid():N}";
        var rule = new AdminSiteSafetyRule(
            RuleId: ruleId,
            Name: "Actor binding regression rule",
            Description: "Proves privileged rule actors come from the authenticated principal.",
            TargetType: AdminSiteSafetyRuleTargetType.PageContent,
            Conditions:
            [
                new AdminSiteSafetyRuleCondition(
                    "Domain",
                    AdminSiteSafetyRuleOperator.EndsWith,
                    JsonSerializer.SerializeToElement(".example"))
            ],
            Effects: new AdminSiteSafetyRuleEffects(AddReason: "Actor binding test matched."),
            Severity: SiteSafetyRuleSeverity.Medium,
            EvidenceQuality: SiteSafetyEvidenceQuality.Medium,
            Status: AdminSiteSafetyRuleStatus.Active,
            Mode: AdminSiteSafetyRuleMode.Enforced,
            CreatedBy: "forged-creator",
            CreatedAtUtc: DateTimeOffset.UtcNow.AddYears(-1),
            ApprovedBy: "forged-approver",
            ApprovedAtUtc: DateTimeOffset.UtcNow.AddYears(-1),
            Version: 1,
            PreviousVersionId: null,
            IsRollbackAvailable: false,
            UpdatedBy: "forged-updater",
            UpdatedAtUtc: DateTimeOffset.UtcNow.AddYears(-1));

        var createResponse = await client.PostAsJsonAsync("/api/v1/admin/site-safety-rules/", rule);
        var created = await ReadSuccessfulResponseAsync<AdminSiteSafetyRule>(createResponse);

        Assert.Multiple(() =>
        {
            Assert.That(created.CreatedBy, Is.EqualTo(AuthenticatedActor));
            Assert.That(created.ApprovedBy, Is.Null);
            Assert.That(created.UpdatedBy, Is.Null);
            Assert.That(created.Status, Is.EqualTo(AdminSiteSafetyRuleStatus.Draft));
        });

        var approvalResponse = await client.PostAsJsonAsync(
            $"/api/v1/admin/site-safety-rules/{created.RuleId}/approve",
            new { ActorId = "forged-action-actor" });
        var approved = await ReadSuccessfulResponseAsync<AdminSiteSafetyRule>(approvalResponse);

        Assert.Multiple(() =>
        {
            Assert.That(approved.ApprovedBy, Is.EqualTo(AuthenticatedActor));
            Assert.That(approved.UpdatedBy, Is.EqualTo(AuthenticatedActor));
        });
    }

    [Test]
    public void Privileged_api_mutations_use_authenticated_actor_and_recent_authentication_policy()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.Web", "Program.cs"));
        var ruleApis = Section(source, "static void MapAdminSiteSafetyRuleApis", "static async Task<IResult> RunRuleActionAsync");
        var overrideApis = Section(source, "static void MapReputationOverrideApis", "static IResult RunReputationOverrideAction");
        var revokeApi = Section(
            source,
            "identityApi.MapPost(\"/websites/{domain}/revoke\"",
            "identityApi.MapGet(\"/websites/{domain}\"");

        Assert.Multiple(() =>
        {
            Assert.That(ruleApis, Does.Not.Contain("request.ActorId"));
            Assert.That(ruleApis, Does.Contain("CreatedBy = actor"));
            Assert.That(ruleApis, Does.Contain("ResolveAdminActor(httpContext)"));
            Assert.That(ruleApis, Does.Contain("AdminPolicies.RecentPrivilegedAuthentication"));
            Assert.That(overrideApis, Does.Not.Contain("request.ActorId"));
            Assert.That(overrideApis, Does.Contain("RequestedBy = ResolveAdminActor(httpContext)"));
            Assert.That(overrideApis, Does.Contain("Approvals = []"));
            Assert.That(overrideApis, Does.Contain("AdminPolicies.RecentPrivilegedAuthentication"));
            Assert.That(revokeApi, Does.Contain("ResolveAdminActor(httpContext)"));
            Assert.That(revokeApi, Does.Contain("AdminPolicies.RecentPrivilegedAuthentication"));
        });
    }

    [Test]
    public void Interactive_sensitive_mutations_fail_closed_without_recent_authentication()
    {
        var root = RepositoryRoot();
        var rules = File.ReadAllText(Path.Combine(root, "src", "HIP.Web", "Components", "Pages", "AdminRules.razor"));
        var overrides = File.ReadAllText(Path.Combine(root, "src", "HIP.Web", "Components", "Pages", "AdminReputationOverrides.razor"));
        var websiteIdentity = File.ReadAllText(Path.Combine(root, "src", "HIP.Web", "Components", "Pages", "AdminWebsiteIdentity.razor"));
        var saveRule = Section(rules, "private async Task SaveRule()", "private async Task RunSimulation()");
        var ruleRecentActorGate = Section(rules, "private async Task<string?> RequireRecentActorAsync", "private async Task RunSimulation()");
        var createOverride = Section(overrides, "private async Task CreateSampleAsync()", "private async Task ApproveAsync");
        var approveOverride = Section(overrides, "private async Task ApproveAsync", "private async Task RejectAsync");
        var rejectOverride = Section(overrides, "private async Task RejectAsync", "private async Task<string?> RequireRecentActorAsync");
        var recentActorGate = Section(overrides, "private async Task<string?> RequireRecentActorAsync", "\n}");
        var revoke = Section(websiteIdentity, "private async Task ConfirmRevokeAsync()", "private async Task RunOperationAsync");

        Assert.Multiple(() =>
        {
            AssertGateBeforeMutation(saveRule, "RequireRecentActorAsync", "AdminRuleService.SaveAsync");
            Assert.That(ruleRecentActorGate, Does.Contain("AdminPolicies.RecentPrivilegedAuthentication"));
            AssertGateBeforeMutation(createOverride, "RequireRecentActorAsync", "ReputationOverrideService.Request");
            AssertGateBeforeMutation(approveOverride, "RequireRecentActorAsync", "ReputationOverrideService.Approve");
            AssertGateBeforeMutation(rejectOverride, "RequireRecentActorAsync", "ReputationOverrideService.Reject");
            Assert.That(recentActorGate, Does.Contain("AdminPolicies.RecentPrivilegedAuthentication"));
            AssertGateBeforeMutation(revoke, "AdminPolicies.RecentPrivilegedAuthentication", "WebsiteIdentityService.RevokeVerificationAsync");
            Assert.That(overrides, Does.Contain("@if (HostEnvironment.IsDevelopment())"));
            Assert.That(overrides, Does.Not.Contain("admin-dev"));
            Assert.That(overrides, Does.Not.Contain("_approvalIndex"));
        });
    }

    [Test]
    public void Website_identity_page_reauthorizes_and_binds_the_current_actor_before_every_mutation()
    {
        var source = File.ReadAllText(Path.Combine(
            RepositoryRoot(),
            "src",
            "HIP.Web",
            "Components",
            "Pages",
            "AdminWebsiteIdentity.razor"));
        var retry = Section(source, "private async Task RetryVerificationAsync", "private void BeginRevoke");
        var revoke = Section(source, "private async Task ConfirmRevokeAsync()", "private async Task RunOperationAsync");
        var register = Section(source, "private async Task RegisterWebsiteAsync()", "private async Task VerifyWebsiteAsync()");
        var verify = Section(source, "private async Task VerifyWebsiteAsync()", "private void ClearForm()");
        var actorGate = Section(source, "private async Task<CurrentAdminActor?> RequireCurrentAdminActorAsync", "private void ClearForm()");

        Assert.Multiple(() =>
        {
            AssertGateBeforeMutation(retry, "RequireCurrentAdminActorAsync", "WebsiteIdentityService.RetryVerificationAsync");
            Assert.That(retry, Does.Contain("AdminPolicies.CanManageDomainVerifications"));
            Assert.That(retry, Does.Contain("currentActor.ActorId"));
            Assert.That(retry, Does.Contain("currentActor.Role"));

            AssertGateBeforeMutation(revoke, "RequireCurrentAdminActorAsync", "WebsiteIdentityService.RevokeVerificationAsync");
            Assert.That(revoke, Does.Contain("AdminPolicies.CanRevokeDomainVerifications"));
            Assert.That(revoke, Does.Contain("AdminPolicies.RecentPrivilegedAuthentication"));
            Assert.That(revoke, Does.Contain("currentActor.ActorId"));
            Assert.That(revoke, Does.Contain("currentActor.Role"));

            AssertGateBeforeMutation(register, "RequireCurrentAdminActorAsync", "WebsiteIdentityService.RegisterAsync");
            Assert.That(register, Does.Contain("AdminPolicies.CanManageDomainVerifications"));
            AssertGateBeforeMutation(verify, "RequireCurrentAdminActorAsync", "WebsiteIdentityService.VerifyAsync");
            Assert.That(verify, Does.Contain("AdminPolicies.CanManageDomainVerifications"));

            Assert.That(actorGate, Does.Contain("AuthenticationStateProvider.GetAuthenticationStateAsync"));
            Assert.That(actorGate, Does.Contain("HipAuthenticatedIdentity.TryResolveUniqueClaim"));
            Assert.That(actorGate, Does.Contain("HipAuthenticationClaimTypes.ActorId"));
            Assert.That(actorGate, Does.Contain("AuthorizationService.AuthorizeAsync"));
            Assert.That(actorGate, Does.Contain("ResolveCurrentAdminRole"));
            Assert.That(source, Does.Not.Contain("private string _actorId"));
            Assert.That(source, Does.Not.Contain("private string _actorRole"));
        });
    }

    private static HttpClient CreateOwnerClient(HipWebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", AdminRoles.Owner);
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", AuthenticatedActor);
        return client;
    }

    private static async Task<T> ReadSuccessfulResponseAsync<T>(HttpResponseMessage response)
        where T : class
    {
        var body = await response.Content.ReadAsStringAsync();
        Assert.That(response.IsSuccessStatusCode, Is.True, body);
        return JsonSerializer.Deserialize<T>(body, new JsonSerializerOptions(JsonSerializerDefaults.Web))
            ?? throw new AssertionException($"Expected a {typeof(T).Name} response body.");
    }

    private static void AssertGateBeforeMutation(string source, string gate, string mutation)
    {
        var gateIndex = source.IndexOf(gate, StringComparison.Ordinal);
        var mutationIndex = source.IndexOf(mutation, StringComparison.Ordinal);
        Assert.That(gateIndex, Is.GreaterThanOrEqualTo(0), $"Expected gate '{gate}'.");
        Assert.That(mutationIndex, Is.GreaterThan(gateIndex), $"Expected '{gate}' before '{mutation}'.");
    }

    private static string Section(string source, string startMarker, string endMarker)
    {
        var start = source.IndexOf(startMarker, StringComparison.Ordinal);
        Assert.That(start, Is.GreaterThanOrEqualTo(0), $"Could not find '{startMarker}'.");
        var end = source.IndexOf(endMarker, start + startMarker.Length, StringComparison.Ordinal);
        Assert.That(end, Is.GreaterThan(start), $"Could not find '{endMarker}' after '{startMarker}'.");
        return source[start..end];
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate repository root.");
    }
}
