using System.Net;
using System.Net.Http.Json;
using HIP.Application.Review;
using HIP.Application.Rules;
using HIP.Application.Simulation;
using HIP.Domain.Audit;
using HIP.Domain.Review;
using HIP.Domain.Rules;
using HIP.Tests.Rules;
using HIP.Web.Security;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HIP.Tests.Api;

public sealed class AdminRolesAuditTests
{
    [Test]
    public void Owner_has_full_permissions()
    {
        foreach (var permission in AdminRoleCatalog.Roles.Single(role => role.Role == AdminRoles.Owner).Permissions)
        {
            Assert.That(AdminRoleCatalog.HasPermission(AdminRoles.Owner, permission), Is.True);
        }

        Assert.That(AdminRoleCatalog.HasPermission(AdminRoles.Owner, AdminPermissions.SystemManage), Is.True);
        Assert.That(AdminRoleCatalog.HasPermission(AdminRoles.Owner, AdminPermissions.AdminsManage), Is.True);
    }

    [Test]
    public void Admin_has_rule_review_and_license_permissions()
    {
        Assert.That(AdminRoleCatalog.HasPermission(AdminRoles.Admin, AdminPermissions.RulesEdit), Is.True);
        Assert.That(AdminRoleCatalog.HasPermission(AdminRoles.Admin, AdminPermissions.ReviewDecide), Is.True);
        Assert.That(AdminRoleCatalog.HasPermission(AdminRoles.Admin, AdminPermissions.LicensesManage), Is.True);
    }

    [Test]
    public void Moderator_can_review_but_cannot_manage_system()
    {
        Assert.That(AdminRoleCatalog.HasPermission(AdminRoles.Moderator, AdminPermissions.ReviewDecide), Is.True);
        Assert.That(AdminRoleCatalog.HasPermission(AdminRoles.Moderator, AdminPermissions.SystemManage), Is.False);
    }

    [Test]
    public void Support_can_view_license_support_info_but_cannot_change_reputation()
    {
        Assert.That(AdminRoleCatalog.HasPermission(AdminRoles.Support, AdminPermissions.LicensesView), Is.True);
        Assert.That(AdminRoleCatalog.HasPermission(AdminRoles.Support, AdminPermissions.ReputationOverrideRequest), Is.False);
    }

    [Test]
    public void Readonly_cannot_change_anything()
    {
        Assert.That(AdminRoleCatalog.HasPermission(AdminRoles.ReadOnly, AdminPermissions.RulesEdit), Is.False);
        Assert.That(AdminRoleCatalog.HasPermission(AdminRoles.ReadOnly, AdminPermissions.ReviewDecide), Is.False);
        Assert.That(AdminRoleCatalog.HasPermission(AdminRoles.ReadOnly, AdminPermissions.LicensesManage), Is.False);
        Assert.That(AdminRoleCatalog.HasPermission(AdminRoles.ReadOnly, AdminPermissions.SystemManage), Is.False);
    }

    [Test]
    public async Task Audit_log_entry_is_created_for_rule_change()
    {
        var audit = new AuditLogService();
        var matching = new RuleMatchingEngine();
        var service = new AdminRuleService(
            new TrustRuleValidator(),
            new InMemoryRuleRepository(),
            new RuleSimulationService(new RuleActionApplier(matching)),
            audit);

        await service.SaveAsync(RuleEngineTests.NewDomainShortenerRule(RuleMode.Watch), CancellationToken.None);

        Assert.That(audit.List().Any(entry => entry.Action == "Rule changed"), Is.True);
    }

    [Test]
    public void Audit_log_does_not_store_private_chat_content()
    {
        var audit = new AuditLogService();

        audit.Write(
            "admin",
            "Review decision made",
            TargetType.Domain,
            "example.com",
            "private chat content should not be logged",
            AuditSeverity.High,
            new Dictionary<string, string>
            {
                ["privateChatLog"] = "raw private message",
                ["reason"] = "privacy-safe reason"
            });

        var entry = audit.List().Single();
        Assert.That(entry.Summary, Does.Not.Contain("private chat content"));
        Assert.That(entry.Metadata.Keys, Does.Not.Contain("privateChatLog"));
        Assert.That(entry.Metadata.Values, Does.Not.Contain("raw private message"));
    }

    [Test]
    public async Task Admin_audit_routes_are_protected()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var audit = await client.GetAsync("/api/v1/admin/audit");
        var query = await client.PostAsJsonAsync("/api/v1/admin/audit/query", new { Limit = 10 });

        Assert.That(audit.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(query.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Roles_api_returns_permission_model_for_admin()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", "Owner");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", "owner-test");

        var body = await client.GetStringAsync("/api/v1/admin/roles");

        Assert.That(body, Does.Contain(AdminRoles.Owner));
        Assert.That(body, Does.Contain(AdminPermissions.RulesEdit));
    }
}
