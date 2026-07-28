using System.Net;
using HIP.Web.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HIP.Tests.Security;

/// <summary>
/// Maintains the exact named-policy boundary for every protected routable Razor component.
/// </summary>
[TestFixture]
public sealed class RazorPageAuthorizationMatrixTests
{
    private static readonly PageAuthorizationCase[] Cases =
    [
        Page("AdminAccessStatusPage", "/access", AdminPolicies.CanViewOwnAdminAccess, DeniedPrincipal.Consumer, "<h1>Access status</h1>"),
        Page("AdminApiDeveloper", "/admin/api", AdminPolicies.CanViewServiceClients, DeniedPrincipal.Moderator, "Integrate HIP into your own tools"),
        Page("AdminDashboard", "/", AdminPolicies.CanViewAdminDashboard, DeniedPrincipal.Consumer, "<h1>Overview</h1>"),
        Page("AdminDashboard", "/admin", AdminPolicies.CanViewAdminDashboard, DeniedPrincipal.Consumer, "<h1>Overview</h1>"),
        Page("AdminFeedbackLoop", "/admin/feedback", AdminPolicies.CanViewAdminDashboard, DeniedPrincipal.Consumer, "<h1>Feedback Loop</h1>"),
        Page("AdminFeedbackLoop", "/admin/feedback/{Domain}", "/admin/feedback/example.com", AdminPolicies.CanViewAdminDashboard, DeniedPrincipal.Consumer, "<h1>Feedback Loop</h1>"),
        Page("AdminMessageShield", "/admin/message-shield", AdminPolicies.CanViewAdminDashboard, DeniedPrincipal.Consumer, "<h1>Message Shield</h1>"),
        Page("AdminPlatformConnections", "/admin/platforms", AdminPolicies.CanViewAdminDashboard, DeniedPrincipal.Consumer, "<h1>Platform Connections</h1>"),
        Page("AdminPrivacySafety", "/admin/privacy", AdminPolicies.CanViewAdminDashboard, DeniedPrincipal.Consumer, "<h1>Privacy"),
        Page("AdminReputationOverview", "/admin/reputation", AdminPolicies.CanViewAdminDashboard, DeniedPrincipal.Consumer, "<h1>Score Overview</h1>"),
        Page("AdminReputationSignals", "/admin/reputation/signals", AdminPolicies.CanViewAdminDashboard, DeniedPrincipal.Consumer, "<h1>Trust Signals</h1>"),
        Page("AdminRoles", "/admin/roles", AdminPolicies.CanViewAdminUsers, DeniedPrincipal.Admin, "<h1>Users and roles</h1>"),
        Page("AdminScanDetails", "/admin/scans/{ScanId}", "/admin/scans/matrix-scan", AdminPolicies.CanViewAdminDashboard, DeniedPrincipal.Consumer, "<h1>Scan Result Details</h1>"),
        Page("AdminSenderProfiles", "/admin/reputation/senders", AdminPolicies.CanViewAdminDashboard, DeniedPrincipal.Consumer, "<h1>Sender Profiles</h1>"),
        Page("AdminTourScan", "/admin/tour-scan", AdminPolicies.CanViewAdminDashboard, DeniedPrincipal.Consumer, "Sample Threat"),
        Page("DevLauncher", "/dev/launcher", AdminPolicies.CanViewAdminDashboard, DeniedPrincipal.Consumer, "<h1>HIP Local Launcher</h1>"),

        Page("AdminAlerts", "/admin/alerts", AdminPolicies.CanViewReviews, DeniedPrincipal.Consumer, "<h1>Alert Center</h1>"),
        Page("AdminDomainCertificates", "/admin/certificates", AdminPolicies.CanViewReviews, DeniedPrincipal.Consumer, "<h1>Domain Trust Certificates</h1>"),
        Page("AdminReportsPage", "/admin/reports", AdminPolicies.CanViewReviews, DeniedPrincipal.Consumer, "<h1>Reports</h1>"),
        Page("AdminReview", "/admin/review", AdminPolicies.CanViewReviews, DeniedPrincipal.Consumer, "<h1>Review Queue</h1>"),
        Page("AdminReview", "/admin/review/{ReviewItemId}", "/admin/review/matrix-review", AdminPolicies.CanViewReviews, DeniedPrincipal.Consumer, "<h1>Review Queue</h1>"),
        Page("AdminReviewSignals", "/admin/review-queue", AdminPolicies.CanViewReviews, DeniedPrincipal.Consumer, "<h1>Safety Review Signals</h1>"),

        Page("AdminAppeals", "/admin/appeals", AdminPolicies.CanViewAppeals, DeniedPrincipal.Support, "<h1>Appeals</h1>"),
        Page("AdminAppeals", "/admin/appeals/{AppealId}", "/admin/appeals/matrix-appeal", AdminPolicies.CanViewAppeals, DeniedPrincipal.Support, "<h1>Appeals</h1>"),
        Page("AdminAuditLogs", "/admin/audit-logs", AdminPolicies.CanViewAuditLogs, DeniedPrincipal.Support, "<h1>Audit Trail</h1>"),
        Page("AdminAuditLogs", "/admin/audit", AdminPolicies.CanViewAuditLogs, DeniedPrincipal.Support, "<h1>Audit Trail</h1>"),
        Page("AdminLicenseDetail", "/admin/licenses/{LicenseId}", "/admin/licenses/matrix-license", AdminPolicies.CanViewLicenses, DeniedPrincipal.Moderator, "<h1>Manage license</h1>"),
        Page("AdminLicenses", "/admin/licenses", AdminPolicies.CanViewLicenses, DeniedPrincipal.Moderator, "<h1>Licenses</h1>"),
        Page("AdminLicenseNew", "/admin/licenses/new", AdminPolicies.CanAdministerLicenses, DeniedPrincipal.Support, "<h1>Create a license</h1>"),
        Page("AdminReputationOverrides", "/admin/reputation-overrides", AdminPolicies.CanApproveOverrides, DeniedPrincipal.Moderator, "<h1>Reputation Overrides</h1>"),
        Page("AdminRules", "/admin/rules", AdminPolicies.CanManageRules, DeniedPrincipal.ReadOnly, "<h1>Admin Rule Builder</h1>"),
        Page("AdminRules", "/admin/rules/new", AdminPolicies.CanManageRules, DeniedPrincipal.ReadOnly, "<h1>Admin Rule Builder</h1>"),
        Page("AdminRules", "/admin/rules/{RuleId}", "/admin/rules/matrix-rule", AdminPolicies.CanManageRules, DeniedPrincipal.ReadOnly, "<h1>Admin Rule Builder</h1>"),
        Page("AdminSelfHealing", "/admin/self-healing", AdminPolicies.CanManageRules, DeniedPrincipal.ReadOnly, "<h1>Self-Healing Rule Detection</h1>"),
        Page("AdminSettings", "/admin/settings", AdminPolicies.CanManageRules, DeniedPrincipal.ReadOnly, "<h1>External Safety Evidence</h1>"),
        Page("AdminSecondLifeHudSimulator", "/admin/sl-hud-simulator", AdminPolicies.CanSupportLicenses, DeniedPrincipal.ReadOnly, "Second Life HUD Simulator"),
        Page("AdminWebsiteIdentity", "/admin/identity/websites", AdminPolicies.CanManageDomainVerifications, DeniedPrincipal.ReadOnly, "<h1>Domain Verification</h1>"),
        Page("HipStepUp", "/step-up", AdminPolicies.CanRequestPrivilegedStepUp, DeniedPrincipal.Moderator, "Confirm it is still you."),

        Page("ConsumerAppeals", "/consumer/appeals", ConsumerPolicies.CanUseConsumerPortal, DeniedPrincipal.Admin, "<h1>Appeals</h1>"),
        Page("ConsumerCertificates", "/consumer/certificates", ConsumerPolicies.CanUseConsumerPortal, DeniedPrincipal.Admin, "<h1>Domain certificates</h1>"),
        Page("ConsumerAccountSecurity", "/consumer/security", ConsumerPolicies.CanUseConsumerPortal, DeniedPrincipal.Admin, "<h1>Account Security</h1>"),
        Page("ConsumerDevices", "/consumer/devices", ConsumerPolicies.CanUseConsumerPortal, DeniedPrincipal.Admin, "<h1>Devices</h1>"),
        Page("ConsumerHome", "/consumer", ConsumerPolicies.CanUseConsumerPortal, DeniedPrincipal.Admin, "<h1>Consumer Portal</h1>"),
        Page("ConsumerLicenses", "/consumer/licenses", ConsumerPolicies.CanUseConsumerPortal, DeniedPrincipal.Admin, "<h1>Licenses</h1>"),
        Page("ConsumerReports", "/consumer/reports", ConsumerPolicies.CanUseConsumerPortal, DeniedPrincipal.Admin, "Report History"),
        Page("ConsumerScans", "/consumer/scans", ConsumerPolicies.CanUseConsumerPortal, DeniedPrincipal.Admin, "Scan History"),
        Page("ConsumerSettingsPage", "/consumer/settings", ConsumerPolicies.CanUseConsumerPortal, DeniedPrincipal.Admin, "<h1>Alert Settings</h1>"),
        Page("ConsumerSettingsPage", "/consumer/alerts", ConsumerPolicies.CanUseConsumerPortal, DeniedPrincipal.Admin, "<h1>Alert Settings</h1>")
    ];

    [Test]
    public void Every_protected_Razor_route_uses_the_exact_maintained_named_policy()
    {
        var actual = typeof(Program).Assembly.GetTypes()
            .Where(type => typeof(IComponent).IsAssignableFrom(type))
            .SelectMany(type =>
            {
                var policies = type.GetCustomAttributes(typeof(AuthorizeAttribute), inherit: false)
                    .Cast<AuthorizeAttribute>()
                    .Select(attribute => attribute.Policy ?? "<unnamed>")
                    .ToArray();
                return type.GetCustomAttributes(typeof(RouteAttribute), inherit: false)
                    .Cast<RouteAttribute>()
                    .SelectMany(route => policies.Select(policy => new PagePolicy(
                        type.Name,
                        NormalizeRoute(route.Template),
                        policy)));
            })
            .ToArray();
        var expected = Cases
            .Select(item => new PagePolicy(item.ComponentName, item.RouteTemplate, item.Policy))
            .ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(Cases, Has.Length.EqualTo(48), "The maintained matrix must contain every protected route template.");
            Assert.That(
                Cases.Select(item => item.ComponentName).Distinct(StringComparer.Ordinal).ToArray(),
                Has.Length.EqualTo(40),
                "The maintained matrix must contain every protected routable component.");
            Assert.That(
                expected.Select(item => $"{item.ComponentName}|{item.RouteTemplate}"),
                Is.Unique,
                "Each protected component route must have exactly one maintained expectation.");
            Assert.That(actual, Is.EquivalentTo(expected));
        });
    }

    [Test]
    public async Task Every_protected_Razor_route_forbids_a_disallowed_authenticated_principal_without_rendering()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        var failures = new List<string>();

        foreach (var item in Cases)
        {
            using var client = Client(factory, item.DeniedPrincipal);
            using var response = await client.GetAsync(item.RequestPath);
            var html = await response.Content.ReadAsStringAsync();

            // Non-API status-code handling deliberately re-executes forbidden pages through
            // /not-found, preserving a non-disclosing 404 while the authorization handler logs the forbid.
            if (response.StatusCode != HttpStatusCode.NotFound)
            {
                failures.Add(
                    $"{item.ComponentName} {item.RouteTemplate} returned {(int)response.StatusCode} {response.StatusCode} " +
                    $"for {item.DeniedPrincipal}; expected the non-disclosing 404 page response.");
            }

            if (html.Contains(item.RenderMarker, StringComparison.Ordinal))
            {
                failures.Add(
                    $"{item.ComponentName} {item.RouteTemplate} rendered marker '{item.RenderMarker}' " +
                    $"for disallowed {item.DeniedPrincipal}.");
            }
        }

        Assert.That(
            failures,
            Is.Empty,
            "Protected Razor route denial failures:" + Environment.NewLine + string.Join(Environment.NewLine, failures));
    }

    [Test]
    public async Task Service_client_navigation_is_visible_only_to_a_role_with_view_permission()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var adminClient = Client(factory, DeniedPrincipal.Admin);
        using var moderatorClient = Client(factory, DeniedPrincipal.Moderator);

        using var adminResponse = await adminClient.GetAsync("/admin");
        using var moderatorResponse = await moderatorClient.GetAsync("/admin");
        var adminHtml = await adminResponse.Content.ReadAsStringAsync();
        var moderatorHtml = await moderatorResponse.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(adminResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(moderatorResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(adminHtml, Does.Contain("href=\"admin/api\""));
            Assert.That(moderatorHtml, Does.Not.Contain("href=\"admin/api\""));
        });
    }

    private static HttpClient Client(
        HipWebApplicationFactory<Program> factory,
        DeniedPrincipal principal)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        if (principal == DeniedPrincipal.Consumer)
        {
            client.DefaultRequestHeaders.Add(
                HipDevHeaderAuthenticationHandler.ConsumerHeaderName,
                "razor-page-matrix-consumer");
            return client;
        }

        var role = principal switch
        {
            DeniedPrincipal.Admin => AdminRoles.Admin,
            DeniedPrincipal.Moderator => AdminRoles.Moderator,
            DeniedPrincipal.Support => AdminRoles.Support,
            DeniedPrincipal.ReadOnly => AdminRoles.ReadOnly,
            _ => throw new ArgumentOutOfRangeException(nameof(principal), principal, null)
        };
        client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.RoleHeaderName, role);
        client.DefaultRequestHeaders.Add(
            HipDevHeaderAuthenticationHandler.UserHeaderName,
            $"razor-page-matrix-{role.ToLowerInvariant()}");
        return client;
    }

    private static PageAuthorizationCase Page(
        string componentName,
        string routeTemplate,
        string policy,
        DeniedPrincipal deniedPrincipal,
        string renderMarker) =>
        Page(componentName, routeTemplate, routeTemplate, policy, deniedPrincipal, renderMarker);

    private static PageAuthorizationCase Page(
        string componentName,
        string routeTemplate,
        string requestPath,
        string policy,
        DeniedPrincipal deniedPrincipal,
        string renderMarker) =>
        new(componentName, NormalizeRoute(routeTemplate), requestPath, policy, deniedPrincipal, renderMarker);

    private static string NormalizeRoute(string route) =>
        route.StartsWith('/') ? route : $"/{route}";

    private sealed record PageAuthorizationCase(
        string ComponentName,
        string RouteTemplate,
        string RequestPath,
        string Policy,
        DeniedPrincipal DeniedPrincipal,
        string RenderMarker);

    private sealed record PagePolicy(
        string ComponentName,
        string RouteTemplate,
        string Policy);

    private enum DeniedPrincipal
    {
        Admin,
        Moderator,
        Support,
        ReadOnly,
        Consumer
    }
}
