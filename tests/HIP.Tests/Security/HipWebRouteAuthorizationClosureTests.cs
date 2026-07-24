using System.Net;
using System.Security.Claims;
using System.Text.RegularExpressions;
using HIP.Application.Performance;
using HIP.Application.SecondLife;
using HIP.Web.Security;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Tests.Security;

/// <summary>
/// Closes the HIP Web protected API surface over exact route policies and middleware outcomes.
/// </summary>
[TestFixture]
public sealed class HipWebRouteAuthorizationClosureTests
{
    private const int ExpectedProtectedRouteCount = 120;

    private static readonly PrincipalKind[] HumanPrincipals = Enum.GetValues<PrincipalKind>();

    private static readonly IReadOnlyDictionary<string, IReadOnlySet<PrincipalKind>> AllowedPrincipalsByPolicy =
        new Dictionary<string, IReadOnlySet<PrincipalKind>>(StringComparer.Ordinal)
        {
            [AdminPolicies.CanManageRules] = Allowed(PrincipalKind.Owner, PrincipalKind.Admin),
            [AdminPolicies.CanViewReviews] = Allowed(
                PrincipalKind.Owner,
                PrincipalKind.Admin,
                PrincipalKind.Moderator,
                PrincipalKind.Support,
                PrincipalKind.ReadOnly),
            [AdminPolicies.CanDecideReviews] = Allowed(
                PrincipalKind.Owner,
                PrincipalKind.Admin,
                PrincipalKind.Moderator),
            [AdminPolicies.CanViewAppeals] = Allowed(
                PrincipalKind.Owner,
                PrincipalKind.Admin,
                PrincipalKind.Moderator,
                PrincipalKind.ReadOnly),
            [AdminPolicies.CanDecideAppeals] = Allowed(
                PrincipalKind.Owner,
                PrincipalKind.Admin,
                PrincipalKind.Moderator),
            [AdminPolicies.CanApproveOverrides] = Allowed(PrincipalKind.Owner, PrincipalKind.Admin),
            [AdminPolicies.CanManageReputation] = Allowed(PrincipalKind.Owner, PrincipalKind.Admin),
            [AdminPolicies.CanViewAuditLogs] = Allowed(
                PrincipalKind.Owner,
                PrincipalKind.Admin,
                PrincipalKind.ReadOnly),
            [AdminPolicies.CanViewLicenses] = Allowed(
                PrincipalKind.Owner,
                PrincipalKind.Admin,
                PrincipalKind.Support,
                PrincipalKind.ReadOnly),
            [AdminPolicies.CanSupportLicenses] = Allowed(
                PrincipalKind.Owner,
                PrincipalKind.Admin,
                PrincipalKind.Support),
            [AdminPolicies.CanAdministerLicenses] = Allowed(PrincipalKind.Owner, PrincipalKind.Admin),
            [AdminPolicies.CanManagePlatforms] = Allowed(PrincipalKind.Owner, PrincipalKind.Admin),
            [AdminPolicies.CanViewServiceClients] = Allowed(PrincipalKind.Owner, PrincipalKind.Admin),
            [AdminPolicies.CanManageServiceClients] = Allowed(PrincipalKind.Owner, PrincipalKind.Admin),
            [AdminPolicies.CanViewAdminDashboard] = Allowed(
                PrincipalKind.Owner,
                PrincipalKind.Admin,
                PrincipalKind.Moderator,
                PrincipalKind.Support,
                PrincipalKind.ReadOnly),
            [AdminPolicies.CanManageDomainVerifications] = Allowed(PrincipalKind.Owner, PrincipalKind.Admin),
            [AdminPolicies.CanRevokeDomainVerifications] = Allowed(PrincipalKind.Owner),
            [AdminPolicies.RecentPrivilegedAuthentication] = Allowed(PrincipalKind.Owner, PrincipalKind.Admin),
            [ConsumerPolicies.CanUseConsumerPortal] = Allowed(PrincipalKind.Consumer),
            // A human identity never substitutes for the separate active-device credential.
            [HudPolicies.CanUseActiveDevice] = Allowed()
        };

    private static readonly ProtectedRoute[] ProtectedRoutes =
    [
        // Admin-managed Site Safety rules: 8.
        Route(HttpMethods.Get, "/api/v1/admin/site-safety-rules", AdminPolicies.CanManageRules),
        Route(HttpMethods.Get, "/api/v1/admin/site-safety-rules/{ruleId}", AdminPolicies.CanManageRules),
        Route(HttpMethods.Post, "/api/v1/admin/site-safety-rules", AdminPolicies.CanManageRules, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Post, "/api/v1/admin/site-safety-rules/{ruleId}/simulate", AdminPolicies.CanManageRules),
        Route(HttpMethods.Post, "/api/v1/admin/site-safety-rules/{ruleId}/approve", AdminPolicies.CanManageRules, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Post, "/api/v1/admin/site-safety-rules/{ruleId}/activate", AdminPolicies.CanManageRules, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Post, "/api/v1/admin/site-safety-rules/{ruleId}/disable", AdminPolicies.CanManageRules, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Post, "/api/v1/admin/site-safety-rules/{ruleId}/rollback", AdminPolicies.CanManageRules, AdminPolicies.RecentPrivilegedAuthentication),

        // Rules, AI, self-healing, and provider administration.
        Route(HttpMethods.Get, "/api/v1/rules", AdminPolicies.CanManageRules),
        Route(HttpMethods.Get, "/api/v1/rules/{id}", AdminPolicies.CanManageRules),
        Route(HttpMethods.Post, "/api/v1/rules/evaluate", AdminPolicies.CanManageRules),
        Route(HttpMethods.Post, "/api/v1/rules/simulate", AdminPolicies.CanManageRules),
        Route(HttpMethods.Get, "/api/v1/rules/simulations/{id}", AdminPolicies.CanManageRules),
        Route(HttpMethods.Post, "/api/v1/rules/{ruleId}/approval-workflows", AdminPolicies.CanManageRules),
        Route(HttpMethods.Get, "/api/v1/rules/approval-workflows/{workflowId}", AdminPolicies.CanManageRules),
        Route(HttpMethods.Post, "/api/v1/rules/approval-workflows/{workflowId}/approvals", AdminPolicies.CanManageRules, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Post, "/api/v1/rules/approval-workflows/{workflowId}/rollback-test", AdminPolicies.CanManageRules, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Post, "/api/v1/rules/approval-workflows/{workflowId}/manual-deployment", AdminPolicies.CanManageRules, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Post, "/api/v1/rules/approval-workflows/{workflowId}/activate", AdminPolicies.CanManageRules, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Get, "/api/v1/rules/deployments/{ruleId}", AdminPolicies.CanManageRules),
        Route(HttpMethods.Post, "/api/v1/rules/deployments/{ruleId}/rollback", AdminPolicies.CanManageRules, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Post, "/api/v1/rules/deployments/{ruleId}/promote", AdminPolicies.CanManageRules, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Post, "/api/v1/ai/analyze-url", AdminPolicies.CanManageRules),
        Route(HttpMethods.Post, "/api/v1/ai/analyze-content", AdminPolicies.CanManageRules),
        Route(HttpMethods.Post, "/api/v1/ai/suggest-rule", AdminPolicies.CanManageRules),
        Route(HttpMethods.Get, "/api/v1/ai/rule-drafts", AdminPolicies.CanManageRules),
        Route(HttpMethods.Get, "/api/v1/ai/rule-drafts/{draftId}", AdminPolicies.CanManageRules),
        Route(HttpMethods.Post, "/api/v1/ai/rule-drafts/{draftId}/submit-for-approval", AdminPolicies.CanManageRules, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Post, "/api/v1/self-healing/detect-patterns", AdminPolicies.CanManageRules),
        Route(HttpMethods.Post, "/api/v1/self-healing/generate-rule", AdminPolicies.CanManageRules),
        Route(HttpMethods.Get, "/api/v1/self-healing/suggestions", AdminPolicies.CanManageRules),
        Route(HttpMethods.Post, "/api/v1/self-healing/suggestions/{id}/approve", AdminPolicies.CanManageRules),
        Route(HttpMethods.Post, "/api/v1/self-healing/suggestions/{id}/reject", AdminPolicies.CanManageRules),
        Route(HttpMethods.Post, "/api/v1/admin/rules/simulate", AdminPolicies.CanManageRules),
        Route(HttpMethods.Post, "/api/v1/admin/self-healing/detect-patterns", AdminPolicies.CanManageRules),
        Route(HttpMethods.Post, "/api/v1/admin/self-healing/generate-rule", AdminPolicies.CanManageRules),
        Route(HttpMethods.Post, "/api/v1/admin/self-healing/analyze-findings", AdminPolicies.CanManageRules),
        Route(HttpMethods.Post, "/api/v1/site-safety/external-evidence/check", AdminPolicies.CanManageRules),
        Route(HttpMethods.Post, "/api/v1/site-safety/external-evidence/jobs", AdminPolicies.CanManageRules),
        Route(HttpMethods.Get, "/api/v1/site-safety/external-evidence/jobs/{jobId}", AdminPolicies.CanManageRules),
        Route(HttpMethods.Post, "/api/v1/admin/site-safety/external-providers", AdminPolicies.CanManageRules, AdminPolicies.RecentPrivilegedAuthentication),

        // Dashboard, platform, scan, and reputation administration: 13 (40 cumulative).
        Route(HttpMethods.Get, "/api/v1/admin/dashboard/summary", AdminPolicies.CanViewAdminDashboard),
        Route(HttpMethods.Get, "/api/v1/admin/dashboard/risky-domains", AdminPolicies.CanViewAdminDashboard),
        Route(HttpMethods.Get, "/api/v1/admin/dashboard/recent-scans", AdminPolicies.CanViewAdminDashboard),
        Route(HttpMethods.Get, "/api/v1/admin/scans/{scanId}", AdminPolicies.CanViewAdminDashboard),
        Route(HttpMethods.Get, "/api/v1/admin/platforms", AdminPolicies.CanViewAdminDashboard),
        Route(HttpMethods.Get, "/api/v1/admin/platforms/discord", AdminPolicies.CanViewAdminDashboard),
        Route(HttpMethods.Post, "/api/v1/admin/platforms/discord/connect", AdminPolicies.CanViewAdminDashboard, AdminPolicies.CanManagePlatforms, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Post, "/api/v1/admin/platforms/discord/disable", AdminPolicies.CanViewAdminDashboard, AdminPolicies.CanManagePlatforms, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Get, "/api/v1/admin/reputation/{targetType}/{targetId}", AdminPolicies.CanViewAdminDashboard),
        Route(HttpMethods.Post, "/api/v1/admin/reputation/events", AdminPolicies.CanViewAdminDashboard, AdminPolicies.CanManageReputation, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Post, "/api/v1/admin/reputation/{targetType}/{targetId}/recalculate", AdminPolicies.CanViewAdminDashboard, AdminPolicies.CanManageReputation, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Get, "/api/v1/admin/roles", AdminPolicies.CanViewAdminDashboard),
        Route(HttpMethods.Get, "/api/v1/admin/site-safety/external-providers", AdminPolicies.CanViewAdminDashboard),

        // Audit, review, appeal, and override workflows: 28 (68 cumulative).
        Route(HttpMethods.Get, "/api/v1/admin/audit-logs", AdminPolicies.CanViewAuditLogs),
        Route(HttpMethods.Get, "/api/v1/admin/audit/export", AdminPolicies.CanViewAuditLogs),
        Route(HttpMethods.Get, "/api/v1/admin/audit", AdminPolicies.CanViewAuditLogs),
        Route(HttpMethods.Post, "/api/v1/admin/audit/query", AdminPolicies.CanViewAuditLogs),
        Route(HttpMethods.Get, "/api/v1/admin/reports", AdminPolicies.CanViewReviews),
        Route(HttpMethods.Get, "/api/v1/admin/review", AdminPolicies.CanViewReviews),
        Route(HttpMethods.Get, "/api/v1/admin/review/{id}", AdminPolicies.CanViewReviews),
        Route(HttpMethods.Post, "/api/v1/admin/review", AdminPolicies.CanDecideReviews),
        Route(HttpMethods.Post, "/api/v1/admin/review/{id}/approve", AdminPolicies.CanDecideReviews),
        Route(HttpMethods.Post, "/api/v1/admin/review/{id}/reject", AdminPolicies.CanDecideReviews),
        Route(HttpMethods.Post, "/api/v1/admin/review/{id}/needs-more-info", AdminPolicies.CanDecideReviews),
        Route(HttpMethods.Post, "/api/v1/admin/review/{id}/decision", AdminPolicies.CanDecideReviews),
        Route(HttpMethods.Post, "/api/v1/admin/review/{id}/assign", AdminPolicies.CanDecideReviews),
        Route(HttpMethods.Get, "/api/v1/admin/review-queue", AdminPolicies.CanViewReviews),
        Route(HttpMethods.Get, "/api/v1/admin/review-queue/{id}", AdminPolicies.CanViewReviews),
        Route(HttpMethods.Post, "/api/v1/admin/review-queue/{id}/assign", AdminPolicies.CanDecideReviews),
        Route(HttpMethods.Post, "/api/v1/admin/review-queue/{id}/decision", AdminPolicies.CanDecideReviews),
        Route(HttpMethods.Post, "/api/v1/admin/review-queue/{id}/dismiss", AdminPolicies.CanDecideReviews),
        Route(HttpMethods.Get, "/api/v1/admin/appeals", AdminPolicies.CanViewAppeals),
        Route(HttpMethods.Get, "/api/v1/admin/appeals/{id}", AdminPolicies.CanViewAppeals),
        Route(HttpMethods.Post, "/api/v1/admin/appeals/{id}/approve", AdminPolicies.CanDecideAppeals),
        Route(HttpMethods.Post, "/api/v1/admin/appeals/{id}/reject", AdminPolicies.CanDecideAppeals),
        Route(HttpMethods.Post, "/api/v1/admin/appeals/{id}/needs-more-info", AdminPolicies.CanDecideAppeals),
        Route(HttpMethods.Post, "/api/v1/admin/appeals/{id}/decision", AdminPolicies.CanDecideAppeals),
        Route(HttpMethods.Get, "/api/v1/admin/reputation-overrides", AdminPolicies.CanApproveOverrides),
        Route(HttpMethods.Post, "/api/v1/admin/reputation-overrides", AdminPolicies.CanApproveOverrides, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Post, "/api/v1/admin/reputation-overrides/{id}/approve", AdminPolicies.CanApproveOverrides, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Post, "/api/v1/admin/reputation-overrides/{id}/reject", AdminPolicies.CanApproveOverrides, AdminPolicies.RecentPrivilegedAuthentication),

        // License and identity administration, including the human-only HUD simulator: 16 (83 cumulative).
        Route(HttpMethods.Post, "/api/v1/licenses/setup-codes", AdminPolicies.CanAdministerLicenses, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Get, "/api/v1/licenses", AdminPolicies.CanViewLicenses),
        Route(HttpMethods.Get, "/api/v1/licenses/{licenseId}", AdminPolicies.CanViewLicenses),
        Route(HttpMethods.Post, "/api/v1/licenses/{licenseId}/reset", AdminPolicies.CanSupportLicenses),
        Route(HttpMethods.Post, "/api/v1/licenses/{licenseId}/revoke", AdminPolicies.CanAdministerLicenses, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Post, "/api/v1/licenses/{licenseId}/suspend", AdminPolicies.CanAdministerLicenses, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Post, "/api/v1/licenses/{licenseId}/reactivate", AdminPolicies.CanAdministerLicenses, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Post, "/api/v1/sl-hud/simulate", AdminPolicies.CanSupportLicenses),
        Route(HttpMethods.Post, "/api/v1/identity/register", AdminPolicies.CanManageDomainVerifications),
        Route(HttpMethods.Post, "/api/v1/identity/websites/register", AdminPolicies.CanManageDomainVerifications),
        Route(HttpMethods.Post, "/api/v1/identity/websites/verify", AdminPolicies.CanManageDomainVerifications),
        Route(HttpMethods.Post, "/api/v1/identity/websites/{domain}/retry", AdminPolicies.CanManageDomainVerifications),
        Route(HttpMethods.Post, "/api/v1/identity/websites/{domain}/renew", AdminPolicies.CanManageDomainVerifications),
        Route(HttpMethods.Post, "/api/v1/identity/websites/{domain}/revoke", AdminPolicies.CanRevokeDomainVerifications, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Get, "/api/v1/identity/websites/{domain}/well-known-template", AdminPolicies.CanManageDomainVerifications),
        Route(HttpMethods.Post, "/api/v1/identity/domain-verification/start", AdminPolicies.CanManageDomainVerifications),
        Route(HttpMethods.Post, "/api/v1/identity/domain-verification/verify", AdminPolicies.CanManageDomainVerifications),
        Route(HttpMethods.Post, "/api/v1/identity/sign", AdminPolicies.CanManageDomainVerifications),

        // Device-authorized HUD routes: 5 (88 cumulative).
        Route(HttpMethods.Post, "/api/v1/sl-hud/scan", HudPolicies.CanUseActiveDevice),
        Route(HttpMethods.Get, "/api/v1/sl-hud/settings/{deviceId}", HudPolicies.CanUseActiveDevice),
        Route(HttpMethods.Post, "/api/v1/sl-hud/settings/{deviceId}", HudPolicies.CanUseActiveDevice),
        Route(HttpMethods.Post, "/api/v1/sl-hud/report", HudPolicies.CanUseActiveDevice),
        Route(HttpMethods.Post, "/api/v1/sl-hud/report-finding", HudPolicies.CanUseActiveDevice),

        // Service-client management: 4 (92 cumulative).
        Route(HttpMethods.Get, "/api/v1/admin/service-clients", AdminPolicies.CanViewServiceClients),
        Route(HttpMethods.Post, "/api/v1/admin/service-clients", AdminPolicies.CanManageServiceClients, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Post, "/api/v1/admin/service-clients/{clientId}/credentials/rotate", AdminPolicies.CanManageServiceClients, AdminPolicies.RecentPrivilegedAuthentication),
        Route(HttpMethods.Post, "/api/v1/admin/service-clients/{clientId}/revoke", AdminPolicies.CanManageServiceClients, AdminPolicies.RecentPrivilegedAuthentication),

        // Consumer portal APIs: 11 (103 cumulative).
        Route(HttpMethods.Get, "/api/v1/consumer/status", ConsumerPolicies.CanUseConsumerPortal),
        Route(HttpMethods.Get, "/api/v1/consumer/scans", ConsumerPolicies.CanUseConsumerPortal),
        Route(HttpMethods.Get, "/api/v1/consumer/reports", ConsumerPolicies.CanUseConsumerPortal),
        Route(HttpMethods.Get, "/api/v1/consumer/appeals", ConsumerPolicies.CanUseConsumerPortal),
        Route(HttpMethods.Post, "/api/v1/consumer/appeals", ConsumerPolicies.CanUseConsumerPortal),
        Route(HttpMethods.Get, "/api/v1/consumer/settings", ConsumerPolicies.CanUseConsumerPortal),
        Route(HttpMethods.Post, "/api/v1/consumer/settings", ConsumerPolicies.CanUseConsumerPortal),
        Route(HttpMethods.Post, "/api/v1/consumer/devices/registration-challenges", ConsumerPolicies.CanUseConsumerPortal),
        Route(HttpMethods.Post, "/api/v1/consumer/devices/registration-challenges/{challengeId}/responses", ConsumerPolicies.CanUseConsumerPortal),
        Route(HttpMethods.Get, "/api/v1/consumer/devices", ConsumerPolicies.CanUseConsumerPortal),
        Route(HttpMethods.Post, "/api/v1/consumer/devices/{deviceId}/revoke", ConsumerPolicies.CanUseConsumerPortal)
    ];

    /// <summary>
    /// Fails closed when a protected v1 route is added, removed, or assigned a different named policy set.
    /// </summary>
    [Test]
    public async Task Protected_v1_routes_match_the_exact_method_route_and_policy_manifest()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        var endpoints = ProtectedV1Endpoints(factory.Services);
        var violations = ManifestViolations(endpoints);

        Assert.That(
            violations,
            Is.Empty,
            $"Protected route manifest: {ProtectedRoutes.Length}; real protected endpoints: {endpoints.Length}." +
            Environment.NewLine + string.Join(Environment.NewLine, violations));
    }

    /// <summary>
    /// Exercises authorization and its real challenge/forbid response handler without invoking application handlers.
    /// </summary>
    [Test]
    public async Task Every_protected_v1_route_enforces_the_eight_principal_middleware_matrix()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        var endpoints = ProtectedV1Endpoints(factory.Services);
        var manifestViolations = ManifestViolations(endpoints);
        Assert.That(manifestViolations, Is.Empty, string.Join(Environment.NewLine, manifestViolations));

        var violations = new List<string>();

        foreach (var expectedRoute in ProtectedRoutes)
        {
            var endpoint = FindEndpoint(endpoints, expectedRoute);

            foreach (var principalKind in HumanPrincipals)
            {
                // Authentication handlers are scoped and cache their initialized HttpContext, so each synthetic
                // request needs the same fresh-scope boundary that ASP.NET Core supplies to a real request.
                using var requestScope = factory.Services.CreateScope();
                var requestServices = requestScope.ServiceProvider;
                var policy = await CombineEndpointPolicyAsync(requestServices, endpoint);
                Assert.That(policy, Is.Not.Null, expectedRoute.Key);
                var policyEvaluator = requestServices.GetRequiredService<IPolicyEvaluator>();
                var resultHandler = requestServices.GetRequiredService<IAuthorizationMiddlewareResultHandler>();
                var context = CreateHttpContext(requestServices, endpoint, expectedRoute, Principal(principalKind));
                var authentication = await policyEvaluator.AuthenticateAsync(policy!, context);
                var authorization = await policyEvaluator.AuthorizeAsync(policy!, authentication, context, context);
                var nextInvoked = false;
                await resultHandler.HandleAsync(
                    _ =>
                    {
                        nextInvoked = true;
                        return Task.CompletedTask;
                    },
                    context,
                    policy!,
                    authorization);

                AddOutcomeViolations(
                    violations,
                    expectedRoute,
                    principalKind,
                    authorization,
                    nextInvoked);
            }
        }

        Assert.That(
            violations,
            Is.Empty,
            $"Evaluated {ProtectedRoutes.Length * HumanPrincipals.Length} route/principal middleware outcomes." +
            Environment.NewLine + string.Join(Environment.NewLine, violations));
    }

    /// <summary>
    /// Proves every protected route returns API status codes rather than login or access-denied redirects.
    /// </summary>
    [Test]
    public async Task Every_protected_v1_route_returns_401_or_403_without_redirects()
    {
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = baseFactory.WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    // Authorization is the subject of this fixture; its 198 bounded requests must not share
                    // the production-oriented fixed-window budget and fail with an unrelated 429.
                    [$"{HipPerformanceOptions.SectionName}:IdentityRequestsPerMinute"] = "500",
                    [$"{HipPerformanceOptions.SectionName}:PublicScanRequestsPerMinute"] = "500",
                    [$"{HipPerformanceOptions.SectionName}:PublicFeedbackRequestsPerMinute"] = "500"
                })));
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        var violations = new List<string>();

        foreach (var route in ProtectedRoutes)
        {
            using (var anonymousRequest = CreateDeniedHttpRequest(route, authenticated: false))
            using (var anonymousResponse = await client.SendAsync(anonymousRequest))
            {
                AddHttpResponseViolations(
                    violations,
                    route,
                    "anonymous",
                    anonymousResponse,
                    HttpStatusCode.Unauthorized);
            }

            using (var authenticatedRequest = CreateDeniedHttpRequest(route, authenticated: true))
            using (var authenticatedResponse = await client.SendAsync(authenticatedRequest))
            {
                AddHttpResponseViolations(
                    violations,
                    route,
                    route.Policies.Contains(ConsumerPolicies.CanUseConsumerPortal, StringComparer.Ordinal)
                        ? "Admin without consumer identity"
                        : "Consumer without route authority",
                    authenticatedResponse,
                    HttpStatusCode.Forbidden);
            }
        }

        Assert.That(
            violations,
            Is.Empty,
            $"Evaluated {ProtectedRoutes.Length * 2} denied HTTP requests." +
            Environment.NewLine + string.Join(Environment.NewLine, violations));
    }

    /// <summary>
    /// Proves a valid active-device credential succeeds against one real HUD route while its handler remains uncalled.
    /// </summary>
    [Test]
    public async Task Active_device_credential_succeeds_through_a_real_HUD_route_policy()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var scope = factory.Services.CreateScope();
        var expectedRoute = ProtectedRoutes.Single(route =>
            route.Method == HttpMethods.Get &&
            route.Pattern == "/api/v1/sl-hud/settings/{deviceId}");
        var endpoint = FindEndpoint(ProtectedV1Endpoints(factory.Services), expectedRoute);
        var licenses = scope.ServiceProvider.GetRequiredService<ISetupCodeLicenseService>();
        var credentials = scope.ServiceProvider.GetRequiredService<IHudDeviceCredentialService>();
        var setup = licenses.CreateSetupCode(new CreateSetupCodeRequest(1, "route-closure-owner", "Normal"));
        var deviceId = $"route-closure-{Guid.NewGuid():N}";
        var activation = licenses.ActivateHud(setup.SetupCode, deviceId, avatarIdHash: null, hudVersion: "route-closure");
        Assert.That(activation.Activated, Is.True);

        var context = CreateHttpContext(
            scope.ServiceProvider,
            endpoint,
            expectedRoute,
            Principal(PrincipalKind.Anonymous));
        context.Request.RouteValues["deviceId"] = deviceId;
        context.Request.Headers[HudPolicies.DeviceCredentialHeader] = credentials.Issue(setup.LicenseId, deviceId);

        var policy = await CombineEndpointPolicyAsync(scope.ServiceProvider, endpoint);
        Assert.That(policy, Is.Not.Null);
        var evaluator = scope.ServiceProvider.GetRequiredService<IPolicyEvaluator>();
        var authentication = await evaluator.AuthenticateAsync(policy!, context);
        var authorization = await evaluator.AuthorizeAsync(policy!, authentication, context, context);
        var nextInvoked = false;
        await scope.ServiceProvider.GetRequiredService<IAuthorizationMiddlewareResultHandler>().HandleAsync(
            _ =>
            {
                nextInvoked = true;
                return Task.CompletedTask;
            },
            context,
            policy!,
            authorization);

        Assert.Multiple(() =>
        {
            Assert.That(authorization.Succeeded, Is.True);
            Assert.That(nextInvoked, Is.True, "Authorization should call only the supplied no-op continuation.");
            Assert.That(context.Response.StatusCode, Is.EqualTo(StatusCodes.Status200OK));
            Assert.That(context.Response.Headers.Location.ToString(), Is.Empty);
        });
    }

    private static List<string> ManifestViolations(IReadOnlyCollection<RouteEndpoint> endpoints)
    {
        var violations = new List<string>();
        if (ProtectedRoutes.Length != ExpectedProtectedRouteCount)
        {
            violations.Add($"Manifest has {ProtectedRoutes.Length} routes; expected {ExpectedProtectedRouteCount}.");
        }

        foreach (var duplicate in ProtectedRoutes.GroupBy(route => route.Key).Where(group => group.Count() != 1))
        {
            violations.Add($"Manifest key {duplicate.Key} appears {duplicate.Count()} times.");
        }

        if (endpoints.Count != ExpectedProtectedRouteCount)
        {
            violations.Add($"Runtime exposes {endpoints.Count} protected /api/v1 endpoints; expected {ExpectedProtectedRouteCount}.");
        }

        var actualBindings = endpoints
            .SelectMany(endpoint => Methods(endpoint).Select(method => new EndpointBinding(method, endpoint)))
            .ToArray();
        foreach (var endpoint in endpoints.Where(endpoint => Methods(endpoint).Length != 1))
        {
            violations.Add($"Protected endpoint {NormalizeRoute(endpoint.RoutePattern.RawText)} has methods [{string.Join(", ", Methods(endpoint))}].");
        }

        var expectedKeys = ProtectedRoutes.Select(route => route.Key).ToHashSet(StringComparer.Ordinal);
        var actualKeys = actualBindings.Select(binding => binding.Key).ToHashSet(StringComparer.Ordinal);
        foreach (var missing in expectedKeys.Except(actualKeys, StringComparer.Ordinal).Order(StringComparer.Ordinal))
        {
            violations.Add($"Manifest route is missing at runtime: {missing}.");
        }

        foreach (var unexpected in actualKeys.Except(expectedKeys, StringComparer.Ordinal).Order(StringComparer.Ordinal))
        {
            violations.Add($"Runtime protected route is absent from manifest: {unexpected}.");
        }

        foreach (var expected in ProtectedRoutes)
        {
            var matches = actualBindings.Where(binding => binding.Key == expected.Key).ToArray();
            if (matches.Length != 1)
            {
                if (matches.Length > 1)
                {
                    violations.Add($"Runtime route {expected.Key} resolves to {matches.Length} endpoints.");
                }

                continue;
            }

            var endpoint = matches[0].Endpoint;
            var authorization = endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>();
            var directPolicies = endpoint.Metadata.GetOrderedMetadata<AuthorizationPolicy>();
            var policies = authorization.Select(item => item.Policy).ToArray();
            if (policies.Any(string.IsNullOrWhiteSpace))
            {
                violations.Add($"{expected.Key} contains unnamed authorization metadata.");
            }

            if (directPolicies.Count > 0)
            {
                violations.Add($"{expected.Key} contains {directPolicies.Count} direct authorization policies instead of named policy metadata.");
            }

            var namedPolicies = policies.Where(policy => !string.IsNullOrWhiteSpace(policy)).Cast<string>().ToArray();
            if (!namedPolicies.Order(StringComparer.Ordinal).SequenceEqual(expected.Policies.Order(StringComparer.Ordinal), StringComparer.Ordinal))
            {
                violations.Add(
                    $"{expected.Key} policies are [{string.Join(", ", namedPolicies)}]; " +
                    $"expected [{string.Join(", ", expected.Policies)}].");
            }

            if (endpoint.Metadata.GetMetadata<IAllowAnonymous>() is not null)
            {
                violations.Add($"{expected.Key} combines a protected policy with AllowAnonymous.");
            }
        }

        foreach (var policy in ProtectedRoutes.SelectMany(route => route.Policies).Distinct(StringComparer.Ordinal))
        {
            if (!AllowedPrincipalsByPolicy.ContainsKey(policy))
            {
                violations.Add($"Route policy {policy} has no principal expectation.");
            }
        }

        return violations;
    }

    private static void AddOutcomeViolations(
        ICollection<string> violations,
        ProtectedRoute route,
        PrincipalKind principalKind,
        PolicyAuthorizationResult authorization,
        bool nextInvoked)
    {
        var expectedAllowed = route.Policies.All(policy => AllowedPrincipalsByPolicy[policy].Contains(principalKind));
        var expectedAuthorizationState = expectedAllowed
            ? authorization.Succeeded
            : principalKind == PrincipalKind.Anonymous
                ? authorization.Challenged
                : authorization.Forbidden;

        if (!expectedAuthorizationState || nextInvoked != expectedAllowed)
        {
            violations.Add(
                $"{route.Key} for {principalKind}: " +
                $"succeeded={authorization.Succeeded}, challenged={authorization.Challenged}, " +
                $"forbidden={authorization.Forbidden}, next={nextInvoked}; " +
                $"expected {(expectedAllowed ? "allow" : principalKind == PrincipalKind.Anonymous ? "challenge" : "forbid")}.");
        }
    }

    private static HttpRequestMessage CreateDeniedHttpRequest(ProtectedRoute route, bool authenticated)
    {
        var request = new HttpRequestMessage(
            new HttpMethod(route.Method),
            Regex.Replace(NormalizeRoute(route.Pattern), "\\{[^}]+\\}", "matrix-value"));
        if (!authenticated)
        {
            return request;
        }

        if (route.Policies.Contains(ConsumerPolicies.CanUseConsumerPortal, StringComparer.Ordinal))
        {
            request.Headers.Add(HipDevHeaderAuthenticationHandler.RoleHeaderName, AdminRoles.Admin);
            request.Headers.Add(HipDevHeaderAuthenticationHandler.UserHeaderName, "route-closure-admin");
        }
        else
        {
            request.Headers.Add(HipDevHeaderAuthenticationHandler.ConsumerHeaderName, "route-closure-consumer");
        }

        return request;
    }

    private static void AddHttpResponseViolations(
        ICollection<string> violations,
        ProtectedRoute route,
        string principal,
        HttpResponseMessage response,
        HttpStatusCode expectedStatus)
    {
        if (response.StatusCode != expectedStatus)
        {
            violations.Add(
                $"{route.Key} for {principal} returned {(int)response.StatusCode}; " +
                $"expected {(int)expectedStatus}.");
        }

        if (response.Headers.Location is not null)
        {
            violations.Add($"{route.Key} for {principal} redirected to {response.Headers.Location}.");
        }
    }

    private static DefaultHttpContext CreateHttpContext(
        IServiceProvider services,
        RouteEndpoint endpoint,
        ProtectedRoute route,
        ClaimsPrincipal principal)
    {
        var context = new DefaultHttpContext
        {
            RequestServices = services,
            User = principal
        };
        context.Connection.RemoteIpAddress = IPAddress.Loopback;
        context.Request.Scheme = "http";
        context.Request.Host = new HostString("localhost");
        context.Request.Method = route.Method;
        context.Request.Path = Regex.Replace(NormalizeRoute(route.Pattern), "\\{[^}]+\\}", "matrix-value");
        context.SetEndpoint(endpoint);
        return context;
    }

    private static RouteEndpoint[] ProtectedV1Endpoints(IServiceProvider services) =>
        services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Where(endpoint => IsV1Route(endpoint.RoutePattern.RawText))
            .Where(endpoint =>
                endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>().Count > 0 ||
                endpoint.Metadata.GetOrderedMetadata<AuthorizationPolicy>().Count > 0)
            .OrderBy(endpoint => NormalizeRoute(endpoint.RoutePattern.RawText), StringComparer.Ordinal)
            .ThenBy(endpoint => string.Join(',', Methods(endpoint)), StringComparer.Ordinal)
            .ToArray();

    private static Task<AuthorizationPolicy?> CombineEndpointPolicyAsync(
        IServiceProvider services,
        RouteEndpoint endpoint) =>
        AuthorizationPolicy.CombineAsync(
            services.GetRequiredService<IAuthorizationPolicyProvider>(),
            endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>(),
            endpoint.Metadata.GetOrderedMetadata<AuthorizationPolicy>());

    private static RouteEndpoint FindEndpoint(IEnumerable<RouteEndpoint> endpoints, ProtectedRoute route) =>
        endpoints.Single(endpoint =>
            NormalizeRoute(endpoint.RoutePattern.RawText) == NormalizeRoute(route.Pattern) &&
            Methods(endpoint).Contains(route.Method, StringComparer.OrdinalIgnoreCase));

    private static string[] Methods(RouteEndpoint endpoint) =>
        endpoint.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods.ToArray() ?? [];

    private static bool IsV1Route(string? route)
    {
        var normalized = NormalizeRoute(route);
        return normalized == "/api/v1" || normalized.StartsWith("/api/v1/", StringComparison.Ordinal);
    }

    private static string NormalizeRoute(string? route) =>
        $"/{(route ?? string.Empty).Trim().Trim('/')}";

    private static ProtectedRoute Route(string method, string pattern, params string[] policies) =>
        new(method, NormalizeRoute(pattern), policies);

    private static IReadOnlySet<PrincipalKind> Allowed(params PrincipalKind[] principals) =>
        new HashSet<PrincipalKind>(principals);

    private static ClaimsPrincipal Principal(PrincipalKind principalKind)
    {
        if (principalKind == PrincipalKind.Anonymous)
        {
            return new ClaimsPrincipal(new ClaimsIdentity());
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, $"route-closure-{principalKind.ToString().ToLowerInvariant()}")
        };
        if (principalKind == PrincipalKind.Consumer)
        {
            claims.Add(new Claim(HipAuthenticationClaimTypes.ConsumerId, "route-closure-consumer"));
        }
        else
        {
            claims.Add(new Claim(HipAuthenticationClaimTypes.ActorId, "route-closure-actor"));
            if (principalKind != PrincipalKind.AuthenticatedActorWithoutRole)
            {
                claims.Add(new Claim(ClaimTypes.Role, Role(principalKind)));
            }
        }

        return new ClaimsPrincipal(new ClaimsIdentity(
            claims,
            authenticationType: "HIP.RouteClosure",
            nameType: ClaimTypes.NameIdentifier,
            roleType: ClaimTypes.Role));
    }

    private static string Role(PrincipalKind principalKind) => principalKind switch
    {
        PrincipalKind.Owner => AdminRoles.Owner,
        PrincipalKind.Admin => AdminRoles.Admin,
        PrincipalKind.Moderator => AdminRoles.Moderator,
        PrincipalKind.Support => AdminRoles.Support,
        PrincipalKind.ReadOnly => AdminRoles.ReadOnly,
        _ => throw new ArgumentOutOfRangeException(nameof(principalKind), principalKind, "Principal is not an admin role.")
    };

    private sealed record ProtectedRoute(string Method, string Pattern, string[] Policies)
    {
        public string Key => $"{Method.ToUpperInvariant()} {NormalizeRoute(Pattern)}";
    }

    private sealed record EndpointBinding(string Method, RouteEndpoint Endpoint)
    {
        public string Key => $"{Method.ToUpperInvariant()} {NormalizeRoute(Endpoint.RoutePattern.RawText)}";
    }

    /// <summary>Names the eight human principal shapes exercised at every protected route.</summary>
    private enum PrincipalKind
    {
        Owner,
        Admin,
        Moderator,
        Support,
        ReadOnly,
        Consumer,
        AuthenticatedActorWithoutRole,
        Anonymous
    }
}
