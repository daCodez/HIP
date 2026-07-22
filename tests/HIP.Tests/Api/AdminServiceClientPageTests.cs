using System.Net;
using HIP.Application.ServiceClients;
using HIP.Domain.ServiceClients;
using HIP.Web.Security;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HIP.Tests.Api;

/// <summary>Guards the real service-client management UI against placeholder or secret-retention regressions.</summary>
[TestFixture]
public sealed class AdminServiceClientPageTests
{
    [Test]
    public async Task Admin_page_renders_real_least_privilege_controls_and_owner_scoped_inventory()
    {
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = baseFactory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IServiceClientLifecycleService>();
                services.AddSingleton<IServiceClientLifecycleService>(new PageLifecycleService());
            }));
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.RoleHeaderName, AdminRoles.Owner);
        client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.UserHeaderName, "page-service-client-owner");

        using var response = await client.GetAsync("/admin/api");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(html, Does.Contain("Integrate HIP into your own tools"));
            Assert.That(html, Does.Contain("Create service client"));
            Assert.That(html, Does.Contain(ServiceClientScopeValues.DomainVerificationCheck));
            Assert.That(html, Does.Contain(ServiceClientScopeValues.SiteSafetyExternalEvidenceCheck));
            Assert.That(html, Does.Contain("Exact domain grants"));
            Assert.That(html, Does.Contain("DNS worker"));
            Assert.That(html, Does.Contain("example.test"));
            Assert.That(html, Does.Contain("Rotate credential"));
            Assert.That(html, Does.Contain("Revoke"));
            Assert.That(html, Does.Contain("least privilege").IgnoreCase);
            Assert.That(html, Does.Contain("does not prove safety").IgnoreCase);
            Assert.That(html, Does.Not.Contain("Development placeholder"));
            Assert.That(html, Does.Not.Contain("API key management not connected"));
            Assert.That(html, Does.Not.Contain("fake token").IgnoreCase);
        });
    }

    [Test]
    public void Page_source_reauthorizes_mutations_and_never_persists_or_logs_the_one_time_credential()
    {
        var root = RepositoryRoot();
        var markup = File.ReadAllText(Path.Combine(
            root, "src", "HIP.Web", "Components", "Pages", "AdminApiDeveloper.razor"));
        var logic = File.ReadAllText(Path.Combine(
            root, "src", "HIP.Web", "Components", "Pages", "AdminApiDeveloper.razor.cs"));
        var styles = File.ReadAllText(Path.Combine(
            root, "src", "HIP.Web", "Components", "Pages", "AdminApiDeveloper.razor.css"));
        var source = string.Concat(markup, Environment.NewLine, logic);

        Assert.Multiple(() =>
        {
            Assert.That(markup, Does.Contain("Authorize(Policy = AdminPolicies.CanViewServiceClients)"));
            Assert.That(source, Does.Contain("IServiceClientLifecycleService"));
            Assert.That(source, Does.Contain("AuthenticationStateProvider"));
            Assert.That(source, Does.Contain("IAuthorizationService"));
            Assert.That(source, Does.Contain("HipAdminPageAccess.ExecuteAuthorizedAsync"));
            Assert.That(source, Does.Contain("AdminPolicies.CanManageServiceClients"));
            Assert.That(source, Does.Contain("AdminPolicies.RecentPrivilegedAuthentication"));
            Assert.That(source, Does.Contain("ServiceClientLifecycleOutcome.Throttled"));
            Assert.That(source, Does.Contain("ServiceClientLifecycleMessages.Throttled"));
            Assert.That(source, Does.Contain("LifecycleService.CreateAsync(actor, actor"));
            Assert.That(source, Does.Contain("LifecycleService.RotateCredentialAsync(actor, actor"));
            Assert.That(source, Does.Contain("LifecycleService.RevokeAsync(actor, actor"));
            Assert.That(markup, Does.Contain("Dismiss credential"));
            Assert.That(markup, Does.Contain("one-time").IgnoreCase);
            Assert.That(markup, Does.Contain("Confirm identity"));
            Assert.That(logic, Does.Contain("/step-up?returnUrl=%2Fadmin%2Fapi"));
            Assert.That(styles, Does.Contain("user-select: all"));
            Assert.That(source, Does.Not.Contain("IAdminDashboardService"));
            Assert.That(source, Does.Not.Contain("DashboardService"));
            Assert.That(source, Does.Not.Contain("localStorage"));
            Assert.That(source, Does.Not.Contain("sessionStorage"));
            Assert.That(source, Does.Not.Contain("Console."));
            Assert.That(source, Does.Not.Contain("Logger"));
            Assert.That(source, Does.Not.Contain("fake token").IgnoreCase);
            Assert.That(source, Does.Not.Contain("Development placeholder"));
        });
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new DirectoryNotFoundException("Could not locate HIP repository root.");
    }

    private sealed class PageLifecycleService : IServiceClientLifecycleService
    {
        private static readonly ServiceClientResponse Client = new(
            "hipc_v1_AAAAAAAAAAAAAAAAAAAAAA",
            "DNS worker",
            ServiceClientScopeValues.DomainVerificationCheck,
            ["example.test"],
            ServiceClientStatus.Active,
            2,
            4,
            new DateTimeOffset(2026, 7, 1, 12, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 7, 10, 12, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 10, 1, 12, 0, 0, TimeSpan.Zero),
            null);

        public Task<ServiceClientCreateResult> CreateAsync(
            string actorId,
            string ownerId,
            CreateServiceClientRequest request,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<ServiceClientListResult> ListAsync(
            string ownerId,
            string? cursor,
            int pageSize,
            CancellationToken cancellationToken) =>
            Task.FromResult(new ServiceClientListResult(
                ServiceClientLifecycleOutcome.Succeeded,
                ServiceClientLifecycleMessages.Succeeded,
                [Client]));

        public Task<ServiceClientRotationResult> RotateCredentialAsync(
            string actorId,
            string ownerId,
            string clientId,
            long expectedAggregateVersion,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<ServiceClientRevocationResult> RevokeAsync(
            string actorId,
            string ownerId,
            string clientId,
            long expectedAggregateVersion,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
