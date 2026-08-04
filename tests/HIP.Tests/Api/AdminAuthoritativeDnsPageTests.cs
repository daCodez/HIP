namespace HIP.Tests.Api;

/// <summary>Locks the authoritative DNS admin page to the owner-only, step-up protected control plane.</summary>
public sealed class AdminAuthoritativeDnsPageTests
{
    [Test]
    public void Page_and_navigation_use_owner_only_authorization_and_real_service_state()
    {
        var root = FindRepositoryRoot();
        var page = File.ReadAllText(Path.Combine(root, "src", "HIP.Web", "Components", "Pages", "AdminAuthoritativeDns.razor"));
        var navigation = File.ReadAllText(Path.Combine(root, "src", "HIP.Web", "Components", "Layout", "ControlCenterNav.razor"));

        Assert.Multiple(() =>
        {
            Assert.That(page, Does.Contain("Authorize(Policy = AdminPolicies.CanManageAuthoritativeDns)"));
            Assert.That(page, Does.Contain("IAuthoritativeDnsManagementService"));
            Assert.That(page, Does.Contain("AdminPolicies.RecentPrivilegedAuthentication"));
            Assert.That(page, Does.Contain("HipAdminPageAccess.ExecuteAuthorizedAsync"));
            Assert.That(page, Does.Contain("id=\"dns-domain\" @bind=\"_domain\" @bind:event=\"oninput\""));
            Assert.That(page, Does.Contain("aria-label=\"Record value\" @bind=\"_records[rowIndex].Content\" @bind:event=\"oninput\""));
            Assert.That(page, Does.Not.Contain("IAdminDashboardService"));
            Assert.That(navigation, Does.Contain("Policy=\"@AdminPolicies.CanManageAuthoritativeDns\""));
            Assert.That(navigation, Does.Contain("href=\"/dns\""));
        });
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (current is not null && !File.Exists(Path.Combine(current.FullName, "HIP.sln")))
        {
            current = current.Parent;
        }

        return current?.FullName ?? throw new DirectoryNotFoundException("HIP repository root was not found.");
    }
}
