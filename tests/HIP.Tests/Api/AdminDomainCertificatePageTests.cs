using System.Runtime.CompilerServices;

namespace HIP.Tests.Api;

public sealed class AdminDomainCertificatePageTests
{
    private static readonly string SourceDirectory = Path.GetDirectoryName(SourceFilePath())!;

    [Test]
    public void Admin_certificate_operations_page_is_role_protected_and_uses_persisted_state()
    {
        var page = File.ReadAllText(WorkspaceFile(
            "src", "HIP.Web", "Components", "Pages", "AdminDomainCertificates.razor"));
        var navigation = File.ReadAllText(WorkspaceFile(
            "src", "HIP.Web", "Components", "Layout", "ControlCenterNav.razor"));

        Assert.Multiple(() =>
        {
            Assert.That(page, Does.Contain("@page \"/admin/certificates\""));
            Assert.That(page, Does.Contain("Authorize(Policy = AdminPolicies.CanViewReviews)"));
            Assert.That(page, Does.Contain("IDomainCertificateAdminQuery"));
            Assert.That(page, Does.Contain("Pending certificate reviews"));
            Assert.That(page, Does.Contain("Failed verification attempts"));
            Assert.That(page, Does.Contain("Recently issued certificates"));
            Assert.That(page, Does.Contain("Recently revoked certificates"));
            Assert.That(page, Does.Contain("Policy version"));
            Assert.That(page, Does.Not.Contain("OwnerId"));
            Assert.That(navigation, Does.Contain("href=\"admin/certificates\""));
            Assert.That(navigation, Does.Contain("Policy=\"@AdminPolicies.CanViewReviews\""));
        });
    }

    private static string WorkspaceFile(params string[] parts)
    {
        foreach (var startPath in new[]
                 {
                     SourceDirectory,
                     Directory.GetCurrentDirectory(),
                     TestContext.CurrentContext.WorkDirectory,
                     TestContext.CurrentContext.TestDirectory
                 })
        {
            var current = new DirectoryInfo(startPath);
            while (current is not null)
            {
                var candidate = Path.Combine([current.FullName, .. parts]);
                if (File.Exists(candidate))
                {
                    return candidate;
                }

                current = current.Parent;
            }
        }

        throw new FileNotFoundException($"Could not locate {Path.Combine(parts)}.");
    }

    private static string SourceFilePath([CallerFilePath] string sourceFilePath = "") => sourceFilePath;
}
