namespace HIP.Tests.Infrastructure;

/// <summary>
/// Keeps all Aspire packages on the approved patch level.
/// </summary>
public sealed class AspirePackageAlignmentTests
{
    [Test]
    public void Aspire_packages_use_approved_13_4_patch_without_mixed_versions()
    {
        var root = RepositoryRoot();
        var projectFiles = new[]
        {
            Path.Combine(root, "src", "HIP.AppHost", "HIP.AppHost.csproj"),
            Path.Combine(root, "src", "HIP.ApiService", "HIP.ApiService.csproj"),
            Path.Combine(root, "src", "HIP.Web", "HIP.Web.csproj")
        };

        Assert.Multiple(() =>
        {
            foreach (var projectFile in projectFiles)
            {
                var project = File.ReadAllText(projectFile);
                Assert.That(project, Does.Not.Contain("13.4.2"), Path.GetFileName(projectFile));
                Assert.That(project, Does.Contain("13.4.6"), Path.GetFileName(projectFile));
            }
        });
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
