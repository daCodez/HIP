namespace HIP.Tests.Infrastructure;

/// <summary>
/// Verifies HIP local startup stays centered on Aspire instead of side-channel project launchers.
/// </summary>
public sealed class AspireAppHostFoundationTests
{
    /// <summary>
    /// Confirms the AppHost explicitly uses the HTTP launch profiles that expose stable local URLs.
    /// </summary>
    [Test]
    public void AppHost_uses_http_launch_profiles_for_api_and_web()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.AppHost", "Program.cs"));

        Assert.That(source, Does.Contain("AddProject<Projects.HIP_ApiService>(\"hip-api\", launchProfileName: \"http\")"));
        Assert.That(source, Does.Contain("AddProject<Projects.HIP_Web>(\"hip-web\", launchProfileName: \"http\")"));
        Assert.That(source, Does.Contain(".WithExternalHttpEndpoints()"));
        Assert.That(source, Does.Contain(".WaitFor(apiService)"));
    }

    /// <summary>
    /// Confirms the stable local ports are owned by the project launch profiles that Aspire consumes.
    /// </summary>
    [Test]
    public void Aspire_project_launch_profiles_expose_expected_local_ports()
    {
        var apiLaunchSettings = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.ApiService", "Properties", "launchSettings.json"));
        var webLaunchSettings = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.Web", "Properties", "launchSettings.json"));

        Assert.That(apiLaunchSettings, Does.Contain("\"applicationUrl\": \"http://localhost:5099\""));
        Assert.That(webLaunchSettings, Does.Contain("\"applicationUrl\": \"http://localhost:5123\""));
    }

    /// <summary>
    /// Confirms the solution no longer advertises a parallel local host runner as the normal startup path.
    /// </summary>
    [Test]
    public void Solution_does_not_include_parallel_localhost_runner()
    {
        var solution = File.ReadAllText(Path.Combine(RepositoryRoot(), "HIP.slnx"));
        var readme = File.ReadAllText(Path.Combine(RepositoryRoot(), "README.md"));

        Assert.That(solution, Does.Not.Contain("HIP.LocalHost"));
        Assert.That(readme, Does.Contain("set `HIP.AppHost` as the Visual Studio startup project"));
        Assert.That(readme, Does.Not.Contain("Docker-free local host"));
    }

    /// <summary>
    /// Resolves the repository root from the test output folder.
    /// </summary>
    /// <returns>Absolute repository root path.</returns>
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
