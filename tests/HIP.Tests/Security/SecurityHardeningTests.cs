namespace HIP.Tests.Security;

/// <summary>
/// Verifies high-risk security and scalability guardrails stay visible in host configuration.
/// </summary>
public sealed class SecurityHardeningTests
{
    /// <summary>
    /// Confirms public read CORS is separated from privacy-safe client write CORS.
    /// </summary>
    [Test]
    public void Public_cors_policies_split_read_and_write_surfaces()
    {
        var apiProgram = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.ApiService", "Program.cs"));
        var webProgram = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.Web", "Program.cs"));
        var securityOptions = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.Application", "Security", "HipSecurityOptions.cs"));

        Assert.That(securityOptions, Does.Contain("PublicRead"));
        Assert.That(securityOptions, Does.Contain("ClientWrite"));
        Assert.That(apiProgram, Does.Contain("WithMethods(\"GET\")"));
        Assert.That(apiProgram, Does.Contain("RequireCors(HipCorsPolicies.ClientWrite)"));
        Assert.That(webProgram, Does.Contain("WithMethods(\"GET\")"));
        Assert.That(webProgram, Does.Contain("RequireCors(HipCorsPolicies.ClientWrite)"));
    }

    /// <summary>
    /// Confirms unauthenticated client provider preference writes are disabled unless a host opts in.
    /// </summary>
    [Test]
    public void Client_provider_preference_writes_are_disabled_by_default()
    {
        var apiSettings = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.ApiService", "appsettings.json"));
        var webSettings = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.Web", "appsettings.json"));
        var apiProgram = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.ApiService", "Program.cs"));

        Assert.That(apiSettings, Does.Contain("\"AllowClientProviderPreferenceWrites\": false"));
        Assert.That(webSettings, Does.Contain("\"AllowClientProviderPreferenceWrites\": false"));
        Assert.That(apiProgram, Does.Contain("Client provider preference writes are disabled"));
    }

    /// <summary>
    /// Confirms external providers do not run inline on public scan requests unless explicitly configured.
    /// </summary>
    [Test]
    public void External_providers_are_not_run_on_request_path_by_default()
    {
        var apiSettings = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.ApiService", "appsettings.json"));
        var webSettings = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.Web", "appsettings.json"));
        var scanner = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.Application", "SiteSafety", "SiteSafetyScanner.cs"));

        Assert.That(apiSettings, Does.Contain("\"RunExternalProvidersOnRequestPath\": false"));
        Assert.That(webSettings, Does.Contain("\"RunExternalProvidersOnRequestPath\": false"));
        Assert.That(scanner, Does.Contain("provider is not IExternalSiteEvidenceProvider"));
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
