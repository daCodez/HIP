namespace HIP.Tests.Performance;

/// <summary>
/// Verifies HIP's host-level performance foundation stays wired for scalable local and production deployments.
/// </summary>
public sealed class PerformanceFoundationTests
{
    /// <summary>
    /// Confirms both public hosts can use Aspire's Redis-backed ASP.NET Core output cache when Redis is available.
    /// </summary>
    [Test]
    public void Public_hosts_reference_aspire_redis_output_cache_package()
    {
        var apiProject = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.ApiService", "HIP.ApiService.csproj"));
        var webProject = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.Web", "HIP.Web.csproj"));

        Assert.That(apiProject, Does.Contain("Aspire.StackExchange.Redis.OutputCaching"));
        Assert.That(webProject, Does.Contain("Aspire.StackExchange.Redis.OutputCaching"));
    }

    /// <summary>
    /// Confirms public lookup and badge endpoints opt into named output-cache policies.
    /// </summary>
    [Test]
    public void Public_lookup_and_badge_endpoints_use_named_output_cache_policies()
    {
        var apiProgram = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.ApiService", "Program.cs"));
        var webProgram = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.Web", "Program.cs"));

        Assert.That(apiProgram, Does.Contain("AddRedisOutputCache(\"redis\")"));
        Assert.That(apiProgram, Does.Contain("AddOutputCache"));
        Assert.That(apiProgram, Does.Contain("UseOutputCache"));
        Assert.That(apiProgram, Does.Contain(".CacheOutput(HipOutputCachePolicies.PublicLookup)"));
        Assert.That(apiProgram, Does.Contain(".CacheOutput(HipOutputCachePolicies.Badge)"));
        Assert.That(webProgram, Does.Contain("AddRedisOutputCache(\"redis\")"));
        Assert.That(webProgram, Does.Contain("AddOutputCache"));
        Assert.That(webProgram, Does.Contain("UseOutputCache"));
        Assert.That(webProgram, Does.Contain(".CacheOutput(HipOutputCachePolicies.PublicLookup)"));
        Assert.That(webProgram, Does.Contain(".CacheOutput(HipOutputCachePolicies.Badge)"));
    }

    /// <summary>
    /// Confirms HIP compresses high-volume public JSON, badge scripts, and static web assets.
    /// </summary>
    [Test]
    public void Public_hosts_enable_response_compression()
    {
        var apiProgram = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.ApiService", "Program.cs"));
        var webProgram = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.Web", "Program.cs"));

        Assert.That(apiProgram, Does.Contain("AddResponseCompression"));
        Assert.That(apiProgram, Does.Contain("UseResponseCompression"));
        Assert.That(webProgram, Does.Contain("AddResponseCompression"));
        Assert.That(webProgram, Does.Contain("UseResponseCompression"));
    }

    /// <summary>
    /// Confirms public write limits are partitioned by privacy-safe client identity rather than one global bucket.
    /// </summary>
    [Test]
    public void Public_rate_limits_use_partitioned_privacy_safe_keys()
    {
        var apiProgram = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.ApiService", "Program.cs"));
        var webProgram = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.Web", "Program.cs"));

        Assert.That(apiProgram, Does.Contain("CreateFixedWindowPartition"));
        Assert.That(apiProgram, Does.Contain("ResolveRateLimitPartitionKey"));
        Assert.That(apiProgram, Does.Contain("X-HIP-API-Key"));
        Assert.That(apiProgram, Does.Contain("X-HIP-Signer"));
        Assert.That(apiProgram, Does.Contain("X-HIP-Instance-Id"));
        Assert.That(webProgram, Does.Contain("CreateFixedWindowPartition"));
        Assert.That(webProgram, Does.Contain("ResolveRateLimitPartitionKey"));
        Assert.That(webProgram, Does.Contain("X-HIP-API-Key"));
        Assert.That(webProgram, Does.Contain("X-HIP-Signer"));
        Assert.That(webProgram, Does.Contain("X-HIP-Instance-Id"));
    }

    /// <summary>
    /// Confirms Aspire supplies Redis to both API and Web so distributed caching can work locally.
    /// </summary>
    [Test]
    public void Aspire_supplies_redis_to_api_and_web_hosts()
    {
        var appHost = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.AppHost", "Program.cs"));

        Assert.That(appHost, Does.Contain("WithReference(redis)"));
        Assert.That(appHost, Does.Contain("WaitFor(redis)"));
        Assert.That(appHost, Does.Contain("AddProject<Projects.HIP_Web>"));
    }

    /// <summary>
    /// Confirms cache durations and request limits are exposed through bindable options.
    /// </summary>
    [Test]
    public void Performance_options_are_configurable_and_validated()
    {
        var options = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.Application", "Performance", "HipPerformanceOptions.cs"));
        var apiSettings = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.ApiService", "appsettings.json"));
        var webSettings = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.Web", "appsettings.json"));

        Assert.That(options, Does.Contain("public sealed class HipPerformanceOptions"));
        Assert.That(options, Does.Contain("UseRedisOutputCacheWhenAvailable"));
        Assert.That(apiSettings, Does.Contain("\"HipPerformance\""));
        Assert.That(webSettings, Does.Contain("\"HipPerformance\""));
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
