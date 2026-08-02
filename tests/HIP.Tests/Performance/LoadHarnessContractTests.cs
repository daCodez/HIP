namespace HIP.Tests.Performance;

public sealed class LoadHarnessContractTests
{
    [Test]
    public void Harness_covers_required_scenarios_thresholds_and_write_gate()
    {
        var script = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "eng", "load", "hip-load.mjs"));

        Assert.Multiple(() =>
        {
            Assert.That(script, Does.Contain("public-lookup-cached"));
            Assert.That(script, Does.Contain("browser-fast-score"));
            Assert.That(script, Does.Contain("public-feedback-write"));
            Assert.That(script, Does.Contain("admin-paged-list"));
            Assert.That(script, Does.Contain("HIP_LOAD_ENABLE_WRITES === '1'"));
            Assert.That(script, Does.Contain("HIP_LOAD_REQUESTS_PER_SECOND"));
            Assert.That(script, Does.Contain("HIP_LOAD_SCENARIOS"));
            Assert.That(script, Does.Contain("statusCodes"));
            Assert.That(script, Does.Contain("p95TargetMs"));
            Assert.That(script, Does.Not.Contain("console.log(response"));
        });
    }

    /// <summary>Production admin load uses a bounded file-backed cookie without printing the secret.</summary>
    [Test]
    public void Harness_supports_secret_safe_production_admin_authentication()
    {
        var script = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "eng", "load", "hip-load.mjs"));

        Assert.Multiple(() =>
        {
            Assert.That(script, Does.Contain("HIP_LOAD_AUTH_COOKIE_FILE"));
            Assert.That(script, Does.Contain("readFileSync(adminCookieFile, 'utf8')"));
            Assert.That(script, Does.Contain("throw new Error('Unable to read HIP_LOAD_AUTH_COOKIE_FILE.')"));
            Assert.That(script, Does.Contain("return { Cookie: cookie }"));
            Assert.That(script, Does.Not.Contain("console.log(cookie"));
            Assert.That(script, Does.Not.Contain("console.log(adminCookieFile"));
            Assert.That(script, Does.Not.Contain("process.stdout.write(adminCookieFile"));
        });
    }

    /// <summary>Development identity headers must never be sent to a remote staging or production target.</summary>
    [Test]
    public void Harness_limits_development_admin_headers_to_loopback_targets()
    {
        var script = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "eng", "load", "hip-load.mjs"));

        Assert.Multiple(() =>
        {
            Assert.That(script, Does.Contain("if (!isLoopbackBaseUrl())"));
            Assert.That(script, Does.Contain("Development admin headers are allowed only for a loopback load target."));
            Assert.That(script, Does.Contain("hostname === 'localhost'"));
            Assert.That(script, Does.Contain("hostname === '127.0.0.1'"));
            Assert.That(script, Does.Contain("hostname === '[::1]'"));
        });
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "HIP.slnx"))) return current.FullName;
            current = current.Parent;
        }
        throw new DirectoryNotFoundException("Could not locate HIP.slnx from the test output directory.");
    }
}
