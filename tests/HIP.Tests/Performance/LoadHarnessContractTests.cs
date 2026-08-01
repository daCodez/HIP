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
