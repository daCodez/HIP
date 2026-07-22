namespace HIP.Tests.Security;

public sealed class ThreatModelDocumentationTests
{
    [Test]
    public void Threat_model_covers_required_assets_boundaries_controls_and_residual_risks()
    {
        var threatModel = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "docs", "threat-model.md"));

        Assert.Multiple(() =>
        {
            Assert.That(threatModel, Does.Contain("## Assets"));
            Assert.That(threatModel, Does.Contain("## Actors"));
            Assert.That(threatModel, Does.Contain("## Trust boundaries"));
            Assert.That(threatModel, Does.Contain("## Threats and controls"));
            Assert.That(threatModel, Does.Contain("SSRF and DNS rebinding"));
            Assert.That(threatModel, Does.Contain("Malicious page/container escape"));
            Assert.That(threatModel, Does.Contain("AI prompt injection or data leakage"));
            Assert.That(threatModel, Does.Contain("## Release gates and residual risk"));
            Assert.That(threatModel, Does.Contain("must never be represented as production-safe or post-quantum-ready"));
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
