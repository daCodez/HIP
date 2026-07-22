namespace HIP.Tests.Security;

public sealed class ProductionRunbookDocumentationTests
{
    [Test]
    public void Deployment_runbook_has_staging_production_migration_secret_and_rollback_gates()
    {
        var deployment = Read("deployment.md");
        Assert.Multiple(() =>
        {
            Assert.That(deployment, Does.Contain("## Staging deployment"));
            Assert.That(deployment, Does.Contain("## Production deployment"));
            Assert.That(deployment, Does.Contain("## Secrets and configuration"));
            Assert.That(deployment, Does.Contain("Run reviewed EF migrations as a separate least-privilege job"));
            Assert.That(deployment, Does.Contain("## Rollback"));
            Assert.That(deployment, Does.Contain("Never restore an old database over the current production database"));
        });
    }

    [Test]
    public void Incident_runbook_covers_severity_containment_evidence_recovery_and_exercises()
    {
        var incident = Read("incident-response.md");
        Assert.Multiple(() =>
        {
            Assert.That(incident, Does.Contain("## Severity"));
            Assert.That(incident, Does.Contain("## First 15 minutes"));
            Assert.That(incident, Does.Contain("## Investigation and containment"));
            Assert.That(incident, Does.Contain("## Communications"));
            Assert.That(incident, Does.Contain("## Recovery"));
            Assert.That(incident, Does.Contain("## Practice schedule"));
        });
    }

    private static string Read(string fileName) => File.ReadAllText(Path.Combine(FindRepositoryRoot(), "docs", fileName));

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
