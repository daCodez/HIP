namespace HIP.Tests.Infrastructure;

public sealed class DevelopmentCertificateSchemaTests
{
    [Test]
    public void Development_schema_repairs_pre_certificate_local_databases_additively()
    {
        var schema = File.ReadAllText(Path.Combine(
            RepositoryRoot(),
            "src",
            "HIP.Infrastructure",
            "Persistence",
            "HipDevelopmentCertificateSchema.cs"));

        Assert.Multiple(() =>
        {
            Assert.That(schema, Does.Contain("CREATE TABLE IF NOT EXISTS hip_domain_enrollments"));
            Assert.That(schema, Does.Contain("CREATE TABLE IF NOT EXISTS hip_domain_certificates"));
            Assert.That(schema, Does.Contain("CREATE TABLE IF NOT EXISTS hip_domain_certificate_events"));
            Assert.That(schema, Does.Contain("ADD COLUMN IF NOT EXISTS \"SignedCertificateJson\""));
            Assert.That(schema, Does.Contain("ADD COLUMN IF NOT EXISTS \"SecurityContactHash\""));
            Assert.That(schema, Does.Contain("CREATE UNIQUE INDEX IF NOT EXISTS \"IX_hip_domain_certificates_Domain\""));
        });
    }

    [Test]
    public void Development_initializer_invokes_certificate_schema_repair()
    {
        var initializer = File.ReadAllText(Path.Combine(
            RepositoryRoot(),
            "src",
            "HIP.Infrastructure",
            "Persistence",
            "HipDatabaseInitializer.cs"));

        Assert.That(
            initializer,
            Does.Contain("await HipDevelopmentCertificateSchema.EnsureAsync(dbContext, cancellationToken);"));
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
