using System.Text.Json;

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

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Contain("AddProject<Projects.HIP_ApiService>(\"hip-api\", launchProfileName: \"http\")"));
            Assert.That(source, Does.Contain("AddProject<Projects.HIP_Web>(\"hip-web\", launchProfileName: \"http\")"));
            Assert.That(source, Does.Contain(".WithExternalHttpEndpoints()"));
            Assert.That(source, Does.Contain(".WithUrlForEndpoint(\"http\", _ => new() { Url = \"/consumer\", DisplayText = \"Consumer\" })"));
            Assert.That(source, Does.Contain(".WithUrlForEndpoint(\"http\", _ => new() { Url = \"/admin\", DisplayText = \"Admin\" })"));
            Assert.That(source, Does.Contain(".WaitFor(apiService)"));
        });
    }

    /// <summary>
    /// Confirms Aspire declares real local container resources instead of relying on undocumented manual Docker setup.
    /// </summary>
    [Test]
    public void AppHost_declares_postgres_and_redis_container_resources()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.AppHost", "Program.cs"));
        var project = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.AppHost", "HIP.AppHost.csproj"));

        Assert.That(source, Does.Contain("AddPostgres(\"postgres\")"));
        Assert.That(source, Does.Contain("postgres.AddDatabase(\"HipDatabase\")"));
        Assert.That(source, Does.Contain("AddRedis(\"redis\")"));
        Assert.That(source, Does.Contain(".WithReference(hipDatabase)"));
        Assert.That(source, Does.Contain(".WithReference(redis)"));
        Assert.That(source, Does.Contain(".WithEnvironment(\"HipInfrastructure__DatabaseProvider\", \"PostgreSQL\")"));
        Assert.That(source, Does.Contain("AddProject<Projects.HIP_Web>(\"hip-web\", launchProfileName: \"http\")"));
        Assert.That(source, Does.Contain(".WaitFor(hipDatabase)"));
        Assert.That(project, Does.Contain("Aspire.Hosting.PostgreSQL"));
        Assert.That(project, Does.Contain("Aspire.Hosting.Redis"));
    }

    /// <summary>
    /// Confirms legacy consumer-history indexing is an explicit, idempotent operator action rather than request-time decryption.
    /// </summary>
    [Test]
    public void AppHost_exposes_consumer_history_owner_index_backfill_as_explicit_maintenance()
    {
        var appHost = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.AppHost", "Program.cs"));
        var webProgram = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.Web", "Program.cs"));
        var launchSettings = File.ReadAllText(Path.Combine(
            RepositoryRoot(),
            "src",
            "HIP.Web",
            "Properties",
            "launchSettings.json"));

        Assert.Multiple(() =>
        {
            Assert.That(
                appHost,
                Does.Contain("AddProject<Projects.HIP_Web>(\"hip-owner-index-backfill\", launchProfileName: \"maintenance\")"));
            Assert.That(appHost, Does.Contain(".WithExplicitStart()"));
            Assert.That(appHost, Does.Contain("ownerIndexBackfill.WithEnvironment"));
            Assert.That(launchSettings, Does.Contain("\"maintenance\""));
            Assert.That(
                launchSettings,
                Does.Contain("--maintenance=consumer-history-owner-index-backfill"));
            Assert.That(
                launchSettings,
                Does.Contain("--confirm=APPLY-CONSUMER-HISTORY-OWNER-INDEX"));
            Assert.That(webProgram, Does.Contain("BackfillAllAsync(batchSize: 100"));
            Assert.That(webProgram, Does.Contain("Consumer-history owner-index backfill completed"));
        });
    }

    /// <summary>
    /// Confirms AppHost treats persistence protection material as secret parameters instead of source-controlled values.
    /// </summary>
    [Test]
    public void AppHost_uses_secret_parameters_for_persistence_protection_keys()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.AppHost", "Program.cs"));

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Contain("AddParameter(\"hip-record-encryption-key\", secret: true)"));
            Assert.That(source, Does.Contain("AddParameter(\"hip-legacy-record-encryption-key\", secret: true)"));
            Assert.That(source, Does.Contain("AddParameter(\"hip-privacy-hashing-key\", secret: true)"));
            Assert.That(source, Does.Contain("AddParameter(\"hip-legacy-privacy-hashing-key\", secret: true)"));
            Assert.That(source, Does.Contain("Parameters:hip-legacy-privacy-hashing-key"));
            Assert.That(source, Does.Contain("var legacyPrivacyHashingKey = string.IsNullOrWhiteSpace("));
            Assert.That(source, Does.Contain("? null"));
            Assert.That(source, Does.Contain(".WithEnvironment(\"HipSecurity__RecordEncryptionKey\", recordEncryptionKey)"));
            Assert.That(source, Does.Contain(".WithEnvironment(\"HipSecurity__LegacyRecordEncryptionKeys__0\", legacyRecordEncryptionKey)"));
            Assert.That(source, Does.Contain(".WithEnvironment(\"HipSecurity__PrivacyHashingKey\", privacyHashingKey)"));
            Assert.That(source, Does.Contain(".WithEnvironment(\"HipSecurity__LegacyPrivacyHashingKeys__0\", legacyPrivacyHashingKey)"));
            Assert.That(source, Does.Not.Contain("LocalRecordEncryptionKey"));
            Assert.That(source, Does.Not.Contain("LocalPrivacyHashingKey"));
            Assert.That(source, Does.Not.Contain("hip-local-dev-record-key"));
            Assert.That(source, Does.Not.Contain("hip-local-dev-privacy-key"));
        });
    }

    /// <summary>
    /// Confirms HIP runtime services require PostgreSQL and do not keep a file-based database fallback.
    /// </summary>
    [Test]
    public void Infrastructure_requires_postgresql_connection_and_has_no_runtime_sqlite_fallback()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.Infrastructure", "DependencyInjection.cs"));
        var project = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.Infrastructure", "HIP.Infrastructure.csproj"));

        Assert.That(source, Does.Contain("HIP requires ConnectionStrings:HipDatabase"));
        Assert.That(source, Does.Not.Contain("?? \"Data Source=hip-dev.db\""));
        Assert.That(source, Does.Contain("UseNpgsql(connectionString)"));
        Assert.That(source, Does.Not.Contain("Use" + "Sql" + "ite(connectionString)"));
        Assert.That(source, Does.Contain("HIP runtime persistence requires PostgreSQL"));
        Assert.That(source, Does.Contain("HipInfrastructure:DatabaseProvider"));
        Assert.That(project, Does.Contain("Npgsql.EntityFrameworkCore.PostgreSQL"));
        Assert.That(project, Does.Not.Contain("Microsoft.EntityFrameworkCore." + "Sql" + "ite"));
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
    /// Confirms Visual Studio cannot block HIP.Web before application startup on an uncompleted Hot Reload handshake.
    /// </summary>
    [Test]
    public void Web_launch_profiles_disable_hot_reload_startup_hooks()
    {
        var launchSettings = File.ReadAllText(Path.Combine(
            RepositoryRoot(),
            "src",
            "HIP.Web",
            "Properties",
            "launchSettings.json"));
        using var document = JsonDocument.Parse(launchSettings);
        var profiles = document.RootElement.GetProperty("profiles");

        Assert.Multiple(() =>
        {
            Assert.That(profiles.GetProperty("http").GetProperty("hotReloadEnabled").GetBoolean(), Is.False);
            Assert.That(profiles.GetProperty("https").GetProperty("hotReloadEnabled").GetBoolean(), Is.False);
            Assert.That(profiles.GetProperty("maintenance").GetProperty("hotReloadEnabled").GetBoolean(), Is.False);
        });
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
