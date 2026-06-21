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
    /// Confirms HIP runtime services require PostgreSQL and do not keep SQLite as a production fallback.
    /// </summary>
    [Test]
    public void Infrastructure_requires_postgresql_connection_and_has_no_runtime_sqlite_fallback()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.Infrastructure", "DependencyInjection.cs"));
        var project = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.Infrastructure", "HIP.Infrastructure.csproj"));

        Assert.That(source, Does.Contain("HIP requires ConnectionStrings:HipDatabase"));
        Assert.That(source, Does.Not.Contain("?? \"Data Source=hip-dev.db\""));
        Assert.That(source, Does.Contain("UseNpgsql(connectionString)"));
        Assert.That(source, Does.Not.Contain("UseSqlite(connectionString)"));
        Assert.That(source, Does.Contain("HIP runtime persistence requires PostgreSQL"));
        Assert.That(source, Does.Contain("HipInfrastructure:DatabaseProvider"));
        Assert.That(project, Does.Contain("Npgsql.EntityFrameworkCore.PostgreSQL"));
        Assert.That(project, Does.Not.Contain("Microsoft.EntityFrameworkCore.Sqlite"));
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
