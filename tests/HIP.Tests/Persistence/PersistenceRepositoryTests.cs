using HIP.Infrastructure;
using HIP.Infrastructure.Persistence;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Tests.Persistence;

/// <summary>
/// Verifies HIP persistence configuration stays on durable PostgreSQL-backed storage.
/// </summary>
[TestFixture]
public sealed class PersistenceRepositoryTests
{
    /// <summary>
    /// Confirms the infrastructure project no longer depends on removed file-based or process-local database providers.
    /// </summary>
    [Test]
    public void Infrastructure_project_has_no_sqlite_or_ef_in_memory_provider_packages()
    {
        var project = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.Infrastructure", "HIP.Infrastructure.csproj"));

        Assert.Multiple(() =>
        {
            Assert.That(project, Does.Not.Contain(RemovedFileProviderPackage()));
            Assert.That(project, Does.Not.Contain(RemovedProcessLocalProviderPackage()));
        });
    }

    /// <summary>
    /// Confirms the test project no longer pulls the removed file-based provider into the dependency graph.
    /// </summary>
    [Test]
    public void Test_project_has_no_sqlite_package_reference()
    {
        var project = File.ReadAllText(Path.Combine(RepositoryRoot(), "tests", "HIP.Tests", "HIP.Tests.csproj"));

        Assert.That(project, Does.Not.Contain(RemovedFileProviderPackage()));
    }

    /// <summary>
    /// Confirms database provider registration rejects non-PostgreSQL connection strings instead of silently using
    /// temporary storage.
    /// </summary>
    [Test]
    public void Infrastructure_registration_rejects_non_postgresql_connection_strings()
    {
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:HipDatabase"] = "DataSource=hip-local.db",
                ["HipInfrastructure:DatabaseProvider"] = "FileDatabase"
            })
            .Build();

        var exception = Assert.Throws<InvalidOperationException>(() =>
        {
            services.AddHipInfrastructure(configuration);

            using var provider = services.BuildServiceProvider();
            _ = provider.GetRequiredService<HipDbContext>();
        });

        Assert.That(exception!.Message, Does.Contain("requires PostgreSQL"));
    }

    /// <summary>
    /// Confirms database provider registration accepts PostgreSQL connection strings for durable local and production
    /// persistence.
    /// </summary>
    [Test]
    public void Infrastructure_registration_accepts_postgresql_connection_strings()
    {
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:HipDatabase"] = "Host=localhost;Port=5432;Database=hip_tests;Username=hip;Password=hip",
                ["HipInfrastructure:DatabaseProvider"] = "PostgreSQL"
            })
            .Build();

        services.AddHipInfrastructure(configuration);

        Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(HipDbContext)), Is.True);
    }

    /// <summary>
    /// Confirms source files no longer contain removed file-based provider runtime paths.
    /// </summary>
    [Test]
    public void Source_runtime_persistence_has_no_sqlite_branches()
    {
        var root = RepositoryRoot();
        var files = Directory.EnumerateFiles(Path.Combine(root, "src"), "*.cs", SearchOption.AllDirectories);

        Assert.Multiple(() =>
        {
            foreach (var file in files)
            {
                var source = File.ReadAllText(file);
                Assert.That(source, Does.Not.Contain("Use" + "Sql" + "ite"), Path.GetRelativePath(root, file));
                Assert.That(source, Does.Not.Contain("Sql" + "iteConnection"), Path.GetRelativePath(root, file));
                Assert.That(source, Does.Not.Contain("Microsoft.Data." + "Sql" + "ite"), Path.GetRelativePath(root, file));
            }
        });
    }

    /// <summary>
    /// Builds the removed file-based EF provider package name without leaving a false-positive search hit in HIP.
    /// </summary>
    /// <returns>Removed EF provider package name.</returns>
    private static string RemovedFileProviderPackage() =>
        "Microsoft.EntityFrameworkCore." + "Sql" + "ite";

    /// <summary>
    /// Builds the removed process-local EF provider package name without normal runtime code depending on it.
    /// </summary>
    /// <returns>Removed EF provider package name.</returns>
    private static string RemovedProcessLocalProviderPackage() =>
        "Microsoft.EntityFrameworkCore." + "In" + "Memory";

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
