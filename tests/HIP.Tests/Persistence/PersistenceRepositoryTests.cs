using HIP.Application.Reporting;
using HIP.Application.Security;
using HIP.Infrastructure.Security;
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
                ["ConnectionStrings:redis"] = "localhost:6379,abortConnect=false",
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
                ["ConnectionStrings:redis"] = "localhost:6379,abortConnect=false",
                ["HipInfrastructure:DatabaseProvider"] = "PostgreSQL"
            })
            .Build();

        services.AddHipInfrastructure(configuration);

        Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(HipDbContext)), Is.True);
    }

    [Test]
    public void Infrastructure_registration_rejects_missing_redis_security_state()
    {
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:HipDatabase"] = "Host=localhost;Database=hip_tests;Username=hip",
                ["HipInfrastructure:DatabaseProvider"] = "PostgreSQL"
            })
            .Build();

        var exception = Assert.Throws<InvalidOperationException>(() =>
            services.AddHipInfrastructure(configuration));

        Assert.That(exception!.Message, Does.Contain("ConnectionStrings:redis"));
    }

    [Test]
    public void Infrastructure_registration_uses_redis_duplicate_and_nonce_adapters()
    {
        var services = new ServiceCollection();
        var configuration = ProductionConfiguration(new Dictionary<string, string?>
        {
            ["HipSecurity:RecordEncryptionKey"] = "test-record-encryption-key-material-32",
            ["HipSecurity:PrivacyHashingKey"] = "test-privacy-hashing-key-material-32"
        });

        services.AddHipInfrastructure(configuration, isLocalDevelopment: false);

        Assert.Multiple(() =>
        {
            Assert.That(
                services.Single(descriptor => descriptor.ServiceType == typeof(IDuplicateSubmissionGuard)).ImplementationType,
                Is.EqualTo(typeof(RedisDuplicateSubmissionGuard)));
            Assert.That(
                services.Single(descriptor => descriptor.ServiceType == typeof(IReplayNonceStore)).ImplementationType,
                Is.EqualTo(typeof(RedisReplayNonceStore)));
        });
    }

    /// <summary>
    /// Confirms production registration rejects missing persistence protection keys immediately at startup.
    /// </summary>
    [Test]
    public void Infrastructure_registration_rejects_missing_production_security_keys()
    {
        var services = new ServiceCollection();
        var configuration = ProductionConfiguration();

        var exception = Assert.Throws<InvalidOperationException>(() =>
            services.AddHipInfrastructure(configuration, isLocalDevelopment: false));

        Assert.That(exception!.Message, Does.Contain("HipSecurity:RecordEncryptionKey"));
    }

    /// <summary>
    /// Confirms production registration rejects built-in development keys before services begin handling requests.
    /// </summary>
    [Test]
    public void Infrastructure_registration_rejects_development_keys_in_production()
    {
        var services = new ServiceCollection();
        var configuration = ProductionConfiguration(new Dictionary<string, string?>
        {
            ["HipSecurity:RecordEncryptionKey"] = DevelopmentHipRecordEncryptor.DevelopmentOnlyKey,
            ["HipSecurity:PrivacyHashingKey"] = Sha256PrivacyHashingService.DevelopmentOnlyKey
        });

        var exception = Assert.Throws<InvalidOperationException>(() =>
            services.AddHipInfrastructure(configuration, isLocalDevelopment: false));

        Assert.That(exception!.Message, Does.Contain("HipSecurity:RecordEncryptionKey"));
    }

    /// <summary>
    /// Confirms production registration rejects weak or obvious placeholder security material.
    /// </summary>
    [TestCase("short-key", "valid-privacy-hashing-key-material-32")]
    [TestCase("CHANGE-BEFORE-PRODUCTION-record-key", "valid-privacy-hashing-key-material-32")]
    [TestCase("valid-record-encryption-key-material-32", "placeholder-privacy-hashing-key")]
    public void Infrastructure_registration_rejects_unsafe_production_security_keys(
        string recordEncryptionKey,
        string privacyHashingKey)
    {
        var services = new ServiceCollection();
        var configuration = ProductionConfiguration(new Dictionary<string, string?>
        {
            ["HipSecurity:RecordEncryptionKey"] = recordEncryptionKey,
            ["HipSecurity:PrivacyHashingKey"] = privacyHashingKey
        });

        Assert.Throws<InvalidOperationException>(() =>
            services.AddHipInfrastructure(configuration, isLocalDevelopment: false));
    }

    /// <summary>
    /// Confirms production registration rejects unsafe legacy decryption keys immediately.
    /// </summary>
    [Test]
    public void Infrastructure_registration_rejects_unsafe_legacy_keys_in_production()
    {
        var services = new ServiceCollection();
        var configuration = ProductionConfiguration(new Dictionary<string, string?>
        {
            ["HipSecurity:RecordEncryptionKey"] = "test-record-encryption-key-material-32",
            ["HipSecurity:PrivacyHashingKey"] = "test-privacy-hashing-key-material-32",
            ["HipSecurity:LegacyRecordEncryptionKeys:0"] = DevelopmentHipRecordEncryptor.DevelopmentOnlyKey
        });

        Assert.Throws<InvalidOperationException>(() =>
            services.AddHipInfrastructure(configuration, isLocalDevelopment: false));
    }

    /// <summary>
    /// Confirms production registration rejects reuse of one secret across encryption and privacy hashing.
    /// </summary>
    [Test]
    public void Infrastructure_registration_rejects_reused_production_security_keys()
    {
        const string reusedKey = "test-reused-security-key-material-32";
        var services = new ServiceCollection();
        var configuration = ProductionConfiguration(new Dictionary<string, string?>
        {
            ["HipSecurity:RecordEncryptionKey"] = reusedKey,
            ["HipSecurity:PrivacyHashingKey"] = reusedKey
        });

        var exception = Assert.Throws<InvalidOperationException>(() =>
            services.AddHipInfrastructure(configuration, isLocalDevelopment: false));

        Assert.That(exception!.Message, Does.Contain("must be different"));
    }

    /// <summary>
    /// Confirms production registration accepts independently configured strong key material.
    /// </summary>
    [Test]
    public void Infrastructure_registration_accepts_strong_production_security_keys()
    {
        var services = new ServiceCollection();
        var configuration = ProductionConfiguration(new Dictionary<string, string?>
        {
            ["HipSecurity:RecordEncryptionKey"] = "test-record-encryption-key-material-32",
            ["HipSecurity:PrivacyHashingKey"] = "test-privacy-hashing-key-material-32"
        });

        services.AddHipInfrastructure(configuration, isLocalDevelopment: false);

        Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(IHipRecordEncryptor)), Is.True);
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
    /// Creates production-like PostgreSQL configuration with optional security overrides.
    /// </summary>
    /// <param name="overrides">Optional security configuration values.</param>
    /// <returns>Configuration used to exercise fail-closed startup validation.</returns>
    private static IConfiguration ProductionConfiguration(IReadOnlyDictionary<string, string?>? overrides = null)
    {
        var values = new Dictionary<string, string?>
        {
            ["ConnectionStrings:HipDatabase"] = "Host=localhost;Port=5432;Database=hip_tests;Username=hip;Password=hip",
            ["ConnectionStrings:redis"] = "localhost:6379,abortConnect=false",
            ["HipInfrastructure:DatabaseProvider"] = "PostgreSQL"
        };

        foreach (var pair in overrides ?? new Dictionary<string, string?>())
        {
            values[pair.Key] = pair.Value;
        }

        return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
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
