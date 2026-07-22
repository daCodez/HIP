using HIP.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Infrastructure;

[NonParallelizable]
public sealed class DatabaseMigrationSafetyTests
{
    [Test]
    public void Production_startup_validates_migrations_without_applying_them()
    {
        var root = RepositoryRoot();
        var initializer = File.ReadAllText(Path.Combine(root, "src", "HIP.Infrastructure", "Persistence", "HipDatabaseInitializer.cs"));
        var webProgram = File.ReadAllText(Path.Combine(root, "src", "HIP.Web", "Program.cs"));
        var apiProgram = File.ReadAllText(Path.Combine(root, "src", "HIP.ApiService", "Program.cs"));

        Assert.Multiple(() =>
        {
            Assert.That(initializer, Does.Contain("GetPendingMigrationsAsync"));
            Assert.That(initializer, Does.Not.Contain(".MigrateAsync("));
            Assert.That(webProgram, Does.Contain("HipDatabaseInitializationMode.ValidateMigrations"));
            Assert.That(apiProgram, Does.Contain("HipDatabaseInitializationMode.ValidateMigrations"));
        });
    }

    [Test]
    public void Initial_migration_contains_only_expected_schema_creation()
    {
        var migrationsDirectory = Path.Combine(
            RepositoryRoot(),
            "src",
            "HIP.Infrastructure",
            "Persistence",
            "Migrations");
        var migrationPath = Directory.GetFiles(migrationsDirectory, "*_InitialHipSchema.cs").Single();
        var migration = File.ReadAllText(migrationPath);

        Assert.Multiple(() =>
        {
            Assert.That(Occurrences(migration, "migrationBuilder.CreateTable("), Is.EqualTo(3));
            Assert.That(migration, Does.Contain("name: \"hip_records\""));
            Assert.That(migration, Does.Contain("name: \"hip_browser_scan_results\""));
            Assert.That(migration, Does.Contain("name: \"hip_dashboard_scan_aggregates\""));
            Assert.That(migration, Does.Not.Contain("DropColumn("));
            Assert.That(migration, Does.Not.Contain("AlterColumn("));
            Assert.That(migration, Does.Not.Contain("migrationBuilder.Sql("));
        });
    }

    [Test]
    public void Expected_migrations_are_compiled_into_the_runtime_model()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseNpgsql("Host=localhost;Database=hip_design;Username=hip")
            .Options;
        using var context = new HipDbContext(options);

        var migrations = context.Database.GetMigrations().ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(migrations, Has.Exactly(1).EndsWith("_InitialHipSchema"));
            Assert.That(migrations, Has.Exactly(1).EndsWith("_AddSigningKeyLifecycleConcurrency"));
            Assert.That(migrations, Has.Exactly(1).EndsWith("_AddTrustReceipts"));
        });
    }

    [Test]
    public void Trust_receipt_migration_adds_only_the_insert_only_receipt_table()
    {
        var migrationsDirectory = Path.Combine(
            RepositoryRoot(),
            "src",
            "HIP.Infrastructure",
            "Persistence",
            "Migrations");
        var migrationPath = Directory.GetFiles(migrationsDirectory, "*_AddTrustReceipts.cs").Single();
        var migration = File.ReadAllText(migrationPath);

        Assert.Multiple(() =>
        {
            Assert.That(Occurrences(migration, "migrationBuilder.CreateTable("), Is.EqualTo(1));
            Assert.That(migration, Does.Contain("name: \"hip_trust_receipts\""));
            Assert.That(migration, Does.Contain("PK_hip_trust_receipts"));
            Assert.That(migration, Does.Contain("IX_hip_trust_receipts_RelatedEvaluationId"));
            Assert.That(migration, Does.Contain("unique: true"));
            Assert.That(migration, Does.Contain("migrationBuilder.DropTable("));
            Assert.That(migration, Does.Not.Contain("DropColumn("));
            Assert.That(migration, Does.Not.Contain("AlterColumn("));
            Assert.That(migration, Does.Not.Contain("migrationBuilder.Sql("));
        });
    }

    [Test]
    public void Design_time_factory_requires_an_explicit_connection_string()
    {
        const string variableName = "HIP_DATABASE_CONNECTION_STRING";
        var previousValue = Environment.GetEnvironmentVariable(variableName);
        Environment.SetEnvironmentVariable(variableName, null);

        try
        {
            var exception = Assert.Throws<InvalidOperationException>(
                () => new HipDbContextDesignTimeFactory().CreateDbContext([]));

            Assert.That(exception!.Message, Does.Contain(variableName));
        }
        finally
        {
            Environment.SetEnvironmentVariable(variableName, previousValue);
        }
    }

    private static int Occurrences(string value, string fragment)
    {
        var count = 0;
        var index = 0;
        while ((index = value.IndexOf(fragment, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += fragment.Length;
        }

        return count;
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
