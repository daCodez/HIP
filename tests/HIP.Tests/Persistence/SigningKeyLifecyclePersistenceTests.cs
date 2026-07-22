using System.Text.Json;
using System.Text.Json.Serialization;
using HIP.Application;
using HIP.Application.Identity;
using HIP.Domain.Identity;
using HIP.Infrastructure;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Tests.Persistence;

/// <summary>
/// Verifies production signing-key lifecycle snapshots use encrypted PostgreSQL compare-and-swap persistence.
/// </summary>
public sealed class SigningKeyLifecyclePersistenceTests
{
    [Test]
    public void Hip_record_model_exposes_an_aggregate_version_for_compare_and_swap()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseNpgsql("Host=localhost;Database=hip_design;Username=hip")
            .Options;
        using var context = new HipDbContext(options);

        var entity = context.Model.FindEntityType(typeof(HipDbRecord));
        var aggregateVersion = entity?.FindProperty(nameof(HipDbRecord.AggregateVersion));

        Assert.Multiple(() =>
        {
            Assert.That(entity, Is.Not.Null);
            Assert.That(aggregateVersion, Is.Not.Null);
            Assert.That(aggregateVersion!.ClrType, Is.EqualTo(typeof(long)));
            Assert.That(aggregateVersion.IsNullable, Is.False);
        });
    }

    [Test]
    public void Signing_key_ring_round_trips_through_the_encrypted_record_json_shape()
    {
        var activatedAt = new DateTimeOffset(2026, 7, 18, 10, 0, 0, TimeSpan.Zero);
        var original = SigningKeyRing.Create("hip:domain:example")
            .RegisterActiveKey(
                "key-1",
                "ML-DSA-65",
                "public-key-1",
                "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                activatedAt)
            .Rotate(
                "key-1",
                "key-2",
                "ML-DSA-65",
                "public-key-2",
                "sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                activatedAt.AddDays(30));
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            WriteIndented = false,
            Converters = { new JsonStringEnumConverter() }
        };

        var json = JsonSerializer.Serialize(original, options);
        var restored = JsonSerializer.Deserialize<SigningKeyRing>(json, options);
        var retired = restored!.Retire("key-1", activatedAt.AddDays(31));

        Assert.Multiple(() =>
        {
            Assert.That(restored.IdentityId, Is.EqualTo(original.IdentityId));
            Assert.That(restored.Version, Is.EqualTo(original.Version));
            Assert.That(restored.Keys, Has.Count.EqualTo(2));
            Assert.That(restored.GetRequiredKey("key-1").Status, Is.EqualTo(SigningKeyStatus.Retiring));
            Assert.That(restored.GetRequiredKey("key-2").Status, Is.EqualTo(SigningKeyStatus.Active));
            Assert.That(retired.GetRequiredKey("key-1").Status, Is.EqualTo(SigningKeyStatus.Retired));
            Assert.That(json, Does.Not.Contain("PrivateKey"));
        });
    }

    [Test]
    public void Infrastructure_registration_selects_the_scoped_ef_lifecycle_repository()
    {
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:HipDatabase"] = "Host=localhost;Database=hip_tests;Username=hip",
                ["ConnectionStrings:redis"] = "localhost:6379,abortConnect=false",
                ["HipInfrastructure:DatabaseProvider"] = "PostgreSQL"
            })
            .Build();

        services.AddHipApplication();
        services.AddHipInfrastructure(configuration);

        var descriptor = services.Last(service =>
            service.ServiceType == typeof(ISigningKeyLifecycleRepository));

        Assert.Multiple(() =>
        {
            Assert.That(descriptor.ImplementationType, Is.EqualTo(typeof(EfSigningKeyLifecycleRepository)));
            Assert.That(descriptor.Lifetime, Is.EqualTo(ServiceLifetime.Scoped));
        });
    }

    [Test]
    public void Versioned_record_write_uses_a_database_filtered_compare_and_swap()
    {
        var root = RepositoryRoot();
        var source = File.ReadAllText(Path.Combine(
            root,
            "src",
            "HIP.Infrastructure",
            "Persistence",
            "HipRecordStore.cs"));

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Contain("ExecuteUpdateAsync"));
            Assert.That(source, Does.Contain("record.AggregateVersion == expectedVersion"));
            Assert.That(source, Does.Contain("keyRing.Version").Or.Contain("newVersion"));
            Assert.That(source, Does.Contain("return false;"));
        });
    }

    [Test]
    public void Signing_key_concurrency_migration_is_additive_and_preserves_existing_records()
    {
        var migrationsDirectory = Path.Combine(
            RepositoryRoot(),
            "src",
            "HIP.Infrastructure",
            "Persistence",
            "Migrations");
        var migrationPath = Directory.GetFiles(
            migrationsDirectory,
            "*_AddSigningKeyLifecycleConcurrency.cs").Single();
        var migration = File.ReadAllText(migrationPath);

        Assert.Multiple(() =>
        {
            Assert.That(migration, Does.Contain("AddColumn<long>"));
            Assert.That(migration, Does.Contain("name: \"AggregateVersion\""));
            Assert.That(migration, Does.Contain("table: \"hip_records\""));
            Assert.That(migration, Does.Contain("defaultValue: 0L"));
            Assert.That(migration, Does.Not.Contain("DropTable("));
            Assert.That(migration, Does.Not.Contain("DeleteData("));
            Assert.That(migration, Does.Not.Contain("migrationBuilder.Sql("));
        });
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
