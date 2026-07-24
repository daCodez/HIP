using HIP.Infrastructure.Persistence.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using Microsoft.EntityFrameworkCore.Migrations;

namespace HIP.Tests.Persistence;

/// <summary>Verifies the domain certificate migration is additive and preserves its audit history relationships.</summary>
public sealed class DomainCertificateMigrationTests
{
    [Test]
    public void Migration_adds_only_the_three_certificate_tables_and_indexes()
    {
        var migration = new AddDomainTrustCertificates();
        var operations = migration.UpOperations;
        var tables = operations.OfType<CreateTableOperation>().ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(
                tables.Select(table => table.Name),
                Is.EquivalentTo(new[]
                {
                    "hip_domain_enrollments",
                    "hip_domain_certificates",
                    "hip_domain_certificate_events"
                }));
            Assert.That(operations.OfType<DropTableOperation>(), Is.Empty);
            Assert.That(operations.OfType<AlterColumnOperation>(), Is.Empty);
            Assert.That(operations.OfType<SqlOperation>(), Is.Empty);
            Assert.That(operations.OfType<CreateIndexOperation>().Count(), Is.EqualTo(10));
        });
    }

    [Test]
    public void Migration_restricts_deletes_and_rolls_back_in_dependency_order()
    {
        var migration = new AddDomainTrustCertificates();
        var foreignKeys = migration.UpOperations
            .OfType<CreateTableOperation>()
            .SelectMany(table => table.ForeignKeys)
            .ToArray();
        var downTables = migration.DownOperations
            .OfType<DropTableOperation>()
            .Select(operation => operation.Name)
            .ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(foreignKeys, Has.Length.EqualTo(3));
            Assert.That(
                foreignKeys.All(key => key.OnDelete == ReferentialAction.Restrict),
                Is.True);
            Assert.That(
                downTables,
                Is.EqualTo(new[]
                {
                    "hip_domain_certificate_events",
                    "hip_domain_certificates",
                    "hip_domain_enrollments"
                }));
        });
    }
}
