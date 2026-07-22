using HIP.Application.Rules;
using HIP.Application.Simulation;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using HIP.Tests.Rules;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Persistence;

/// <summary>Verifies HIP-0403 immutable encrypted simulation-result persistence.</summary>
public sealed class RuleSimulationResultPersistenceTests
{
    [Test]
    public async Task Durable_result_is_encrypted_versioned_and_cannot_be_overwritten()
    {
        await using var context = new HipDbContext(
            new DbContextOptionsBuilder<HipDbContext>()
                .UseInMemoryDatabase($"simulation-{Guid.NewGuid():N}")
                .Options);
        var encryptor = new DevelopmentHipRecordEncryptor();
        var repository = new EfRuleSimulationResultRepository(new HipRecordStore(context, encryptor));
        var result = Service().Simulate(
            RuleEngineTests.NewDomainShortenerRule(HIP.Domain.Rules.RuleMode.Active),
            [new RuleSimulationTestCase(
                "durable fixture",
                new FactSet(new Dictionary<string, object?>
                {
                    ["domain.ageDays"] = 5,
                    ["url.usesShortener"] = true
                }),
                true,
                HIP.Domain.Risk.RiskStatus.HighRisk,
                true)]);

        await repository.SaveAsync(result.SimulationId, result, CancellationToken.None);
        var restored = await repository.GetAsync(result.SimulationId, CancellationToken.None);
        var row = await context.Records.AsNoTracking().SingleAsync();

        Assert.Multiple(() =>
        {
            Assert.That(restored!.SimulationId, Is.EqualTo(result.SimulationId));
            Assert.That(restored.RuleVersion, Is.EqualTo(result.RuleVersion));
            Assert.That(restored.FixtureSetId, Is.EqualTo(result.FixtureSetId));
            Assert.That(restored.CaseResults.Select(item => item.Name),
                Is.EqualTo(result.CaseResults.Select(item => item.Name)));
            Assert.That(row.AggregateVersion, Is.EqualTo(1));
            Assert.That(encryptor.IsProtectedPayload(row.Json), Is.True);
            Assert.That(row.Json, Does.Not.Contain("domain.ageDays"));
            Assert.That(
                async () => await repository.SaveAsync(result.SimulationId, result, CancellationToken.None),
                Throws.InvalidOperationException.With.Message.Contains("immutable"));
        });
    }

    [Test]
    public async Task In_memory_repository_rejects_duplicate_and_mismatched_identifiers()
    {
        var repository = new InMemoryRuleSimulationResultRepository();
        var result = Service().Simulate(RuleEngineTests.NewDomainShortenerRule(HIP.Domain.Rules.RuleMode.Active), null);

        await repository.SaveAsync(result.SimulationId, result, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(
                async () => await repository.SaveAsync(result.SimulationId, result, CancellationToken.None),
                Throws.InvalidOperationException);
            Assert.That(
                async () => await new InMemoryRuleSimulationResultRepository().SaveAsync("simulation:wrong", result, CancellationToken.None),
                Throws.InvalidOperationException);
        });
    }

    private static RuleSimulationService Service() =>
        new(new RuleActionApplier(new RuleMatchingEngine()));
}
