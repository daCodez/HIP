using HIP.Application.Rules;
using HIP.Application.Scalability;
using HIP.Domain.Rules;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using HIP.Tests.Rules;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Persistence;

/// <summary>Verifies HIP-0405 encrypted CAS transitions and atomic audit persistence.</summary>
public sealed class RuleDeploymentPersistenceTests
{
    [Test]
    public async Task Missing_deployment_returns_null_instead_of_a_default_tuple()
    {
        await using var context = Context($"rule-deployment-missing-{Guid.NewGuid():N}");

        var missing = await new EfRuleDeploymentRepository(Store(context))
            .GetAsync("missing-rule", CancellationToken.None);

        Assert.That(missing, Is.Null);
    }

    [Test]
    public async Task Concurrent_transitions_preserve_one_state_and_one_winning_audit_event()
    {
        var database = $"rule-deployment-{Guid.NewGuid():N}";
        var initial = State(version: 1, transition: "Created", actor: "actor-initial", reason: "Initial deployment.");
        await using (var setup = Context(database))
        {
            var created = await new EfRuleDeploymentRepository(Store(setup)).TryCreateAsync(
                initial,
                Event(initial, "RuleVersionActivated"),
                CancellationToken.None);
            Assert.That(created, Is.True);
        }

        var first = initial with
        {
            LastTransitionId = $"rule-transition:{Guid.NewGuid():N}",
            LastTransitionType = "UpdatedByFirst",
            LastActorId = "actor-first-sensitive",
            LastReason = "First sensitive reason.",
            UpdatedAtUtc = initial.UpdatedAtUtc.AddMinutes(1),
            Version = 2
        };
        var second = initial with
        {
            LastTransitionId = $"rule-transition:{Guid.NewGuid():N}",
            LastTransitionType = "UpdatedBySecond",
            LastActorId = "actor-second-sensitive",
            LastReason = "Second sensitive reason.",
            UpdatedAtUtc = initial.UpdatedAtUtc.AddMinutes(1),
            Version = 2
        };
        await using var contextA = Context(database);
        await using var contextB = Context(database);
        var results = await Task.WhenAll(
            new EfRuleDeploymentRepository(Store(contextA)).TryUpdateAsync(first, 1, Event(first, "RuleDeploymentUpdated"), CancellationToken.None),
            new EfRuleDeploymentRepository(Store(contextB)).TryUpdateAsync(second, 1, Event(second, "RuleDeploymentUpdated"), CancellationToken.None));

        await using var verify = Context(database);
        var store = Store(verify);
        var restored = await new EfRuleDeploymentRepository(store).GetAsync(initial.RuleId, CancellationToken.None);
        var events = await new EfOutboxEventRepository(store).ListPendingAsync(10, CancellationToken.None);
        var rows = await verify.Records.AsNoTracking().ToArrayAsync();

        Assert.Multiple(() =>
        {
            Assert.That(results.Count(value => value), Is.EqualTo(1));
            Assert.That(restored!.Version, Is.EqualTo(2));
            Assert.That(events, Has.Count.EqualTo(2));
            Assert.That(rows, Has.All.Matches<HipDbRecord>(row =>
                new DevelopmentHipRecordEncryptor().IsProtectedPayload(row.Json)));
            Assert.That(rows.Select(row => row.Json), Has.None.Contains("sensitive"));
        });
    }

    private static RuleDeploymentState State(long version, string transition, string actor, string reason)
    {
        var now = new DateTimeOffset(2026, 7, 20, 18, 0, 0, TimeSpan.Zero);
        var rule = RuleEngineTests.NewDomainShortenerRule(RuleMode.Watch) with
        {
            Severity = RuleSeverity.High,
            CreatedBy = "creator:1",
            Version = 3,
            ApprovalStatus = ApprovalStatus.Approved
        };
        return new RuleDeploymentState(
            RuleDeploymentContract.DeploymentId(rule.RuleId),
            rule.RuleId,
            rule,
            null,
            UseDisabledRollback: true,
            RollbackAvailable: true,
            RuleDeploymentStatus.Watch,
            $"rule-approval:{new string('a', 32)}",
            $"rule-transition:{Guid.NewGuid():N}",
            transition,
            actor,
            reason,
            now,
            now,
            version);
    }

    private static HipDurableEvent Event(RuleDeploymentState state, string type) => new(
        $"evt:{Guid.NewGuid():N}",
        type,
        "RuleDeployment",
        state.DeploymentId,
        state.UpdatedAtUtc,
        "{\"privacy\":\"safe\"}",
        HipDurableEventPrivacyLevel.PublicSafe);

    private static HipDbContext Context(string database) =>
        new(new DbContextOptionsBuilder<HipDbContext>().UseInMemoryDatabase(database).Options);

    private static HipRecordStore Store(HipDbContext context) =>
        new(context, new DevelopmentHipRecordEncryptor());
}
