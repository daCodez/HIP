using HIP.Application.Rules;
using HIP.Domain.Rules;

namespace HIP.Tests.Rules;

/// <summary>Locks the immutable rule-version browser repository contract.</summary>
public sealed class RuleVersionHistoryTests
{
    [Test]
    public async Task Repository_lists_saved_versions_newest_first_without_changing_current_lookup()
    {
        var repository = new InMemoryRuleRepository();
        var first = RuleEngineTests.NewDomainShortenerRule(RuleMode.Watch) with
        {
            RuleId = "rule:history",
            Version = 1,
            CreatedBy = "creator:1"
        };
        var second = first with { Version = 2, Description = "Second version" };

        await repository.SaveAsync(first, CancellationToken.None);
        await repository.SaveAsync(second, CancellationToken.None);

        var versions = await repository.ListVersionsAsync(first.RuleId, CancellationToken.None);
        var current = await repository.GetByIdAsync(first.RuleId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(versions.Select(rule => rule.Version), Is.EqualTo(new[] { 2, 1 }));
            Assert.That(current, Is.EqualTo(second));
        });
    }

    [Test]
    public async Task Repository_rejects_changed_content_for_an_existing_version()
    {
        var repository = new InMemoryRuleRepository();
        var first = RuleEngineTests.NewDomainShortenerRule(RuleMode.Watch) with
        {
            RuleId = "rule:immutable-history",
            Version = 1,
            CreatedBy = "creator:1"
        };
        await repository.SaveAsync(first, CancellationToken.None);

        Assert.That(
            async () => await repository.SaveAsync(first with { Description = "Tampered" }, CancellationToken.None),
            Throws.InvalidOperationException.With.Message.Contains("immutable"));
    }
}
