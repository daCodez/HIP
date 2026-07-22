using HIP.Application.Identity;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Persistence;

/// <summary>Locks encrypted, create-only website owner bindings.</summary>
public sealed class WebsiteOwnershipClaimPersistenceTests
{
    [Test]
    public async Task First_normalized_domain_claim_wins_and_raw_owner_is_not_stored()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-website-owner-{Guid.NewGuid():N}")
            .Options;
        await using var context = new HipDbContext(options);
        var repository = new EfWebsiteOwnershipClaimRepository(
            new HipRecordStore(context, new DevelopmentHipRecordEncryptor()));
        var first = new WebsiteOwnershipClaim(
            " Example.COM. ",
            $"sha256:{new string('a', 64)}",
            "Admin",
            DateTimeOffset.UtcNow);
        var competing = first with { Domain = "example.com", OwnerScopeHash = $"sha256:{new string('b', 64)}" };

        var created = await repository.TryCreateAsync(first, CancellationToken.None);
        var replaced = await repository.TryCreateAsync(competing, CancellationToken.None);
        var stored = await repository.GetAsync("EXAMPLE.COM.", CancellationToken.None);
        var encryptedRow = await context.Records.AsNoTracking().SingleAsync();

        Assert.Multiple(() =>
        {
            Assert.That(created, Is.True);
            Assert.That(replaced, Is.False);
            Assert.That(stored!.OwnerScopeHash, Is.EqualTo(first.OwnerScopeHash));
            Assert.That(encryptedRow.Json, Does.Not.Contain(first.OwnerScopeHash));
            Assert.That(encryptedRow.AggregateVersion, Is.EqualTo(1));
        });
    }
}
