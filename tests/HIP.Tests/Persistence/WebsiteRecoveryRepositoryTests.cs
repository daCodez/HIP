using HIP.Domain.Identity;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Persistence;

/// <summary>
/// Proves website recovery repositories elect one normalized-domain winner without overwriting it.
/// </summary>
public sealed class WebsiteRecoveryRepositoryTests
{
    private static readonly DateTimeOffset CreatedAtUtc =
        new(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Website_try_create_normalizes_domain_and_preserves_the_first_registration()
    {
        await using var context = CreateContext();
        var repository = new EfWebsiteIdentityRepository(
            new HipRecordStore(context, new DevelopmentHipRecordEncryptor()));
        var winner = CreateWebsite("  Example.COM. ", "hip:web:winner");
        var loser = CreateWebsite("example.com", "hip:web:loser");

        var winnerCreated = await repository.TryCreateAsync(winner, CancellationToken.None);
        var loserCreated = await repository.TryCreateAsync(loser, CancellationToken.None);
        var stored = await repository.GetAsync("EXAMPLE.COM.", CancellationToken.None);
        var storedRow = await context.Records.AsNoTracking().SingleAsync();

        Assert.Multiple(() =>
        {
            Assert.That(winnerCreated, Is.True);
            Assert.That(loserCreated, Is.False);
            Assert.That(stored, Is.Not.Null);
            Assert.That(stored!.Domain, Is.EqualTo("example.com"));
            Assert.That(stored.HipIdentityId, Is.EqualTo(winner.HipIdentityId));
            Assert.That(stored.PublicKeys, Is.EquivalentTo(winner.PublicKeys));
            Assert.That(storedRow.AggregateVersion, Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Website_try_update_advances_a_legacy_zero_version_row()
    {
        await using var context = CreateContext();
        var repository = new EfWebsiteIdentityRepository(
            new HipRecordStore(context, new DevelopmentHipRecordEncryptor()));
        var original = CreateWebsite("  Example.COM. ", "hip:web:legacy");
        await repository.SaveAsync(original, CancellationToken.None);
        var expected = await repository.GetAsync("example.com", CancellationToken.None);
        var checkedAtUtc = CreatedAtUtc.AddMinutes(5);
        var updated = expected! with
        {
            VerificationStatus = VerificationStatus.Verified,
            VerifiedAtUtc = checkedAtUtc,
            LastCheckedAtUtc = checkedAtUtc,
            LastCheckMessage = "Domain verification succeeded."
        };

        var saved = await repository.TryUpdateAsync(expected, updated, CancellationToken.None);

        var stored = await repository.GetAsync("EXAMPLE.COM.", CancellationToken.None);
        var storedRow = await context.Records.AsNoTracking().SingleAsync();
        Assert.Multiple(() =>
        {
            Assert.That(saved, Is.True);
            Assert.That(stored, Is.Not.Null);
            Assert.That(stored!.VerificationStatus, Is.EqualTo(VerificationStatus.Verified));
            Assert.That(stored.VerifiedAtUtc, Is.EqualTo(checkedAtUtc));
            Assert.That(stored.LastCheckedAtUtc, Is.EqualTo(checkedAtUtc));
            Assert.That(stored.LastCheckMessage, Is.EqualTo("Domain verification succeeded."));
            Assert.That(storedRow.AggregateVersion, Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Website_try_update_rejects_a_competing_stale_snapshot_without_overwriting_the_winner()
    {
        await using var context = CreateContext();
        var repository = new EfWebsiteIdentityRepository(
            new HipRecordStore(context, new DevelopmentHipRecordEncryptor()));
        Assert.That(
            await repository.TryCreateAsync(
                CreateWebsite("example.com", "hip:web:concurrent"),
                CancellationToken.None),
            Is.True);
        var winnerSnapshot = await repository.GetAsync("example.com", CancellationToken.None);
        var staleSnapshot = await repository.GetAsync("example.com", CancellationToken.None);
        var winnerCheckedAtUtc = CreatedAtUtc.AddMinutes(5);
        var winner = winnerSnapshot! with
        {
            VerificationStatus = VerificationStatus.Verified,
            VerifiedAtUtc = winnerCheckedAtUtc,
            LastCheckedAtUtc = winnerCheckedAtUtc,
            LastCheckMessage = "Winning verification result."
        };
        var stale = staleSnapshot! with
        {
            VerificationStatus = VerificationStatus.Suspended,
            LastCheckedAtUtc = CreatedAtUtc.AddMinutes(6),
            LastCheckMessage = "Stale competing result."
        };

        var winnerSaved = await repository.TryUpdateAsync(
            winnerSnapshot,
            winner,
            CancellationToken.None);
        var staleSaved = await repository.TryUpdateAsync(
            staleSnapshot,
            stale,
            CancellationToken.None);

        var stored = await repository.GetAsync("example.com", CancellationToken.None);
        var storedRow = await context.Records.AsNoTracking().SingleAsync();
        Assert.Multiple(() =>
        {
            Assert.That(winnerSaved, Is.True);
            Assert.That(staleSaved, Is.False);
            Assert.That(stored, Is.Not.Null);
            Assert.That(stored!.VerificationStatus, Is.EqualTo(VerificationStatus.Verified));
            Assert.That(stored.VerifiedAtUtc, Is.EqualTo(winnerCheckedAtUtc));
            Assert.That(stored.LastCheckedAtUtc, Is.EqualTo(winnerCheckedAtUtc));
            Assert.That(stored.LastCheckMessage, Is.EqualTo("Winning verification result."));
            Assert.That(storedRow.AggregateVersion, Is.EqualTo(2));
        });
    }

    [Test]
    public async Task Versioned_store_rejects_a_stale_update_from_a_second_database_context()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-versioned-store-cas-{Guid.NewGuid():N}")
            .Options;
        var original = CreateWebsite("example.com", "hip:web:cross-context");
        await using (var seedContext = new HipDbContext(options))
        {
            var seedStore = new HipRecordStore(seedContext, new DevelopmentHipRecordEncryptor());
            Assert.That(
                await seedStore.TrySaveVersionedAsync(
                    "website-identity",
                    "example.com",
                    original,
                    0,
                    1,
                    CancellationToken.None),
                Is.True);
        }

        await using var winnerContext = new HipDbContext(options);
        await using var staleContext = new HipDbContext(options);
        _ = await winnerContext.Records.SingleAsync();
        _ = await staleContext.Records.SingleAsync();
        var winnerStore = new HipRecordStore(winnerContext, new DevelopmentHipRecordEncryptor());
        var staleStore = new HipRecordStore(staleContext, new DevelopmentHipRecordEncryptor());
        var winner = original with { VerificationStatus = VerificationStatus.Verified };
        var stale = original with { VerificationStatus = VerificationStatus.Suspended };

        var winnerSaved = await winnerStore.TryUpdateVersionedAsync(
            "website-identity",
            "example.com",
            winner,
            1,
            2,
            CancellationToken.None);
        var staleSaved = await staleStore.TryUpdateVersionedAsync(
            "website-identity",
            "example.com",
            stale,
            1,
            2,
            CancellationToken.None);

        await using var verificationContext = new HipDbContext(options);
        var stored = await new HipRecordStore(verificationContext, new DevelopmentHipRecordEncryptor())
            .GetAsync<WebsiteIdentity>("website-identity", "example.com", CancellationToken.None);
        Assert.Multiple(() =>
        {
            Assert.That(winnerSaved, Is.True);
            Assert.That(staleSaved, Is.False);
            Assert.That(stored!.VerificationStatus, Is.EqualTo(VerificationStatus.Verified));
        });
    }

    [Test]
    public async Task Versioned_store_with_related_records_returns_false_for_cross_context_concurrency_loss()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-versioned-related-cas-{Guid.NewGuid():N}")
            .Options;
        var original = CreateWebsite("related.example", "hip:web:related-context");
        await using (var seedContext = new HipDbContext(options))
        {
            Assert.That(
                await new HipRecordStore(seedContext, new DevelopmentHipRecordEncryptor())
                    .TrySaveVersionedAsync(
                        "website-identity",
                        "related.example",
                        original,
                        0,
                        1,
                        CancellationToken.None),
                Is.True);
        }

        await using var winnerContext = new HipDbContext(options);
        await using var staleContext = new HipDbContext(options);
        _ = await winnerContext.Records.SingleAsync();
        _ = await staleContext.Records.SingleAsync();
        var winnerStore = new HipRecordStore(winnerContext, new DevelopmentHipRecordEncryptor());
        var staleStore = new HipRecordStore(staleContext, new DevelopmentHipRecordEncryptor());
        HipRelatedRecordWrite[] winnerRelated =
        [
            new HipRelatedRecordWrite<WebsiteIdentity>(
                "cas-audit",
                "winner",
                original with { VerificationStatus = VerificationStatus.Verified })
        ];
        HipRelatedRecordWrite[] staleRelated =
        [
            new HipRelatedRecordWrite<WebsiteIdentity>(
                "cas-audit",
                "stale",
                original with { VerificationStatus = VerificationStatus.Suspended })
        ];

        var winnerSaved = await winnerStore.TrySaveVersionedWithRelatedRecordsAsync(
            "website-identity",
            "related.example",
            original with { VerificationStatus = VerificationStatus.Verified },
            1,
            2,
            winnerRelated,
            CancellationToken.None);
        var staleSaved = await staleStore.TrySaveVersionedWithRelatedRecordsAsync(
            "website-identity",
            "related.example",
            original with { VerificationStatus = VerificationStatus.Suspended },
            1,
            2,
            staleRelated,
            CancellationToken.None);

        await using var verificationContext = new HipDbContext(options);
        var rows = await verificationContext.Records.AsNoTracking().ToArrayAsync();
        Assert.Multiple(() =>
        {
            Assert.That(winnerSaved, Is.True);
            Assert.That(staleSaved, Is.False);
            Assert.That(rows.Any(row => row.Partition == "cas-audit" && row.Id == "winner"), Is.True);
            Assert.That(rows.Any(row => row.Partition == "cas-audit" && row.Id == "stale"), Is.False);
        });
    }

    [Test]
    public async Task Challenge_try_create_preserves_the_first_token_and_scopes_uniqueness_by_method()
    {
        await using var context = CreateContext();
        var repository = new EfDomainVerificationRequestRepository(
            new HipRecordStore(context, new DevelopmentHipRecordEncryptor()));
        var dnsWinner = CreateChallenge("  Example.COM. ", VerificationMethod.DnsTxt, "winner-token");
        var dnsLoser = CreateChallenge("example.com", VerificationMethod.DnsTxt, "loser-token");
        var httpChallenge = CreateChallenge("EXAMPLE.COM.", VerificationMethod.WellKnownHipJson, "http-token");

        var dnsWinnerCreated = await repository.TryCreateAsync(dnsWinner, CancellationToken.None);
        var dnsLoserCreated = await repository.TryCreateAsync(dnsLoser, CancellationToken.None);
        var httpCreated = await repository.TryCreateAsync(httpChallenge, CancellationToken.None);
        var storedDns = await repository.GetAsync(
            "example.com",
            VerificationMethod.DnsTxt,
            CancellationToken.None);
        var storedHttp = await repository.GetAsync(
            "example.com",
            VerificationMethod.WellKnownHipJson,
            CancellationToken.None);
        var storedRows = await context.Records.AsNoTracking().ToArrayAsync();

        Assert.Multiple(() =>
        {
            Assert.That(dnsWinnerCreated, Is.True);
            Assert.That(dnsLoserCreated, Is.False);
            Assert.That(httpCreated, Is.True);
            Assert.That(storedDns, Is.EqualTo(dnsWinner with { Domain = "example.com" }));
            Assert.That(storedHttp, Is.EqualTo(httpChallenge with { Domain = "example.com" }));
            Assert.That(storedRows, Has.Length.EqualTo(2));
            Assert.That(storedRows, Has.All.Matches<HipDbRecord>(row => row.AggregateVersion == 1));
        });
    }

    [Test]
    public async Task Identity_try_update_uses_snapshot_cas_and_advances_legacy_version()
    {
        await using var context = CreateContext();
        var repository = new EfHipIdentityRepository(
            new HipRecordStore(context, new DevelopmentHipRecordEncryptor()));
        var identity = new HipIdentity(
            "hip:web:identity-cas.example",
            IdentitySubjectType.Website,
            "Identity CAS",
            "public-key",
            "ML-DSA-65",
            VerificationStatus.Pending,
            CreatedAtUtc,
            "identity-cas.example");
        await repository.SaveAsync(identity, CancellationToken.None);
        var expected = await repository.GetAsync(identity.IdentityId, CancellationToken.None);

        Assert.ThrowsAsync<ArgumentException>(() => repository.TryUpdateAsync(
            expected!,
            expected! with
            {
                PublicKey = "replacement-key",
                KeyAlgorithm = "replacement-algorithm",
                ReputationTargetId = "replacement.example"
            },
            CancellationToken.None));

        var saved = await repository.TryUpdateAsync(
            expected!,
            expected! with { VerificationStatus = VerificationStatus.Verified },
            CancellationToken.None);
        var staleSaved = await repository.TryUpdateAsync(
            expected,
            expected with { VerificationStatus = VerificationStatus.Suspended },
            CancellationToken.None);
        var stored = await repository.GetAsync(identity.IdentityId, CancellationToken.None);
        var row = await context.Records.AsNoTracking().SingleAsync();

        Assert.Multiple(() =>
        {
            Assert.That(saved, Is.True);
            Assert.That(staleSaved, Is.False);
            Assert.That(stored!.VerificationStatus, Is.EqualTo(VerificationStatus.Verified));
            Assert.That(row.AggregateVersion, Is.EqualTo(1));
        });
    }

    private static WebsiteIdentity CreateWebsite(string domain, string identityId) =>
        new(
            domain,
            identityId,
            [new SigningKey("default", "ML-DSA-65", "public-key")],
            VerificationStatus.Pending,
            VerificationMethod.DnsTxt,
            CreatedAtUtc,
            null);

    private static DomainVerificationRequest CreateChallenge(
        string domain,
        VerificationMethod method,
        string token) =>
        new(
            domain,
            method,
            token,
            VerificationStatus.Pending,
            CreatedAtUtc,
            null);

    private static HipDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-website-recovery-repository-{Guid.NewGuid():N}")
            .Options;
        return new HipDbContext(options);
    }
}
