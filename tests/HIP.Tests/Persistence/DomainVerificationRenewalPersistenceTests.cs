using HIP.Application.Identity;
using HIP.Domain.Identity;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Persistence;

/// <summary>Locks the single permitted token-changing persistence transition.</summary>
public sealed class DomainVerificationRenewalPersistenceTests
{
    [Test]
    public async Task Expired_challenge_can_rotate_once_without_storing_plaintext_tokens()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-domain-renewal-{Guid.NewGuid():N}")
            .Options;
        await using var context = new HipDbContext(options);
        var repository = new EfDomainVerificationRequestRepository(
            new HipRecordStore(context, new DevelopmentHipRecordEncryptor()));
        var createdAt = new DateTimeOffset(2026, 7, 20, 12, 0, 0, TimeSpan.Zero);
        var expired = new DomainVerificationRequest(
            "renew.example",
            VerificationMethod.DnsTxt,
            "old-secret-token",
            VerificationStatus.Expired,
            createdAt,
            null,
            createdAt.AddHours(1),
            createdAt.AddHours(1),
            "Challenge expired.");
        var renewed = expired with
        {
            Token = "new-secret-token",
            Status = VerificationStatus.Pending,
            CreatedAtUtc = createdAt.AddDays(1),
            ExpiresAtUtc = createdAt.AddDays(2),
            LastCheckedAtUtc = null,
            LastCheckMessage = null,
            ChallengeVersion = 2
        };

        Assert.That(await repository.TryCreateAsync(expired, CancellationToken.None), Is.True);
        var rotated = await repository.TryUpdateAsync(expired, renewed, CancellationToken.None);
        var staleReplay = await repository.TryUpdateAsync(expired, renewed, CancellationToken.None);
        var stored = await repository.GetAsync("renew.example", VerificationMethod.DnsTxt, CancellationToken.None);
        var encryptedRow = await context.Records.AsNoTracking().SingleAsync();

        Assert.Multiple(() =>
        {
            Assert.That(rotated, Is.True);
            Assert.That(staleReplay, Is.False);
            Assert.That(stored, Is.EqualTo(renewed));
            Assert.That(encryptedRow.Json, Does.Not.Contain(expired.Token));
            Assert.That(encryptedRow.Json, Does.Not.Contain(renewed.Token));
            Assert.That(encryptedRow.AggregateVersion, Is.EqualTo(2));
        });
    }
}
