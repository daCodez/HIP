using HIP.Application.Identity;
using HIP.Domain.Identity;

namespace HIP.Tests.Identity;

/// <summary>Locks bounded challenge expiry, renewal, and terminal revocation.</summary>
public sealed class DomainVerificationChallengeLifecycleTests
{
    private static readonly DateTimeOffset Start = new(2026, 7, 21, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Expired_challenge_cannot_verify_and_renewal_rotates_the_token_generation()
    {
        var clock = new ManualTimeProvider(Start);
        var service = new InMemoryDomainVerificationService(
            new DomainVerificationLifecycleOptions(TimeSpan.FromMinutes(10), TimeSpan.FromDays(7)),
            clock);
        var started = await service.StartAsync("expiry.example", VerificationMethod.DnsTxt, CancellationToken.None);

        clock.UtcNow = started.ExpiresAtUtc!.Value;
        var expired = await service.VerifyAsync(
            started.Domain,
            started.Method,
            started.Token,
            CancellationToken.None);
        var renewed = await service.RenewExpiredAsync(started.Domain, started.Method, CancellationToken.None);
        var oldTokenResult = await service.VerifyAsync(
            renewed.Domain,
            renewed.Method,
            started.Token,
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(started.ExpiresAtUtc, Is.EqualTo(Start.AddMinutes(10)));
            Assert.That(expired.Status, Is.EqualTo(VerificationStatus.Expired));
            Assert.That(expired.VerifiedAtUtc, Is.Null);
            Assert.That(renewed.Status, Is.EqualTo(VerificationStatus.Pending));
            Assert.That(renewed.ChallengeVersion, Is.EqualTo(2));
            Assert.That(renewed.Token, Is.Not.EqualTo(started.Token));
            Assert.That(oldTokenResult.Status, Is.EqualTo(VerificationStatus.Unverified));
        });
    }

    [Test]
    public async Task Revoked_challenge_is_terminal_and_cannot_be_renewed()
    {
        var clock = new ManualTimeProvider(Start);
        var service = new InMemoryDomainVerificationService(
            new DomainVerificationLifecycleOptions(TimeSpan.FromMinutes(10), TimeSpan.FromDays(7)),
            clock);
        var started = await service.StartAsync("revoked-expiry.example", VerificationMethod.DnsTxt, CancellationToken.None);
        var revoked = await service.RevokeAsync(started.Domain, started.Method, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(revoked.Status, Is.EqualTo(VerificationStatus.Revoked));
            Assert.That(revoked.RevokedAtUtc, Is.EqualTo(Start));
            Assert.That(
                async () => await service.RenewExpiredAsync(started.Domain, started.Method, CancellationToken.None),
                Throws.InvalidOperationException.With.Message.Contains("Revoked"));
        });
    }

    private sealed class ManualTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = utcNow;
        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
