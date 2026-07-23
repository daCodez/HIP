using HIP.Application.Reputation;
using HIP.Domain.Reputation;
using HIP.Domain.Risk;

namespace HIP.Tests.Reputation;

/// <summary>
/// Verifies the administrative sender-profile projection stays real, bounded, and sender-specific.
/// </summary>
public sealed class AdminSenderProfileServiceTests
{
    [Test]
    public async Task List_returns_only_stored_sender_profiles_newest_first()
    {
        var profiles = new InMemoryReputationProfileRepository();
        await profiles.SaveAsync(Profile(ReputationSubjectType.Sender, "older-sender", DateTimeOffset.UtcNow.AddHours(-2)), CancellationToken.None);
        await profiles.SaveAsync(Profile(ReputationSubjectType.Domain, "domain.example", DateTimeOffset.UtcNow), CancellationToken.None);
        await profiles.SaveAsync(Profile(ReputationSubjectType.Sender, "newer-sender", DateTimeOffset.UtcNow.AddMinutes(-2)), CancellationToken.None);
        var service = new AdminSenderProfileService(profiles, new InMemoryReputationEventRepository());

        var result = await service.ListAsync(CancellationToken.None);

        Assert.That(result.Select(profile => profile.SenderId), Is.EqualTo(new[] { "newer-sender", "older-sender" }));
    }

    [Test]
    public async Task Get_returns_bounded_privacy_safe_sender_event_history_newest_first()
    {
        var profiles = new InMemoryReputationProfileRepository();
        var events = new InMemoryReputationEventRepository();
        await profiles.SaveAsync(Profile(ReputationSubjectType.Sender, "sender-42", DateTimeOffset.UtcNow), CancellationToken.None);
        await events.AddAsync(Event("older", DateTimeOffset.UtcNow.AddHours(-1)), CancellationToken.None);
        await events.AddAsync(Event("newer", DateTimeOffset.UtcNow), CancellationToken.None);
        var service = new AdminSenderProfileService(profiles, events);

        var result = await service.GetAsync("sender-42", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.Not.Null);
            Assert.That(result!.Profile.SenderId, Is.EqualTo("sender-42"));
            Assert.That(result.Events.Select(item => item.Reason), Is.EqualTo(new[] { "newer", "older" }));
            Assert.That(result.Explanations, Is.EqualTo(new[] { "Stored privacy-safe explanation." }));
        });
    }

    [Test]
    public async Task Get_does_not_return_a_non_sender_profile()
    {
        var profiles = new InMemoryReputationProfileRepository();
        await profiles.SaveAsync(Profile(ReputationSubjectType.Domain, "same-id", DateTimeOffset.UtcNow), CancellationToken.None);
        var service = new AdminSenderProfileService(profiles, new InMemoryReputationEventRepository());

        var result = await service.GetAsync("same-id", CancellationToken.None);

        Assert.That(result, Is.Null);
    }

    private static ReputationProfile Profile(
        ReputationSubjectType targetType,
        string targetId,
        DateTimeOffset updatedAtUtc) =>
        new(
            $"profile-{targetId}",
            targetType,
            targetId,
            72,
            RiskStatus.MostlyTrusted,
            2,
            1,
            0,
            updatedAtUtc,
            ["Stored privacy-safe explanation."]);

    private static ReputationEvent Event(string reason, DateTimeOffset createdAtUtc) =>
        new(
            $"event-{reason}",
            ReputationSubjectType.Sender,
            "sender-42",
            ReputationEventType.SuspiciousReport,
            ReputationEventSeverity.Medium,
            -8,
            ReporterTrustLevel.Verified,
            reason,
            createdAtUtc,
            createdAtUtc.AddDays(30),
            false,
            false);
}
