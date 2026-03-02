using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Infrastructure.Persistence;
using HIP.ApiService.Infrastructure.Reputation;
using HIP.ApiService.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace HIP.Tests.Infrastructure;

public sealed class TokenAndReplayCoverageTests
{
    [Test]
    public async Task JarvisTokenService_IssueValidateRefreshRevoke_CoversCorePaths()
    {
        await using var db = CreateDb();
        var keyPolicy = new InMemoryKeyRotationPolicy();
        var service = new InMemoryJarvisTokenService(keyPolicy, db);

        var issued = await service.IssueAsync(new TokenIssueRequest("hip-system", "aud-1", "dev-1"), CancellationToken.None);
        Assert.That(issued.AccessToken, Is.Not.Empty);
        Assert.That(issued.RefreshToken, Does.StartWith("rtk_"));

        var valid = await service.ValidateAsync(new TokenValidationRequest(issued.AccessToken, "aud-1", "dev-1"), CancellationToken.None);
        Assert.That(valid.IsValid, Is.True);

        var badAudience = await service.ValidateAsync(new TokenValidationRequest(issued.AccessToken, "aud-x", "dev-1"), CancellationToken.None);
        Assert.That(badAudience.IsValid, Is.False);
        Assert.That(badAudience.Reason, Is.EqualTo("policy.invalidAudience"));

        var badDevice = await service.ValidateAsync(new TokenValidationRequest(issued.AccessToken, "aud-1", "dev-x"), CancellationToken.None);
        Assert.That(badDevice.IsValid, Is.False);
        Assert.That(badDevice.Reason, Is.EqualTo("device_mismatch"));

        var refreshed = await service.RefreshAsync(new TokenRefreshRequest(issued.RefreshToken), CancellationToken.None);
        Assert.That(refreshed.Success, Is.True);
        Assert.That(refreshed.TokenSet, Is.Not.Null);

        var refreshMissing = await service.RefreshAsync(new TokenRefreshRequest("rtk_missing"), CancellationToken.None);
        Assert.That(refreshMissing.Success, Is.False);

        var revokedNone = await service.RevokeAsync(new TokenRevokeRequest(null, null, null), CancellationToken.None);
        Assert.That(revokedNone.Success, Is.False);

        var revokedIdentity = await service.RevokeAsync(new TokenRevokeRequest(null, null, "hip-system"), CancellationToken.None);
        Assert.That(revokedIdentity.Success, Is.True);

        var revokedAccess = await service.RevokeAsync(new TokenRevokeRequest(issued.AccessToken, null, null), CancellationToken.None);
        Assert.That(revokedAccess.Success, Is.True);

        // soft revoke path
        var softRevoked = await service.ValidateAsync(new TokenValidationRequest(issued.AccessToken, "aud-1", "dev-1"), CancellationToken.None);
        Assert.That(softRevoked.IsValid, Is.False);
        Assert.That(softRevoked.Reason, Is.EqualTo("soft_revoked"));
    }

    [Test]
    public async Task JarvisTokenService_ProofToken_CoversIssueConsumeBranches()
    {
        await using var db = CreateDb();
        var service = new InMemoryJarvisTokenService(new InMemoryKeyRotationPolicy(), db);

        var badTtl = await service.IssueProofTokenAsync(new ProofTokenIssueRequest("hip", "aud", "dev", "act", TimeSpan.FromMinutes(10)), CancellationToken.None);
        Assert.That(badTtl.Success, Is.False);

        var proof = await service.IssueProofTokenAsync(new ProofTokenIssueRequest("hip", "aud", "dev", "act", TimeSpan.FromSeconds(30)), CancellationToken.None);
        Assert.That(proof.Success, Is.True);

        var actionMismatch = await service.ConsumeProofTokenAsync(new ProofTokenConsumeRequest(proof.ProofToken!, "act2", "aud", "dev"), CancellationToken.None);
        Assert.That(actionMismatch.Success, Is.False);
        Assert.That(actionMismatch.Reason, Is.EqualTo("action_mismatch"));

        var consumed = await service.ConsumeProofTokenAsync(new ProofTokenConsumeRequest(proof.ProofToken!, "act", "aud", "dev"), CancellationToken.None);
        Assert.That(consumed.Success, Is.True);

        var consumedAgain = await service.ConsumeProofTokenAsync(new ProofTokenConsumeRequest(proof.ProofToken!, "act", "aud", "dev"), CancellationToken.None);
        Assert.That(consumedAgain.Success, Is.False);
        Assert.That(consumedAgain.Reason, Is.EqualTo("already_used"));
    }

    [Test]
    public async Task ReplayServices_CoverNominalAndAbusePaths()
    {
        await using var db = CreateDb();
        var replayProtection = new InMemoryReplayProtectionService(db);

        Assert.That(await replayProtection.TryConsumeAsync("m1", "id1", CancellationToken.None), Is.True);
        Assert.That(await replayProtection.TryConsumeAsync("m1", "id1", CancellationToken.None), Is.False);
        Assert.That(await replayProtection.TryConsumeAsync("", "id1", CancellationToken.None), Is.False);

        var assessment = new InMemoryReplayAssessmentService();
        ReplayAssessment last = default!;
        for (var i = 0; i < 5; i++)
        {
            last = assessment.RegisterReplay("id1", $"m{i}");
        }

        Assert.That(last.ShouldPenalize, Is.True);
        Assert.That(last.Classification, Is.EqualTo("abuse_suspected"));
    }

    [Test]
    public async Task DatabaseReputationService_RecordSecurityEvent_PersistsDurableEvent()
    {
        await using var db = CreateDb();
        var service = new DatabaseReputationService(db, NullLogger<DatabaseReputationService>.Instance);

        await service.RecordSecurityEventAsync("hip-system", "policy_blocked", CancellationToken.None);

        var events = await db.ReputationEvents
            .Where(x => x.IdentityId == "hip-system" && x.EventType == "policy_blocked")
            .ToListAsync(CancellationToken.None);

        Assert.That(events, Has.Count.EqualTo(1));
        Assert.That(events[0].CreatedAtUtc, Is.Not.EqualTo(default(DateTimeOffset)));
    }

    [Test]
    public async Task DatabaseReputationService_GetScore_RecentSecurityEventsPenalizeMoreThanOldEvents()
    {
        await using var db = CreateDb();
        db.ReputationSignals.Add(new ReputationSignalRecord
        {
            IdentityId = "decay-user",
            AcceptanceRatio = 0,
            FeedbackScore = 0,
            DaysActive = 0,
            AbuseReports = 0,
            AuthFailures = 0,
            SpamFlags = 0,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        });
        await db.SaveChangesAsync(CancellationToken.None);

        var service = new DatabaseReputationService(db, NullLogger<DatabaseReputationService>.Instance);

        db.ReputationEvents.Add(new ReputationEventRecord
        {
            IdentityId = "decay-user",
            EventType = "replay_abuse",
            CreatedAtUtc = DateTimeOffset.UtcNow
        });
        await db.SaveChangesAsync(CancellationToken.None);

        var recentScore = await service.GetScoreAsync("decay-user", CancellationToken.None);

        db.ReputationEvents.RemoveRange(db.ReputationEvents.Where(x => x.IdentityId == "decay-user"));
        db.ReputationEvents.Add(new ReputationEventRecord
        {
            IdentityId = "decay-user",
            EventType = "replay_abuse",
            CreatedAtUtc = DateTimeOffset.UtcNow.AddDays(-60)
        });
        await db.SaveChangesAsync(CancellationToken.None);

        var oldScore = await service.GetScoreAsync("decay-user", CancellationToken.None);

        Assert.That(recentScore, Is.LessThan(oldScore));
    }

    [Test]
    public async Task DatabaseReputationService_RepeatedReplayAbuse_ProgressivelyLowersScore()
    {
        await using var db = CreateDb();
        db.ReputationSignals.Add(new ReputationSignalRecord
        {
            IdentityId = "abuse-user",
            AcceptanceRatio = 0,
            FeedbackScore = 0,
            DaysActive = 0,
            AbuseReports = 0,
            AuthFailures = 0,
            SpamFlags = 0,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        });
        await db.SaveChangesAsync(CancellationToken.None);

        var service = new DatabaseReputationService(db, NullLogger<DatabaseReputationService>.Instance);

        var baseline = await service.GetScoreAsync("abuse-user", CancellationToken.None);
        await service.RecordSecurityEventAsync("abuse-user", "replay_abuse", CancellationToken.None);
        var afterOne = await service.GetScoreAsync("abuse-user", CancellationToken.None);
        await service.RecordSecurityEventAsync("abuse-user", "replay_abuse", CancellationToken.None);
        var afterTwo = await service.GetScoreAsync("abuse-user", CancellationToken.None);

        Assert.That(afterOne, Is.LessThan(baseline));
        Assert.That(afterTwo, Is.LessThan(afterOne));
    }

    [Test]
    public async Task DatabaseReputationService_ReplayBenign_DoesNotAddEventPenalty()
    {
        await using var db = CreateDb();
        db.ReputationSignals.Add(new ReputationSignalRecord
        {
            IdentityId = "benign-user",
            AcceptanceRatio = 0,
            FeedbackScore = 0,
            DaysActive = 0,
            AbuseReports = 0,
            AuthFailures = 0,
            SpamFlags = 0,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        });
        await db.SaveChangesAsync(CancellationToken.None);

        var service = new DatabaseReputationService(db, NullLogger<DatabaseReputationService>.Instance);
        await service.RecordSecurityEventAsync("benign-user", "replay_benign", CancellationToken.None);

        var breakdown = await service.GetScoreBreakdownAsync("benign-user", CancellationToken.None);

        Assert.That(breakdown.EventCount, Is.EqualTo(1));
        Assert.That(breakdown.EventPenaltyComponent, Is.EqualTo(0).Within(0.0001));
    }

    private static HipDbContext CreateDb()
    {
        var conn = new SqliteConnection("DataSource=:memory:");
        conn.Open();
        var options = new DbContextOptionsBuilder<HipDbContext>().UseSqlite(conn).Options;
        var db = new HipDbContext(options);
        db.Database.EnsureCreated();
        return db;
    }
}
