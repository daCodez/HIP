using Microsoft.EntityFrameworkCore;

namespace HIP.ApiService.Infrastructure.Persistence;

public static class HipDbInitializer
{
    public static async Task InitializeAsync(IServiceProvider services, CancellationToken cancellationToken)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<HipDbContext>();

        await db.Database.EnsureCreatedAsync(cancellationToken);

        await db.Database.ExecuteSqlRawAsync(
            """
            CREATE TABLE IF NOT EXISTS reputation_signals (
              IdentityId TEXT NOT NULL PRIMARY KEY,
              AcceptanceRatio REAL NOT NULL,
              FeedbackScore REAL NOT NULL,
              DaysActive INTEGER NOT NULL,
              AbuseReports INTEGER NOT NULL,
              AuthFailures INTEGER NOT NULL,
              SpamFlags INTEGER NOT NULL,
              UpdatedAtUtc TEXT NOT NULL
            );
            """,
            cancellationToken);

        await db.Database.ExecuteSqlRawAsync(
            """
            CREATE TABLE IF NOT EXISTS refresh_tokens (
              TokenHash TEXT NOT NULL PRIMARY KEY,
              IdentityId TEXT NOT NULL,
              Audience TEXT NOT NULL,
              DeviceId TEXT NULL,
              KeyId TEXT NOT NULL,
              Version INTEGER NOT NULL,
              ExpiresAtUtc TEXT NOT NULL,
              CreatedAtUtc TEXT NOT NULL
            );
            """,
            cancellationToken);

        await db.Database.ExecuteSqlRawAsync(
            """
            CREATE TABLE IF NOT EXISTS consumed_proof_tokens (
              Jti TEXT NOT NULL PRIMARY KEY,
              IdentityId TEXT NOT NULL,
              Action TEXT NOT NULL,
              ExpiresAtUtc TEXT NOT NULL,
              ConsumedAtUtc TEXT NOT NULL
            );
            """,
            cancellationToken);

        await db.Database.ExecuteSqlRawAsync(
            """
            CREATE TABLE IF NOT EXISTS replay_nonces (
              MessageId TEXT NOT NULL PRIMARY KEY,
              IdentityId TEXT NOT NULL,
              ExpiresAtUtc TEXT NOT NULL,
              CreatedAtUtc TEXT NOT NULL
            );
            """,
            cancellationToken);

        var identityExists = await db.Identities.AnyAsync(x => x.Id == "hip-system", cancellationToken);
        if (!identityExists)
        {
            db.Identities.Add(new IdentityRecord
            {
                Id = "hip-system",
                PublicKeyRef = "pkref:placeholder",
                CreatedAtUtc = DateTimeOffset.UtcNow
            });
        }

        var reputationExists = await db.ReputationSignals.AnyAsync(x => x.IdentityId == "hip-system", cancellationToken);
        if (!reputationExists)
        {
            db.ReputationSignals.Add(new ReputationSignalRecord
            {
                IdentityId = "hip-system",
                AcceptanceRatio = 0,
                FeedbackScore = 0,
                DaysActive = 0,
                AbuseReports = 0,
                AuthFailures = 0,
                SpamFlags = 0,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            });
        }

        await db.SaveChangesAsync(cancellationToken);
    }
}
