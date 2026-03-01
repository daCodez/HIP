using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;

namespace HIP.ApiService.Infrastructure.Persistence;

/// <summary>
/// Represents a publicly visible API member.
/// </summary>
public static class HipDbInitializer
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="services">The services value used by this operation.</param>
    /// <param name="cancellationToken">The cancellationToken value used by this operation.</param>
    /// <returns>The operation result.</returns>
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

        await db.Database.ExecuteSqlRawAsync(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
              Id TEXT NOT NULL PRIMARY KEY,
              CreatedAtUtc TEXT NOT NULL,
              EventType TEXT NOT NULL,
              Subject TEXT NOT NULL,
              Source TEXT NOT NULL,
              Detail TEXT NOT NULL,
              Category TEXT NULL,
              Outcome TEXT NULL,
              ReasonCode TEXT NULL,
              Route TEXT NULL,
              CorrelationId TEXT NULL,
              LatencyMs REAL NULL
            );
            """,
            cancellationToken);

        var now = DateTimeOffset.UtcNow;

        var identityExists = await db.Identities.AnyAsync(x => x.Id == "hip-system", cancellationToken);
        if (!identityExists)
        {
            db.Identities.Add(new IdentityRecord
            {
                Id = "hip-system",
                PublicKeyRef = "pkref:placeholder",
                CreatedAtUtc = now
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
                UpdatedAtUtc = now
            });
        }

        var environment = scope.ServiceProvider.GetRequiredService<IHostEnvironment>();
        if (environment.IsDevelopment())
        {
            var seedIdentities = new[]
            {
                (Id: "hip-system", PublicKeyRef: "pkref:hip-system-main"),
                (Id: "alpha-node", PublicKeyRef: "pkref:alpha-node-main"),
                (Id: "beta-node", PublicKeyRef: "pkref:beta-node-main"),
                (Id: "gamma-node", PublicKeyRef: "pkref:gamma-node-main")
            };

            foreach (var seed in seedIdentities)
            {
                var identity = await db.Identities.FirstOrDefaultAsync(x => x.Id == seed.Id, cancellationToken);
                if (identity is null)
                {
                    db.Identities.Add(new IdentityRecord
                    {
                        Id = seed.Id,
                        PublicKeyRef = seed.PublicKeyRef,
                        CreatedAtUtc = now
                    });
                }
                else
                {
                    identity.PublicKeyRef = seed.PublicKeyRef;
                }
            }

            var seedReputation = new[]
            {
                new ReputationSignalRecord { IdentityId = "hip-system", AcceptanceRatio = 0.94, FeedbackScore = 0.88, DaysActive = 420, AbuseReports = 0, AuthFailures = 1, SpamFlags = 0, UpdatedAtUtc = now },
                new ReputationSignalRecord { IdentityId = "alpha-node", AcceptanceRatio = 0.87, FeedbackScore = 0.82, DaysActive = 180, AbuseReports = 1, AuthFailures = 2, SpamFlags = 0, UpdatedAtUtc = now },
                new ReputationSignalRecord { IdentityId = "beta-node", AcceptanceRatio = 0.76, FeedbackScore = 0.71, DaysActive = 95, AbuseReports = 2, AuthFailures = 4, SpamFlags = 1, UpdatedAtUtc = now },
                new ReputationSignalRecord { IdentityId = "gamma-node", AcceptanceRatio = 0.63, FeedbackScore = 0.59, DaysActive = 40, AbuseReports = 4, AuthFailures = 7, SpamFlags = 2, UpdatedAtUtc = now }
            };

            foreach (var seed in seedReputation)
            {
                var record = await db.ReputationSignals.FirstOrDefaultAsync(x => x.IdentityId == seed.IdentityId, cancellationToken);
                if (record is null)
                {
                    db.ReputationSignals.Add(seed);
                }
                else
                {
                    record.AcceptanceRatio = seed.AcceptanceRatio;
                    record.FeedbackScore = seed.FeedbackScore;
                    record.DaysActive = seed.DaysActive;
                    record.AbuseReports = seed.AbuseReports;
                    record.AuthFailures = seed.AuthFailures;
                    record.SpamFlags = seed.SpamFlags;
                    record.UpdatedAtUtc = now;
                }
            }

            if (!await db.ReplayNonces.AnyAsync(cancellationToken))
            {
                db.ReplayNonces.AddRange(
                    new ReplayNonceRecord { MessageId = "msg-demo-001", IdentityId = "alpha-node", ExpiresAtUtc = now.AddMinutes(20), CreatedAtUtc = now.AddMinutes(-2) },
                    new ReplayNonceRecord { MessageId = "msg-demo-002", IdentityId = "beta-node", ExpiresAtUtc = now.AddMinutes(20), CreatedAtUtc = now.AddMinutes(-1) },
                    new ReplayNonceRecord { MessageId = "msg-demo-003", IdentityId = "gamma-node", ExpiresAtUtc = now.AddMinutes(20), CreatedAtUtc = now }
                );
            }

            if (!await db.ConsumedProofTokens.AnyAsync(cancellationToken))
            {
                db.ConsumedProofTokens.AddRange(
                    new ConsumedProofTokenRecord { Jti = "jti-demo-001", IdentityId = "alpha-node", Action = "tool-access", ExpiresAtUtc = now.AddMinutes(10), ConsumedAtUtc = now.AddMinutes(-5) },
                    new ConsumedProofTokenRecord { Jti = "jti-demo-002", IdentityId = "beta-node", Action = "policy-evaluate", ExpiresAtUtc = now.AddMinutes(10), ConsumedAtUtc = now.AddMinutes(-3) }
                );
            }

            if (!await db.RefreshTokens.AnyAsync(cancellationToken))
            {
                db.RefreshTokens.AddRange(
                    new RefreshTokenRecord { TokenHash = "rt-demo-hash-001", IdentityId = "alpha-node", Audience = "jarvis", DeviceId = "webchat-dev", KeyId = "hip-system", Version = 1, ExpiresAtUtc = now.AddDays(7), CreatedAtUtc = now.AddDays(-2) },
                    new RefreshTokenRecord { TokenHash = "rt-demo-hash-002", IdentityId = "beta-node", Audience = "jarvis", DeviceId = "telegram-dev", KeyId = "hip-system", Version = 2, ExpiresAtUtc = now.AddDays(3), CreatedAtUtc = now.AddDays(-1) }
                );
            }
        }

        await db.SaveChangesAsync(cancellationToken);
    }
}
