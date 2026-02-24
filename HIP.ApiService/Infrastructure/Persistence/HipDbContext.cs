using Microsoft.EntityFrameworkCore;

namespace HIP.ApiService.Infrastructure.Persistence;

public sealed class HipDbContext(DbContextOptions<HipDbContext> options) : DbContext(options)
{
    public DbSet<IdentityRecord> Identities => Set<IdentityRecord>();
    public DbSet<ReputationSignalRecord> ReputationSignals => Set<ReputationSignalRecord>();
    public DbSet<RefreshTokenRecord> RefreshTokens => Set<RefreshTokenRecord>();
    public DbSet<ConsumedProofTokenRecord> ConsumedProofTokens => Set<ConsumedProofTokenRecord>();
    public DbSet<ReplayNonceRecord> ReplayNonces => Set<ReplayNonceRecord>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        var identity = modelBuilder.Entity<IdentityRecord>();
        identity.ToTable("identities");
        identity.HasKey(x => x.Id);
        identity.Property(x => x.Id).HasMaxLength(64);
        identity.Property(x => x.PublicKeyRef).HasMaxLength(256).IsRequired();
        identity.Property(x => x.CreatedAtUtc).IsRequired();

        var reputation = modelBuilder.Entity<ReputationSignalRecord>();
        reputation.ToTable("reputation_signals");
        reputation.HasKey(x => x.IdentityId);
        reputation.Property(x => x.IdentityId).HasMaxLength(64);
        reputation.Property(x => x.AcceptanceRatio).IsRequired();
        reputation.Property(x => x.FeedbackScore).IsRequired();
        reputation.Property(x => x.DaysActive).IsRequired();
        reputation.Property(x => x.AbuseReports).IsRequired();
        reputation.Property(x => x.AuthFailures).IsRequired();
        reputation.Property(x => x.SpamFlags).IsRequired();
        reputation.Property(x => x.UpdatedAtUtc).IsRequired();

        var refresh = modelBuilder.Entity<RefreshTokenRecord>();
        refresh.ToTable("refresh_tokens");
        refresh.HasKey(x => x.TokenHash);
        refresh.Property(x => x.TokenHash).HasMaxLength(128);
        refresh.Property(x => x.IdentityId).HasMaxLength(64).IsRequired();
        refresh.Property(x => x.Audience).HasMaxLength(128).IsRequired();
        refresh.Property(x => x.DeviceId).HasMaxLength(128);
        refresh.Property(x => x.KeyId).HasMaxLength(64).IsRequired();
        refresh.Property(x => x.Version).IsRequired();
        refresh.Property(x => x.ExpiresAtUtc).IsRequired();
        refresh.Property(x => x.CreatedAtUtc).IsRequired();

        var proof = modelBuilder.Entity<ConsumedProofTokenRecord>();
        proof.ToTable("consumed_proof_tokens");
        proof.HasKey(x => x.Jti);
        proof.Property(x => x.Jti).HasMaxLength(64);
        proof.Property(x => x.IdentityId).HasMaxLength(64).IsRequired();
        proof.Property(x => x.Action).HasMaxLength(128).IsRequired();
        proof.Property(x => x.ExpiresAtUtc).IsRequired();
        proof.Property(x => x.ConsumedAtUtc).IsRequired();

        var replay = modelBuilder.Entity<ReplayNonceRecord>();
        replay.ToTable("replay_nonces");
        replay.HasKey(x => x.MessageId);
        replay.Property(x => x.MessageId).HasMaxLength(128);
        replay.Property(x => x.IdentityId).HasMaxLength(64).IsRequired();
        replay.Property(x => x.ExpiresAtUtc).IsRequired();
        replay.Property(x => x.CreatedAtUtc).IsRequired();
    }
}
