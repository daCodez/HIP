using Microsoft.EntityFrameworkCore;

namespace HIP.ApiService.Infrastructure.Persistence;

/// <summary>
/// Represents the Entity Framework database context used by HIP.ApiService to persist
/// identities, reputation signals, refresh tokens, proof-token consumption records, and replay nonces.
/// </summary>
/// <param name="options">
/// The context options that configure the provider, connection, and runtime behavior for this context.
/// </param>
public sealed class HipDbContext(DbContextOptions<HipDbContext> options) : DbContext(options)
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <returns>The operation result.</returns>
    public DbSet<IdentityRecord> Identities => Set<IdentityRecord>();
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <returns>The operation result.</returns>
    public DbSet<ReputationSignalRecord> ReputationSignals => Set<ReputationSignalRecord>();
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <returns>The operation result.</returns>
    public DbSet<RefreshTokenRecord> RefreshTokens => Set<RefreshTokenRecord>();
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <returns>The operation result.</returns>
    public DbSet<ConsumedProofTokenRecord> ConsumedProofTokens => Set<ConsumedProofTokenRecord>();
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <returns>The operation result.</returns>
    public DbSet<ReplayNonceRecord> ReplayNonces => Set<ReplayNonceRecord>();
    /// <summary>
    /// Durable audit event records used for security/policy observability.
    /// </summary>
    /// <returns>The operation result.</returns>
    public DbSet<AuditEventRecord> AuditEvents => Set<AuditEventRecord>();
    /// <summary>
    /// Durable reputation-impacting event records.
    /// </summary>
    public DbSet<ReputationEventRecord> ReputationEvents => Set<ReputationEventRecord>();

    /// <summary>
    /// Configures entity mappings, table names, key constraints, and property limits for HIP persistence models.
    /// </summary>
    /// <param name="modelBuilder">The model builder used to configure EF Core entity metadata.</param>
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

        var audit = modelBuilder.Entity<AuditEventRecord>();
        audit.ToTable("audit_events");
        audit.HasKey(x => x.Id);
        audit.Property(x => x.Id).HasMaxLength(64);
        audit.Property(x => x.CreatedAtUtc).IsRequired();
        audit.Property(x => x.EventType).HasMaxLength(128).IsRequired();
        audit.Property(x => x.Subject).HasMaxLength(128).IsRequired();
        audit.Property(x => x.Source).HasMaxLength(64).IsRequired();
        audit.Property(x => x.Detail).HasMaxLength(512).IsRequired();
        audit.Property(x => x.Category).HasMaxLength(64);
        audit.Property(x => x.Outcome).HasMaxLength(32);
        audit.Property(x => x.ReasonCode).HasMaxLength(128);
        audit.Property(x => x.Route).HasMaxLength(256);
        audit.Property(x => x.CorrelationId).HasMaxLength(128);

        audit.HasIndex(x => x.CreatedAtUtc);
        audit.HasIndex(x => x.EventType);
        audit.HasIndex(x => x.Subject);
        audit.HasIndex(x => x.Outcome);
        audit.HasIndex(x => x.ReasonCode);

        var reputationEvent = modelBuilder.Entity<ReputationEventRecord>();
        reputationEvent.ToTable("reputation_events");
        reputationEvent.HasKey(x => x.Id);
        reputationEvent.Property(x => x.Id).HasMaxLength(64);
        reputationEvent.Property(x => x.IdentityId).HasMaxLength(64).IsRequired();
        reputationEvent.Property(x => x.EventType).HasMaxLength(64).IsRequired();
        reputationEvent.Property(x => x.CreatedAtUtc).IsRequired();
        reputationEvent.HasIndex(x => x.IdentityId);
        reputationEvent.HasIndex(x => x.EventType);
        reputationEvent.HasIndex(x => x.CreatedAtUtc);
    }
}
