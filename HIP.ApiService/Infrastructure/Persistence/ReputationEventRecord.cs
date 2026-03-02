namespace HIP.ApiService.Infrastructure.Persistence;

/// <summary>
/// Durable record of reputation-impacting security events.
/// </summary>
public sealed class ReputationEventRecord
{
    /// <summary>Event identifier.</summary>
    public string Id { get; set; } = Guid.NewGuid().ToString("n");

    /// <summary>Identity associated with this event.</summary>
    public required string IdentityId { get; set; }

    /// <summary>Event type (for example: replay_abuse, policy_blocked).</summary>
    public required string EventType { get; set; }

    /// <summary>Event creation timestamp.</summary>
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}
