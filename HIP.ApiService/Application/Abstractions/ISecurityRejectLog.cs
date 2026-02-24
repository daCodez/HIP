namespace HIP.ApiService.Application.Abstractions;

public interface ISecurityRejectLog
{
    void Add(SecurityRejectEvent evt);
    IReadOnlyList<SecurityRejectEvent> Recent(int take);
}

public sealed record SecurityRejectEvent(
    string Reason,
    string IdentityId,
    string? MessageId,
    double? ClockSkewSeconds,
    string? Classification,
    DateTimeOffset UtcTimestamp);
