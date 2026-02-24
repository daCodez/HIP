using System.Collections.Concurrent;
using HIP.ApiService.Application.Abstractions;

namespace HIP.ApiService.Infrastructure.Security;

public sealed class InMemoryReplayProtectionService : IReplayProtectionService
{
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(15);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _seen = new();

    public bool TryConsume(string messageId)
    {
        if (string.IsNullOrWhiteSpace(messageId))
        {
            return false;
        }

        var now = DateTimeOffset.UtcNow;
        SweepExpired(now);

        return _seen.TryAdd(messageId, now.Add(Ttl));
    }

    private void SweepExpired(DateTimeOffset now)
    {
        foreach (var kvp in _seen)
        {
            if (kvp.Value <= now)
            {
                _seen.TryRemove(kvp.Key, out _);
            }
        }
    }
}
