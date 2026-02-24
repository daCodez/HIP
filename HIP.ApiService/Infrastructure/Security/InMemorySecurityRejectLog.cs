using System.Collections.Concurrent;
using HIP.ApiService.Application.Abstractions;

namespace HIP.ApiService.Infrastructure.Security;

public sealed class InMemorySecurityRejectLog : ISecurityRejectLog
{
    private const int MaxEvents = 300;
    private readonly ConcurrentQueue<SecurityRejectEvent> _events = new();

    public void Add(SecurityRejectEvent evt)
    {
        _events.Enqueue(evt);
        while (_events.Count > MaxEvents && _events.TryDequeue(out _)) { }
    }

    public IReadOnlyList<SecurityRejectEvent> Recent(int take)
    {
        var count = Math.Clamp(take, 1, 100);
        var snapshot = _events.ToArray();
        var slice = snapshot.TakeLast(count).Reverse().ToArray();
        return slice;
    }
}
