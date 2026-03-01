using System.Collections.Concurrent;
using HIP.ApiService.Application.Abstractions;

namespace HIP.ApiService.Infrastructure.Security;

/// <summary>
/// Represents a publicly visible API member.
/// </summary>
public sealed class InMemorySecurityRejectLog : ISecurityRejectLog
{
    private const int MaxEvents = 300;
    private readonly ConcurrentQueue<SecurityRejectEvent> _events = new();

    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="evt">The evt value used by this operation.</param>
    public void Add(SecurityRejectEvent evt)
    {
        _events.Enqueue(evt);
        while (_events.Count > MaxEvents && _events.TryDequeue(out _)) { }
    }

    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="take">The take value used by this operation.</param>
    /// <returns>The operation result.</returns>
    public IReadOnlyList<SecurityRejectEvent> Recent(int take)
    {
        var count = Math.Clamp(take, 1, 100);
        var snapshot = _events.ToArray();
        var slice = snapshot.TakeLast(count).Reverse().ToArray();
        return slice;
    }
}
