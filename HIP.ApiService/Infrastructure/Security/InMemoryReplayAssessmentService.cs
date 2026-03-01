using System.Collections.Concurrent;
using HIP.ApiService.Application.Abstractions;

namespace HIP.ApiService.Infrastructure.Security;

/// <summary>
/// Represents a publicly visible API member.
/// </summary>
public sealed class InMemoryReplayAssessmentService : IReplayAssessmentService
{
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(10);
    private readonly ConcurrentDictionary<string, ConcurrentQueue<DateTimeOffset>> _replaysByIdentity = new();

    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="identityId">The identityId value used by this operation.</param>
    /// <param name="messageId">The messageId value used by this operation.</param>
    /// <returns>The operation result.</returns>
    public ReplayAssessment RegisterReplay(string identityId, string messageId)
    {
        var now = DateTimeOffset.UtcNow;
        var queue = _replaysByIdentity.GetOrAdd(identityId, _ => new ConcurrentQueue<DateTimeOffset>());
        queue.Enqueue(now);

        while (queue.TryPeek(out var ts) && now - ts > Window)
        {
            queue.TryDequeue(out _);
        }

        var count = queue.Count;
        if (count >= 5)
        {
            return new ReplayAssessment("abuse_suspected", count, ShouldPenalize: true);
        }

        return new ReplayAssessment("benign_suspected", count, ShouldPenalize: false);
    }
}
