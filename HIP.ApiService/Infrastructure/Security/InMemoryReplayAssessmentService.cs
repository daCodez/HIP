using System.Collections.Concurrent;
using HIP.ApiService.Application.Abstractions;

namespace HIP.ApiService.Infrastructure.Security;

public sealed class InMemoryReplayAssessmentService : IReplayAssessmentService
{
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(10);
    private readonly ConcurrentDictionary<string, ConcurrentQueue<DateTimeOffset>> _replaysByIdentity = new();

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
