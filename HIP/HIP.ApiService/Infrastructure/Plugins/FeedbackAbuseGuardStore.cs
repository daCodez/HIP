using System.Collections.Concurrent;

namespace HIP.ApiService.Infrastructure.Plugins;

/// <summary>
/// Tracks recent feedback submissions to suppress duplicates and rate abuse.
/// </summary>
public sealed class FeedbackAbuseGuardStore
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastByReporterSubject = new();
    private readonly ConcurrentDictionary<string, Queue<DateTimeOffset>> _byReporter = new();
    private readonly object _gate = new();

    /// <summary>
    /// Returns true when the same reporter already submitted feedback for the same subject within the window.
    /// </summary>
    public bool IsDuplicate(string reporter, string subject, TimeSpan window, DateTimeOffset now)
    {
        var key = $"{reporter}|{subject}";
        if (_lastByReporterSubject.TryGetValue(key, out var last) && now - last < window)
        {
            return true;
        }

        _lastByReporterSubject[key] = now;
        return false;
    }

    /// <summary>
    /// Returns true when a reporter exceeds the configured per-minute submission limit.
    /// </summary>
    public bool IsRateLimited(string reporter, int maxPerMinute, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (!_byReporter.TryGetValue(reporter, out var q))
            {
                q = new Queue<DateTimeOffset>();
                _byReporter[reporter] = q;
            }

            var cutoff = now.AddMinutes(-1);
            while (q.Count > 0 && q.Peek() < cutoff)
            {
                q.Dequeue();
            }

            if (q.Count >= maxPerMinute)
            {
                return true;
            }

            q.Enqueue(now);
            return false;
        }
    }
}
