using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace HIP.Application.Security;

/// <summary>
/// Tracks recent public submissions so obvious repeated payloads can be ignored before they flood storage or review.
/// </summary>
public interface IDuplicateSubmissionGuard
{
    /// <summary>
    /// Attempts to accept a submission fingerprint for a short duplicate window.
    /// </summary>
    /// <param name="scope">Submission scope, such as browser-scan or public-feedback.</param>
    /// <param name="parts">Privacy-safe values used to build the duplicate fingerprint.</param>
    /// <param name="window">How long identical submissions should be treated as duplicates.</param>
    /// <returns>True when the submission is new enough to process.</returns>
    bool TryAccept(string scope, IEnumerable<string?> parts, TimeSpan window);
}

/// <summary>
/// In-memory duplicate submission guard for the single-node MVP.
/// </summary>
/// <remarks>
/// This is intentionally lightweight and local. It is not a distributed abuse-control system, but it prevents rapid
/// duplicate browser scans and feedback bursts during development and early testing.
/// </remarks>
public sealed class InMemoryDuplicateSubmissionGuard : IDuplicateSubmissionGuard
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> acceptedUntil = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public bool TryAccept(string scope, IEnumerable<string?> parts, TimeSpan window)
    {
        var now = DateTimeOffset.UtcNow;
        Cleanup(now);
        var key = Fingerprint(scope, parts);
        var expiresAt = now.Add(window);
        if (acceptedUntil.TryAdd(key, expiresAt))
        {
            return true;
        }

        if (acceptedUntil.TryGetValue(key, out var existing) && existing > now)
        {
            return false;
        }

        acceptedUntil[key] = expiresAt;
        return true;
    }

    /// <summary>
    /// Builds a stable duplicate fingerprint without storing raw submitted content as dictionary keys.
    /// </summary>
    /// <param name="scope">Submission scope.</param>
    /// <param name="parts">Privacy-safe values.</param>
    /// <returns>Duplicate fingerprint.</returns>
    private static string Fingerprint(string scope, IEnumerable<string?> parts)
    {
        var joined = string.Join("|", parts.Select(part => (part ?? string.Empty).Trim().ToLowerInvariant()));
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"{scope}|{joined}"));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>
    /// Removes expired duplicate fingerprints to keep local memory bounded.
    /// </summary>
    /// <param name="now">Current UTC timestamp.</param>
    private void Cleanup(DateTimeOffset now)
    {
        foreach (var (key, expiresAt) in acceptedUntil.Where(entry => entry.Value <= now).Take(100))
        {
            acceptedUntil.TryRemove(key, out _);
        }
    }
}
