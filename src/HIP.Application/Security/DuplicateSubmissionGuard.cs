using System.Security.Cryptography;
using System.Text;

namespace HIP.Application.Security;

/// <summary>
/// Tracks recent public submissions so obvious repeated payloads can be ignored before they flood storage or review.
/// </summary>
public interface IDuplicateSubmissionGuard
{
    /// <summary>
    /// Atomically attempts to accept a submission fingerprint for a short duplicate window.
    /// </summary>
    /// <param name="scope">Submission scope, such as browser-scan or public-feedback.</param>
    /// <param name="parts">Privacy-safe values used to build the duplicate fingerprint.</param>
    /// <param name="window">How long identical submissions should be treated as duplicates.</param>
    /// <param name="cancellationToken">Token used to cancel distributed state access.</param>
    /// <returns>True only when this caller atomically reserved the fingerprint.</returns>
    ValueTask<bool> TryAcceptAsync(
        string scope,
        IEnumerable<string?> parts,
        TimeSpan window,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// In-memory duplicate submission guard for explicit isolated tests.
/// </summary>
public sealed class InMemoryDuplicateSubmissionGuard(TimeProvider? timeProvider = null) : IDuplicateSubmissionGuard
{
    private readonly Dictionary<string, DateTimeOffset> acceptedUntil = new(StringComparer.Ordinal);
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;
    private readonly object sync = new();

    /// <inheritdoc />
    public ValueTask<bool> TryAcceptAsync(
        string scope,
        IEnumerable<string?> parts,
        TimeSpan window,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        SecurityStateValidation.Validate(scope, parts, window);

        var now = clock.GetUtcNow();
        var normalizedParts = parts.Select(part => (part ?? string.Empty).Trim().ToLowerInvariant());
        var key = SecurityStateKey.Fingerprint("duplicate", scope.Trim().ToLowerInvariant(), normalizedParts);
        lock (sync)
        {
            Cleanup(now);
            if (acceptedUntil.TryGetValue(key, out var existing) && existing > now)
            {
                return ValueTask.FromResult(false);
            }

            acceptedUntil[key] = now.Add(window);
            return ValueTask.FromResult(true);
        }
    }

    private void Cleanup(DateTimeOffset now)
    {
        foreach (var key in acceptedUntil
                     .Where(entry => entry.Value <= now)
                     .Take(100)
                     .Select(entry => entry.Key)
                     .ToArray())
        {
            acceptedUntil.Remove(key);
        }
    }
}

/// <summary>
/// Provides privacy-safe keys and validation shared by security-state adapters.
/// </summary>
public static class SecurityStateKey
{
    /// <summary>
    /// Hashes namespaced state parts so raw submissions and nonces never become storage keys.
    /// </summary>
    public static string Fingerprint(string category, string scope, IEnumerable<string?> parts)
    {
        var canonical = new StringBuilder();
        AppendPart(canonical, category);
        AppendPart(canonical, scope);
        foreach (var part in parts)
        {
            AppendPart(canonical, part);
        }

        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(canonical.ToString()));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static void AppendPart(StringBuilder canonical, string? value)
    {
        if (value is null)
        {
            canonical.Append("-1:");
            return;
        }

        canonical.Append(value.Length).Append(':').Append(value);
    }
}

internal static class SecurityStateValidation
{
    public static void Validate(string scope, IEnumerable<string?> parts, TimeSpan window)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);
        ArgumentNullException.ThrowIfNull(parts);
        if (window <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(window), window, "Security-state expiry must be positive.");
        }
    }
}
