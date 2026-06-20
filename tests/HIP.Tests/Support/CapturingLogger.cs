using Microsoft.Extensions.Logging;

namespace HIP.Tests.Support;

/// <summary>
/// Captures formatted log entries so tests can verify that important paths emit useful diagnostics.
/// </summary>
/// <typeparam name="T">Logger category type being captured.</typeparam>
public sealed class CapturingLogger<T> : ILogger<T>
{
    /// <summary>
    /// Gets the captured log entries in write order.
    /// </summary>
    public List<CapturedLogEntry> Entries { get; } = [];

    /// <summary>
    /// Gets the formatted log messages without levels or exceptions.
    /// </summary>
    public IReadOnlyCollection<string> Messages => Entries.Select(entry => entry.Message).ToArray();

    /// <inheritdoc />
    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull =>
        null;

    /// <inheritdoc />
    public bool IsEnabled(LogLevel logLevel) => true;

    /// <inheritdoc />
    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        Entries.Add(new CapturedLogEntry(logLevel, eventId, formatter(state, exception), exception));
    }
}

/// <summary>
/// Immutable log entry captured by <see cref="CapturingLogger{T}"/>.
/// </summary>
/// <param name="LogLevel">Log severity.</param>
/// <param name="EventId">Optional event identifier.</param>
/// <param name="Message">Formatted log message.</param>
/// <param name="Exception">Exception attached to the log entry, when present.</param>
public sealed record CapturedLogEntry(
    LogLevel LogLevel,
    EventId EventId,
    string Message,
    Exception? Exception);
