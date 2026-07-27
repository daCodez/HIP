using System.Collections.Concurrent;
using HIP.Domain.Reporting;

namespace HIP.Application.Reporting;

/// <summary>
/// Keeps accepted privacy-safe reports available across request scopes.
/// </summary>
public sealed class PrivacySafeReportStore
{
    internal ConcurrentDictionary<string, PrivacySafeReport> Reports { get; } =
        new(StringComparer.OrdinalIgnoreCase);
}
