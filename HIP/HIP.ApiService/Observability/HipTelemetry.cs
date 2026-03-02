using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace HIP.ApiService.Observability;

/// <summary>
/// Centralized OpenTelemetry metric emitters for HIP API observability.
/// </summary>
public static class HipTelemetry
{
    private static readonly Meter Meter = new("HIP.ApiService", "1.0.0");

    private static readonly Counter<long> Requests = Meter.CreateCounter<long>(
        name: "hip_requests_total",
        unit: "requests",
        description: "Total HIP API operations by feature/result.");

    private static readonly Histogram<double> DurationMs = Meter.CreateHistogram<double>(
        name: "hip_request_duration_ms",
        unit: "ms",
        description: "HIP API operation duration in milliseconds.");

    private static readonly Histogram<long> RequestBodyBytes = Meter.CreateHistogram<long>(
        name: "hip_http_request_body_bytes",
        unit: "By",
        description: "Observed HIP HTTP request body size in bytes (sampled).");

    /// <summary>
    /// Records a logical operation request count and duration metric.
    /// </summary>
    /// <param name="operation">Operation name tag.</param>
    /// <param name="result">Operation result tag.</param>
    /// <param name="durationMs">Operation duration in milliseconds.</param>
    public static void Record(string operation, string result, double durationMs)
    {
        var tags = new TagList
        {
            { "operation", operation },
            { "result", result }
        };

        Requests.Add(1, tags);
        DurationMs.Record(durationMs, tags);
    }

    /// <summary>
    /// Records sampled HTTP request body size metrics for endpoint capacity analysis.
    /// </summary>
    /// <param name="bytes">Request body size in bytes.</param>
    /// <param name="route">Route template tag.</param>
    /// <param name="method">HTTP method tag.</param>
    /// <param name="statusClass">HTTP status class tag (for example: 2xx, 4xx).</param>
    public static void RecordHttpRequestSize(long bytes, string route, string method, string statusClass)
    {
        var tags = new TagList
        {
            { "route", route },
            { "method", method },
            { "status_class", statusClass }
        };

        RequestBodyBytes.Record(bytes, tags);
    }
}
