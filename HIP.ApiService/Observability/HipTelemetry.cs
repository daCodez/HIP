using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace HIP.ApiService.Observability;

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
}
