using System.Diagnostics;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace Microsoft.Extensions.Hosting;

/// <summary>
/// Shared Aspire service defaults for HIP services.
/// </summary>
public static class Extensions
{
    /// <summary>
    /// Adds HIP's shared service-discovery, health-check, structured logging, and OpenTelemetry defaults.
    /// </summary>
    /// <typeparam name="TBuilder">The host application builder type.</typeparam>
    /// <param name="builder">Application builder for a HIP service.</param>
    /// <returns>The same builder so callers can continue composing service registrations.</returns>
    public static TBuilder AddServiceDefaults<TBuilder>(this TBuilder builder)
        where TBuilder : IHostApplicationBuilder
    {
        builder.ConfigureHipStructuredLogging();
        builder.ConfigureHipOpenTelemetry();

        builder.Services.AddServiceDiscovery();
        builder.Services.ConfigureHttpClientDefaults(http =>
        {
            http.AddServiceDiscovery();
        });

        builder.Services.AddHealthChecks();

        return builder;
    }

    /// <summary>
    /// Maps development health endpoints used by Aspire and service probes.
    /// </summary>
    /// <param name="app">The web application to map health endpoints on.</param>
    /// <returns>The same application so endpoint mapping remains composable.</returns>
    public static WebApplication MapDefaultEndpoints(this WebApplication app)
    {
        if (app.Environment.IsDevelopment())
        {
            app.MapHealthChecks("/health");
        }

        app.MapHealthChecks("/alive", new HealthCheckOptions
        {
            Predicate = _ => false
        });

        return app;
    }

    /// <summary>
    /// Configures structured JSON logs and exports OpenTelemetry logs when Aspire provides an OTLP endpoint.
    /// </summary>
    /// <typeparam name="TBuilder">The host application builder type.</typeparam>
    /// <param name="builder">Application builder for a HIP service.</param>
    private static void ConfigureHipStructuredLogging<TBuilder>(this TBuilder builder)
        where TBuilder : IHostApplicationBuilder
    {
        builder.Logging.ClearProviders();
        builder.Logging.AddJsonConsole(options =>
        {
            options.IncludeScopes = true;
            options.TimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";
            options.UseUtcTimestamp = true;
            options.JsonWriterOptions = new JsonWriterOptions { Indented = false };
        });

        builder.Logging.AddOpenTelemetry(logging =>
        {
            logging.IncludeFormattedMessage = true;
            logging.IncludeScopes = true;
            logging.ParseStateValues = true;

            if (HasOtlpEndpoint(builder))
            {
                logging.AddOtlpExporter();
            }
        });
    }

    /// <summary>
    /// Configures OpenTelemetry tracing and metrics for Aspire dashboard correlation.
    /// </summary>
    /// <typeparam name="TBuilder">The host application builder type.</typeparam>
    /// <param name="builder">Application builder for a HIP service.</param>
    private static void ConfigureHipOpenTelemetry<TBuilder>(this TBuilder builder)
        where TBuilder : IHostApplicationBuilder
    {
        var resourceBuilder = ResourceBuilder.CreateDefault()
            .AddService(
                serviceName: builder.Environment.ApplicationName,
                serviceVersion: typeof(Extensions).Assembly.GetName().Version?.ToString() ?? "unknown",
                serviceInstanceId: Environment.MachineName);

        builder.Services.AddOpenTelemetry()
            .ConfigureResource(resource => resource.AddService(
                serviceName: builder.Environment.ApplicationName,
                serviceVersion: typeof(Extensions).Assembly.GetName().Version?.ToString() ?? "unknown",
                serviceInstanceId: Environment.MachineName))
            .WithTracing(tracing =>
            {
                tracing
                    .SetResourceBuilder(resourceBuilder)
                    .AddSource(builder.Environment.ApplicationName)
                    .AddAspNetCoreInstrumentation(options =>
                    {
                        options.RecordException = true;
                        options.Filter = context => !IsHealthProbe(context.Request.Path);
                        options.EnrichWithHttpRequest = RedactIncomingRequestTags;
                    })
                    .AddHttpClientInstrumentation(options =>
                    {
                        options.RecordException = true;
                        options.EnrichWithHttpRequestMessage = RedactOutgoingRequestTags;
                    });

                if (HasOtlpEndpoint(builder))
                {
                    tracing.AddOtlpExporter();
                }
            })
            .WithMetrics(metrics =>
            {
                metrics
                    .SetResourceBuilder(resourceBuilder)
                    .AddAspNetCoreInstrumentation()
                    .AddHttpClientInstrumentation();

                if (HasOtlpEndpoint(builder))
                {
                    metrics.AddOtlpExporter();
                }
            });
    }

    /// <summary>
    /// Checks whether Aspire or deployment configuration provided an OTLP endpoint for telemetry export.
    /// </summary>
    /// <typeparam name="TBuilder">The host application builder type.</typeparam>
    /// <param name="builder">Application builder for a HIP service.</param>
    /// <returns>True when OpenTelemetry should export to an OTLP collector.</returns>
    private static bool HasOtlpEndpoint<TBuilder>(TBuilder builder)
        where TBuilder : IHostApplicationBuilder =>
        !string.IsNullOrWhiteSpace(builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"]) ||
        !string.IsNullOrWhiteSpace(builder.Configuration["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"]) ||
        !string.IsNullOrWhiteSpace(builder.Configuration["OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"]) ||
        !string.IsNullOrWhiteSpace(builder.Configuration["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"]);

    /// <summary>
    /// Suppresses health probe paths from request tracing so Aspire traces focus on real user/API work.
    /// </summary>
    /// <param name="path">Request path being traced.</param>
    /// <returns>True when the path is a health probe endpoint.</returns>
    private static bool IsHealthProbe(PathString path) =>
        path.StartsWithSegments("/health") ||
        path.StartsWithSegments("/alive");

    /// <summary>
    /// Replaces inbound request URL telemetry with a query-free value and masks sensitive headers.
    /// </summary>
    /// <param name="activity">Trace activity being enriched.</param>
    /// <param name="request">Inbound HTTP request.</param>
    private static void RedactIncomingRequestTags(Activity activity, HttpRequest request)
    {
        var sanitizedUrl = $"{request.Scheme}://{request.Host}{request.Path}";
        activity.SetTag("url.full", sanitizedUrl);
        activity.SetTag("http.url", sanitizedUrl);
        activity.SetTag("http.target", request.Path.Value ?? "/");
        activity.SetTag("url.query", null);
        RedactSensitiveHeaders(activity, request.Headers.Keys, "http.request.header.");
    }

    /// <summary>
    /// Replaces outgoing HTTP client URL telemetry with a query-free value and masks sensitive headers.
    /// </summary>
    /// <param name="activity">Trace activity being enriched.</param>
    /// <param name="request">Outgoing HTTP request message.</param>
    private static void RedactOutgoingRequestTags(Activity activity, HttpRequestMessage request)
    {
        if (request.RequestUri is not null)
        {
            var sanitizedUrl = RedactUrl(request.RequestUri);
            activity.SetTag("url.full", sanitizedUrl);
            activity.SetTag("http.url", sanitizedUrl);
            activity.SetTag("url.query", null);
        }

        RedactSensitiveHeaders(activity, request.Headers.Select(header => header.Key), "http.request.header.");
    }

    /// <summary>
    /// Removes query strings and fragments from a telemetry URL.
    /// </summary>
    /// <param name="uri">Original URI.</param>
    /// <returns>URL without query string or fragment.</returns>
    private static string RedactUrl(Uri uri)
    {
        var builder = new UriBuilder(uri)
        {
            Query = string.Empty,
            Fragment = string.Empty
        };

        return builder.Uri.ToString();
    }

    /// <summary>
    /// Masks telemetry header tags that may carry credentials, tokens, cookies, or API keys.
    /// </summary>
    /// <param name="activity">Trace activity being enriched.</param>
    /// <param name="headerNames">Header names observed on the request.</param>
    /// <param name="tagPrefix">Telemetry tag prefix used for request headers.</param>
    private static void RedactSensitiveHeaders(Activity activity, IEnumerable<string> headerNames, string tagPrefix)
    {
        foreach (var headerName in headerNames.Where(IsSensitiveHeaderName))
        {
            activity.SetTag($"{tagPrefix}{headerName.ToLowerInvariant()}", "[redacted]");
        }
    }

    /// <summary>
    /// Identifies headers that should never appear in raw telemetry.
    /// </summary>
    /// <param name="headerName">Header name.</param>
    /// <returns>True when the header likely carries sensitive data.</returns>
    private static bool IsSensitiveHeaderName(string headerName) =>
        headerName.Contains("authorization", StringComparison.OrdinalIgnoreCase) ||
        headerName.Contains("auth", StringComparison.OrdinalIgnoreCase) ||
        headerName.Contains("cookie", StringComparison.OrdinalIgnoreCase) ||
        headerName.Contains("token", StringComparison.OrdinalIgnoreCase) ||
        headerName.Contains("key", StringComparison.OrdinalIgnoreCase) ||
        headerName.Contains("secret", StringComparison.OrdinalIgnoreCase);
}
