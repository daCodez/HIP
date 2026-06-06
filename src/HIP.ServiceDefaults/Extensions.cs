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
                    })
                    .AddHttpClientInstrumentation(options => options.RecordException = true);

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
}
