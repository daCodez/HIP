# Aspire Observability

HIP uses `HIP.ServiceDefaults` as the shared observability entry point for Aspire-hosted services.

## What Is Enabled

Every service that calls `builder.AddServiceDefaults()` gets:

- structured JSON console logs
- log scopes and structured state values
- OpenTelemetry logs
- OpenTelemetry HTTP server traces
- OpenTelemetry HTTP client traces
- OpenTelemetry HTTP server metrics
- OpenTelemetry HTTP client metrics
- OTLP export when Aspire or deployment configuration provides an OTLP endpoint

The current HIP services using this shared setup are:

- `HIP.Web`
- `HIP.ApiService`

## Aspire Dashboard

`HIP.AppHost` already provides the Aspire dashboard launch settings:

- `ASPIRE_DASHBOARD_OTLP_HTTP_ENDPOINT_URL`
- `ASPIRE_RESOURCE_SERVICE_ENDPOINT_URL`

When launched through Aspire, HIP services receive OTLP configuration and export telemetry to the Aspire dashboard. The dashboard should show correlated logs, traces, and metrics for `hip-web` and `hip-api`.

## Structured Logging

Logs are written as compact JSON to stdout. This keeps local development readable by tools and keeps production log shipping straightforward.

The logging setup includes:

- UTC timestamps
- scopes
- formatted messages
- parsed state values

Do not log private content. HIP logs must not include:

- passwords
- tokens
- cookies
- private chat logs
- private message bodies
- form values
- raw page content

## Tracing

Tracing captures inbound ASP.NET Core requests and outbound HTTP calls.

Health probes are filtered from traces:

- `/health`
- `/alive`

This keeps the Aspire trace view focused on real app/API activity.

## Configuration

OTLP export activates only when one of these configuration values is present:

- `OTEL_EXPORTER_OTLP_ENDPOINT`
- `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`
- `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`
- `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`

This allows HIP to run without an OTLP collector in simple local/test environments.

## Current NuGet Advisory Caveat

NuGet currently reports moderate vulnerability advisories for OpenTelemetry packages used for OTLP export. HIP pins the packages to `1.15.0`, the newest version resolved during this pass, but the advisory feed still reports warnings.

Before production release, re-run:

```powershell
dotnet list HIP.slnx package --vulnerable --include-transitive
```

Upgrade OpenTelemetry packages as soon as a patched release is available.

## Manual Verification

1. Start `HIP.AppHost` from Visual Studio.
2. Open the Aspire dashboard.
3. Send requests to `HIP.Web` and `HIP.ApiService`.
4. Confirm `hip-web` and `hip-api` show logs.
5. Confirm request traces appear for API/browser/public lookup calls.
6. Confirm `/health` and `/alive` do not dominate trace output.

## Known Limitations

- HIP does not yet define custom `ActivitySource` spans for domain-specific operations such as site scoring, rule simulation, or external provider checks.
- HIP does not yet emit custom metrics for scan counts, rule matches, review items, or provider failures.
- Production log retention and export policy still need an operations decision.
