using System.Diagnostics.Metrics;
using HIP.Application.ServiceClients;
using HIP.Domain.ServiceClients;

namespace HIP.Tests.ServiceClients;

/// <summary>Guards the low-cardinality, credential-free HIP service-client telemetry contract.</summary>
public sealed class ServiceClientTelemetryTests
{
    [Test]
    public void Service_client_metrics_expose_only_bounded_operation_outcome_and_scope_tags()
    {
        var measurements = new List<Measurement>();
        using var listener = new MeterListener
        {
            InstrumentPublished = (instrument, currentListener) =>
            {
                if (string.Equals(instrument.Meter.Name, ServiceClientTelemetry.MeterName, StringComparison.Ordinal))
                {
                    currentListener.EnableMeasurementEvents(instrument);
                }
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
        {
            measurements.Add(new Measurement(
                instrument.Name,
                value,
                tags.ToArray().ToDictionary(tag => tag.Key, tag => tag.Value?.ToString(), StringComparer.Ordinal)));
        });
        listener.Start();

        ServiceClientTelemetry.RecordLifecycle(
            ServiceClientLifecycleOperation.RotateCredential,
            ServiceClientLifecycleOutcome.Conflict,
            ServiceClientScope.DomainVerificationCheck);
        ServiceClientTelemetry.RecordAuthentication(
            ServiceClientAuthenticationOutcome.Succeeded,
            ServiceClientScope.SiteSafetyExternalEvidenceCheck);

        Assert.That(measurements, Has.Count.EqualTo(2));
        Assert.Multiple(() =>
        {
            AssertMeasurement(
                measurements.Single(item => item.InstrumentName == ServiceClientTelemetry.LifecycleCounterName),
                new Dictionary<string, string?>(StringComparer.Ordinal)
                {
                    ["operation"] = "rotate-credential",
                    ["outcome"] = "conflict",
                    ["scope"] = ServiceClientScopeValues.DomainVerificationCheck
                });
            AssertMeasurement(
                measurements.Single(item => item.InstrumentName == ServiceClientTelemetry.AuthenticationCounterName),
                new Dictionary<string, string?>(StringComparer.Ordinal)
                {
                    ["outcome"] = "succeeded",
                    ["scope"] = ServiceClientScopeValues.SiteSafetyExternalEvidenceCheck
                });
        });
    }

    [Test]
    public void Service_defaults_exports_the_service_client_meter()
    {
        var source = File.ReadAllText(Path.Combine(
            FindRepositoryRoot(),
            "src",
            "HIP.ServiceDefaults",
            "Extensions.cs"));

        Assert.That(source, Does.Contain(".AddMeter(\"HIP.ServiceClients\")"));
    }

    [Test]
    public void Throttled_management_outcome_is_emitted_as_a_bounded_tag()
    {
        IReadOnlyDictionary<string, string?>? capturedTags = null;
        using var listener = new MeterListener
        {
            InstrumentPublished = (instrument, currentListener) =>
            {
                if (string.Equals(
                        instrument.Name,
                        ServiceClientTelemetry.LifecycleCounterName,
                        StringComparison.Ordinal))
                {
                    currentListener.EnableMeasurementEvents(instrument);
                }
            }
        };
        listener.SetMeasurementEventCallback<long>((_, _, tags, _) =>
        {
            capturedTags = tags.ToArray().ToDictionary(
                tag => tag.Key,
                tag => tag.Value?.ToString(),
                StringComparer.Ordinal);
        });
        listener.Start();

        ServiceClientTelemetry.RecordLifecycle(
            ServiceClientLifecycleOperation.Create,
            ServiceClientLifecycleOutcome.Throttled);

        Assert.That(capturedTags, Is.Not.Null);
        Assert.That(capturedTags!["outcome"], Is.EqualTo("throttled"));
        Assert.That(capturedTags.Keys, Is.EquivalentTo(new[] { "operation", "outcome", "scope" }));
    }

    private static void AssertMeasurement(
        Measurement measurement,
        IReadOnlyDictionary<string, string?> expectedTags)
    {
        Assert.That(measurement.Value, Is.EqualTo(1));
        Assert.That(measurement.Tags, Is.EqualTo(expectedTags));
        Assert.That(measurement.Tags.Keys, Has.None.Matches<string>(key =>
            key.Contains("client", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("owner", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("domain", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("source", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("secret", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("credential", StringComparison.OrdinalIgnoreCase)));
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null && !File.Exists(Path.Combine(current.FullName, "HIP.slnx")))
        {
            current = current.Parent;
        }

        return current?.FullName ?? throw new DirectoryNotFoundException("HIP repository root was not found.");
    }

    private sealed record Measurement(
        string InstrumentName,
        long Value,
        IReadOnlyDictionary<string, string?> Tags);
}
