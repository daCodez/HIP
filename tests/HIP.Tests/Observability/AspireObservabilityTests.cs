namespace HIP.Tests.Observability;

/// <summary>
/// Verifies HIP's Aspire service defaults keep structured logging and tracing wired in one shared place.
/// </summary>
[TestFixture]
public sealed class AspireObservabilityTests
{
    /// <summary>
    /// ServiceDefaults must configure structured JSON console logging for every HIP Aspire service.
    /// </summary>
    [Test]
    public void Service_defaults_configure_structured_json_logging()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.ServiceDefaults", "Extensions.cs"));

        Assert.That(source, Does.Contain("AddJsonConsole"));
        Assert.That(source, Does.Contain("IncludeScopes = true"));
        Assert.That(source, Does.Contain("ParseStateValues = true"));
    }

    /// <summary>
    /// ServiceDefaults must configure OpenTelemetry traces, metrics, and OTLP export for Aspire dashboard correlation.
    /// </summary>
    [Test]
    public void Service_defaults_configure_open_telemetry_for_aspire()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.ServiceDefaults", "Extensions.cs"));

        Assert.That(source, Does.Contain("AddOpenTelemetry"));
        Assert.That(source, Does.Contain("AddAspNetCoreInstrumentation"));
        Assert.That(source, Does.Contain("AddHttpClientInstrumentation"));
        Assert.That(source, Does.Contain("AddOtlpExporter"));
    }

    /// <summary>
    /// Web should not override the shared ServiceDefaults logging pipeline.
    /// </summary>
    [Test]
    public void Web_project_uses_shared_service_default_logging()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.Web", "Program.cs"));

        Assert.That(source, Does.Contain("builder.AddServiceDefaults();"));
        Assert.That(source, Does.Not.Contain("builder.Logging.ClearProviders();"));
        Assert.That(source, Does.Not.Contain("builder.Logging.AddConsole();"));
    }

    /// <summary>
    /// Locates the repository root from the test output directory without depending on a fixed drive path.
    /// </summary>
    /// <returns>Absolute repository root path.</returns>
    private static string RepositoryRoot()
    {
        var current = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (current is not null && !File.Exists(Path.Combine(current.FullName, "HIP.slnx")))
        {
            current = current.Parent;
        }

        return current?.FullName ?? throw new InvalidOperationException("Could not locate HIP repository root.");
    }
}
