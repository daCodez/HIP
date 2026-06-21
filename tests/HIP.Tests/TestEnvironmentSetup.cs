namespace HIP.Tests;

/// <summary>
/// Configures process-level test settings before any WebApplicationFactory host starts.
/// </summary>
/// <remarks>
/// HIP runtime hosts now require an explicit database connection so they do not silently fall back to SQLite.
/// API and Web integration tests still need isolated persistence without requiring Aspire containers, so this setup
/// fixture requests HIP's test-only EF Core in-memory provider when the developer has not already provided one.
/// </remarks>
[SetUpFixture]
public sealed class TestEnvironmentSetup
{
    /// <summary>
    /// Sets test-only database configuration before integration tests boot the API or Web host.
    /// </summary>
    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ConnectionStrings__HipDatabase")))
        {
            Environment.SetEnvironmentVariable("ConnectionStrings__HipDatabase", $"hip-tests-{Environment.ProcessId}");
        }

        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("HipInfrastructure__DatabaseProvider")))
        {
            Environment.SetEnvironmentVariable("HipInfrastructure__DatabaseProvider", "InMemory");
        }
    }
}
