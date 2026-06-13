namespace HIP.Tests;

/// <summary>
/// Configures process-level test settings before any WebApplicationFactory host starts.
/// </summary>
/// <remarks>
/// HIP runtime hosts now require an explicit database connection so they do not silently fall back to SQLite.
/// API and Web integration tests still need an isolated local database without requiring Aspire containers, so this
/// setup fixture supplies a test-only SQLite connection when the developer has not already provided one.
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
            var databasePath = Path.Combine(Path.GetTempPath(), $"hip-tests-{Environment.ProcessId}.db");
            Environment.SetEnvironmentVariable("ConnectionStrings__HipDatabase", $"Data Source={databasePath}");
        }

        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("HipInfrastructure__DatabaseProvider")))
        {
            Environment.SetEnvironmentVariable("HipInfrastructure__DatabaseProvider", "SQLite");
        }
    }
}
