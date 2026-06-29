namespace HIP.Tests;

/// <summary>
/// Configures process-level test settings before any WebApplicationFactory host starts.
/// </summary>
/// <remarks>
/// HIP runtime hosts now require an explicit PostgreSQL connection so tests cannot silently fall back to disposable
/// process-local storage.
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
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("HipInfrastructure__DatabaseProvider")))
        {
            Environment.SetEnvironmentVariable("HipInfrastructure__DatabaseProvider", "PostgreSQL");
        }
    }
}
