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

        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ConnectionStrings__HipDatabase")))
        {
            // Tests replace EF with an isolated local store, but production startup still requires an explicit database
            // connection so accidental process-local persistence cannot sneak into runtime builds.
            Environment.SetEnvironmentVariable(
                "ConnectionStrings__HipDatabase",
                "Host=localhost;Port=5432;Database=hip_tests;Username=hip;Password=hip");
        }

        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("HipSecurity__RecordEncryptionKey")))
        {
            // This deterministic test key keeps encrypted-record repositories usable without reading developer secrets.
            Environment.SetEnvironmentVariable("HipSecurity__RecordEncryptionKey", "hip-test-record-key-32bytes-local");
        }

        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("HipSecurity__PrivacyHashingKey")))
        {
            // This deterministic test key lets privacy hashing behave consistently while avoiding real production keys.
            Environment.SetEnvironmentVariable("HipSecurity__PrivacyHashingKey", "hip-test-privacy-key-32bytes-local");
        }
    }
}
