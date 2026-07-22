namespace HIP.Tests.Infrastructure;

/// <summary>
/// Verifies the explicit-port HIP launcher supplies every required distributed dependency.
/// </summary>
public sealed class HipLocalLauncherTests
{
    /// <summary>
    /// Confirms direct API and Web processes receive the Redis connection required by infrastructure hardening.
    /// </summary>
    [Test]
    public void Local_launcher_supplies_the_required_redis_connection_string()
    {
        var launcher = File.ReadAllText(Path.Combine(RepositoryRoot(), "eng", "Start-HipLocal.ps1"));

        Assert.That(
            launcher,
            Does.Contain("$env:ConnectionStrings__redis = \"localhost:$($env:HIP_REDIS_PORT),abortConnect=false\""));
    }

    /// <summary>
    /// Resolves the repository root from the test output folder.
    /// </summary>
    /// <returns>Absolute repository root path.</returns>
    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate repository root.");
    }
}
