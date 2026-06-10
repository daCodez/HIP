namespace HIP.Tests.Api;

/// <summary>
/// Verifies public feedback API behavior that browser-plugin UX depends on.
/// </summary>
public sealed class PublicFeedbackApiTests
{
    /// <summary>
    /// Confirms duplicate public feedback is treated as accepted idempotent input instead of a visible browser-plugin error.
    /// </summary>
    [Test]
    public void Duplicate_feedback_returns_ok_instead_of_conflict()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.ApiService", "Program.cs"));

        Assert.That(source, Does.Contain("duplicateSuppressed = true"));
        Assert.That(source, Does.Contain("Duplicate feedback submission already accepted recently."));
        Assert.That(source, Does.Not.Contain("Results.Conflict(new { error = \"Duplicate feedback submission ignored.\" })"));
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
