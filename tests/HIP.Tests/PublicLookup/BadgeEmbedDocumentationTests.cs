namespace HIP.Tests.PublicLookup;

/// <summary>
/// Verifies the embeddable badge script documents and renders anti-fake domain mismatch behavior.
/// </summary>
public sealed class BadgeEmbedDocumentationTests
{
    /// <summary>
    /// Confirms the static badge script includes the domain mismatch behavior required by the live badge MVP.
    /// </summary>
    [Test]
    public void Badge_script_documents_domain_mismatch_behavior()
    {
        var script = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "src", "HIP.Web", "wwwroot", "hip-badge.js"));

        Assert.That(script, Does.Contain("HIP Badge Domain Mismatch"));
        Assert.That(script, Does.Contain("badge.domain"));
        Assert.That(script, Does.Contain("window.location.hostname"));
    }

    /// <summary>
    /// Finds the repository root from any test output folder so file-based tests work with isolated build output.
    /// </summary>
    /// <returns>The absolute repository root.</returns>
    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);

        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "HIP.slnx")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate HIP.slnx from the test output directory.");
    }
}
