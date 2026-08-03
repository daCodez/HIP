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

        Assert.That(script, Does.Contain("Domain mismatch"));
        Assert.That(script, Does.Contain("badge.domain"));
        Assert.That(script, Does.Contain("window.location.hostname"));
        Assert.That(script, Does.Contain("payload.certificate"));
        Assert.That(script, Does.Contain("certificate.isActive"));
        Assert.That(script, Does.Contain("Protected by"));
        Assert.That(script, Does.Contain("role=\"tooltip\""));
        Assert.That(script, Does.Contain("aria-describedby"));
        Assert.That(script, Does.Contain("dataset.opacity"));
        Assert.That(script, Does.Contain("DEFAULT_OPACITY = 82"));
        Assert.That(script, Does.Contain("number >= 60 && number <= 100"));
        Assert.That(script, Does.Contain("data-theme"));
        Assert.That(script, Does.Contain("data-position"));
        Assert.That(script, Does.Contain("ResizeObserver"));
        Assert.That(script, Does.Contain("[\"fixed\", \"sticky\"]"));
        Assert.That(script, Does.Contain("position:fixed"));
        Assert.That(script, Does.Contain("background:transparent"));
        Assert.That(script, Does.Contain("shieldMarkup"));
        Assert.That(script, Does.Contain("/images/public/marketing/hip-logo.png?v=3"));
        Assert.That(script, Does.Not.Contain("m15 27 6 6 13-15"));
        Assert.That(script, Does.Contain("/api/v1/public/certificates/"));
        Assert.That(script, Does.Contain("payload.certificateId !== badge.certificate.certificateId"));
        Assert.That(script, Does.Contain("HIP does not replace TLS"));
        Assert.That(script, Does.Contain("completedVerificationMethods"));
        Assert.That(script, Does.Contain("publicFindingCodes"));
        Assert.That(script, Does.Contain("function safeApiBase() { return scriptOrigin; }"));
        Assert.That(script, Does.Contain("#22C55E"));
        Assert.That(script, Does.Contain("#14B8A6"));
        Assert.That(script, Does.Contain("#3082F6"));
        Assert.That(script, Does.Contain("#F59E0B"));
        Assert.That(script, Does.Contain("#EF4444"));
        Assert.That(script, Does.Contain("#B91C1C"));
        Assert.That(script, Does.Contain("prefers-reduced-motion"));
        Assert.That(script, Does.Contain("The signed badge summary above remains unchanged."));
        Assert.That(script, Does.Not.Contain("container.querySelector(\".hip-badge-score\").textContent = \"—\""));
        Assert.That(script, Does.Not.Contain("localStorage"));
        Assert.That(script, Does.Not.Contain("sessionStorage"));
    }

    /// <summary>
    /// Finds the repository root from any test output folder so file-based tests work with isolated build output.
    /// </summary>
    /// <returns>The absolute repository root.</returns>
    private static string FindRepositoryRoot(
        [System.Runtime.CompilerServices.CallerFilePath] string sourceFilePath = "")
    {
        var current = new DirectoryInfo(Path.GetDirectoryName(sourceFilePath)!);

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
