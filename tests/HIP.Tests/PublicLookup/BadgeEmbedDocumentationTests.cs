namespace HIP.Tests.PublicLookup;

public sealed class BadgeEmbedDocumentationTests
{
    [Test]
    public void Badge_script_documents_domain_mismatch_behavior()
    {
        var script = File.ReadAllText(Path.Combine(
            TestContext.CurrentContext.TestDirectory,
            "..",
            "..",
            "..",
            "..",
            "..",
            "src",
            "HIP.Web",
            "wwwroot",
            "hip-badge.js"));

        Assert.That(script, Does.Contain("HIP Badge Domain Mismatch"));
        Assert.That(script, Does.Contain("badge.domain"));
        Assert.That(script, Does.Contain("window.location.hostname"));
    }
}
