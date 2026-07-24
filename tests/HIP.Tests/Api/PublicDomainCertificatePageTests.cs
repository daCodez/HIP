using System.Runtime.CompilerServices;

namespace HIP.Tests.Api;

public sealed class PublicDomainCertificatePageTests
{
    private static readonly string SourceDirectory = Path.GetDirectoryName(SourceFilePath())!;

    [Test]
    public void Page_explains_certificate_status_without_overclaiming_safety_or_tls()
    {
        var razor = File.ReadAllText(WorkspaceFile(
            "src", "HIP.Web", "Components", "Pages", "PublicDomainCertificate.razor"));

        Assert.Multiple(() =>
        {
            Assert.That(razor, Does.Contain("@page \"/certificate/{CertificateId}\""));
            Assert.That(razor, Does.Contain("Signature verification"));
            Assert.That(razor, Does.Contain("does not replace the website’s SSL/TLS certificate"));
            Assert.That(razor, Does.Contain("does not, by itself, prove that a site is safe"));
            Assert.That(razor, Does.Contain("Do not treat a copied badge or screenshot as proof"));
            Assert.That(razor, Does.Not.Contain("OwnerId"));
            Assert.That(razor, Does.Not.Contain("ActorId"));
        });
    }

    [Test]
    public void Page_uses_accessible_trust_colours_and_reduced_motion()
    {
        var css = File.ReadAllText(WorkspaceFile(
            "src", "HIP.Web", "Components", "Pages", "PublicDomainCertificate.razor.css"));

        Assert.Multiple(() =>
        {
            Assert.That(css, Does.Contain(".certificate-active { --certificate-accent: #00c9c8; }"));
            Assert.That(css, Does.Contain(".certificate-caution { --certificate-accent: #f0ad3d; }"));
            Assert.That(css, Does.Contain(".certificate-revoked { --certificate-accent: #f14968; }"));
            Assert.That(css, Does.Contain(".certificate-unavailable"));
            Assert.That(css, Does.Contain("--certificate-accent: #7d8ba1"));
            Assert.That(css, Does.Contain("@media (prefers-reduced-motion: reduce)"));
        });
    }

    private static string WorkspaceFile(params string[] parts)
    {
        foreach (var startPath in new[]
                 {
                     SourceDirectory,
                     Directory.GetCurrentDirectory(),
                     TestContext.CurrentContext.WorkDirectory,
                     TestContext.CurrentContext.TestDirectory,
                     AppContext.BaseDirectory
                 })
        {
            var current = new DirectoryInfo(startPath);
            while (current is not null)
            {
                var candidate = Path.Combine([current.FullName, .. parts]);
                if (File.Exists(candidate))
                {
                    return candidate;
                }

                current = current.Parent;
            }
        }

        throw new FileNotFoundException($"Could not locate {Path.Combine(parts)}.");
    }

    private static string SourceFilePath([CallerFilePath] string sourceFilePath = "") => sourceFilePath;
}
