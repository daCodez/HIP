namespace HIP.Tests.Certificates;

/// <summary>Locks the public certificate and badge documentation to the implemented trust boundaries.</summary>
public sealed class DomainCertificateDocumentationTests
{
    [Test]
    public void Certificate_guide_covers_required_operations_and_avoids_unsupported_claims()
    {
        var root = FindRepositoryRoot();
        var guide = File.ReadAllText(Path.Combine(root, "docs", "domain-trust-certificates.md"));

        Assert.Multiple(() =>
        {
            Assert.That(guide, Does.Contain("does not replace the website's TLS certificate"));
            Assert.That(guide, Does.Contain("HIP Registered"));
            Assert.That(guide, Does.Contain("HIP Verified"));
            Assert.That(guide, Does.Contain("HIP Monitored"));
            Assert.That(guide, Does.Contain("_hip-challenge.<domain>"));
            Assert.That(guide, Does.Contain("/.well-known/hip.json"));
            Assert.That(guide, Does.Contain("Renewal"));
            Assert.That(guide, Does.Contain("Revocation"));
            Assert.That(guide, Does.Contain("Browser extension verification"));
            Assert.That(guide, Does.Contain("Development with .NET Aspire"));
            Assert.That(guide, Does.Contain("not quantum-resistant"));
            Assert.That(guide, Does.Contain("default application registration uses an unavailable managed signer"));
            Assert.That(guide, Does.Not.Contain("HIP is quantum-resistant"));
            Assert.That(guide, Does.Not.Contain("certified compliant"));
        });
    }

    [Test]
    public void Badge_guide_and_adr_describe_current_signed_fail_closed_behavior()
    {
        var root = FindRepositoryRoot();
        var badgeGuide = File.ReadAllText(Path.Combine(root, "docs", "public-lookup-and-badges.md"));
        var decision = File.ReadAllText(Path.Combine(
            root,
            "docs",
            "decisions",
            "ADR-013-domain-certificate-and-badge-trust-model.md"));

        Assert.Multiple(() =>
        {
            Assert.That(badgeGuide, Does.Contain("POST /api/v1/public/badge/verify"));
            Assert.That(badgeGuide, Does.Contain("exact canonical hostname"));
            Assert.That(badgeGuide, Does.Contain("server-authoritative and online"));
            Assert.That(badgeGuide, Does.Not.Contain("Badge responses are not cryptographically signed yet"));
            Assert.That(badgeGuide, Does.Not.Contain("future browser plugin check"));
            Assert.That(decision, Does.Contain("## Status"));
            Assert.That(decision, Does.Contain("Accepted"));
            Assert.That(decision, Does.Contain("signature establishes origin and integrity only"));
            Assert.That(decision, Does.Contain("make no quantum-resistant claim"));
        });
    }

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

        throw new InvalidOperationException("HIP repository root was not found.");
    }
}
