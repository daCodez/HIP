using System.Net;

namespace HIP.Tests.Api;

/// <summary>Guards the admin compliance-readiness view against unsupported certification claims.</summary>
public sealed class AdminPrivacySafetyPageTests
{
    /// <summary>Verifies the page exposes an evidence-based framework matrix to authorized operators.</summary>
    [Test]
    public async Task Privacy_page_shows_truthful_compliance_readiness()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", "Admin");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", "admin-compliance-test");

        var response = await client.GetAsync("/admin/privacy");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(html, Does.Contain("Compliance Readiness"));
            Assert.That(html, Does.Contain("PIPEDA"));
            Assert.That(html, Does.Contain("ISO/IEC 27001:2022"));
            Assert.That(html, Does.Contain("HIPAA"));
            Assert.That(html, Does.Contain("OWASP ASVS 5.0"));
            Assert.That(html, Does.Contain("Not certified"));
            Assert.That(html, Does.Contain("Applicability depends on deployment and data use"));
            Assert.That(html, Does.Not.Contain("HIP is HIPAA compliant"));
            Assert.That(html, Does.Not.Contain("HIP is ISO 27001 certified"));
        });
    }
}
