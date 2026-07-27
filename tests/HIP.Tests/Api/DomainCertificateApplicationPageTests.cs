namespace HIP.Tests.Api;

public sealed class DomainCertificateApplicationPageTests
{
    [Test]
    public void Owner_page_requires_authenticated_attestation_and_approval_before_review()
    {
        var page = Read("src", "HIP.Web", "Components", "Pages", "ConsumerCertificates.razor");

        Assert.Multiple(() =>
        {
            Assert.That(page, Does.Contain("IDomainCertificateApplicationService"));
            Assert.That(page, Does.Contain("DomainCertificateApplicantAttestation.AuthorityStatement"));
            Assert.That(page, Does.Contain("DomainCertificateApplicantAttestation.AccuracyStatement"));
            Assert.That(page, Does.Contain("Submit application"));
            Assert.That(page, Does.Contain("ApplicationStatus == DomainCertificateApplicationStatus.Approved"));
            Assert.That(page, Does.Contain("Run security review and issue certificate"));
            Assert.That(page, Does.Contain("ProvisioningService.ReviewAndIssueAsync"));
            Assert.That(page, Does.Contain("The security review passed, but HIP could not sign and store the certificate."));
        });
    }

    [Test]
    public void Admin_page_requires_authorized_reasoned_application_decision()
    {
        var page = Read("src", "HIP.Web", "Components", "Pages", "AdminDomainCertificates.razor");

        Assert.Multiple(() =>
        {
            Assert.That(page, Does.Contain(">Approve</button>"));
            Assert.That(page, Does.Contain("Request changes"));
            Assert.That(page, Does.Contain(">Deny</button>"));
            Assert.That(page, Does.Contain("AdminPolicies.CanManageDomainVerifications"));
            Assert.That(page, Does.Contain("Decision reason"));
            Assert.That(page, Does.Contain("ApplicationService.DecideAsync"));
        });
    }

    private static string Read(params string[] segments)
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
        {
            directory = directory.Parent;
        }
        return File.ReadAllText(Path.Combine(directory!.FullName, Path.Combine(segments)));
    }
}
