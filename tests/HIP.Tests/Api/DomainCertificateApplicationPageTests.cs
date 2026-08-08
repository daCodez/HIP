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
    public void Owner_page_explains_authenticated_score_progression_and_monitoring()
    {
        var page = Read("src", "HIP.Web", "Components", "Pages", "ConsumerCertificates.razor");

        Assert.Multiple(() =>
        {
            Assert.That(page, Does.Contain("How HIP trust strengthens"));
            Assert.That(page, Does.Contain("starting it runs an immediate HIP-owned check"));
            Assert.That(page, Does.Contain("schedules a new check every 24 hours"));
            Assert.That(page, Does.Contain("Missing evidence is not a low score"));
            Assert.That(page, Does.Contain("never prove the site is safe"));
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

    [Test]
    public void Managed_application_review_api_uses_authenticated_actor_and_step_up_policy()
    {
        var program = Read("src", "HIP.Web", "Program.cs");
        var routeStart = program.IndexOf("static void MapAdminManagedDomainApplicationApis", StringComparison.Ordinal);
        var routeEnd = program.IndexOf("static void MapConsumerDeviceApis", routeStart, StringComparison.Ordinal);
        var route = program[routeStart..routeEnd];

        Assert.Multiple(() =>
        {
            Assert.That(route, Does.Contain("ResolveAdminActor(context)"));
            Assert.That(route, Does.Contain("ValidateConsumerDeviceAntiforgeryAsync"));
            Assert.That(route, Does.Contain("AdminPolicies.CanManageDomainVerifications"));
            Assert.That(route, Does.Contain("AdminPolicies.RecentPrivilegedAuthentication"));
            Assert.That(route, Does.Not.Contain("request.ActorId"));
        });
    }

    private static string Read(params string[] segments) =>
        File.ReadAllText(Path.Combine(FindRepositoryRoot(), Path.Combine(segments)));

    private static string FindRepositoryRoot(
        [System.Runtime.CompilerServices.CallerFilePath] string sourceFilePath = "")
    {
        var directory = new DirectoryInfo(Path.GetDirectoryName(sourceFilePath)!);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate the HIP repository root for page contract tests.");
    }
}
