using HIP.Application.Certificates;
using HIP.Application.Domains;
using HIP.Domain.Certificates;
using HIP.Domain.Domains;

namespace HIP.Tests.Domains;

public sealed class ManagedDomainDashboardServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 8, 19, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Organization_member_sees_only_authorized_domain_dashboard_rows()
    {
        var repository = new InMemoryManagedDomainRepository();
        var management = new DomainManagementService(
            repository, new DomainRegistrationNormalizer(new TestPublicSuffixResolver()), new FixedTimeProvider(Now));
        var organization = await management.CreateOrganizationAsync("owner", "Example Org", default);
        await management.AddOrganizationMemberAsync("owner", organization.OrganizationId, "member", DomainAccessRole.Viewer, default);
        var visible = await management.RegisterAsync("owner", new("example.com", organization.OrganizationId), default);
        var hidden = await management.RegisterAsync("other-owner", new("other.example"), default);
        var data = new StubDataSource(new Dictionary<string, ManagedDomainDashboardEvidence>
        {
            [visible.DomainId] = Evidence("Example Org"),
            [hidden.DomainId] = Evidence(null)
        });
        var service = new ManagedDomainDashboardService(management, data, new FixedTimeProvider(Now));

        var result = await service.ListAsync("member", new ManagedDomainQuery(), default);

        Assert.Multiple(() =>
        {
            Assert.That(result, Has.Count.EqualTo(1));
            Assert.That(result.Single().DomainId, Is.EqualTo(visible.DomainId));
            Assert.That(result.Single().AccessRole, Is.EqualTo(DomainAccessRole.Viewer));
            Assert.That(data.RequestedDomainIds, Is.EquivalentTo(new[] { visible.DomainId }));
        });
    }

    [Test]
    public async Task Dashboard_summarizes_score_certificate_badge_and_required_actions()
    {
        var repository = new InMemoryManagedDomainRepository();
        var management = new DomainManagementService(
            repository, new DomainRegistrationNormalizer(new TestPublicSuffixResolver()), new FixedTimeProvider(Now));
        var domain = await management.RegisterAsync("owner", new("example.com"), default);
        var data = new StubDataSource(new Dictionary<string, ManagedDomainDashboardEvidence>
        {
            [domain.DomainId] = Evidence(null) with
            {
                CertificateStatus = DomainCertificateStatus.Suspended,
                CriticalFindingCount = 2,
                RequiredRemediation = ["Resolve the critical findings."]
            }
        });
        var service = new ManagedDomainDashboardService(management, data, new FixedTimeProvider(Now));

        var result = (await service.ListAsync("owner", new ManagedDomainQuery(), default)).Single();

        Assert.Multiple(() =>
        {
            Assert.That(result.HipScore, Is.EqualTo(91));
            Assert.That(result.BadgeStatus, Is.EqualTo("Unavailable"));
            Assert.That(result.SecurityFindingCount, Is.EqualTo(3));
            Assert.That(result.ActionRequired, Does.Contain("Resolve the critical findings."));
            Assert.That(result.ActionRequired, Does.Contain("Certificate status is Suspended."));
            Assert.That(result.NextReviewAtUtc, Is.EqualTo(Now.AddDays(30)));
        });
    }

    private static ManagedDomainDashboardEvidence Evidence(string? organizationName) => new(
        organizationName,
        HipScore: 91,
        CertificationLevel: DomainCertificateLevel.Verified,
        CertificateStatus: DomainCertificateStatus.Active,
        CertificateExpiresAtUtc: Now.AddDays(60),
        PublicCertificateNumber: "HIP-2026-00112233445566778899AABB",
        HttpsAvailable: true,
        LastScanAtUtc: Now.AddHours(-1),
        HighRiskFindingCount: 1,
        CriticalFindingCount: 0,
        RequiredRemediation: [],
        NextReviewAtUtc: Now.AddDays(30));

    private sealed class StubDataSource(IReadOnlyDictionary<string, ManagedDomainDashboardEvidence> values)
        : IManagedDomainDashboardDataSource
    {
        public List<string> RequestedDomainIds { get; } = [];
        public Task<ManagedDomainDashboardEvidence> GetAsync(string domainId, string domainName, CancellationToken cancellationToken)
        {
            RequestedDomainIds.Add(domainId);
            return Task.FromResult(values[domainId]);
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider { public override DateTimeOffset GetUtcNow() => now; }
    private sealed class TestPublicSuffixResolver : IPublicSuffixResolver { public string? RegistrableDomain(string canonicalDomain) => canonicalDomain; }
}
