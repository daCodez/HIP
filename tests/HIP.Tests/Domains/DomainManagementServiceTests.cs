using HIP.Application.Certificates;
using HIP.Application.Domains;
using HIP.Domain.Domains;

namespace HIP.Tests.Domains;

/// <summary>Specifies the unified single-domain and multi-domain ownership boundary.</summary>
public sealed class DomainManagementServiceTests
{
    [Test]
    public async Task One_user_can_register_one_or_many_domains_in_the_same_registry()
    {
        var service = Service();

        var first = await service.RegisterAsync("user-a", new RegisterManagedDomainRequest("example.com"), CancellationToken.None);
        var second = await service.RegisterAsync("user-a", new RegisterManagedDomainRequest("shop.example.com"), CancellationToken.None);
        var domains = await service.ListAsync("user-a", new ManagedDomainQuery(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(first.DomainName, Is.EqualTo("example.com"));
            Assert.That(second.DomainName, Is.EqualTo("shop.example.com"));
            Assert.That(domains.Select(item => item.DomainName), Is.EqualTo(new[] { "example.com", "shop.example.com" }));
            Assert.That(domains.All(item => item.AccessRole == DomainAccessRole.Owner), Is.True);
        });
    }

    [Test]
    public async Task Organization_membership_grants_access_to_each_assigned_domain()
    {
        var service = Service();
        var organization = await service.CreateOrganizationAsync("owner", "Example Company", CancellationToken.None);
        await service.AddOrganizationMemberAsync(
            "owner",
            organization.OrganizationId,
            "manager",
            DomainAccessRole.DomainManager,
            CancellationToken.None);
        var first = await service.RegisterAsync(
            "owner",
            new RegisterManagedDomainRequest("example.com", organization.OrganizationId),
            CancellationToken.None);
        var second = await service.RegisterAsync(
            "owner",
            new RegisterManagedDomainRequest("example.ca", organization.OrganizationId),
            CancellationToken.None);

        var visible = await service.ListAsync("manager", new ManagedDomainQuery(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(visible.Select(item => item.DomainId), Is.EquivalentTo(new[] { first.DomainId, second.DomainId }));
            Assert.That(visible.All(item => item.OrganizationId == organization.OrganizationId), Is.True);
            Assert.That(visible.All(item => item.AccessRole == DomainAccessRole.DomainManager), Is.True);
        });
    }

    [Test]
    public async Task Unauthorized_user_receives_the_same_not_found_result_for_foreign_and_unknown_domains()
    {
        var service = Service();
        var domain = await service.RegisterAsync("owner", new RegisterManagedDomainRequest("example.com"), CancellationToken.None);

        var foreign = await service.GetAsync("other-user", domain.DomainId, CancellationToken.None);
        var unknown = await service.GetAsync("other-user", "domain_unknown", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(foreign, Is.Null);
            Assert.That(unknown, Is.Null);
        });
    }

    [Test]
    public async Task Ownership_transfer_removes_the_prior_owners_management_access()
    {
        var service = Service();
        var domain = await service.RegisterAsync("owner-a", new RegisterManagedDomainRequest("example.com"), CancellationToken.None);

        var transferred = await service.TransferOwnershipAsync(
            "owner-a",
            domain.DomainId,
            "owner-b",
            CancellationToken.None);

        Assert.Multiple(async () =>
        {
            Assert.That(transferred.OwnerId, Is.EqualTo("owner-b"));
            Assert.That(await service.GetAsync("owner-a", domain.DomainId, CancellationToken.None), Is.Null);
            Assert.That((await service.GetAsync("owner-b", domain.DomainId, CancellationToken.None))?.AccessRole, Is.EqualTo(DomainAccessRole.Owner));
        });
    }

    [Test]
    public async Task Viewer_can_read_but_cannot_change_domain_organization_or_dnssec_state()
    {
        var service = Service();
        var organization = await service.CreateOrganizationAsync("owner", "Example Company", CancellationToken.None);
        await service.AddOrganizationMemberAsync(
            "owner",
            organization.OrganizationId,
            "viewer",
            DomainAccessRole.Viewer,
            CancellationToken.None);
        var domain = await service.RegisterAsync(
            "owner",
            new RegisterManagedDomainRequest("example.com", organization.OrganizationId),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(service.GetAsync("viewer", domain.DomainId, CancellationToken.None).Result, Is.Not.Null);
            Assert.That(
                async () => await service.UpdateDnssecAsync(
                    "viewer",
                    domain.DomainId,
                    DomainDnssecStatus.Valid,
                    "Validated chain of trust.",
                    CancellationToken.None),
                Throws.TypeOf<DomainAccessDeniedException>());
            Assert.That(
                async () => await service.AssignOrganizationAsync(
                    "viewer",
                    domain.DomainId,
                    null,
                    CancellationToken.None),
                Throws.TypeOf<DomainAccessDeniedException>());
        });
    }

    private static DomainManagementService Service() => new(
        new InMemoryManagedDomainRepository(),
        new DomainRegistrationNormalizer(new TestPublicSuffixResolver()),
        TimeProvider.System);

    private sealed class TestPublicSuffixResolver : IPublicSuffixResolver
    {
        public string? RegistrableDomain(string canonicalDomain) =>
            canonicalDomain.EndsWith(".com", StringComparison.Ordinal) ||
            canonicalDomain.EndsWith(".ca", StringComparison.Ordinal)
                ? canonicalDomain.Split('.', 2, StringSplitOptions.RemoveEmptyEntries) is { Length: 2 } parts
                    ? parts[1].Contains('.') ? canonicalDomain[(canonicalDomain.IndexOf('.') + 1)..] : canonicalDomain
                    : null
                : null;
    }
}
