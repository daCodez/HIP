using HIP.Application.Domains;
using HIP.Domain.Domains;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using HIP.Domain.Identity;
using HIP.Application.Certificates;
using HIP.Domain.Certificates;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Persistence;

/// <summary>Locks the durable shape and round-trip behavior of the unified managed-domain registry.</summary>
public sealed class ManagedDomainPersistenceTests
{
    [Test]
    public void Managed_domain_tables_keys_and_indexes_are_present()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-managed-domain-model-{Guid.NewGuid():N}")
            .Options;
        using var context = new HipDbContext(options);

        var domain = context.Model.FindEntityType("HIP.Infrastructure.Persistence.Entities.HipManagedDomainEntity")!;
        var organization = context.Model.FindEntityType("HIP.Infrastructure.Persistence.Entities.HipDomainOrganizationEntity")!;
        var membership = context.Model.FindEntityType("HIP.Infrastructure.Persistence.Entities.HipOrganizationMembershipEntity")!;
        var grant = context.Model.FindEntityType("HIP.Infrastructure.Persistence.Entities.HipManagedDomainAccessEntity")!;

        Assert.Multiple(() =>
        {
            Assert.That(domain.GetTableName(), Is.EqualTo("hip_managed_domains"));
            Assert.That(organization.GetTableName(), Is.EqualTo("hip_domain_organizations"));
            Assert.That(membership.GetTableName(), Is.EqualTo("hip_organization_memberships"));
            Assert.That(grant.GetTableName(), Is.EqualTo("hip_managed_domain_access"));
            Assert.That(domain.GetIndexes().Single(index => index.Properties.Single().Name == "DomainName").IsUnique, Is.True);
            Assert.That(domain.FindProperty("Version")!.IsConcurrencyToken, Is.True);
            Assert.That(domain.FindProperty("VerificationStatus")!.GetDefaultValue()?.ToString(), Is.EqualTo("Unverified"));
            Assert.That(membership.FindPrimaryKey()!.Properties.Select(item => item.Name), Is.EqualTo(new[] { "OrganizationId", "UserId" }));
            Assert.That(grant.FindPrimaryKey()!.Properties.Select(item => item.Name), Is.EqualTo(new[] { "DomainId", "UserId" }));
        });
    }

    [Test]
    public async Task Repository_round_trips_domains_organizations_memberships_and_grants()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-managed-domain-roundtrip-{Guid.NewGuid():N}")
            .Options;
        var now = new DateTimeOffset(2026, 8, 8, 12, 0, 0, TimeSpan.Zero);
        await using (var writeContext = new HipDbContext(options))
        {
            var repository = new EfManagedDomainRepository(writeContext);
            await repository.AddOrganizationAsync(new DomainOrganization("org_1", "Example", now, now, 1), default);
            await repository.AddOrUpdateOrganizationMembershipAsync(
                new OrganizationDomainMembership("org_1", "user_owner", DomainAccessRole.Owner, now, now), default);
            await repository.AddDomainAsync(new ManagedDomain(
                "domain_1", "example.com", "user_owner", "org_1", ManagedDomainStatus.Active,
                DomainDnssecStatus.Valid, "Validated chain", now, now, 1), default);
            await repository.AddOrUpdateDomainAccessAsync(
                new ManagedDomainAccessGrant("domain_1", "user_viewer", DomainAccessRole.Viewer, now, now), default);
        }

        await using var readContext = new HipDbContext(options);
        var reader = new EfManagedDomainRepository(readContext);
        var domain = await reader.GetDomainByNameAsync("example.com", default);
        var organization = await reader.GetOrganizationAsync("org_1", default);
        var membership = await reader.GetOrganizationMembershipAsync("org_1", "user_owner", default);
        var grant = await reader.GetDomainAccessAsync("domain_1", "user_viewer", default);

        Assert.Multiple(() =>
        {
            Assert.That(domain, Is.Not.Null);
            Assert.That(domain!.DnssecStatus, Is.EqualTo(DomainDnssecStatus.Valid));
            Assert.That(domain.OrganizationId, Is.EqualTo("org_1"));
            Assert.That(organization?.Name, Is.EqualTo("Example"));
            Assert.That(membership?.Role, Is.EqualTo(DomainAccessRole.Owner));
            Assert.That(grant?.Role, Is.EqualTo(DomainAccessRole.Viewer));
        });
    }

    [Test]
    public async Task Verification_history_is_append_only_and_token_digests_round_trip()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-managed-domain-verification-{Guid.NewGuid():N}")
            .Options;
        var now = new DateTimeOffset(2026, 8, 8, 12, 0, 0, TimeSpan.Zero);
        await using var context = new HipDbContext(options);
        var domains = new EfManagedDomainRepository(context);
        await domains.AddDomainAsync(new ManagedDomain(
            "domain_1", "example.com", "owner", null, ManagedDomainStatus.Active,
            DomainDnssecStatus.Unknown, null, now, now, 1), default);
        var audit = new EfManagedDomainVerificationAuditRepository(context);
        await audit.AppendAsync(new(
            "event_1", "domain_1", VerificationMethod.DnsTxt, "challenge-started",
            DomainVerificationAttemptOutcome.Pending, $"sha256:{new string('a', 64)}", 1, now, now.AddDays(1)), default);
        await audit.AppendAsync(new(
            "event_2", "domain_1", VerificationMethod.DnsTxt, "verification-checked",
            DomainVerificationAttemptOutcome.Succeeded, $"sha256:{new string('a', 64)}", 1, now.AddMinutes(1), now.AddDays(1)), default);

        var events = await audit.ListAsync("domain_1", default);

        Assert.Multiple(() =>
        {
            Assert.That(events, Has.Count.EqualTo(2));
            Assert.That(events.Select(item => item.EventId), Is.EqualTo(new[] { "event_1", "event_2" }));
            Assert.That(events.All(item => item.TokenDigest.Length == 71), Is.True);
        });
    }

    [Test]
    public async Task Certificate_application_round_trips_eligibility_and_history_fields()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-managed-domain-application-{Guid.NewGuid():N}").Options;
        var now = new DateTimeOffset(2026, 8, 8, 12, 0, 0, TimeSpan.Zero);
        await using var context = new HipDbContext(options);
        await new EfManagedDomainRepository(context).AddDomainAsync(new ManagedDomain(
            "domain_1", "example.com", "owner", null, ManagedDomainStatus.Active,
            DomainDnssecStatus.Valid, null, now, now, 1), default);
        var evaluation = new DomainCertificatePolicyEvaluationResult(
            "example.com", DomainCertificateLevel.Certified, "policy-v1",
            DomainCertificatePolicyDecision.RequiresReview, "Review required.",
            [new("review.certified", DomainCertificateRequirementStatus.ReviewRequired, "Review required.")], now);
        var repository = new EfManagedDomainCertificateApplicationRepository(context);
        await repository.AddAsync(new ManagedDomainCertificateApplication(
            "application_1", "domain_1", "example.com", DomainCertificateLevel.Certified, "owner", null,
            DomainCertificateApplicationStatus.PendingReview, now, now, evaluation,
            ["review.certified"], [], null, null, null, null, 1), default);

        var stored = await repository.GetAsync("application_1", default);

        Assert.Multiple(() =>
        {
            Assert.That(stored?.Status, Is.EqualTo(DomainCertificateApplicationStatus.PendingReview));
            Assert.That(stored?.Eligibility?.PolicyVersion, Is.EqualTo("policy-v1"));
            Assert.That(stored?.SecurityFindings, Is.EqualTo(new[] { "review.certified" }));
        });
    }
}
