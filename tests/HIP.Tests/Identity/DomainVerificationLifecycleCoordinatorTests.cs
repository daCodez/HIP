using HIP.Application.Identity;
using HIP.Domain.Identity;

namespace HIP.Tests.Identity;

/// <summary>Locks bounded, due-only scheduled DNS ownership rechecks.</summary>
public sealed class DomainVerificationLifecycleCoordinatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 21, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Recheck_due_only_processes_stale_verified_dns_identities()
    {
        var identities = new StubWebsiteIdentityRepository(
        [
            Identity("due.example", VerificationMethod.DnsTxt, Now.AddDays(-8)),
            Identity("fresh.example", VerificationMethod.DnsTxt, Now.AddDays(-2)),
            Identity("well-known.example", VerificationMethod.WellKnownHipJson, Now.AddDays(-8)),
            Identity("pending.example", VerificationMethod.DnsTxt, Now.AddDays(-8), VerificationStatus.Pending)
        ]);
        var service = new RecordingWebsiteIdentityService();
        var coordinator = new DomainVerificationLifecycleCoordinator(
            identities,
            service,
            new DomainVerificationLifecycleOptions(TimeSpan.FromHours(24), TimeSpan.FromDays(7)),
            new FixedTimeProvider(Now));

        var summary = await coordinator.RecheckDueAsync(100, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(summary, Is.EqualTo(new DomainVerificationRecheckSummary(1, 1, 0)));
            Assert.That(service.RetriedDomains, Is.EqualTo(new[] { "due.example" }));
            Assert.That(service.ActorIds, Is.EqualTo(new[] { "system:domain-verification-recheck" }));
            Assert.That(service.ActorRoles, Is.EqualTo(new[] { "Owner" }));
        });
    }

    [TestCase(0)]
    [TestCase(501)]
    public void Recheck_due_rejects_unbounded_batch_sizes(int maximum)
    {
        var coordinator = new DomainVerificationLifecycleCoordinator(
            new StubWebsiteIdentityRepository([]),
            new RecordingWebsiteIdentityService());

        Assert.That(
            async () => await coordinator.RecheckDueAsync(maximum, CancellationToken.None),
            Throws.TypeOf<ArgumentOutOfRangeException>());
    }

    private static WebsiteIdentity Identity(
        string domain,
        VerificationMethod method,
        DateTimeOffset lastCheckedAtUtc,
        VerificationStatus status = VerificationStatus.Verified) =>
        new(
            domain,
            $"hip:web:{domain}",
            [],
            status,
            method,
            Now.AddDays(-30),
            status == VerificationStatus.Verified ? Now.AddDays(-20) : null,
            lastCheckedAtUtc);

    private sealed class StubWebsiteIdentityRepository(IReadOnlyCollection<WebsiteIdentity> identities)
        : IWebsiteIdentityRepository
    {
        public Task<IReadOnlyCollection<WebsiteIdentity>> ListAsync(CancellationToken cancellationToken) =>
            Task.FromResult(identities);

        public Task<WebsiteIdentity?> GetAsync(string domain, CancellationToken cancellationToken) =>
            Task.FromResult(identities.SingleOrDefault(item => item.Domain == domain));

        public Task<bool> TryCreateAsync(WebsiteIdentity websiteIdentity, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<bool> TryUpdateAsync(WebsiteIdentity expected, WebsiteIdentity updated, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<WebsiteIdentity> SaveAsync(WebsiteIdentity websiteIdentity, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class RecordingWebsiteIdentityService : IWebsiteIdentityService
    {
        public List<string> RetriedDomains { get; } = [];
        public List<string> ActorIds { get; } = [];
        public List<string> ActorRoles { get; } = [];

        public Task<WebsiteIdentity> RetryVerificationAsync(
            string domain,
            string actorId,
            string actorRole,
            CancellationToken cancellationToken)
        {
            RetriedDomains.Add(domain);
            ActorIds.Add(actorId);
            ActorRoles.Add(actorRole);
            return Task.FromResult(Identity(domain, VerificationMethod.DnsTxt, Now));
        }

        public Task<WebsiteIdentityRegistrationResponse> RegisterAsync(WebsiteIdentityRegistrationRequest request, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<WebsiteIdentityRegistrationResponse> RegisterAsync(WebsiteIdentityRegistrationRequest request, string actorId, string actorRole, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<WebsiteIdentity> VerifyAsync(WebsiteVerificationRequest request, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<WebsiteIdentity> VerifyAsync(WebsiteVerificationRequest request, string actorId, string actorRole, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<WebsiteIdentity?> GetAsync(string domain, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<WebsiteIdentity?> GetAsync(string domain, string actorId, string actorRole, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<IReadOnlyCollection<WebsiteIdentity>> ListAsync(CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<IReadOnlyCollection<WebsiteIdentity>> ListAsync(string actorId, string actorRole, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<WebsiteIdentityRegistrationResponse> RenewExpiredVerificationAsync(string domain, string actorId, string actorRole, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<WebsiteIdentity> RevokeVerificationAsync(string domain, string reason, string actorId, string actorRole, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<HipWellKnownDocument> BuildWellKnownDocumentAsync(string domain, CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
