using HIP.Application.Certificates;
using HIP.Application.Domains;
using HIP.Application.Identity;
using HIP.Domain.Domains;
using HIP.Domain.Identity;

namespace HIP.Tests.Domains;

public sealed class ManagedDomainVerificationServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 8, 14, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Starting_a_challenge_does_not_verify_the_domain()
    {
        var fixture = await Fixture.CreateAsync();

        var challenge = await fixture.Service.StartAsync("owner", fixture.DomainId, VerificationMethod.DnsTxt, default);
        var domain = await fixture.Management.GetAsync("owner", fixture.DomainId, default);

        Assert.Multiple(() =>
        {
            Assert.That(challenge.Token, Is.EqualTo("token-1"));
            Assert.That(domain?.VerificationStatus, Is.EqualTo(ManagedDomainVerificationStatus.Pending));
            Assert.That(domain?.OwnershipVerifiedAtUtc, Is.Null);
            Assert.That(fixture.Audit.Events, Has.Count.EqualTo(1));
            Assert.That(fixture.Audit.Events[0].TokenDigest, Does.StartWith("sha256:"));
            Assert.That(fixture.Audit.Events[0].TokenDigest, Does.Not.Contain("token-1"));
        });
    }

    [Test]
    public async Task Successful_live_check_marks_domain_verified_and_retains_attempt_history()
    {
        var fixture = await Fixture.CreateAsync(VerificationStatus.Verified);
        await fixture.Service.StartAsync("owner", fixture.DomainId, VerificationMethod.HtmlFile, default);

        var result = await fixture.Service.CheckAsync("owner", fixture.DomainId, VerificationMethod.HtmlFile, default);
        var domain = await fixture.Management.GetAsync("owner", fixture.DomainId, default);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(ManagedDomainVerificationStatus.Verified));
            Assert.That(domain?.VerificationStatus, Is.EqualTo(ManagedDomainVerificationStatus.Verified));
            Assert.That(domain?.OwnershipVerifiedAtUtc, Is.EqualTo(Now));
            Assert.That(fixture.Audit.Events.Select(item => item.EventType), Is.EqualTo(new[] { "challenge-started", "verification-checked" }));
        });
    }

    [Test]
    public async Task Unauthorized_actor_cannot_probe_or_change_a_domain_verification()
    {
        var fixture = await Fixture.CreateAsync();

        Assert.That(
            async () => await fixture.Service.StartAsync("stranger", fixture.DomainId, VerificationMethod.DnsTxt, default),
            Throws.TypeOf<DomainAccessDeniedException>());
        Assert.Multiple(() =>
        {
            Assert.That(fixture.Verifier.StartCalls, Is.Zero);
            Assert.That(fixture.Audit.Events, Is.Empty);
        });
    }

    private sealed record Fixture(
        string DomainId,
        DomainManagementService Management,
        ManagedDomainVerificationService Service,
        StubVerificationService Verifier,
        InMemoryManagedDomainVerificationAuditRepository Audit)
    {
        public static async Task<Fixture> CreateAsync(VerificationStatus checkStatus = VerificationStatus.Pending)
        {
            var repository = new InMemoryManagedDomainRepository();
            var management = new DomainManagementService(
                repository,
                new DomainRegistrationNormalizer(new TestPublicSuffixResolver()),
                new FixedTimeProvider(Now));
            var domain = await management.RegisterAsync("owner", new("example.com"), default);
            var verifier = new StubVerificationService(checkStatus);
            var audit = new InMemoryManagedDomainVerificationAuditRepository();
            return new(domain.DomainId, management,
                new ManagedDomainVerificationService(management, verifier, audit, new FixedTimeProvider(Now)), verifier, audit);
        }
    }

    private sealed class StubVerificationService(VerificationStatus checkStatus) : IDomainVerificationService
    {
        private DomainVerificationRequest? request;
        public int StartCalls { get; private set; }
        public Task<DomainVerificationRequest> StartAsync(string domain, VerificationMethod method, CancellationToken cancellationToken)
        {
            StartCalls++;
            request = new(domain, method, "token-1", VerificationStatus.Pending, Now, null, Now.AddDays(1));
            return Task.FromResult(request);
        }
        public Task<DomainVerificationRequest> GetOrStartAsync(string domain, VerificationMethod method, CancellationToken cancellationToken) => StartAsync(domain, method, cancellationToken);
        public Task<DomainVerificationRequest?> GetAsync(string domain, VerificationMethod method, CancellationToken cancellationToken) => Task.FromResult(request);
        public Task<DomainVerificationRequest> VerifyAsync(string domain, VerificationMethod method, string token, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<DomainVerificationRetryResult> RetryAsync(string domain, VerificationMethod method, CancellationToken cancellationToken)
        {
            request = request! with { Status = checkStatus, VerifiedAtUtc = checkStatus == VerificationStatus.Verified ? Now : null, LastCheckedAtUtc = Now };
            return Task.FromResult(new DomainVerificationRetryResult(request, new(domain, domain, DomainVerificationCheckStatus.Verified, Now, "Checked.")));
        }
        public Task<DomainVerificationRequest> RevokeAsync(string domain, VerificationMethod method, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<DomainVerificationRequest> RenewExpiredAsync(string domain, VerificationMethod method, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<DomainVerificationRequest> RegenerateAsync(string domain, VerificationMethod method, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<DomainVerificationCheckResult> CheckDnsTxtAsync(string domain, string expectedToken, CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class TestPublicSuffixResolver : IPublicSuffixResolver
    {
        public string? RegistrableDomain(string canonicalDomain) => canonicalDomain;
    }
}
