using System.Security.Cryptography;
using System.Text;
using HIP.Application.Identity;
using HIP.Application.Protocol;
using HIP.Application.Review;
using HIP.Domain.Identity;

namespace HIP.Tests.Protocol;

/// <summary>
/// Proves that initial identity and signing-key registration has one atomic, idempotent commit boundary.
/// </summary>
[NonParallelizable]
public sealed class IdentitySigningKeyAtomicRegistrationTests
{
    private static readonly DateTimeOffset CreatedAtUtc =
        new(2026, 7, 18, 18, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Registration_commits_identity_ring_and_audit_together()
    {
        var fixture = CreateFixture();
        var request = CreateRequest();

        var result = await fixture.Service.RegisterIdentityAsync(request, CancellationToken.None);

        var storedIdentity = await ((IHipIdentityRepository)fixture.Repository)
            .GetAsync(request.Identity.IdentityId, CancellationToken.None);
        var storedRing = await fixture.Repository.GetAsync(
            request.Identity.IdentityId,
            CancellationToken.None);
        var audits = await fixture.Repository.ListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Identity, Is.SameAs(request.Identity));
            Assert.That(result.KeyRing.Version, Is.EqualTo(1));
            Assert.That(storedIdentity, Is.SameAs(result.Identity));
            Assert.That(storedRing, Is.SameAs(result.KeyRing));
            Assert.That(storedRing!.Keys.Single().Status, Is.EqualTo(SigningKeyStatus.Active));
            Assert.That(audits, Has.Count.EqualTo(1));
            Assert.That(audits.Single().Action, Is.EqualTo("IdentityAndSigningKeyRegistered"));
        });
    }

    [Test]
    public async Task Exact_retry_returns_canonical_registration_without_duplicate_audit()
    {
        var fixture = CreateFixture();
        var request = CreateRequest();

        var first = await fixture.Service.RegisterIdentityAsync(request, CancellationToken.None);
        var retry = await fixture.Service.RegisterIdentityAsync(
            request with
            {
                ActorId = "registration-retry",
                Reason = "Reconcile an ambiguous registration response"
            },
            CancellationToken.None);
        var audits = await fixture.Repository.ListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(retry.Identity, Is.SameAs(first.Identity));
            Assert.That(retry.KeyRing, Is.SameAs(first.KeyRing));
            Assert.That(audits, Has.Count.EqualTo(1));
        });
    }

    [Test]
    public async Task Conflicting_retry_fails_closed_without_mutating_the_winner()
    {
        var fixture = CreateFixture();
        var request = CreateRequest();
        var winner = await fixture.Service.RegisterIdentityAsync(request, CancellationToken.None);

        var exception = Assert.ThrowsAsync<IdentitySigningKeyRegistrationConflictException>(() =>
            fixture.Service.RegisterIdentityAsync(
                request with
                {
                    Identity = request.Identity with { DisplayName = "Conflicting identity" }
                },
                CancellationToken.None));
        var storedIdentity = await fixture.Repository.GetRegisteredIdentityAsync(
            request.Identity.IdentityId,
            CancellationToken.None);
        var storedRing = await fixture.Repository.GetAsync(
            request.Identity.IdentityId,
            CancellationToken.None);
        var audits = await fixture.Repository.ListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(exception!.IdentityId, Is.EqualTo(request.Identity.IdentityId));
            Assert.That(storedIdentity, Is.SameAs(winner.Identity));
            Assert.That(storedRing, Is.SameAs(winner.KeyRing));
            Assert.That(audits, Has.Count.EqualTo(1));
        });
    }

    [Test]
    public async Task Identity_only_state_is_reported_as_inconsistent_and_is_not_repaired()
    {
        var fixture = CreateFixture();
        var request = CreateRequest();
        await ((IHipIdentityRepository)fixture.Repository)
            .SaveAsync(request.Identity, CancellationToken.None);

        var exception = Assert.ThrowsAsync<IdentitySigningKeyRegistrationInconsistencyException>(() =>
            fixture.Service.RegisterIdentityAsync(request, CancellationToken.None));
        var storedRing = await fixture.Repository.GetAsync(
            request.Identity.IdentityId,
            CancellationToken.None);
        var audits = await fixture.Repository.ListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(exception!.IdentityExists, Is.True);
            Assert.That(exception.KeyRingExists, Is.False);
            Assert.That(storedRing, Is.Null);
            Assert.That(audits, Is.Empty);
        });
    }

    [Test]
    public async Task Ring_only_state_is_reported_as_inconsistent_and_is_not_repaired()
    {
        var fixture = CreateFixture();
        var request = CreateRequest();
        await fixture.Service.RegisterAsync(
            new RegisterSigningKeyRequest(
                request.Identity.IdentityId,
                request.KeyId,
                request.Identity.KeyAlgorithm,
                request.Identity.PublicKey,
                request.ActorId,
                request.Reason,
                request.TransitionAtUtc),
            CancellationToken.None);

        var exception = Assert.ThrowsAsync<IdentitySigningKeyRegistrationInconsistencyException>(() =>
            fixture.Service.RegisterIdentityAsync(request, CancellationToken.None));
        var storedIdentity = await fixture.Repository.GetRegisteredIdentityAsync(
            request.Identity.IdentityId,
            CancellationToken.None);
        var audits = await fixture.Repository.ListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(exception!.IdentityExists, Is.False);
            Assert.That(exception.KeyRingExists, Is.True);
            Assert.That(storedIdentity, Is.Null);
            Assert.That(audits, Has.Count.EqualTo(1));
        });
    }

    [Test]
    public async Task Concurrent_exact_registrations_share_one_commit_winner()
    {
        var fixture = CreateFixture();
        var request = CreateRequest();

        var results = await Task.WhenAll(
            Task.Run(() => fixture.Service.RegisterIdentityAsync(request, CancellationToken.None)),
            Task.Run(() => fixture.Service.RegisterIdentityAsync(request, CancellationToken.None)));
        var audits = await fixture.Repository.ListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(results[0].Identity, Is.SameAs(results[1].Identity));
            Assert.That(results[0].KeyRing, Is.SameAs(results[1].KeyRing));
            Assert.That(audits, Has.Count.EqualTo(1));
        });
    }

    [Test]
    public async Task Commit_before_repository_exception_is_reconciled_as_success()
    {
        var inner = new InMemorySigningKeyLifecycleRepository();
        var repository = new CommitThenThrowRepository(inner);
        var service = new SigningKeyLifecycleService(
            repository,
            new AuditLogService(inner),
            new DeterministicFingerprintService());
        var request = CreateRequest();

        var result = await service.RegisterIdentityAsync(request, CancellationToken.None);
        var audits = await inner.ListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(repository.ExceptionWasThrown, Is.True);
            Assert.That(result.Identity, Is.SameAs(request.Identity));
            Assert.That(result.KeyRing.Version, Is.EqualTo(1));
            Assert.That(audits, Has.Count.EqualTo(1));
        });
    }

    [Test]
    public async Task Exception_before_commit_propagates_and_publishes_no_registration_state()
    {
        var inner = new InMemorySigningKeyLifecycleRepository();
        var repository = new ThrowBeforeCommitRepository(inner);
        var service = new SigningKeyLifecycleService(
            repository,
            new AuditLogService(inner),
            new DeterministicFingerprintService());
        var request = CreateRequest();

        var exception = Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.RegisterIdentityAsync(request, CancellationToken.None));
        var storedIdentity = await inner.GetRegisteredIdentityAsync(
            request.Identity.IdentityId,
            CancellationToken.None);
        var storedRing = await inner.GetAsync(
            request.Identity.IdentityId,
            CancellationToken.None);
        var audits = await inner.ListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(exception!.Message, Is.EqualTo("The registration commit failed."));
            Assert.That(storedIdentity, Is.Null);
            Assert.That(storedRing, Is.Null);
            Assert.That(audits, Is.Empty);
        });
    }

    private static RegistrationFixture CreateFixture()
    {
        var repository = new InMemorySigningKeyLifecycleRepository();
        return new RegistrationFixture(
            repository,
            new SigningKeyLifecycleService(
                repository,
                new AuditLogService(repository),
                new DeterministicFingerprintService()));
    }

    private static RegisterIdentitySigningKeyRequest CreateRequest()
    {
        var identity = new HipIdentity(
            "hip:app:atomic-registration",
            IdentitySubjectType.App,
            "Atomic App",
            "test-public-key",
            "TEST-SIGNATURE-1",
            VerificationStatus.Pending,
            CreatedAtUtc,
            "atomic-app");
        return new RegisterIdentitySigningKeyRequest(
            identity,
            "key-1",
            "identity-registration",
            "Create identity and signing key in one commit",
            CreatedAtUtc);
    }

    private sealed record RegistrationFixture(
        InMemorySigningKeyLifecycleRepository Repository,
        SigningKeyLifecycleService Service);

    private sealed class DeterministicFingerprintService : IHipPublicKeyFingerprintService
    {
        public string ComputePublicKeyFingerprint(string algorithm, string publicKey)
        {
            var bytes = Encoding.UTF8.GetBytes($"{algorithm.Length}:{algorithm}{publicKey}");
            var digest = SHA256.HashData(bytes);
            return $"sha256:{Convert.ToBase64String(digest).TrimEnd('=').Replace('+', '-').Replace('/', '_')}";
        }
    }

    private sealed class CommitThenThrowRepository(
        InMemorySigningKeyLifecycleRepository inner) : ISigningKeyLifecycleRepository
    {
        public bool ExceptionWasThrown { get; private set; }

        public Task<HipIdentity?> GetRegisteredIdentityAsync(
            string identityId,
            CancellationToken cancellationToken) =>
            inner.GetRegisteredIdentityAsync(identityId, cancellationToken);

        public Task<SigningKeyRing?> GetAsync(
            string identityId,
            CancellationToken cancellationToken) =>
            inner.GetAsync(identityId, cancellationToken);

        public async Task<bool> TryRegisterIdentityAsync(
            IdentitySigningKeyRegistrationBatch registrationBatch,
            CancellationToken cancellationToken)
        {
            var saved = await inner.TryRegisterIdentityAsync(registrationBatch, cancellationToken);
            if (saved)
            {
                ExceptionWasThrown = true;
                throw new InvalidOperationException("The commit response was lost.");
            }

            return false;
        }

        public Task<bool> TrySaveAsync(
            SigningKeyLifecycleTransitionBatch transitionBatch,
            CancellationToken cancellationToken) =>
            inner.TrySaveAsync(transitionBatch, cancellationToken);
    }

    private sealed class ThrowBeforeCommitRepository(
        InMemorySigningKeyLifecycleRepository inner) : ISigningKeyLifecycleRepository
    {
        public Task<HipIdentity?> GetRegisteredIdentityAsync(
            string identityId,
            CancellationToken cancellationToken) =>
            inner.GetRegisteredIdentityAsync(identityId, cancellationToken);

        public Task<SigningKeyRing?> GetAsync(
            string identityId,
            CancellationToken cancellationToken) =>
            inner.GetAsync(identityId, cancellationToken);

        public Task<bool> TryRegisterIdentityAsync(
            IdentitySigningKeyRegistrationBatch registrationBatch,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("The registration commit failed.");

        public Task<bool> TrySaveAsync(
            SigningKeyLifecycleTransitionBatch transitionBatch,
            CancellationToken cancellationToken) =>
            inner.TrySaveAsync(transitionBatch, cancellationToken);
    }
}
