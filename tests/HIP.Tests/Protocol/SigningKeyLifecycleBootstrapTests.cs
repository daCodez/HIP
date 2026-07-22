using HIP.Application.Identity;
using HIP.Application.Protocol;
using HIP.Application.Review;
using HIP.Domain.Identity;

namespace HIP.Tests.Protocol;

/// <summary>
/// Proves legacy identity bootstrap is idempotent, fail-closed, and audit-safe under concurrency.
/// </summary>
public sealed class SigningKeyLifecycleBootstrapTests
{
    private const string FirstFingerprint = "sha256:AAAAAAAAAAAAAAAAAAAAAA";
    private const string SecondFingerprint = "sha256:BBBBBBBBBBBBBBBBBBBBBB";
    private static readonly DateTimeOffset InitialTime =
        new(2026, 7, 18, 16, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Missing_legacy_ring_is_registered_once_with_one_audit_fact()
    {
        var fixture = CreateFixture();

        var ensured = await fixture.Service.EnsureInitialKeyAsync(
            CreateRequest(),
            CancellationToken.None);

        var stored = await fixture.Repository.GetAsync(ensured.IdentityId, CancellationToken.None);
        var audits = await fixture.Repository.ListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(ensured.Version, Is.EqualTo(1));
            Assert.That(ensured.Keys, Has.Count.EqualTo(1));
            Assert.That(ensured.Keys.Single().Status, Is.EqualTo(SigningKeyStatus.Active));
            Assert.That(ensured.Keys.Single().PublicKeyFingerprint, Is.EqualTo(FirstFingerprint));
            Assert.That(stored, Is.SameAs(ensured));
            Assert.That(audits, Has.Count.EqualTo(1));
            Assert.That(audits.Single().Metadata["identityId"], Is.EqualTo(ensured.IdentityId));
            Assert.That(audits.Single().Metadata["keyId"], Is.EqualTo("key-1"));
        });
    }

    [Test]
    public async Task Concurrent_matching_ensures_return_the_single_compare_and_swap_winner()
    {
        var innerRepository = new InMemorySigningKeyLifecycleRepository();
        var repository = new ConcurrentFirstReadRepository(innerRepository);
        var audit = new AuditLogService(innerRepository);
        var service = new SigningKeyLifecycleService(
            repository, audit, new DeterministicFingerprintService());
        var request = CreateRequest();

        var first = Task.Run(() => service.EnsureInitialKeyAsync(request, CancellationToken.None));
        var second = Task.Run(() => service.EnsureInitialKeyAsync(request, CancellationToken.None));
        var results = await Task.WhenAll(first, second);

        var stored = await innerRepository.GetAsync(request.IdentityId, CancellationToken.None);
        var audits = await innerRepository.ListAsync(CancellationToken.None);
        var resultKeys = results.SelectMany(result => result.Keys).ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(repository.MissingInitialReadCount, Is.EqualTo(2));
            Assert.That(results.Select(result => result.Version), Is.All.EqualTo(1));
            Assert.That(results.Select(result => result.IdentityId), Is.All.EqualTo(request.IdentityId));
            Assert.That(resultKeys, Has.Length.EqualTo(2));
            Assert.That(resultKeys.Select(key => key.KeyId), Is.All.EqualTo(request.KeyId));
            Assert.That(stored!.Keys, Has.Count.EqualTo(1));
            Assert.That(audits, Has.Count.EqualTo(1));
        });
    }

    [Test]
    public async Task Repeated_matching_ensure_does_not_advance_version_or_duplicate_audit()
    {
        var fixture = CreateFixture();
        var request = CreateRequest();

        var first = await fixture.Service.EnsureInitialKeyAsync(request, CancellationToken.None);
        var second = await fixture.Service.EnsureInitialKeyAsync(
            request with
            {
                PublicKey = "equivalent-public-material-with-different-PEM-wrapping",
                ActorId = "different-bootstrap-worker",
                Reason = "A retry supplies new audit context",
                TransitionAtUtc = InitialTime.AddMinutes(1)
            },
            CancellationToken.None);
        var audits = await fixture.Repository.ListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(second, Is.SameAs(first));
            Assert.That(second.Version, Is.EqualTo(1));
            Assert.That(second.Keys, Has.Count.EqualTo(1));
            Assert.That(second.Keys.Single().PublicKey, Is.EqualTo(request.PublicKey));
            Assert.That(audits, Has.Count.EqualTo(1));
        });
    }

    [Test]
    public async Task Existing_ring_mismatch_fails_closed_without_state_or_audit_change()
    {
        var fixture = CreateFixture();
        var request = CreateRequest();
        var registered = await fixture.Service.EnsureInitialKeyAsync(request, CancellationToken.None);
        var mismatches = new[]
        {
            request with { IdentityId = "HIP:DOMAIN:EXAMPLE" },
            request with { KeyId = "key-2" },
            request with { Algorithm = "different-algorithm" },
            request with { PublicKey = "different-public-material" }
        };

        foreach (var mismatch in mismatches)
        {
            var exception = Assert.ThrowsAsync<SigningKeyBootstrapMismatchException>(() =>
                fixture.Service.EnsureInitialKeyAsync(mismatch, CancellationToken.None));

            Assert.Multiple(() =>
            {
                Assert.That(exception!.IdentityId, Is.EqualTo(registered.IdentityId));
                Assert.That(exception.Message, Does.Not.Contain(request.PublicKey));
                Assert.That(exception.Message, Does.Not.Contain(FirstFingerprint));
            });
        }

        var stored = await fixture.Repository.GetAsync(registered.IdentityId, CancellationToken.None);
        var audits = await fixture.Repository.ListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(stored, Is.SameAs(registered));
            Assert.That(stored!.Version, Is.EqualTo(1));
            Assert.That(audits, Has.Count.EqualTo(1));
        });
    }

    [Test]
    public async Task Matching_retired_or_revoked_key_is_returned_without_reactivation_or_duplicate_audit()
    {
        var fixture = CreateFixture();
        var initialRequest = CreateRequest();
        var registered = await fixture.Service.EnsureInitialKeyAsync(initialRequest, CancellationToken.None);
        var rotation = await fixture.Service.RotateAsync(
            new RotateSigningKeyRequest(
                registered.IdentityId,
                "key-1",
                registered.Version,
                "key-2",
                "ML-DSA-65",
                "public-material-2",
                "operator-1",
                "Scheduled rotation",
                InitialTime.AddMinutes(1)),
            CancellationToken.None);
        var retired = await fixture.Service.RetireAsync(
            new ChangeSigningKeyStateRequest(
                registered.IdentityId,
                "key-1",
                rotation.KeyRing.Version,
                "operator-1",
                "Rotation overlap complete",
                InitialTime.AddMinutes(2)),
            CancellationToken.None);
        var auditCountBeforeRetiredEnsure =
            (await fixture.Repository.ListAsync(CancellationToken.None)).Count;

        var ensuredRetired = await fixture.Service.EnsureInitialKeyAsync(
            initialRequest,
            CancellationToken.None);

        var auditCountAfterRetiredEnsure =
            (await fixture.Repository.ListAsync(CancellationToken.None)).Count;
        var revoked = await fixture.Service.RevokeAsync(
            new ChangeSigningKeyStateRequest(
                registered.IdentityId,
                "key-1",
                ensuredRetired.Version,
                "security-operator",
                "Historical key compromised",
                InitialTime.AddMinutes(3)),
            CancellationToken.None);
        var auditCountBeforeRevokedEnsure =
            (await fixture.Repository.ListAsync(CancellationToken.None)).Count;

        var ensuredRevoked = await fixture.Service.EnsureInitialKeyAsync(
            initialRequest,
            CancellationToken.None);

        var auditCountAfterRevokedEnsure =
            (await fixture.Repository.ListAsync(CancellationToken.None)).Count;

        Assert.Multiple(() =>
        {
            Assert.That(ensuredRetired, Is.SameAs(retired));
            Assert.That(ensuredRetired.GetRequiredKey("key-1").Status, Is.EqualTo(SigningKeyStatus.Retired));
            Assert.That(auditCountAfterRetiredEnsure, Is.EqualTo(auditCountBeforeRetiredEnsure));
            Assert.That(ensuredRevoked, Is.SameAs(revoked));
            Assert.That(ensuredRevoked.GetRequiredKey("key-1").Status, Is.EqualTo(SigningKeyStatus.Revoked));
            Assert.That(auditCountAfterRevokedEnsure, Is.EqualTo(auditCountBeforeRevokedEnsure));
        });
    }

    private static RegisterSigningKeyRequest CreateRequest() =>
        new(
            "hip:domain:example",
            "key-1",
            "ML-DSA-65",
            "public-material-1",
            "legacy-bootstrap",
            "Backfill lifecycle for existing identity",
            InitialTime);

    private static LifecycleFixture CreateFixture()
    {
        var repository = new InMemorySigningKeyLifecycleRepository();
        var audit = new AuditLogService(repository);
        return new LifecycleFixture(
            repository,
            new SigningKeyLifecycleService(repository, audit, new DeterministicFingerprintService()));
    }

    private sealed record LifecycleFixture(
        InMemorySigningKeyLifecycleRepository Repository,
        SigningKeyLifecycleService Service);

    private sealed class DeterministicFingerprintService : IHipPublicKeyFingerprintService
    {
        public string ComputePublicKeyFingerprint(string algorithm, string publicKey) =>
            publicKey switch
            {
                "public-material-1" or
                "equivalent-public-material-with-different-PEM-wrapping" => FirstFingerprint,
                "public-material-2" => SecondFingerprint,
                _ => "sha256:CCCCCCCCCCCCCCCCCCCCCC"
            };
    }

    private sealed class ConcurrentFirstReadRepository(
        InMemorySigningKeyLifecycleRepository innerRepository) : ISigningKeyLifecycleRepository
    {
        private readonly TaskCompletionSource initialReadsReached =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int missingInitialReadCount;

        public int MissingInitialReadCount => Volatile.Read(ref missingInitialReadCount);

        public Task<HipIdentity?> GetRegisteredIdentityAsync(
            string identityId,
            CancellationToken cancellationToken) =>
            innerRepository.GetRegisteredIdentityAsync(identityId, cancellationToken);

        public async Task<SigningKeyRing?> GetAsync(
            string identityId,
            CancellationToken cancellationToken)
        {
            var snapshot = await innerRepository.GetAsync(identityId, cancellationToken);
            if (snapshot is not null)
            {
                return snapshot;
            }

            if (Interlocked.Increment(ref missingInitialReadCount) == 2)
            {
                initialReadsReached.TrySetResult();
            }

            await initialReadsReached.Task.WaitAsync(cancellationToken);
            return snapshot;
        }

        public Task<bool> TrySaveAsync(
            SigningKeyLifecycleTransitionBatch transitionBatch,
            CancellationToken cancellationToken) =>
            innerRepository.TrySaveAsync(transitionBatch, cancellationToken);

        public Task<bool> TryRegisterIdentityAsync(
            IdentitySigningKeyRegistrationBatch registrationBatch,
            CancellationToken cancellationToken) =>
            innerRepository.TryRegisterIdentityAsync(registrationBatch, cancellationToken);
    }
}
