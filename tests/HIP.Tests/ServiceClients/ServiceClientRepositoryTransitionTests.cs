using System.Text;
using HIP.Application.ServiceClients;
using HIP.Domain.Audit;
using HIP.Domain.Review;
using HIP.Domain.ServiceClients;

namespace HIP.Tests.ServiceClients;

[TestFixture]
public sealed class ServiceClientRepositoryTransitionTests
{
    private const string ClientIdA = "hipc_v1_ABCDEFGHIJKLMNOPQRSTUQ";
    private const string ClientIdB = "hipc_v1_BCDEFGHIJKLMNOPQRSTUVA";
    private const string OwnerA =
        "service-client-owner-hmac-sha256-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string OwnerB =
        "service-client-owner-hmac-sha256-v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private const string VerifierA =
        "pbkdf2-sha256-v1$600000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string VerifierB =
        "pbkdf2-sha256-v1$600000$QQQQQQQQQQQQQQQQQQQQQQ$QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ";
    private const string VerifierC =
        "pbkdf2-sha256-v1$600000$gggggggggggggggggggggg$ggggggggggggggggggggggggggggggggggggggggggg";
    private static readonly DateTimeOffset CreatedAtUtc =
        new(2026, 7, 20, 20, 0, 0, TimeSpan.Zero);

    [Test]
    public void Shared_validator_accepts_only_create_rotate_and_revoke_with_exact_audit_versions()
    {
        var created = Registration(ClientIdA, OwnerA, "Client A", VerifierA);
        var rotatedAt = CreatedAtUtc.AddDays(1);
        var rotated = created.RotateCredential(VerifierB, rotatedAt);
        var revokedAt = CreatedAtUtc.AddDays(2);
        var revoked = rotated.Revoke(revokedAt);

        Assert.Multiple(() =>
        {
            Assert.That(
                () => ServiceClientTransitionValidator.ValidateDelta(
                    previous: null,
                    Batch(created, 0, AuditForCreate(created))),
                Throws.Nothing);
            Assert.That(
                () => ServiceClientTransitionValidator.ValidateDelta(
                    created,
                    Batch(rotated, 1, AuditForRotation(created, rotated))),
                Throws.Nothing);
            Assert.That(
                () => ServiceClientTransitionValidator.ValidateDelta(
                    rotated,
                    Batch(revoked, 2, AuditForRevocation(rotated, revoked))),
                Throws.Nothing);
        });
    }

    [Test]
    public void Shared_validator_rejects_immutable_registration_fact_mutation()
    {
        var previous = Registration(ClientIdA, OwnerA, "Client A", VerifierA);
        var mutatedBase = Registration(ClientIdA, OwnerA, "Mutated name", VerifierA);
        var mutated = mutatedBase.RotateCredential(VerifierB, CreatedAtUtc.AddDays(1));

        Assert.That(
            () => ServiceClientTransitionValidator.ValidateDelta(
                previous,
                Batch(mutated, 1, AuditForRotation(previous, mutated))),
            Throws.ArgumentException);
    }

    [Test]
    public void Shared_validator_rejects_verifier_change_during_revocation()
    {
        var previous = Registration(ClientIdA, OwnerA, "Client A", VerifierA);
        var changedBase = Registration(ClientIdA, OwnerA, "Client A", VerifierB);
        var invalidRevocation = changedBase.Revoke(CreatedAtUtc.AddDays(1));

        Assert.That(
            () => ServiceClientTransitionValidator.ValidateDelta(
                previous,
                Batch(invalidRevocation, 1, AuditForRevocation(previous, invalidRevocation))),
            Throws.ArgumentException);
    }

    [Test]
    public void Shared_validator_rejects_transition_from_terminal_revocation()
    {
        var original = Registration(ClientIdA, OwnerA, "Client A", VerifierA);
        var previous = original.Revoke(CreatedAtUtc.AddDays(1));
        var invalid = original
            .RotateCredential(VerifierB, CreatedAtUtc.AddHours(12))
            .RotateCredential(VerifierC, CreatedAtUtc.AddDays(2));

        Assert.That(
            () => ServiceClientTransitionValidator.ValidateDelta(
                previous,
                Batch(invalid, 2, AuditForRotation(previous, invalid))),
            Throws.InvalidOperationException);
    }

    [Test]
    public void Shared_validator_rejects_revocation_that_precedes_the_current_credential_version()
    {
        var original = Registration(ClientIdA, OwnerA, "Client A", VerifierA);
        var previous = original.RotateCredential(VerifierB, CreatedAtUtc.AddDays(2));
        var invalid = original
            .RotateCredential(VerifierB, CreatedAtUtc.AddHours(12))
            .Revoke(CreatedAtUtc.AddDays(1));

        Assert.That(
            () => ServiceClientTransitionValidator.ValidateDelta(
                previous,
                Batch(invalid, 2, AuditForRevocation(previous, invalid))),
            Throws.ArgumentException);
    }

    [Test]
    public void Shared_validator_rejects_non_exact_audit_actor_identifiers()
    {
        var created = Registration(ClientIdA, OwnerA, "Client A", VerifierA);
        var audit = AuditForCreate(created) with { ActorId = " actor-from-principal " };

        Assert.That(
            () => ServiceClientTransitionValidator.ValidateDelta(null, Batch(created, 0, audit)),
            Throws.ArgumentException);
    }

    [Test]
    public void Shared_validator_rejects_wrong_audit_action_version_metadata_and_sensitive_facts()
    {
        var created = Registration(ClientIdA, OwnerA, "Client A", VerifierA);
        var validAudit = AuditForCreate(created);
        var wrongAction = validAudit with { Action = ServiceClientAuditActions.Revoked };
        var wrongVersion = validAudit with
        {
            Metadata = new Dictionary<string, string>(validAudit.Metadata, StringComparer.Ordinal)
            {
                ["aggregateVersion"] = "99"
            }
        };
        var leakedDomain = validAudit with
        {
            Metadata = new Dictionary<string, string>(validAudit.Metadata, StringComparer.Ordinal)
            {
                ["domain"] = created.DomainGrants.Single()
            }
        };

        Assert.Multiple(() =>
        {
            Assert.That(
                () => ServiceClientTransitionValidator.ValidateDelta(
                    null,
                    Batch(created, 0, wrongAction)),
                Throws.ArgumentException);
            Assert.That(
                () => ServiceClientTransitionValidator.ValidateDelta(
                    null,
                    Batch(created, 0, wrongVersion)),
                Throws.ArgumentException);
            Assert.That(
                () => ServiceClientTransitionValidator.ValidateDelta(
                    null,
                    Batch(created, 0, leakedDomain)),
                Throws.ArgumentException);
        });
    }

    [Test]
    public async Task In_memory_repository_globally_keys_client_ids_and_enforces_version_CAS()
    {
        var repository = new InMemoryServiceClientRepository();
        var original = Registration(ClientIdA, OwnerA, "Client A", VerifierA);
        var sameIdOtherOwner = Registration(ClientIdA, OwnerB, "Client B", VerifierA);
        var rotatedA = original.RotateCredential(VerifierB, CreatedAtUtc.AddDays(1));
        var competingRotation = original.RotateCredential(VerifierC, CreatedAtUtc.AddDays(1));

        var created = await repository.TrySaveAsync(
            Batch(original, 0, AuditForCreate(original)), CancellationToken.None);
        var globalCollision = await repository.TrySaveAsync(
            Batch(sameIdOtherOwner, 0, AuditForCreate(sameIdOtherOwner, "audit-other-owner")),
            CancellationToken.None);
        var winner = await repository.TrySaveAsync(
            Batch(rotatedA, 1, AuditForRotation(original, rotatedA)), CancellationToken.None);
        var stale = await repository.TrySaveAsync(
            Batch(competingRotation, 1, AuditForRotation(original, competingRotation, "audit-stale")),
            CancellationToken.None);
        var stored = await repository.GetAsync(ClientIdA, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(created, Is.EqualTo(ServiceClientSaveOutcome.Succeeded));
            Assert.That(globalCollision, Is.EqualTo(ServiceClientSaveOutcome.VersionConflict));
            Assert.That(winner, Is.EqualTo(ServiceClientSaveOutcome.Succeeded));
            Assert.That(stale, Is.EqualTo(ServiceClientSaveOutcome.VersionConflict));
            Assert.That(stored!.OwnerScopeId, Is.EqualTo(OwnerA));
            Assert.That(stored.CredentialVerifier, Is.EqualTo(VerifierB));
            Assert.That(stored.AggregateVersion, Is.EqualTo(2));
        });
    }

    [Test]
    public async Task In_memory_repository_commits_audit_and_state_atomically()
    {
        var repository = new InMemoryServiceClientRepository();
        var first = Registration(ClientIdA, OwnerA, "Client A", VerifierA);
        var second = Registration(ClientIdB, OwnerA, "Client B", VerifierB);
        const string reusedAuditId = "audit-reused";

        var firstOutcome = await repository.TrySaveAsync(
            Batch(first, 0, AuditForCreate(first, reusedAuditId)), CancellationToken.None);
        var secondOutcome = await repository.TrySaveAsync(
            Batch(second, 0, AuditForCreate(second, reusedAuditId)), CancellationToken.None);
        var secondStored = await repository.GetAsync(ClientIdB, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(firstOutcome, Is.EqualTo(ServiceClientSaveOutcome.Succeeded));
            Assert.That(secondOutcome, Is.EqualTo(ServiceClientSaveOutcome.VersionConflict));
            Assert.That(secondStored, Is.Null, "State must not commit when its audit fact conflicts.");
        });
    }

    [Test]
    public async Task In_memory_repository_returns_bounded_ordinal_owner_pages_with_owner_bound_cursors()
    {
        var repository = new InMemoryServiceClientRepository();
        var first = Registration(ClientIdA, OwnerA, "Client A", VerifierA);
        var second = Registration(ClientIdB, OwnerA, "Client B", VerifierB);
        await repository.TrySaveAsync(
            Batch(second, 0, AuditForCreate(second, "audit-page-B")), CancellationToken.None);
        await repository.TrySaveAsync(
            Batch(first, 0, AuditForCreate(first, "audit-page-A")), CancellationToken.None);

        var firstPage = await repository.ListByOwnerAsync(OwnerA, null, 1, CancellationToken.None);
        var secondPage = await repository.ListByOwnerAsync(OwnerA, firstPage.NextCursor, 1, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(firstPage.Items.Select(item => item.ClientId), Is.EqualTo(new[] { ClientIdA }));
            Assert.That(firstPage.NextCursor, Is.Not.Null);
            Assert.That(secondPage.Items.Select(item => item.ClientId), Is.EqualTo(new[] { ClientIdB }));
            Assert.That(secondPage.NextCursor, Is.Null);
            Assert.That(
                async () => await repository.ListByOwnerAsync(
                    OwnerB, firstPage.NextCursor, 1, CancellationToken.None),
                Throws.ArgumentException);
            Assert.That(
                async () => await repository.ListByOwnerAsync(
                    OwnerA, null, ServiceClientRepositoryPage.MaximumPageSize + 1, CancellationToken.None),
                Throws.InstanceOf<ArgumentOutOfRangeException>());
        });
    }

    [Test]
    public void Shared_cursor_codec_is_canonical_and_exactly_owner_bound()
    {
        var cursor = ServiceClientRepositoryCursor.Encode(OwnerA, ClientIdA);
        var encodedPayload = cursor[(cursor.IndexOf('_') + 1)..]
            .Replace('-', '+')
            .Replace('_', '/');
        encodedPayload = encodedPayload.PadRight(
            encodedPayload.Length + ((4 - encodedPayload.Length % 4) % 4),
            '=');
        var decodedPayload = Convert.FromBase64String(encodedPayload);
        var tampered = cursor[..^1] + (cursor[^1] == 'A' ? 'B' : 'A');

        Assert.Multiple(() =>
        {
            Assert.That(ServiceClientRepositoryCursor.Decode(cursor, OwnerA), Is.EqualTo(ClientIdA));
            Assert.That(
                Encoding.UTF8.GetString(decodedPayload),
                Does.Not.Contain(OwnerA),
                "An opaque cursor must not disclose its owner partition.");
            Assert.That(
                () => ServiceClientRepositoryCursor.Decode(cursor, OwnerB),
                Throws.ArgumentException);
            Assert.That(
                () => ServiceClientRepositoryCursor.Decode(tampered, OwnerA),
                Throws.ArgumentException);
            Assert.That(
                () => ServiceClientRepositoryCursor.Decode(cursor + "=", OwnerA),
                Throws.ArgumentException);
            Assert.That(
                () => ServiceClientRepositoryCursor.Decode(new string('x', 513), OwnerA),
                Throws.ArgumentException);
            Assert.That(
                () => ServiceClientRepositoryCursor.Encode(OwnerA, "hipc_v1_invalid"),
                Throws.ArgumentException);
        });
    }

    [Test]
    public void In_memory_repository_propagates_pre_cancelled_operations()
    {
        var repository = new InMemoryServiceClientRepository();
        var registration = Registration(ClientIdA, OwnerA, "Client A", VerifierA);
        var transition = Batch(registration, 0, AuditForCreate(registration));
        using var source = new CancellationTokenSource();
        source.Cancel();

        Assert.Multiple(() =>
        {
            Assert.That(
                async () => await repository.GetAsync(ClientIdA, source.Token),
                Throws.InstanceOf<OperationCanceledException>());
            Assert.That(
                async () => await repository.ListByOwnerAsync(OwnerA, null, 1, source.Token),
                Throws.InstanceOf<OperationCanceledException>());
            Assert.That(
                async () => await repository.TrySaveAsync(transition, source.Token),
                Throws.InstanceOf<OperationCanceledException>());
        });
    }

    private static ServiceClientRegistration Registration(
        string clientId,
        string ownerScopeId,
        string displayName,
        string verifier) =>
        ServiceClientRegistration.Create(
            clientId,
            ownerScopeId,
            displayName,
            ServiceClientScope.DomainVerificationCheck,
            ["example.com"],
            verifier,
            CreatedAtUtc,
            CreatedAtUtc.AddDays(90));

    private static ServiceClientTransitionBatch Batch(
        ServiceClientRegistration registration,
        long expectedVersion,
        AuditLogEntry audit) =>
        new(registration, expectedVersion, [audit]);

    private static AuditLogEntry AuditForCreate(
        ServiceClientRegistration current,
        string auditId = "audit-create") =>
        Audit(
            auditId,
            ServiceClientAuditActions.Created,
            current,
            current.CreatedAtUtc,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["scope"] = ServiceClientScopeValues.ToExternalValue(current.Scope),
                ["domainGrantCount"] = current.DomainGrants.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["credentialVersion"] = current.CredentialVersion.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["aggregateVersion"] = current.AggregateVersion.ToString(System.Globalization.CultureInfo.InvariantCulture)
            });

    private static AuditLogEntry AuditForRotation(
        ServiceClientRegistration previous,
        ServiceClientRegistration current,
        string auditId = "audit-rotate") =>
        Audit(
            auditId,
            ServiceClientAuditActions.CredentialRotated,
            current,
            current.CredentialChangedAtUtc,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["scope"] = ServiceClientScopeValues.ToExternalValue(current.Scope),
                ["domainGrantCount"] = current.DomainGrants.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["previousCredentialVersion"] = previous.CredentialVersion.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["credentialVersion"] = current.CredentialVersion.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["previousAggregateVersion"] = previous.AggregateVersion.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["aggregateVersion"] = current.AggregateVersion.ToString(System.Globalization.CultureInfo.InvariantCulture)
            });

    private static AuditLogEntry AuditForRevocation(
        ServiceClientRegistration previous,
        ServiceClientRegistration current,
        string auditId = "audit-revoke") =>
        Audit(
            auditId,
            ServiceClientAuditActions.Revoked,
            current,
            current.RevokedAtUtc!.Value,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["scope"] = ServiceClientScopeValues.ToExternalValue(current.Scope),
                ["domainGrantCount"] = current.DomainGrants.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["credentialVersion"] = current.CredentialVersion.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["previousAggregateVersion"] = previous.AggregateVersion.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["aggregateVersion"] = current.AggregateVersion.ToString(System.Globalization.CultureInfo.InvariantCulture)
            });

    private static AuditLogEntry Audit(
        string auditId,
        string action,
        ServiceClientRegistration current,
        DateTimeOffset atUtc,
        IReadOnlyDictionary<string, string> metadata) =>
        new(
            auditId,
            "actor-from-principal",
            action,
            TargetType.ServiceClient,
            current.ClientId,
            action switch
            {
                ServiceClientAuditActions.Created => "A service client was registered.",
                ServiceClientAuditActions.CredentialRotated => "A service-client credential was replaced.",
                ServiceClientAuditActions.Revoked => "A service client was irreversibly revoked.",
                _ => "A service-client lifecycle transition was recorded."
            },
            atUtc,
            metadata,
            action == ServiceClientAuditActions.Revoked ? AuditSeverity.High : AuditSeverity.Medium)
        {
            ActorRole = "Administrator"
        };
}
