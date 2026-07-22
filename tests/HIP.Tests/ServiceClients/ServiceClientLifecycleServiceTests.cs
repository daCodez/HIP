using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using HIP.Application.Reporting;
using HIP.Application.Review;
using HIP.Application.ServiceClients;
using HIP.Domain.Audit;
using HIP.Domain.ServiceClients;

namespace HIP.Tests.ServiceClients;

[TestFixture]
public sealed class ServiceClientLifecycleServiceTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 7, 20, 20, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Create_stores_only_a_protected_verifier_and_returns_the_secret_only_on_that_transition()
    {
        const string rawSecret = "hips_v1_create-only-secret-material";
        var fixture = Fixture.Create(
            clientIds: [ClientId(1)],
            secrets: [rawSecret]);

        var result = await fixture.Service.CreateAsync(
            "actor-from-principal",
            "owner-from-principal",
            Request(),
            CancellationToken.None);
        var stored = await fixture.InnerRepository.GetAsync(ClientId(1), CancellationToken.None);
        var listed = await fixture.Service.ListAsync(
            "owner-from-principal",
            cursor: null,
            pageSize: 25,
            CancellationToken.None);
        var transition = fixture.Repository.Transitions.Single();
        var audit = transition.AuditEntries.Single();
        var auditText = string.Join(
            "|",
            audit.Metadata.SelectMany(pair => new[] { pair.Key, pair.Value })
                .Append(audit.Summary)
                .Append(audit.Action));

        Assert.Multiple(() =>
        {
            Assert.That(result.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.Succeeded));
            Assert.That(result.Registration, Is.Not.Null);
            Assert.That(result.Registration!.OneTimeSecret.Reveal(), Is.EqualTo(rawSecret));
            Assert.That(stored, Is.Not.Null);
            Assert.That(stored!.CredentialVerifier, Is.Not.EqualTo(rawSecret));
            Assert.That(stored.CredentialVerifier, Does.Not.Contain(rawSecret));
            Assert.That(listed.Items, Has.Count.EqualTo(1));
            Assert.That(
                typeof(ServiceClientResponse).GetProperties().Select(property => property.Name),
                Has.None.EqualTo("OwnerScopeId"));
            Assert.That(
                typeof(ServiceClientResponse).GetProperties().Select(property => property.Name),
                Has.None.EqualTo("CredentialVerifier"));
            Assert.That(
                typeof(ServiceClientResponse).GetProperties().Select(property => property.Name),
                Has.None.EqualTo("Secret"));
            Assert.That(audit.ActorId, Is.EqualTo("actor-from-principal"));
            Assert.That(audit.TargetId, Is.EqualTo(ClientId(1)));
            Assert.That(audit.Action, Is.EqualTo(ServiceClientAuditActions.Created));
            Assert.That(audit.CreatedAtUtc, Is.EqualTo(Now));
            Assert.That(AuditLogIntegrity.Verify(audit), Is.True);
            Assert.That(auditText, Does.Not.Contain(rawSecret));
            Assert.That(auditText, Does.Not.Contain("owner-from-principal"));
            Assert.That(auditText, Does.Not.Contain(stored.OwnerScopeId));
            Assert.That(auditText, Does.Not.Contain(stored.CredentialVerifier));
            Assert.That(auditText, Does.Not.Contain("example.com"));
            Assert.That(
                audit.Metadata.Keys,
                Is.EquivalentTo(new[]
                {
                    "scope", "domainGrantCount", "credentialVersion", "aggregateVersion"
                }));
        });
    }

    [Test]
    public async Task Create_uses_the_default_or_validated_lifetime_from_server_time()
    {
        var fixture = Fixture.Create(
            clientIds: [ClientId(1), ClientId(2)],
            secrets: ["hips_v1_default-lifetime", "hips_v1_custom-lifetime"]);

        var defaultLifetime = await fixture.Service.CreateAsync(
            "actor-A", "owner-A", Request(), CancellationToken.None);
        var customLifetime = await fixture.Service.CreateAsync(
            "actor-A", "owner-A", Request(lifetimeDays: 12), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(defaultLifetime.Registration!.Client.ExpiresAtUtc, Is.EqualTo(Now.AddDays(90)));
            Assert.That(customLifetime.Registration!.Client.ExpiresAtUtc, Is.EqualTo(Now.AddDays(12)));
        });
    }

    [Test]
    public async Task Owner_listing_is_exact_cursor_paged_and_never_returns_another_owners_clients()
    {
        var fixture = Fixture.Create(
            clientIds: [ClientId(3), ClientId(1), ClientId(4), ClientId(2)],
            secrets: ["hips_v1_1", "hips_v1_2", "hips_v1_other", "hips_v1_3"]);
        await fixture.Service.CreateAsync("actor-A", "owner-A", Request("A-3"), CancellationToken.None);
        await fixture.Service.CreateAsync("actor-A", "owner-A", Request("A-1"), CancellationToken.None);
        await fixture.Service.CreateAsync("actor-B", "owner-B", Request("B-4"), CancellationToken.None);
        await fixture.Service.CreateAsync("actor-A", "owner-A", Request("A-2"), CancellationToken.None);

        var firstPage = await fixture.Service.ListAsync(
            "owner-A", cursor: null, pageSize: 2, CancellationToken.None);
        var secondPage = await fixture.Service.ListAsync(
            "owner-A", firstPage.NextCursor, pageSize: 2, CancellationToken.None);
        var otherOwner = await fixture.Service.ListAsync(
            "owner-B", cursor: null, pageSize: 10, CancellationToken.None);
        var crossOwnerCursor = await fixture.Service.ListAsync(
            "owner-B", firstPage.NextCursor, pageSize: 10, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(firstPage.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.Succeeded));
            Assert.That(firstPage.Items.Select(item => item.ClientId),
                Is.EqualTo(new[] { ClientId(1), ClientId(2) }));
            Assert.That(firstPage.NextCursor, Is.Not.Null.And.Not.Empty);
            Assert.That(secondPage.Items.Select(item => item.ClientId), Is.EqualTo(new[] { ClientId(3) }));
            Assert.That(secondPage.NextCursor, Is.Null);
            Assert.That(otherOwner.Items.Select(item => item.ClientId), Is.EqualTo(new[] { ClientId(4) }));
            Assert.That(crossOwnerCursor.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.InvalidRequest));
            Assert.That(crossOwnerCursor.Items, Is.Empty);
        });
    }

    [Test]
    public async Task Legacy_privacy_key_keeps_existing_owner_clients_listable_rotatable_and_revocable()
    {
        const string ownerId = "owner-from-principal";
        const string oldPrivacyKey = "service-client-old-privacy-key-material";
        const string currentPrivacyKey = "service-client-current-privacy-key-material";
        var repository = new InMemoryServiceClientRepository();
        var clock = new MutableTimeProvider(Now);
        var oldHost = Fixture.Create(
            repository,
            clock,
            clientIds: [ClientId(2)],
            secrets: ["hips_v1_original-secret"],
            privacyOptions: new PrivacyHashingOptions(oldPrivacyKey, AllowDevelopmentKey: false));
        var created = await oldHost.Service.CreateAsync(
            "actor-A", ownerId, Request("Legacy client"), CancellationToken.None);
        var currentHost = Fixture.Create(
            repository,
            clock,
            clientIds: [ClientId(1)],
            secrets: ["hips_v1_current-secret", "hips_v1_rotated-secret"],
            privacyOptions: new PrivacyHashingOptions(
                currentPrivacyKey,
                AllowDevelopmentKey: false,
                LegacyKeys: [oldPrivacyKey]));
        await currentHost.Service.CreateAsync(
            "actor-A", ownerId, Request("Current client"), CancellationToken.None);

        var firstPage = await currentHost.Service.ListAsync(
            ownerId, cursor: null, pageSize: 1, CancellationToken.None);
        var secondPage = await currentHost.Service.ListAsync(
            ownerId, firstPage.NextCursor, pageSize: 1, CancellationToken.None);
        var storedBeforeRotation = await repository.GetAsync(
            created.Registration!.Client.ClientId, CancellationToken.None);
        var rotated = await currentHost.Service.RotateCredentialAsync(
            "actor-B", ownerId, created.Registration.Client.ClientId, 1, CancellationToken.None);
        var revoked = await currentHost.Service.RevokeAsync(
            "actor-B", ownerId, created.Registration.Client.ClientId, 2, CancellationToken.None);
        var stored = await repository.GetAsync(
            created.Registration.Client.ClientId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(firstPage.Items.Select(item => item.ClientId), Is.EqualTo(new[] { ClientId(1) }));
            Assert.That(secondPage.Items.Select(item => item.ClientId), Is.EqualTo(new[] { ClientId(2) }));
            Assert.That(currentHost.Protector.Verify(
                created.Registration.Client.ClientId,
                new ServiceClientSecret("hips_v1_original-secret"),
                storedBeforeRotation!.CredentialVerifier), Is.True,
                "Authentication lookup and verification must remain independent of the current owner hashing key.");
            Assert.That(rotated.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.Succeeded));
            Assert.That(rotated.Registration!.OneTimeSecret.Reveal(), Is.EqualTo("hips_v1_rotated-secret"));
            Assert.That(revoked.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.Succeeded));
            Assert.That(stored!.Status, Is.EqualTo(ServiceClientStatus.Revoked));
            Assert.That(stored.OwnerScopeId, Is.EqualTo(
                new ServiceClientOwnerScopeDerivation(
                    new PrivacyHashingOptions(oldPrivacyKey, AllowDevelopmentKey: false))
                .OwnerScopeId(ownerId)));
        });
    }

    [Test]
    public async Task Rotation_preserves_expiry_replaces_the_old_verifier_and_returns_only_the_replacement_secret()
    {
        const string originalSecret = "hips_v1_original-secret";
        const string replacementSecret = "hips_v1_replacement-secret";
        var fixture = Fixture.Create(
            clientIds: [ClientId(1)],
            secrets: [originalSecret, replacementSecret]);
        var created = await fixture.Service.CreateAsync(
            "actor-A", "owner-A", Request(), CancellationToken.None);
        var originalExpiry = created.Registration!.Client.ExpiresAtUtc;
        var originalVerifier = (await fixture.InnerRepository.GetAsync(ClientId(1), CancellationToken.None))!
            .CredentialVerifier;
        fixture.Clock.UtcNow = Now.AddDays(7);

        var rotated = await fixture.Service.RotateCredentialAsync(
            "actor-B",
            "owner-A",
            ClientId(1),
            expectedAggregateVersion: 1,
            CancellationToken.None);
        var stored = await fixture.InnerRepository.GetAsync(ClientId(1), CancellationToken.None);
        var audit = fixture.Repository.Transitions.Last().AuditEntries.Single();

        Assert.Multiple(() =>
        {
            Assert.That(rotated.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.Succeeded));
            Assert.That(rotated.Registration!.OneTimeSecret.Reveal(), Is.EqualTo(replacementSecret));
            Assert.That(rotated.Registration.Client.ExpiresAtUtc, Is.EqualTo(originalExpiry));
            Assert.That(stored!.CredentialVerifier, Is.Not.EqualTo(originalVerifier));
            Assert.That(fixture.Protector.Verify(
                ClientId(1), new ServiceClientSecret(originalSecret), stored.CredentialVerifier), Is.False);
            Assert.That(fixture.Protector.Verify(
                ClientId(1), new ServiceClientSecret(replacementSecret), stored.CredentialVerifier), Is.True);
            Assert.That(stored.CredentialVersion, Is.EqualTo(2));
            Assert.That(stored.AggregateVersion, Is.EqualTo(2));
            Assert.That(audit.ActorId, Is.EqualTo("actor-B"));
            Assert.That(audit.Action, Is.EqualTo(ServiceClientAuditActions.CredentialRotated));
        });
    }

    [Test]
    public async Task Concurrent_rotation_with_one_expected_version_has_exactly_one_winner_and_no_retry()
    {
        var fixture = Fixture.Create(
            clientIds: [ClientId(1)],
            secrets: ["hips_v1_original", "hips_v1_replacement-A", "hips_v1_replacement-B"]);
        await fixture.Service.CreateAsync("actor-A", "owner-A", Request(), CancellationToken.None);
        fixture.Clock.UtcNow = Now.AddHours(1);

        var start = new ManualResetEventSlim();
        var rotations = Enumerable.Range(0, 2)
            .Select(index => Task.Run(async () =>
            {
                start.Wait();
                return await fixture.Service.RotateCredentialAsync(
                    $"actor-{index}",
                    "owner-A",
                    ClientId(1),
                    expectedAggregateVersion: 1,
                    CancellationToken.None);
            }))
            .ToArray();
        start.Set();
        var results = await Task.WhenAll(rotations);
        var stored = await fixture.InnerRepository.GetAsync(ClientId(1), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(results.Count(result => result.Outcome == ServiceClientLifecycleOutcome.Succeeded), Is.EqualTo(1));
            Assert.That(results.Count(result => result.Outcome == ServiceClientLifecycleOutcome.Conflict), Is.EqualTo(1));
            Assert.That(results.Single(result => result.Outcome == ServiceClientLifecycleOutcome.Conflict).Registration, Is.Null);
            Assert.That(stored!.CredentialVersion, Is.EqualTo(2));
            Assert.That(stored.AggregateVersion, Is.EqualTo(2));
            Assert.That(
                fixture.Repository.Transitions.Count(transition =>
                    transition.AuditEntries.Single().Action == ServiceClientAuditActions.CredentialRotated),
                Is.InRange(1, 2),
                "A caller that reaches stale CAS must not retry; an already-observed stale caller need not write.");
        });
    }

    [Test]
    public async Task Cross_owner_mutations_are_not_disclosed_and_do_not_generate_a_secret()
    {
        var fixture = Fixture.Create(
            clientIds: [ClientId(1)],
            secrets: ["hips_v1_original", "hips_v1_should-not-be-generated"]);
        await fixture.Service.CreateAsync("actor-A", "owner-A", Request(), CancellationToken.None);
        var generatedBefore = fixture.Generator.SecretGenerationCount;

        var rotation = await fixture.Service.RotateCredentialAsync(
            "actor-B", "owner-B", ClientId(1), 1, CancellationToken.None);
        var revocation = await fixture.Service.RevokeAsync(
            "actor-B", "owner-B", ClientId(1), 1, CancellationToken.None);
        var stored = await fixture.InnerRepository.GetAsync(ClientId(1), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(rotation.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.NotFound));
            Assert.That(revocation.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.NotFound));
            Assert.That(fixture.Generator.SecretGenerationCount, Is.EqualTo(generatedBefore));
            Assert.That(stored!.AggregateVersion, Is.EqualTo(1));
            Assert.That(stored.Status, Is.EqualTo(ServiceClientStatus.Active));
        });
    }

    [Test]
    public async Task Revocation_is_terminal_and_uses_exact_optimistic_concurrency()
    {
        var fixture = Fixture.Create(
            clientIds: [ClientId(1)],
            secrets: ["hips_v1_original"]);
        await fixture.Service.CreateAsync("actor-A", "owner-A", Request(), CancellationToken.None);
        fixture.Clock.UtcNow = Now.AddDays(2);

        var stale = await fixture.Service.RevokeAsync(
            "actor-A", "owner-A", ClientId(1), 7, CancellationToken.None);
        var revoked = await fixture.Service.RevokeAsync(
            "actor-A", "owner-A", ClientId(1), 1, CancellationToken.None);
        var repeated = await fixture.Service.RevokeAsync(
            "actor-A", "owner-A", ClientId(1), 2, CancellationToken.None);
        var rotateRevoked = await fixture.Service.RotateCredentialAsync(
            "actor-A", "owner-A", ClientId(1), 2, CancellationToken.None);
        var stored = await fixture.InnerRepository.GetAsync(ClientId(1), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(stale.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.Conflict));
            Assert.That(revoked.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.Succeeded));
            Assert.That(repeated.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.Revoked));
            Assert.That(rotateRevoked.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.Revoked));
            Assert.That(stored!.Status, Is.EqualTo(ServiceClientStatus.Revoked));
            Assert.That(stored.AggregateVersion, Is.EqualTo(2));
            Assert.That(stored.CredentialVersion, Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Rotation_at_expiry_is_rejected_without_generating_replacement_material()
    {
        var fixture = Fixture.Create(
            clientIds: [ClientId(1)],
            secrets: ["hips_v1_original", "hips_v1_unused"]);
        var created = await fixture.Service.CreateAsync(
            "actor-A", "owner-A", Request(lifetimeDays: 1), CancellationToken.None);
        fixture.Clock.UtcNow = created.Registration!.Client.ExpiresAtUtc;
        var generatedBefore = fixture.Generator.SecretGenerationCount;

        var result = await fixture.Service.RotateCredentialAsync(
            "actor-A", "owner-A", ClientId(1), 1, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.Expired));
            Assert.That(result.Registration, Is.Null);
            Assert.That(fixture.Generator.SecretGenerationCount, Is.EqualTo(generatedBefore));
        });
    }

    [Test]
    public async Task Three_client_id_collisions_are_retried_and_the_fourth_candidate_can_win()
    {
        var repository = new InMemoryServiceClientRepository();
        var clock = new MutableTimeProvider(Now);
        for (var index = 1; index <= 3; index++)
        {
            var seeder = Fixture.Create(
                repository,
                clock,
                clientIds: [ClientId(index)],
                secrets: [$"hips_v1_seed-{index}"]);
            var seeded = await seeder.Service.CreateAsync(
                "seed-actor", $"seed-owner-{index}", Request(), CancellationToken.None);
            Assert.That(seeded.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.Succeeded));
        }

        var fixture = Fixture.Create(
            repository,
            clock,
            clientIds: [ClientId(1), ClientId(2), ClientId(3), ClientId(4)],
            secrets: ["hips_v1_try-1", "hips_v1_try-2", "hips_v1_try-3", "hips_v1_try-4"]);

        var result = await fixture.Service.CreateAsync(
            "actor-A", "owner-A", Request(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.Succeeded));
            Assert.That(result.Registration!.Client.ClientId, Is.EqualTo(ClientId(4)));
            Assert.That(fixture.Generator.ClientIdGenerationCount, Is.EqualTo(4));
            Assert.That(fixture.Generator.SecretGenerationCount, Is.EqualTo(4));
        });
    }

    [Test]
    public async Task A_fourth_collision_exhausts_the_bounded_create_attempts()
    {
        var repository = new InMemoryServiceClientRepository();
        var clock = new MutableTimeProvider(Now);
        for (var index = 1; index <= 4; index++)
        {
            var seeder = Fixture.Create(
                repository,
                clock,
                clientIds: [ClientId(index)],
                secrets: [$"hips_v1_seed-{index}"]);
            await seeder.Service.CreateAsync(
                "seed-actor", $"seed-owner-{index}", Request(), CancellationToken.None);
        }

        var fixture = Fixture.Create(
            repository,
            clock,
            clientIds: [ClientId(1), ClientId(2), ClientId(3), ClientId(4), ClientId(5)],
            secrets: ["hips_v1_try-1", "hips_v1_try-2", "hips_v1_try-3", "hips_v1_try-4", "hips_v1_unused"]);

        var result = await fixture.Service.CreateAsync(
            "actor-A", "owner-A", Request(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.Conflict));
            Assert.That(result.Registration, Is.Null);
            Assert.That(fixture.Generator.ClientIdGenerationCount, Is.EqualTo(4));
            Assert.That(fixture.Generator.SecretGenerationCount, Is.EqualTo(4));
        });
    }

    [Test]
    public void Pre_cancelled_operations_propagate_cancellation()
    {
        var fixture = Fixture.Create(
            clientIds: [ClientId(1)],
            secrets: ["hips_v1_unused"]);
        using var source = new CancellationTokenSource();
        source.Cancel();

        Assert.Multiple(() =>
        {
            Assert.That(
                async () => await fixture.Service.CreateAsync(
                    "actor-A", "owner-A", Request(), source.Token),
                Throws.InstanceOf<OperationCanceledException>());
            Assert.That(
                async () => await fixture.Service.ListAsync(
                    "owner-A", null, 10, source.Token),
                Throws.InstanceOf<OperationCanceledException>());
            Assert.That(
                async () => await fixture.Service.RotateCredentialAsync(
                    "actor-A", "owner-A", ClientId(1), 1, source.Token),
                Throws.InstanceOf<OperationCanceledException>());
            Assert.That(
                async () => await fixture.Service.RevokeAsync(
                    "actor-A", "owner-A", ClientId(1), 1, source.Token),
                Throws.InstanceOf<OperationCanceledException>());
        });
    }

    [TestCase("")]
    [TestCase(" actor-A")]
    [TestCase("actor-A ")]
    [TestCase("actor\nA")]
    public async Task Invalid_actor_identifiers_are_rejected_without_generating_credentials(string actorId)
    {
        var fixture = Fixture.Create(
            clientIds: [ClientId(1)],
            secrets: ["hips_v1_unused"]);

        var result = await fixture.Service.CreateAsync(
            actorId, "owner-A", Request(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.InvalidRequest));
            Assert.That(result.Message, Is.EqualTo(ServiceClientLifecycleMessages.InvalidRequest));
            if (actorId.Length > 0)
            {
                Assert.That(result.Message, Does.Not.Contain(actorId));
            }
            Assert.That(fixture.Generator.ClientIdGenerationCount, Is.Zero);
            Assert.That(fixture.Generator.SecretGenerationCount, Is.Zero);
        });
    }

    [Test]
    public async Task Overlong_actor_and_owner_identifiers_are_rejected_without_echo_or_secret_generation()
    {
        var fixture = Fixture.Create(
            clientIds: [ClientId(1)],
            secrets: ["hips_v1_unused"]);
        var oversized = new string('x', 513);

        var actorResult = await fixture.Service.CreateAsync(
            oversized, "owner-A", Request(), CancellationToken.None);
        var ownerResult = await fixture.Service.CreateAsync(
            "actor-A", oversized, Request(), CancellationToken.None);
        var controlOwnerResult = await fixture.Service.ListAsync(
            "owner\0A", null, 10, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(actorResult.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.InvalidRequest));
            Assert.That(ownerResult.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.InvalidRequest));
            Assert.That(controlOwnerResult.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.InvalidRequest));
            Assert.That(actorResult.Message, Does.Not.Contain(oversized));
            Assert.That(ownerResult.Message, Does.Not.Contain(oversized));
            Assert.That(fixture.Generator.ClientIdGenerationCount, Is.Zero);
            Assert.That(fixture.Generator.SecretGenerationCount, Is.Zero);
        });
    }

    [TestCase("")]
    [TestCase(" owner-A")]
    [TestCase("owner-A ")]
    [TestCase("owner\tA")]
    public async Task Invalid_owner_identifiers_are_rejected_without_generating_credentials(string ownerId)
    {
        var fixture = Fixture.Create(
            clientIds: [ClientId(1)],
            secrets: ["hips_v1_unused"]);

        var result = await fixture.Service.CreateAsync(
            "actor-A", ownerId, Request(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.InvalidRequest));
            Assert.That(result.Message, Is.EqualTo(ServiceClientLifecycleMessages.InvalidRequest));
            Assert.That(fixture.Generator.ClientIdGenerationCount, Is.Zero);
            Assert.That(fixture.Generator.SecretGenerationCount, Is.Zero);
        });
    }

    [Test]
    public async Task Malformed_create_request_maps_to_stable_invalid_without_generating_material()
    {
        var fixture = Fixture.Create(
            clientIds: [ClientId(1)],
            secrets: ["hips_v1_unused"]);
        var malformed = new CreateServiceClientRequest(
            "Evidence checker",
            ["*"],
            ["example.com"],
            LifetimeDays: 90);

        var result = await fixture.Service.CreateAsync(
            "actor-A", "owner-A", malformed, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.InvalidRequest));
            Assert.That(result.Message, Is.EqualTo(ServiceClientLifecycleMessages.InvalidRequest));
            Assert.That(result.Registration, Is.Null);
            Assert.That(fixture.Generator.ClientIdGenerationCount, Is.Zero);
            Assert.That(fixture.Generator.SecretGenerationCount, Is.Zero);
        });
    }

    [TestCase("hipc_v1_invalid", 1)]
    [TestCase("hipc_v1_ABCDEFGHIJKLMNOPQRSTUQ", 0)]
    [TestCase("hipc_v1_ABCDEFGHIJKLMNOPQRSTUQ", -1)]
    [TestCase("hipc_v1_ABCDEFGHIJKLMNOPQRSTUQ", long.MaxValue)]
    public async Task Invalid_client_id_or_expected_version_is_rejected_before_repository_or_secret_work(
        string clientId,
        long expectedVersion)
    {
        var fixture = Fixture.Create(
            clientIds: [ClientId(1)],
            secrets: ["hips_v1_unused"]);

        var rotation = await fixture.Service.RotateCredentialAsync(
            "actor-A", "owner-A", clientId, expectedVersion, CancellationToken.None);
        var revocation = await fixture.Service.RevokeAsync(
            "actor-A", "owner-A", clientId, expectedVersion, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(rotation.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.InvalidRequest));
            Assert.That(revocation.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.InvalidRequest));
            Assert.That(fixture.Generator.SecretGenerationCount, Is.Zero);
            Assert.That(fixture.Repository.GetCallCount, Is.Zero);
        });
    }

    [TestCase(0)]
    [TestCase(101)]
    public async Task Invalid_page_size_is_rejected_before_repository_access(int pageSize)
    {
        var fixture = Fixture.Create(
            clientIds: [ClientId(1)],
            secrets: ["hips_v1_unused"]);

        var result = await fixture.Service.ListAsync(
            "owner-A", null, pageSize, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.InvalidRequest));
            Assert.That(result.Items, Is.Empty);
            Assert.That(fixture.Repository.ListCallCount, Is.Zero);
        });
    }

    [Test]
    public async Task Malformed_cursor_is_mapped_to_stable_invalid_request()
    {
        var fixture = Fixture.Create(
            clientIds: [ClientId(1)],
            secrets: ["hips_v1_unused"]);

        var result = await fixture.Service.ListAsync(
            "owner-A", "not-a-service-client-cursor", 10, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Outcome, Is.EqualTo(ServiceClientLifecycleOutcome.InvalidRequest));
            Assert.That(result.Message, Is.EqualTo(ServiceClientLifecycleMessages.InvalidRequest));
            Assert.That(result.Items, Is.Empty);
        });
    }

    private static CreateServiceClientRequest Request(
        string displayName = "Evidence checker",
        int? lifetimeDays = null) =>
        new(
            displayName,
            [ServiceClientScopeValues.DomainVerificationCheck],
            ["example.com"],
            lifetimeDays);

    private static string ClientId(int value)
    {
        var bytes = Enumerable.Repeat((byte)value, 16).ToArray();
        return "hipc_v1_" + Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private sealed record Fixture(
        ServiceClientLifecycleService Service,
        CapturingRepository Repository,
        InMemoryServiceClientRepository InnerRepository,
        DeterministicCredentialGenerator Generator,
        HashingSecretProtector Protector,
        MutableTimeProvider Clock)
    {
        public static Fixture Create(
            IReadOnlyCollection<string> clientIds,
            IReadOnlyCollection<string> secrets) =>
            Create(new InMemoryServiceClientRepository(), new MutableTimeProvider(Now), clientIds, secrets);

        public static Fixture Create(
            InMemoryServiceClientRepository repository,
            MutableTimeProvider clock,
            IReadOnlyCollection<string> clientIds,
            IReadOnlyCollection<string> secrets,
            PrivacyHashingOptions? privacyOptions = null)
        {
            var capturing = new CapturingRepository(repository);
            var generator = new DeterministicCredentialGenerator(clientIds, secrets);
            var protector = new HashingSecretProtector();
            var service = new ServiceClientLifecycleService(
                capturing,
                generator,
                protector,
                new ServiceClientOwnerScopeDerivation(
                    privacyOptions ?? new PrivacyHashingOptions(
                        "service-client-lifecycle-test-key",
                        AllowDevelopmentKey: false)),
                new AuditLogService(new InMemoryAuditLogRepository()),
                clock);
            return new Fixture(service, capturing, repository, generator, protector, clock);
        }
    }

    private sealed class CapturingRepository(IServiceClientRepository inner) : IServiceClientRepository
    {
        private readonly ConcurrentQueue<ServiceClientTransitionBatch> transitions = new();
        private int getCallCount;
        private int listCallCount;

        public IReadOnlyCollection<ServiceClientTransitionBatch> Transitions => transitions.ToArray();

        public int GetCallCount => Volatile.Read(ref getCallCount);

        public int ListCallCount => Volatile.Read(ref listCallCount);

        public Task<ServiceClientRegistration?> GetAsync(string clientId, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref getCallCount);
            return inner.GetAsync(clientId, cancellationToken);
        }

        public Task<ServiceClientRepositoryPage> ListByOwnerAsync(
            string ownerScopeId,
            string? cursor,
            int pageSize,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref listCallCount);
            return inner.ListByOwnerAsync(ownerScopeId, cursor, pageSize, cancellationToken);
        }

        public Task<ServiceClientRepositoryPage> ListByOwnerAsync(
            IReadOnlyList<string> ownerScopeIds,
            string? cursor,
            int pageSize,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref listCallCount);
            return inner.ListByOwnerAsync(ownerScopeIds, cursor, pageSize, cancellationToken);
        }

        public Task<ServiceClientSaveOutcome> TrySaveAsync(
            ServiceClientTransitionBatch transition,
            CancellationToken cancellationToken)
        {
            transitions.Enqueue(transition);
            return inner.TrySaveAsync(transition, cancellationToken);
        }
    }

    private sealed class DeterministicCredentialGenerator(
        IEnumerable<string> clientIds,
        IEnumerable<string> secrets) : IServiceClientCredentialGenerator
    {
        private readonly ConcurrentQueue<string> clientIds = new(clientIds);
        private readonly ConcurrentQueue<string> secrets = new(secrets);
        private int clientIdGenerationCount;
        private int secretGenerationCount;

        public int ClientIdGenerationCount => Volatile.Read(ref clientIdGenerationCount);

        public int SecretGenerationCount => Volatile.Read(ref secretGenerationCount);

        public string GenerateClientId()
        {
            Interlocked.Increment(ref clientIdGenerationCount);
            return clientIds.TryDequeue(out var value)
                ? value
                : throw new InvalidOperationException("No deterministic client ID remains.");
        }

        public ServiceClientSecret GenerateSecret()
        {
            Interlocked.Increment(ref secretGenerationCount);
            return secrets.TryDequeue(out var value)
                ? new ServiceClientSecret(value)
                : throw new InvalidOperationException("No deterministic secret remains.");
        }
    }

    private sealed class HashingSecretProtector : IServiceClientSecretProtector
    {
        public string Protect(string clientId, ServiceClientSecret secret)
        {
            var digest = SHA256.HashData(Encoding.UTF8.GetBytes(clientId + "\0" + secret.Reveal()));
            return "test-sha256-v1$" + Convert.ToHexString(digest).ToLowerInvariant();
        }

        public bool Verify(
            string clientId,
            ServiceClientSecret presentedSecret,
            string credentialVerifier) =>
            string.Equals(Protect(clientId, presentedSecret), credentialVerifier, StringComparison.Ordinal);
    }

    private sealed class MutableTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = utcNow;

        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
