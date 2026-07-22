using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using HIP.Application.ServiceClients;
using HIP.Domain.Audit;
using HIP.Domain.Review;
using HIP.Domain.ServiceClients;
using HIP.Infrastructure;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Tests.Persistence;

/// <summary>
/// Verifies service-client credentials use encrypted, owner-isolated, bounded and atomic production persistence.
/// </summary>
public sealed class ServiceClientPersistenceTests
{
    private const string OwnerPartitionPrefix = "service-client-v1:";
    private const string ClientBindingPartition = "service-client-v1:client-id-binding";
    private const string AuditPartition = "audit-log";
    private const string CreatedSummary = "A service client was registered.";
    private const string RotatedSummary = "A service-client credential was replaced.";
    private const string RevokedSummary = "A service client was irreversibly revoked.";
    private static readonly DateTimeOffset Now =
        new(2026, 7, 20, 20, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Create_commits_encrypted_aggregate_global_binding_and_exact_audit()
    {
        using var context = CreateContext();
        var encryptor = new DevelopmentHipRecordEncryptor();
        var repository = Repository(context, encryptor);
        var registration = Registration('A', 'a', Verifier('a'));

        var outcome = await repository.TrySaveAsync(
            Batch(registration, 0, AuditForCreate(registration, "audit-create-a")),
            CancellationToken.None);
        var restored = await repository.GetAsync(registration.ClientId, CancellationToken.None);
        var rows = await context.Records.AsNoTracking().ToArrayAsync();

        Assert.Multiple(() =>
        {
            Assert.That(outcome, Is.EqualTo(ServiceClientSaveOutcome.Succeeded));
            Assert.That(restored, Is.Not.Null);
            Assert.That(restored!.OwnerScopeId, Is.EqualTo(registration.OwnerScopeId));
            Assert.That(restored.CredentialVerifier, Is.EqualTo(registration.CredentialVerifier));
            Assert.That(rows, Has.Length.EqualTo(3));
            Assert.That(rows.Select(row => row.Partition), Is.EquivalentTo(new[]
            {
                OwnerPartition(registration.OwnerScopeId),
                ClientBindingPartition,
                AuditPartition
            }));
            Assert.That(
                rows.Single(row => row.Partition == OwnerPartition(registration.OwnerScopeId)).AggregateVersion,
                Is.EqualTo(registration.AggregateVersion));
            Assert.That(rows, Has.All.Matches<HipDbRecord>(row => encryptor.IsProtectedPayload(row.Json)));
            Assert.That(rows, Has.All.Matches<HipDbRecord>(row =>
                !row.Json.Contains(registration.CredentialVerifier, StringComparison.Ordinal)));
            Assert.That(rows.Count(row => row.Partition == ClientBindingPartition), Is.EqualTo(1));
            Assert.That(rows.Count(row => row.Partition == AuditPartition), Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Rotation_and_revocation_never_replace_the_global_binding_and_each_add_one_audit()
    {
        using var context = CreateContext();
        var repository = Repository(context);
        var original = Registration('A', 'a', Verifier('a'));
        Assert.That(
            await repository.TrySaveAsync(
                Batch(original, 0, AuditForCreate(original, "audit-create")),
                CancellationToken.None),
            Is.EqualTo(ServiceClientSaveOutcome.Succeeded));
        var initialBinding = await context.Records.AsNoTracking().SingleAsync(row =>
            row.Partition == ClientBindingPartition && row.Id == original.ClientId);

        var rotated = original.RotateCredential(Verifier('b'), Now.AddDays(1));
        var rotationOutcome = await repository.TrySaveAsync(
            Batch(rotated, original.AggregateVersion, AuditForRotation(original, rotated, "audit-rotate")),
            CancellationToken.None);
        var revoked = rotated.Revoke(Now.AddDays(2));
        var revocationOutcome = await repository.TrySaveAsync(
            Batch(revoked, rotated.AggregateVersion, AuditForRevocation(rotated, revoked, "audit-revoke")),
            CancellationToken.None);
        var finalBinding = await context.Records.AsNoTracking().SingleAsync(row =>
            row.Partition == ClientBindingPartition && row.Id == original.ClientId);
        var restored = await repository.GetAsync(original.ClientId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(rotationOutcome, Is.EqualTo(ServiceClientSaveOutcome.Succeeded));
            Assert.That(revocationOutcome, Is.EqualTo(ServiceClientSaveOutcome.Succeeded));
            Assert.That(finalBinding.Json, Is.EqualTo(initialBinding.Json));
            Assert.That(finalBinding.CreatedAtUtc, Is.EqualTo(initialBinding.CreatedAtUtc));
            Assert.That(finalBinding.UpdatedAtUtc, Is.EqualTo(initialBinding.UpdatedAtUtc));
            Assert.That(context.Records.AsNoTracking().Count(row => row.Partition == ClientBindingPartition), Is.EqualTo(1));
            Assert.That(context.Records.AsNoTracking().Count(row => row.Partition == AuditPartition), Is.EqualTo(3));
            Assert.That(restored!.Status, Is.EqualTo(ServiceClientStatus.Revoked));
            Assert.That(restored.AggregateVersion, Is.EqualTo(3));
        });
    }

    [Test]
    public async Task Global_client_id_collision_rolls_back_the_other_owner_aggregate_audit_and_binding()
    {
        using var context = CreateContext();
        var repository = Repository(context);
        var first = Registration('A', 'a', Verifier('a'));
        var otherOwner = Registration('A', 'b', Verifier('b'));

        var firstOutcome = await repository.TrySaveAsync(
            Batch(first, 0, AuditForCreate(first, "audit-first")),
            CancellationToken.None);
        var collisionOutcome = await repository.TrySaveAsync(
            Batch(otherOwner, 0, AuditForCreate(otherOwner, "audit-other-owner")),
            CancellationToken.None);
        var restored = await repository.GetAsync(first.ClientId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(firstOutcome, Is.EqualTo(ServiceClientSaveOutcome.Succeeded));
            Assert.That(collisionOutcome, Is.EqualTo(ServiceClientSaveOutcome.VersionConflict));
            Assert.That(restored!.OwnerScopeId, Is.EqualTo(first.OwnerScopeId));
            Assert.That(context.Records.AsNoTracking().Any(row =>
                row.Partition == OwnerPartition(otherOwner.OwnerScopeId) && row.Id == otherOwner.ClientId), Is.False);
            Assert.That(context.Records.AsNoTracking().Any(row =>
                row.Partition == AuditPartition && row.Id == "audit-other-owner"), Is.False);
            Assert.That(context.Records.AsNoTracking().Count(row =>
                row.Partition == ClientBindingPartition && row.Id == first.ClientId), Is.EqualTo(1));
            Assert.That(context.Records.AsNoTracking().Count(), Is.EqualTo(3));
        });
    }

    [Test]
    public async Task Concurrent_stale_rotations_have_one_winner_and_one_atomic_audit()
    {
        var options = CreateOptions($"hip-service-client-concurrency-{Guid.NewGuid():N}");
        var original = Registration('A', 'a', Verifier('a'));
        using (var seedContext = new HipDbContext(options))
        {
            var seedRepository = Repository(seedContext);
            Assert.That(
                await seedRepository.TrySaveAsync(
                    Batch(original, 0, AuditForCreate(original, "audit-create")),
                    CancellationToken.None),
                Is.EqualTo(ServiceClientSaveOutcome.Succeeded));
        }

        var firstRotation = original.RotateCredential(Verifier('b'), Now.AddDays(1));
        var secondRotation = original.RotateCredential(Verifier('c'), Now.AddDays(1));
        using var firstContext = new HipDbContext(options);
        using var secondContext = new HipDbContext(options);
        var outcomes = await Task.WhenAll(
            Repository(firstContext).TrySaveAsync(
                Batch(firstRotation, 1, AuditForRotation(original, firstRotation, "audit-rotate-b")),
                CancellationToken.None),
            Repository(secondContext).TrySaveAsync(
                Batch(secondRotation, 1, AuditForRotation(original, secondRotation, "audit-rotate-c")),
                CancellationToken.None));

        using var verificationContext = new HipDbContext(options);
        var restored = await Repository(verificationContext).GetAsync(original.ClientId, CancellationToken.None);
        var rotationAuditIds = await verificationContext.Records.AsNoTracking()
            .Where(row => row.Partition == AuditPartition && row.Id.StartsWith("audit-rotate-"))
            .Select(row => row.Id)
            .ToArrayAsync();

        Assert.Multiple(() =>
        {
            Assert.That(outcomes, Is.EquivalentTo(new[]
            {
                ServiceClientSaveOutcome.Succeeded,
                ServiceClientSaveOutcome.VersionConflict
            }));
            Assert.That(restored!.AggregateVersion, Is.EqualTo(2));
            Assert.That(restored.CredentialVersion, Is.EqualTo(2));
            Assert.That(restored.CredentialVerifier, Is.AnyOf(Verifier('b'), Verifier('c')));
            Assert.That(rotationAuditIds, Has.Length.EqualTo(1));
        });
    }

    [Test]
    public async Task Repository_rejects_a_transition_from_terminal_revocation_without_an_audit_write()
    {
        using var context = CreateContext();
        var repository = Repository(context);
        var original = Registration('A', 'a', Verifier('a'));
        await repository.TrySaveAsync(
            Batch(original, 0, AuditForCreate(original, "audit-create")),
            CancellationToken.None);
        var revoked = original.Revoke(Now.AddDays(1));
        await repository.TrySaveAsync(
            Batch(revoked, 1, AuditForRevocation(original, revoked, "audit-revoke")),
            CancellationToken.None);
        var forgedActive = original
            .RotateCredential(Verifier('b'), Now.AddHours(12))
            .RotateCredential(Verifier('c'), Now.AddDays(2));

        Assert.ThrowsAsync<InvalidOperationException>(() => repository.TrySaveAsync(
            Batch(forgedActive, 2, AuditForRotation(revoked, forgedActive, "audit-forged")),
            CancellationToken.None));
        var restored = await repository.GetAsync(original.ClientId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(restored!.Status, Is.EqualTo(ServiceClientStatus.Revoked));
            Assert.That(restored.AggregateVersion, Is.EqualTo(2));
            Assert.That(context.Records.AsNoTracking().Any(row =>
                row.Partition == AuditPartition && row.Id == "audit-forged"), Is.False);
        });
    }

    [Test]
    public async Task Audit_identifier_conflict_rolls_back_new_aggregate_and_global_binding()
    {
        using var context = CreateContext();
        var repository = Repository(context);
        var first = Registration('A', 'a', Verifier('a'));
        var second = Registration('B', 'a', Verifier('b'));
        const string duplicateAuditId = "audit-duplicate";

        var firstOutcome = await repository.TrySaveAsync(
            Batch(first, 0, AuditForCreate(first, duplicateAuditId)),
            CancellationToken.None);
        var secondOutcome = await repository.TrySaveAsync(
            Batch(second, 0, AuditForCreate(second, duplicateAuditId)),
            CancellationToken.None);
        var secondStored = await repository.GetAsync(second.ClientId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(firstOutcome, Is.EqualTo(ServiceClientSaveOutcome.Succeeded));
            Assert.That(secondOutcome, Is.EqualTo(ServiceClientSaveOutcome.VersionConflict));
            Assert.That(secondStored, Is.Null);
            Assert.That(context.Records.AsNoTracking().Any(row =>
                row.Partition == OwnerPartition(second.OwnerScopeId) && row.Id == second.ClientId), Is.False);
            Assert.That(context.Records.AsNoTracking().Any(row =>
                row.Partition == ClientBindingPartition && row.Id == second.ClientId), Is.False);
            Assert.That(context.Records.AsNoTracking().Count(row =>
                row.Partition == AuditPartition && row.Id == duplicateAuditId), Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Read_and_owner_list_fail_closed_on_payload_and_database_version_mismatch()
    {
        using var context = CreateContext();
        var repository = Repository(context);
        var registration = Registration('A', 'a', Verifier('a'));
        await repository.TrySaveAsync(
            Batch(registration, 0, AuditForCreate(registration, "audit-create")),
            CancellationToken.None);
        context.ChangeTracker.Clear();
        var aggregateRow = await context.Records.SingleAsync(row =>
            row.Partition == OwnerPartition(registration.OwnerScopeId) && row.Id == registration.ClientId);
        aggregateRow.AggregateVersion = 2;
        await context.SaveChangesAsync();
        context.ChangeTracker.Clear();

        Assert.Multiple(() =>
        {
            Assert.That(
                async () => await repository.GetAsync(registration.ClientId, CancellationToken.None),
                Throws.InstanceOf<InvalidOperationException>());
            Assert.That(
                async () => await repository.ListByOwnerAsync(
                    registration.OwnerScopeId, null, 10, CancellationToken.None),
                Throws.InstanceOf<InvalidOperationException>());
        });
    }

    [Test]
    public async Task Read_and_owner_list_reject_legacy_plaintext_aggregate_rows()
    {
        using var context = CreateContext();
        var repository = Repository(context);
        var registration = Registration('A', 'a', Verifier('a'));
        await repository.TrySaveAsync(
            Batch(registration, 0, AuditForCreate(registration, "audit-create")),
            CancellationToken.None);
        context.ChangeTracker.Clear();
        var aggregateRow = await context.Records.SingleAsync(row =>
            row.Partition == OwnerPartition(registration.OwnerScopeId) && row.Id == registration.ClientId);
        aggregateRow.Json = "{}";
        await context.SaveChangesAsync();
        context.ChangeTracker.Clear();

        Assert.Multiple(() =>
        {
            Assert.That(
                async () => await repository.GetAsync(registration.ClientId, CancellationToken.None),
                Throws.InstanceOf<InvalidOperationException>());
            Assert.That(
                async () => await repository.ListByOwnerAsync(
                    registration.OwnerScopeId, null, 10, CancellationToken.None),
                Throws.InstanceOf<InvalidOperationException>());
        });
    }

    [Test]
    public async Task Stored_revocation_cannot_precede_the_latest_credential_rotation()
    {
        using var context = CreateContext();
        var encryptor = new DevelopmentHipRecordEncryptor();
        var repository = Repository(context, encryptor);
        var original = Registration('A', 'a', Verifier('a'));
        await repository.TrySaveAsync(
            Batch(original, 0, AuditForCreate(original, "audit-create")),
            CancellationToken.None);
        var rotated = original.RotateCredential(Verifier('b'), Now.AddDays(2));
        var serializerOptions = SerializerOptions();
        var tampered = JsonNode.Parse(JsonSerializer.Serialize(rotated, serializerOptions))!.AsObject();
        tampered["status"] = nameof(ServiceClientStatus.Revoked);
        tampered["statusChangedAtUtc"] = JsonValue.Create(Now.AddDays(1));
        tampered["revokedAtUtc"] = JsonValue.Create(Now.AddDays(1));
        context.ChangeTracker.Clear();
        var aggregateRow = await context.Records.SingleAsync(row =>
            row.Partition == OwnerPartition(original.OwnerScopeId) && row.Id == original.ClientId);
        aggregateRow.Json = encryptor.Protect(tampered.ToJsonString(serializerOptions));
        aggregateRow.AggregateVersion = rotated.AggregateVersion;
        await context.SaveChangesAsync();
        context.ChangeTracker.Clear();

        Assert.Multiple(() =>
        {
            Assert.That(
                async () => await repository.GetAsync(original.ClientId, CancellationToken.None),
                Throws.Exception);
            Assert.That(
                async () => await repository.ListByOwnerAsync(
                    original.OwnerScopeId, null, 10, CancellationToken.None),
                Throws.Exception);
        });
    }

    [Test]
    public async Task Ef_and_in_memory_repositories_return_identical_owner_bound_pages_and_cursor_rejections()
    {
        using var context = CreateContext();
        var efRepository = Repository(context);
        var memoryRepository = new InMemoryServiceClientRepository();
        var registrations = new[]
        {
            Registration('B', 'a', Verifier('b')),
            Registration('A', 'a', Verifier('a')),
            Registration('D', 'b', Verifier('d')),
            Registration('C', 'a', Verifier('c')),
            Registration('a', 'a', Verifier('e'))
        };
        foreach (var registration in registrations)
        {
            var transition = Batch(
                registration,
                0,
                AuditForCreate(registration, $"audit-{registration.ClientId}"));
            Assert.That(
                await efRepository.TrySaveAsync(transition, CancellationToken.None),
                Is.EqualTo(ServiceClientSaveOutcome.Succeeded));
            Assert.That(
                await memoryRepository.TrySaveAsync(transition, CancellationToken.None),
                Is.EqualTo(ServiceClientSaveOutcome.Succeeded));
        }

        var ownerA = OwnerScope('a');
        var firstEfPage = await efRepository.ListByOwnerAsync(ownerA, null, 2, CancellationToken.None);
        var firstMemoryPage = await memoryRepository.ListByOwnerAsync(ownerA, null, 2, CancellationToken.None);
        var secondEfPage = await efRepository.ListByOwnerAsync(
            ownerA, firstEfPage.NextCursor, 2, CancellationToken.None);
        var secondMemoryPage = await memoryRepository.ListByOwnerAsync(
            ownerA, firstMemoryPage.NextCursor, 2, CancellationToken.None);
        var ownerBPage = await efRepository.ListByOwnerAsync(
            OwnerScope('b'), null, 10, CancellationToken.None);
        var absentOwnerACursor = ServiceClientRepositoryCursor.Encode(ownerA, ClientId('D'));
        var afterAbsentEfPage = await efRepository.ListByOwnerAsync(
            ownerA, absentOwnerACursor, 2, CancellationToken.None);
        var afterAbsentMemoryPage = await memoryRepository.ListByOwnerAsync(
            ownerA, absentOwnerACursor, 2, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(
                firstEfPage.Items.Select(item => item.ClientId),
                Is.EqualTo(firstMemoryPage.Items.Select(item => item.ClientId)));
            Assert.That(
                firstEfPage.Items.Select(item => item.ClientId),
                Is.EqualTo(new[] { ClientId('A'), ClientId('B') }));
            Assert.That(firstEfPage.NextCursor, Is.EqualTo(firstMemoryPage.NextCursor).And.Not.Null);
            Assert.That(
                secondEfPage.Items.Select(item => item.ClientId),
                Is.EqualTo(secondMemoryPage.Items.Select(item => item.ClientId)));
            Assert.That(
                secondEfPage.Items.Select(item => item.ClientId),
                Is.EqualTo(new[] { ClientId('C'), ClientId('a') }));
            Assert.That(secondEfPage.NextCursor, Is.Null);
            Assert.That(ownerBPage.Items.Select(item => item.ClientId), Is.EqualTo(new[] { ClientId('D') }));
            Assert.That(
                async () => await efRepository.ListByOwnerAsync(
                    OwnerScope('b'), firstEfPage.NextCursor, 2, CancellationToken.None),
                Throws.ArgumentException);
            Assert.That(
                afterAbsentEfPage.Items.Select(item => item.ClientId),
                Is.EqualTo(new[] { ClientId('a') }),
                "An authenticated global cursor need not exist in every queried owner partition.");
            Assert.That(
                afterAbsentMemoryPage.Items.Select(item => item.ClientId),
                Is.EqualTo(afterAbsentEfPage.Items.Select(item => item.ClientId)));
        });
    }

    [Test]
    public async Task Current_and_legacy_owner_partitions_are_globally_ordinal_cursor_paged()
    {
        using var context = CreateContext();
        var efRepository = Repository(context);
        var memoryRepository = new InMemoryServiceClientRepository();
        var currentOwner = OwnerScope('a');
        var legacyOwner = OwnerScope('b');
        var ownerScopes = new[] { currentOwner, legacyOwner };
        var registrations = new[]
        {
            Registration('D', 'a', Verifier('d')),
            Registration('A', 'b', Verifier('a')),
            Registration('C', 'b', Verifier('c')),
            Registration('B', 'a', Verifier('b'))
        };
        foreach (var registration in registrations)
        {
            var transition = Batch(
                registration,
                0,
                AuditForCreate(registration, $"audit-global-{registration.ClientId}"));
            Assert.That(
                await efRepository.TrySaveAsync(transition, CancellationToken.None),
                Is.EqualTo(ServiceClientSaveOutcome.Succeeded));
            Assert.That(
                await memoryRepository.TrySaveAsync(transition, CancellationToken.None),
                Is.EqualTo(ServiceClientSaveOutcome.Succeeded));
        }

        var firstEf = await efRepository.ListByOwnerAsync(
            ownerScopes, null, 2, CancellationToken.None);
        var firstMemory = await memoryRepository.ListByOwnerAsync(
            ownerScopes, null, 2, CancellationToken.None);
        var secondEf = await efRepository.ListByOwnerAsync(
            ownerScopes, firstEf.NextCursor, 2, CancellationToken.None);
        var secondMemory = await memoryRepository.ListByOwnerAsync(
            ownerScopes, firstMemory.NextCursor, 2, CancellationToken.None);
        var cursorForAnotherCurrentOwner = ServiceClientRepositoryCursor.Encode(
            OwnerScope('c'), ClientId('B'));

        Assert.Multiple(() =>
        {
            Assert.That(firstEf.Items.Select(item => item.ClientId),
                Is.EqualTo(new[] { ClientId('A'), ClientId('B') }));
            Assert.That(firstMemory.Items.Select(item => item.ClientId),
                Is.EqualTo(firstEf.Items.Select(item => item.ClientId)));
            Assert.That(firstEf.NextCursor, Is.EqualTo(firstMemory.NextCursor).And.Not.Null);
            Assert.That(secondEf.Items.Select(item => item.ClientId),
                Is.EqualTo(new[] { ClientId('C'), ClientId('D') }));
            Assert.That(secondMemory.Items.Select(item => item.ClientId),
                Is.EqualTo(secondEf.Items.Select(item => item.ClientId)));
            Assert.That(secondEf.NextCursor, Is.Null);
            Assert.That(
                async () => await efRepository.ListByOwnerAsync(
                    ownerScopes, cursorForAnotherCurrentOwner, 2, CancellationToken.None),
                Throws.ArgumentException);
        });
    }

    [Test]
    public async Task Owner_page_decrypts_only_requested_rows_while_querying_one_bounded_sentinel()
    {
        using var context = CreateContext();
        var encryptor = new CountingRecordEncryptor();
        var repository = Repository(context, encryptor);
        foreach (var clientMarker in new[] { 'C', 'A', 'B' })
        {
            var registration = Registration(clientMarker, 'a', Verifier(char.ToLowerInvariant(clientMarker)));
            Assert.That(
                await repository.TrySaveAsync(
                    Batch(registration, 0, AuditForCreate(registration, $"audit-{clientMarker}")),
                    CancellationToken.None),
                Is.EqualTo(ServiceClientSaveOutcome.Succeeded));
        }

        var page = await repository.ListByOwnerAsync(
            OwnerScope('a'), null, 2, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(page.Items, Has.Count.EqualTo(2));
            Assert.That(page.NextCursor, Is.Not.Null);
            Assert.That(encryptor.UnprotectCount, Is.EqualTo(2));
        });
    }

    [Test]
    public void Encrypted_record_paging_rejects_unbounded_or_non_exact_query_arguments()
    {
        using var context = CreateContext();
        var store = new HipRecordStore(context, new DevelopmentHipRecordEncryptor());

        Assert.Multiple(() =>
        {
            Assert.That(
                async () => await store.ListEncryptedPageAsync<object>(
                    " ", null, 1, CancellationToken.None),
                Throws.ArgumentException);
            Assert.That(
                async () => await store.ListEncryptedPageAsync<object>(
                    new string('p', 161), null, 1, CancellationToken.None),
                Throws.ArgumentException);
            Assert.That(
                async () => await store.ListEncryptedPageAsync<object>(
                    "partition", " padded-cursor ", 1, CancellationToken.None),
                Throws.ArgumentException);
            Assert.That(
                async () => await store.ListEncryptedPageAsync<object>(
                    "partition", new string('i', 221), 1, CancellationToken.None),
                Throws.ArgumentException);
            Assert.That(
                async () => await store.ListEncryptedPageAsync<object>(
                    "partition", null, 0, CancellationToken.None),
                Throws.InstanceOf<ArgumentOutOfRangeException>());
            Assert.That(
                async () => await store.ListEncryptedPageAsync<object>(
                    "partition", null, 101, CancellationToken.None),
                Throws.InstanceOf<ArgumentOutOfRangeException>());
        });
    }

    [Test]
    public void Encrypted_record_paging_filters_orders_and_bounds_before_materialization()
    {
        var root = RepositoryRoot();
        var storeSource = File.ReadAllText(Path.Combine(
            root, "src", "HIP.Infrastructure", "Persistence", "HipRecordStore.cs"));
        var repositorySource = File.ReadAllText(Path.Combine(
            root, "src", "HIP.Infrastructure", "Persistence", "Repositories", "EfServiceClientRepository.cs"));
        var methodStart = storeSource.IndexOf(
            "public async Task<HipEncryptedRecordPage<T>> ListEncryptedPageAsync<T>",
            StringComparison.Ordinal);
        Assert.That(methodStart, Is.GreaterThanOrEqualTo(0));
        var method = storeSource[methodStart..];
        var partitionFilter = method.IndexOf(
            ".Where(record => record.Partition == partition)",
            StringComparison.Ordinal);
        var order = method.IndexOf(".OrderBy(record => record.Id)", StringComparison.Ordinal);
        var bound = method.IndexOf(".Take(pageSize + 1)", StringComparison.Ordinal);
        var materialize = method.IndexOf(".ToArrayAsync(cancellationToken)", StringComparison.Ordinal);

        Assert.Multiple(() =>
        {
            Assert.That(partitionFilter, Is.GreaterThanOrEqualTo(0));
            Assert.That(order, Is.GreaterThan(partitionFilter));
            Assert.That(bound, Is.GreaterThan(order));
            Assert.That(materialize, Is.GreaterThan(bound));
            Assert.That(method, Does.Contain("record.Id.CompareTo(afterId) > 0"));
            Assert.That(method, Does.Contain("EF.Functions.Collate(record.Id, \"C\")"));
            Assert.That(repositorySource, Does.Contain("ListEncryptedPageAsync<ServiceClientRegistration>"));
            Assert.That(repositorySource, Does.Not.Contain("ListAsync<ServiceClientRegistration>"));
        });
    }

    [Test]
    public void PostgreSql_provider_translates_the_identifier_cursor_to_a_bounded_server_query()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseNpgsql("Host=localhost;Database=hip_query_shape;Username=hip")
            .Options;
        using var context = new HipDbContext(options);
        var partition = OwnerPartition(OwnerScope('a'));
        var afterId = ClientId('A');
        var query = context.Records.AsNoTracking()
            .Where(record => record.Partition == partition)
            .Where(record => EF.Functions.Collate(record.Id, "C").CompareTo(afterId) > 0)
            .OrderBy(record => EF.Functions.Collate(record.Id, "C"))
            .Take(3);

        var sql = query.ToQueryString();

        Assert.Multiple(() =>
        {
            Assert.That(sql, Does.Contain("WHERE"));
            Assert.That(sql, Does.Contain("ORDER BY"));
            Assert.That(sql, Does.Contain("LIMIT"));
            Assert.That(sql, Does.Contain("COLLATE \"C\""));
            Assert.That(sql, Does.Contain("Partition"));
            Assert.That(sql, Does.Contain("Id"));
        });
    }

    [Test]
    public void Ef_repository_propagates_pre_cancelled_operations()
    {
        using var context = CreateContext();
        var repository = Repository(context);
        var registration = Registration('A', 'a', Verifier('a'));
        var transition = Batch(registration, 0, AuditForCreate(registration, "audit-create"));
        using var source = new CancellationTokenSource();
        source.Cancel();

        Assert.Multiple(() =>
        {
            Assert.That(
                async () => await repository.GetAsync(registration.ClientId, source.Token),
                Throws.InstanceOf<OperationCanceledException>());
            Assert.That(
                async () => await repository.ListByOwnerAsync(
                    registration.OwnerScopeId, null, 1, source.Token),
                Throws.InstanceOf<OperationCanceledException>());
            Assert.That(
                async () => await repository.TrySaveAsync(transition, source.Token),
                Throws.InstanceOf<OperationCanceledException>());
        });
    }

    [Test]
    public void Infrastructure_registration_selects_the_scoped_service_client_repository()
    {
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:HipDatabase"] = "Host=localhost;Database=hip_tests;Username=hip",
                ["ConnectionStrings:redis"] = "localhost:6379,abortConnect=false",
                ["HipInfrastructure:DatabaseProvider"] = "PostgreSQL"
            })
            .Build();

        services.AddHipInfrastructure(configuration);
        var descriptor = services.Last(service =>
            service.ServiceType == typeof(IServiceClientRepository));

        Assert.Multiple(() =>
        {
            Assert.That(descriptor.ImplementationType, Is.EqualTo(typeof(EfServiceClientRepository)));
            Assert.That(descriptor.Lifetime, Is.EqualTo(ServiceLifetime.Scoped));
        });
    }

    private static EfServiceClientRepository Repository(
        HipDbContext context,
        IHipRecordEncryptor? encryptor = null) =>
        new(new HipRecordStore(context, encryptor ?? new DevelopmentHipRecordEncryptor()));

    private static ServiceClientRegistration Registration(
        char clientMarker,
        char ownerMarker,
        string verifier) =>
        ServiceClientRegistration.Create(
            ClientId(clientMarker),
            OwnerScope(ownerMarker),
            $"Client {clientMarker}",
            ServiceClientScope.DomainVerificationCheck,
            ["example.com"],
            verifier,
            Now,
            Now.AddDays(90));

    private static ServiceClientTransitionBatch Batch(
        ServiceClientRegistration registration,
        long expectedVersion,
        AuditLogEntry audit) =>
        new(registration, expectedVersion, [audit]);

    private static AuditLogEntry AuditForCreate(
        ServiceClientRegistration current,
        string auditId) =>
        Audit(
            auditId,
            ServiceClientAuditActions.Created,
            current,
            current.CreatedAtUtc,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["scope"] = ServiceClientScopeValues.ToExternalValue(current.Scope),
                ["domainGrantCount"] = current.DomainGrants.Count.ToString(CultureInfo.InvariantCulture),
                ["credentialVersion"] = current.CredentialVersion.ToString(CultureInfo.InvariantCulture),
                ["aggregateVersion"] = current.AggregateVersion.ToString(CultureInfo.InvariantCulture)
            });

    private static AuditLogEntry AuditForRotation(
        ServiceClientRegistration previous,
        ServiceClientRegistration current,
        string auditId) =>
        Audit(
            auditId,
            ServiceClientAuditActions.CredentialRotated,
            current,
            current.CredentialChangedAtUtc,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["scope"] = ServiceClientScopeValues.ToExternalValue(current.Scope),
                ["domainGrantCount"] = current.DomainGrants.Count.ToString(CultureInfo.InvariantCulture),
                ["previousCredentialVersion"] = previous.CredentialVersion.ToString(CultureInfo.InvariantCulture),
                ["credentialVersion"] = current.CredentialVersion.ToString(CultureInfo.InvariantCulture),
                ["previousAggregateVersion"] = previous.AggregateVersion.ToString(CultureInfo.InvariantCulture),
                ["aggregateVersion"] = current.AggregateVersion.ToString(CultureInfo.InvariantCulture)
            });

    private static AuditLogEntry AuditForRevocation(
        ServiceClientRegistration previous,
        ServiceClientRegistration current,
        string auditId) =>
        Audit(
            auditId,
            ServiceClientAuditActions.Revoked,
            current,
            current.RevokedAtUtc!.Value,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["scope"] = ServiceClientScopeValues.ToExternalValue(current.Scope),
                ["domainGrantCount"] = current.DomainGrants.Count.ToString(CultureInfo.InvariantCulture),
                ["credentialVersion"] = current.CredentialVersion.ToString(CultureInfo.InvariantCulture),
                ["previousAggregateVersion"] = previous.AggregateVersion.ToString(CultureInfo.InvariantCulture),
                ["aggregateVersion"] = current.AggregateVersion.ToString(CultureInfo.InvariantCulture)
            });

    private static AuditLogEntry Audit(
        string auditId,
        string action,
        ServiceClientRegistration current,
        DateTimeOffset createdAtUtc,
        IReadOnlyDictionary<string, string> metadata) =>
        new(
            auditId,
            "actor-from-principal",
            action,
            TargetType.ServiceClient,
            current.ClientId,
            action switch
            {
                ServiceClientAuditActions.Created => CreatedSummary,
                ServiceClientAuditActions.CredentialRotated => RotatedSummary,
                ServiceClientAuditActions.Revoked => RevokedSummary,
                _ => "A service-client lifecycle transition was recorded."
            },
            createdAtUtc,
            metadata,
            action == ServiceClientAuditActions.Revoked ? AuditSeverity.High : AuditSeverity.Medium)
        {
            ActorRole = "Administrator"
        };

    private static string ClientId(char marker) =>
        $"hipc_v1_{new string(marker, 21)}A";

    private static string OwnerScope(char marker) =>
        $"service-client-owner-hmac-sha256-v1:{new string(marker, 64)}";

    private static string Verifier(char marker) =>
        $"pbkdf2-sha256-v1$600000${new string(marker, 22)}${new string(marker, 43)}";

    private static string OwnerPartition(string ownerScopeId) =>
        OwnerPartitionPrefix + ownerScopeId;

    private static HipDbContext CreateContext() =>
        new(CreateOptions($"hip-service-clients-{Guid.NewGuid():N}"));

    private static DbContextOptions<HipDbContext> CreateOptions(string databaseName) =>
        new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase(databaseName)
            .Options;

    private static JsonSerializerOptions SerializerOptions() =>
        new(JsonSerializerDefaults.Web)
        {
            Converters = { new JsonStringEnumConverter() }
        };

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate repository root.");
    }

    private sealed class CountingRecordEncryptor : IHipRecordEncryptor
    {
        private readonly DevelopmentHipRecordEncryptor inner = new();
        private int unprotectCount;

        public int UnprotectCount => Volatile.Read(ref unprotectCount);

        public string Protect(string plaintextJson) => inner.Protect(plaintextJson);

        public string Unprotect(string storedPayload)
        {
            Interlocked.Increment(ref unprotectCount);
            return inner.Unprotect(storedPayload);
        }

        public bool IsProtectedPayload(string storedPayload) => inner.IsProtectedPayload(storedPayload);
    }
}
