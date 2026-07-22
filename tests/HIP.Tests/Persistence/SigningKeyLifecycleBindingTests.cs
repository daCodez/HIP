using System.Text.Json;
using System.Text.Json.Serialization;
using HIP.Domain.Identity;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Persistence;

public sealed class SigningKeyLifecycleBindingTests
{
    private const string Partition = "signing-key-ring";

    [Test]
    public void Security_sensitive_reads_reject_legacy_plaintext_records()
    {
        using var context = CreateContext();
        var now = DateTimeOffset.UtcNow;
        context.Records.Add(new HipDbRecord
        {
            Partition = Partition,
            Id = "hip:domain:example",
            Json = "{}",
            AggregateVersion = 1,
            CreatedAtUtc = now,
            UpdatedAtUtc = now
        });
        context.SaveChanges();
        var store = new HipRecordStore(context, new DevelopmentHipRecordEncryptor());

        Assert.ThrowsAsync<InvalidOperationException>(() => store.GetEncryptedAsync<SigningKeyRing>(
            Partition,
            "hip:domain:example",
            CancellationToken.None));
    }

    [Test]
    public void Lifecycle_repository_rejects_an_encrypted_ring_copied_from_another_identity()
    {
        using var context = CreateContext();
        var encryptor = new DevelopmentHipRecordEncryptor();
        var activatedAt = new DateTimeOffset(2026, 7, 18, 12, 0, 0, TimeSpan.Zero);
        var otherIdentityRing = SigningKeyRing.Create("hip:domain:other")
            .RegisterActiveKey("key-1", "ML-DSA-65", "public-key", activatedAt);
        var json = JsonSerializer.Serialize(otherIdentityRing, SerializerOptions());
        context.Records.Add(new HipDbRecord
        {
            Partition = Partition,
            Id = "hip:domain:requested",
            Json = encryptor.Protect(json),
            AggregateVersion = otherIdentityRing.Version,
            CreatedAtUtc = activatedAt,
            UpdatedAtUtc = activatedAt
        });
        context.SaveChanges();
        var repository = new EfSigningKeyLifecycleRepository(new HipRecordStore(context, encryptor));

        Assert.ThrowsAsync<InvalidOperationException>(() => repository.GetAsync(
            "hip:domain:requested",
            CancellationToken.None));
    }

    [Test]
    public async Task Lifecycle_repository_accepts_an_encrypted_ring_bound_to_the_requested_identity()
    {
        using var context = CreateContext();
        var encryptor = new DevelopmentHipRecordEncryptor();
        var activatedAt = new DateTimeOffset(2026, 7, 18, 12, 0, 0, TimeSpan.Zero);
        var original = SigningKeyRing.Create("hip:domain:requested")
            .RegisterActiveKey("key-1", "ML-DSA-65", "public-key", activatedAt);
        context.Records.Add(new HipDbRecord
        {
            Partition = Partition,
            Id = original.IdentityId,
            Json = encryptor.Protect(JsonSerializer.Serialize(original, SerializerOptions())),
            AggregateVersion = original.Version,
            CreatedAtUtc = activatedAt,
            UpdatedAtUtc = activatedAt
        });
        context.SaveChanges();
        var repository = new EfSigningKeyLifecycleRepository(new HipRecordStore(context, encryptor));

        var restored = await repository.GetAsync(original.IdentityId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(restored, Is.Not.Null);
            Assert.That(restored!.IdentityId, Is.EqualTo(original.IdentityId));
            Assert.That(restored.GetRequiredKey("key-1").Status, Is.EqualTo(SigningKeyStatus.Active));
        });
    }

    private static HipDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-key-binding-{Guid.NewGuid():N}")
            .Options;
        return new HipDbContext(options);
    }

    private static JsonSerializerOptions SerializerOptions() =>
        new(JsonSerializerDefaults.Web)
        {
            Converters = { new JsonStringEnumConverter() }
        };
}
