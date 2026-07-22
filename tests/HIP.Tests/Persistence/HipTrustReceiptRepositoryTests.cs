using System.Security.Cryptography;
using System.Text;
using HIP.Application.Protocol;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;
using HIP.Domain.Risk;
using HIP.Infrastructure;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Entities;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Tests.Persistence;

/// <summary>Verifies immutable, idempotent trust-receipt persistence.</summary>
[TestFixture]
public sealed class HipTrustReceiptRepositoryTests
{
    private static readonly ICanonicalJsonService Canonicalizer = new Rfc8785CanonicalJsonService();

    [Test]
    public async Task In_memory_repository_creates_and_returns_the_exact_signed_receipt()
    {
        var repository = new InMemoryHipTrustReceiptRepository();
        var candidate = StoredReceipt();

        var result = await repository.TryCreateAsync(candidate, CancellationToken.None);
        var byId = await repository.GetByIdAsync(candidate.Receipt.ReceiptId, CancellationToken.None);
        var byEvaluation = await repository.GetByRelatedEvaluationIdAsync(
            candidate.Receipt.RelatedEvaluationId,
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(HipTrustReceiptRepositoryWriteStatus.Created));
            AssertStoredReceipt(result.StoredReceipt, candidate);
            AssertStoredReceipt(byId, candidate);
            AssertStoredReceipt(byEvaluation, candidate);
        });
    }

    [Test]
    public async Task In_memory_repository_returns_existing_same_only_for_exact_retries()
    {
        var repository = new InMemoryHipTrustReceiptRepository();
        var candidate = StoredReceipt();
        await repository.TryCreateAsync(candidate, CancellationToken.None);

        var result = await repository.TryCreateAsync(candidate, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(HipTrustReceiptRepositoryWriteStatus.ExistingSame));
            AssertStoredReceipt(result.StoredReceipt, candidate);
        });
    }

    [Test]
    public async Task In_memory_repository_rejects_conflicting_receipt_or_evaluation_identity_without_overwrite()
    {
        var repository = new InMemoryHipTrustReceiptRepository();
        var winner = StoredReceipt();
        var sameReceiptId = StoredReceipt(
            receiptId: winner.Receipt.ReceiptId,
            relatedEvaluationId: "scan-conflicting-id");
        var sameEvaluationId = StoredReceipt(
            receiptId: "receipt-conflicting-id",
            relatedEvaluationId: winner.Receipt.RelatedEvaluationId);
        var changedSignedDocument = StoredReceipt(
            receiptId: winner.Receipt.ReceiptId,
            relatedEvaluationId: winner.Receipt.RelatedEvaluationId,
            domainTrustScore: winner.Receipt.Scores.DomainTrustScore - 1);
        await repository.TryCreateAsync(winner, CancellationToken.None);

        var receiptConflict = await repository.TryCreateAsync(sameReceiptId, CancellationToken.None);
        var evaluationConflict = await repository.TryCreateAsync(sameEvaluationId, CancellationToken.None);
        var signedDocumentConflict = await repository.TryCreateAsync(changedSignedDocument, CancellationToken.None);
        var stored = await repository.GetByIdAsync(winner.Receipt.ReceiptId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(receiptConflict.Status, Is.EqualTo(HipTrustReceiptRepositoryWriteStatus.Conflict));
            Assert.That(evaluationConflict.Status, Is.EqualTo(HipTrustReceiptRepositoryWriteStatus.Conflict));
            Assert.That(signedDocumentConflict.Status, Is.EqualTo(HipTrustReceiptRepositoryWriteStatus.Conflict));
            AssertStoredReceipt(stored, winner);
        });
    }

    [Test]
    public async Task In_memory_repository_serializes_concurrent_exact_retries()
    {
        var repository = new InMemoryHipTrustReceiptRepository();
        var candidate = StoredReceipt();

        var results = await Task.WhenAll(Enumerable.Range(0, 32)
            .Select(_ => repository.TryCreateAsync(candidate, CancellationToken.None)));

        Assert.Multiple(() =>
        {
            Assert.That(
                results.Count(result => result.Status == HipTrustReceiptRepositoryWriteStatus.Created),
                Is.EqualTo(1));
            Assert.That(
                results.Count(result => result.Status == HipTrustReceiptRepositoryWriteStatus.ExistingSame),
                Is.EqualTo(31));
            Assert.That(results, Has.All.Property(nameof(HipTrustReceiptRepositoryWriteResult.StoredReceipt)).Not.Null);
        });
    }

    [Test]
    public async Task In_memory_repository_serializes_concurrent_competing_evaluations()
    {
        var repository = new InMemoryHipTrustReceiptRepository();
        var first = StoredReceipt(receiptId: "receipt-concurrent-a");
        var second = StoredReceipt(receiptId: "receipt-concurrent-b");

        var results = await Task.WhenAll(
            repository.TryCreateAsync(first, CancellationToken.None),
            repository.TryCreateAsync(second, CancellationToken.None));
        var stored = await repository.GetByRelatedEvaluationIdAsync(
            first.Receipt.RelatedEvaluationId,
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(
                results.Count(result => result.Status == HipTrustReceiptRepositoryWriteStatus.Created),
                Is.EqualTo(1));
            Assert.That(
                results.Count(result => result.Status == HipTrustReceiptRepositoryWriteStatus.Conflict),
                Is.EqualTo(1));
            Assert.That(
                stored!.Receipt.ReceiptId,
                Is.EqualTo(results.Single(result => result.Status == HipTrustReceiptRepositoryWriteStatus.Created)
                    .StoredReceipt!.Receipt.ReceiptId));
        });
    }

    [Test]
    public void Repositories_reject_mismatched_or_noncanonical_stored_material()
    {
        var candidate = StoredReceipt();
        var wrongJson = candidate with { ReceiptJson = candidate.ReceiptJson + " " };
        var wrongReceiptDigest = candidate with { ReceiptDigest = $"sha256:{new string('0', 64)}" };
        var wrongSourceDigest = candidate with { SourceEvaluationDigest = $"sha256:{new string('1', 64)}" };

        Assert.Multiple(() =>
        {
            Assert.ThrowsAsync<ArgumentException>(() =>
                new InMemoryHipTrustReceiptRepository().TryCreateAsync(wrongJson, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentException>(() =>
                new InMemoryHipTrustReceiptRepository().TryCreateAsync(wrongReceiptDigest, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentException>(() =>
                new InMemoryHipTrustReceiptRepository().TryCreateAsync(wrongSourceDigest, CancellationToken.None));
        });
    }

    [Test]
    public async Task Ef_repository_preserves_exact_material_and_reports_sequential_idempotency_and_conflicts()
    {
        var options = NewDatabaseOptions();
        await using var dbContext = new HipDbContext(options);
        var repository = new EfHipTrustReceiptRepository(dbContext, Canonicalizer);
        var winner = StoredReceipt();
        var conflicting = StoredReceipt(
            receiptId: "receipt-ef-conflict",
            relatedEvaluationId: winner.Receipt.RelatedEvaluationId);
        var changedSignedDocument = StoredReceipt(
            receiptId: winner.Receipt.ReceiptId,
            relatedEvaluationId: winner.Receipt.RelatedEvaluationId,
            domainTrustScore: winner.Receipt.Scores.DomainTrustScore - 1);

        var created = await repository.TryCreateAsync(winner, CancellationToken.None);
        var existing = await repository.TryCreateAsync(winner, CancellationToken.None);
        var conflict = await repository.TryCreateAsync(conflicting, CancellationToken.None);
        var signedDocumentConflict = await repository.TryCreateAsync(changedSignedDocument, CancellationToken.None);
        var stored = await repository.GetByIdAsync(winner.Receipt.ReceiptId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(created.Status, Is.EqualTo(HipTrustReceiptRepositoryWriteStatus.Created));
            Assert.That(existing.Status, Is.EqualTo(HipTrustReceiptRepositoryWriteStatus.ExistingSame));
            Assert.That(conflict.Status, Is.EqualTo(HipTrustReceiptRepositoryWriteStatus.Conflict));
            Assert.That(signedDocumentConflict.Status, Is.EqualTo(HipTrustReceiptRepositoryWriteStatus.Conflict));
            AssertStoredReceipt(stored, winner);
            Assert.That(dbContext.TrustReceipts.Count(), Is.EqualTo(1));
        });
    }

    [Test]
    public void Ef_model_has_primary_receipt_and_unique_related_evaluation_constraints()
    {
        using var dbContext = new HipDbContext(NewDatabaseOptions());
        var entity = dbContext.Model.FindEntityType(typeof(HipTrustReceiptEntity));

        Assert.Multiple(() =>
        {
            Assert.That(
                entity!.FindPrimaryKey()!.Properties.Select(property => property.Name),
                Is.EqualTo(new[] { nameof(HipTrustReceiptEntity.ReceiptId) }));
            Assert.That(
                entity.GetIndexes().Single(index => index.IsUnique).Properties.Select(property => property.Name),
                Is.EqualTo(new[] { nameof(HipTrustReceiptEntity.RelatedEvaluationId) }));
        });
    }

    [Test]
    public void Infrastructure_registers_the_durable_trust_receipt_repository()
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

        var descriptor = services.Single(service => service.ServiceType == typeof(IHipTrustReceiptRepository));
        Assert.Multiple(() =>
        {
            Assert.That(descriptor.ImplementationType, Is.EqualTo(typeof(EfHipTrustReceiptRepository)));
            Assert.That(descriptor.Lifetime, Is.EqualTo(ServiceLifetime.Scoped));
        });
    }

    private static DbContextOptions<HipDbContext> NewDatabaseOptions() =>
        new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-trust-receipts-{Guid.NewGuid():N}")
            .Options;

    private static HipStoredTrustReceipt StoredReceipt(
        string receiptId = "receipt-persistence-1",
        string relatedEvaluationId = "scan-persistence-1",
        int domainTrustScore = 82)
    {
        var issuedAtUtc = new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);
        var evidenceDigest = HipContentDigest.FromPrefixedString($"sha256:{new string('a', 64)}");
        var receipt = new HipTrustReceipt(
            HipTrustReceipt.TrustReceiptDocumentType,
            HipProtocolVersion.Current,
            receiptId,
            relatedEvaluationId,
            new HipProtocolSubject(IdentitySubjectType.Website, "example.com"),
            issuedAtUtc.AddSeconds(-2),
            issuedAtUtc,
            issuedAtUtc.AddMinutes(10),
            new HipTrustReceiptScores(domainTrustScore, 74, 61, 39),
            RiskStatus.ProbablySafe,
            HipTrustConfidence.High,
            new[] { "domain-verified", "tls-valid" },
            new[] { "limited-content-evidence" },
            "policy-2026.07",
            "site-safety-2026.07",
            evidenceDigest,
            new HipProtocolIssuer("hip:domain:issuer.example"),
            new HipProtocolSignature(
                HipProtocolSignature.OriginAndIntegrityScope,
                "dev-key-1",
                "PQ-Placeholder-Development-Only",
                SignatureAlgorithmFamily.Unknown,
                HipProtocolSignature.Rfc8785Canonicalization,
                $"devsig:{new string('b', 64)}"));
        var receiptJson = HipTrustReceiptJson.Serialize(receipt);
        var receiptDigest = Sha256(Canonicalizer.Canonicalize(Encoding.UTF8.GetBytes(receiptJson)));
        return new HipStoredTrustReceipt(
            receipt,
            receiptJson,
            receiptDigest,
            evidenceDigest.ToPrefixedString());
    }

    private static string Sha256(ReadOnlySpan<byte> value) =>
        $"sha256:{Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant()}";

    private static void AssertStoredReceipt(HipStoredTrustReceipt? actual, HipStoredTrustReceipt expected)
    {
        Assert.That(actual, Is.Not.Null);
        Assert.Multiple(() =>
        {
            Assert.That(actual!.Receipt.ReceiptId, Is.EqualTo(expected.Receipt.ReceiptId));
            Assert.That(actual.Receipt.RelatedEvaluationId, Is.EqualTo(expected.Receipt.RelatedEvaluationId));
            Assert.That(actual.ReceiptJson, Is.EqualTo(expected.ReceiptJson));
            Assert.That(actual.ReceiptDigest, Is.EqualTo(expected.ReceiptDigest));
            Assert.That(actual.SourceEvaluationDigest, Is.EqualTo(expected.SourceEvaluationDigest));
        });
    }
}
