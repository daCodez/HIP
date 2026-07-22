using System.Text;
using HIP.Application.Reporting;
using HIP.Application.Review;
using HIP.Domain.Reporting;
using HIP.Domain.Review;
using HIP.Domain.Risk;
using HIP.Domain.SelfHealing;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Persistence;

[TestFixture]
public sealed class ConsumerHistoryOwnerIndexBackfillTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 7, 20, 20, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Backfill_indexes_global_only_consumer_history_and_is_idempotent()
    {
        await using var dbContext = Context();
        var encryptor = new TestRecordEncryptor();
        var store = new HipRecordStore(dbContext, encryptor);
        var ownerHash = $"sha256:{new string('a', 64)}";
        var finding = Finding("legacy-report", ownerHash);
        var unownedFinding = Finding("anonymous-report", consumerScopeHash: null);
        var appeal = Appeal("legacy-appeal", ownerHash);
        await store.SaveAsync("risk-finding-report", finding.ReportId, finding, CancellationToken.None);
        await store.SaveAsync(
            "risk-finding-report",
            unownedFinding.ReportId,
            unownedFinding,
            CancellationToken.None);
        await store.SaveAsync("appeal", appeal.AppealId, appeal, CancellationToken.None);
        var service = new ConsumerHistoryOwnerIndexBackfillService(store, dbContext, encryptor);

        var first = await service.BackfillAllAsync(batchSize: 1, CancellationToken.None);
        var second = await service.BackfillAllAsync(batchSize: 2, CancellationToken.None);

        var findingRepository = new EfRiskFindingReportRepository(store, dbContext, encryptor);
        var appealRepository = new EfAppealRepository(store, dbContext, encryptor);
        var visibleFindings = await findingRepository.ListByConsumerScopeHashesAsync(
            [ownerHash],
            maximumResults: 10,
            CancellationToken.None);
        var visibleAppeals = await appealRepository.ListBySubmitterHashesAsync(
            [ownerHash],
            maximumResults: 10,
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(first.CreatedOwnerRecords, Is.EqualTo(2));
            Assert.That(first.SkippedWithoutOwner, Is.EqualTo(1));
            Assert.That(first.ProcessedGlobalRecords, Is.EqualTo(3));
            Assert.That(second.CreatedOwnerRecords, Is.Zero);
            Assert.That(second.AlreadyIndexedRecords, Is.EqualTo(2));
            Assert.That(visibleFindings.Select(item => item.ReportId), Is.EqualTo([finding.ReportId]));
            Assert.That(visibleAppeals.Select(item => item.AppealId), Is.EqualTo([appeal.AppealId]));
            Assert.That(
                dbContext.Records.Count(record => record.Partition.StartsWith("risk-finding-report-owner-v1:")),
                Is.EqualTo(1));
            Assert.That(
                dbContext.Records.Count(record => record.Partition.StartsWith("appeal-owner-v1:")),
                Is.EqualTo(1));
        });
    }

    [Test]
    public void Backfill_rejects_an_existing_owner_copy_that_does_not_match_the_global_record()
    {
        Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await using var dbContext = Context();
            var encryptor = new TestRecordEncryptor();
            var store = new HipRecordStore(dbContext, encryptor);
            var ownerHash = $"sha256:{new string('b', 64)}";
            var global = Finding("report-conflict", ownerHash);
            var conflicting = global with { Domain = "different.example" };
            await store.SaveAsync("risk-finding-report", global.ReportId, global, CancellationToken.None);
            await store.SaveAsync(
                "risk-finding-report-owner-v1:" + ownerHash,
                conflicting.ReportId,
                conflicting,
                CancellationToken.None);
            var service = new ConsumerHistoryOwnerIndexBackfillService(store, dbContext, encryptor);

            await service.BackfillAllAsync(batchSize: 10, CancellationToken.None);
        });
    }

    private static HipDbContext Context() =>
        new(new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-consumer-history-backfill-{Guid.NewGuid():N}")
            .Options);

    private static RiskFindingReport Finding(string id, string? consumerScopeHash) =>
        new(
            id,
            SourceClient.BrowserPlugin,
            ReportPlatform.Web,
            TargetType.Url,
            "example.com",
            $"sha256:{new string('c', 64)}",
            OriginalUrl: null,
            SenderHash: null,
            RiskStatus.HighRisk,
            "Privacy-safe risk summary.",
            Now,
            ReporterTrustLevel.Trusted,
            new PrivacySafeEvidence("test", "Privacy-safe evidence.", new Dictionary<string, string>()),
            "hip-signature-placeholder",
            consumerScopeHash);

    private static AppealRequest Appeal(string id, string submittedByHash) =>
        new(
            id,
            TargetType.Domain,
            "example.com",
            submittedByHash,
            "Privacy-safe appeal reason.",
            AppealStatus.Submitted,
            Now,
            Now,
            ReviewerId: null,
            Decision: null,
            DecisionReason: null,
            PrivacySafeEvidence: new Dictionary<string, string>());

    private sealed class TestRecordEncryptor : IHipRecordEncryptor
    {
        private const string Prefix = "hip-test-protected:";

        public string Protect(string plaintextJson) =>
            Prefix + Convert.ToBase64String(Encoding.UTF8.GetBytes(plaintextJson));

        public string Unprotect(string storedPayload)
        {
            if (!IsProtectedPayload(storedPayload))
            {
                throw new InvalidOperationException("The test payload was not protected.");
            }

            return Encoding.UTF8.GetString(Convert.FromBase64String(storedPayload[Prefix.Length..]));
        }

        public bool IsProtectedPayload(string storedPayload) =>
            storedPayload.StartsWith(Prefix, StringComparison.Ordinal);
    }
}
