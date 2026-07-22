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
public sealed class ConsumerHistoryRepositoryTests
{
    private const string CurrentKey = "consumer-history-current-key-material";
    private const string LegacyKey = "consumer-history-legacy-key-material";
    private static readonly DateTimeOffset Now =
        new(2026, 7, 20, 18, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Risk_history_query_decrypts_only_the_bounded_candidate_owner_rows()
    {
        await using var dbContext = Context();
        var encryptor = new TrackingRecordEncryptor();
        var store = new HipRecordStore(dbContext, encryptor);
        var repository = new EfRiskFindingReportRepository(store, dbContext, encryptor);
        var ownerHash = Hashing(CurrentKey).Hash("consumer-A");
        var otherHash = Hashing(CurrentKey).Hash("consumer-B");
        for (var index = 0; index < 12; index++)
        {
            await repository.AddAsync(
                Finding($"report-{index:D2}", $"owner-{index:D2}.example", ownerHash, Now.AddMinutes(index)),
                CancellationToken.None);
        }
        await repository.AddAsync(
            Finding("report-other", "must-not-decrypt.example", otherHash, Now.AddHours(1)),
            CancellationToken.None);
        encryptor.ResetTracking();

        var results = await repository.ListByConsumerScopeHashesAsync(
            [ownerHash],
            maximumResults: 5,
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(results.Select(report => report.ReportId), Is.EqualTo(new[]
            {
                "report-11", "report-10", "report-09", "report-08", "report-07"
            }));
            Assert.That(encryptor.UnprotectCount, Is.EqualTo(5));
            Assert.That(
                encryptor.UnprotectedPayloads.Any(payload => payload.Contains("must-not-decrypt.example", StringComparison.Ordinal)),
                Is.False);
        });
    }

    [Test]
    public async Task Report_and_appeal_queries_share_current_and_legacy_owner_partitions_only()
    {
        await using var dbContext = Context();
        var encryptor = new TrackingRecordEncryptor();
        var store = new HipRecordStore(dbContext, encryptor);
        var findings = new EfRiskFindingReportRepository(store, dbContext, encryptor);
        var appeals = new EfAppealRepository(store, dbContext, encryptor);
        var currentHash = Hashing(CurrentKey).Hash("consumer-A");
        var legacyHash = Hashing(LegacyKey).Hash("consumer-A");
        var otherHash = Hashing(CurrentKey).Hash("consumer-B");
        await findings.AddAsync(Finding("report-current", "current.example", currentHash, Now), CancellationToken.None);
        await findings.AddAsync(Finding("report-legacy", "legacy.example", legacyHash, Now.AddMinutes(-1)), CancellationToken.None);
        await findings.AddAsync(Finding("report-other", "other.example", otherHash, Now.AddMinutes(1)), CancellationToken.None);
        await appeals.SaveAsync(Appeal("appeal-current", currentHash, Now), CancellationToken.None);
        await appeals.SaveAsync(Appeal("appeal-legacy", legacyHash, Now.AddMinutes(-1)), CancellationToken.None);
        await appeals.SaveAsync(Appeal("appeal-other", otherHash, Now.AddMinutes(1)), CancellationToken.None);
        encryptor.ResetTracking();

        var visibleFindings = await findings.ListByConsumerScopeHashesAsync(
            [currentHash, legacyHash],
            maximumResults: 10,
            CancellationToken.None);
        var visibleAppeals = await appeals.ListBySubmitterHashesAsync(
            [currentHash, legacyHash],
            maximumResults: 10,
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(
                visibleFindings.Select(report => report.ReportId),
                Is.EqualTo(new[] { "report-current", "report-legacy" }));
            Assert.That(
                visibleAppeals.Select(appeal => appeal.AppealId),
                Is.EqualTo(new[] { "appeal-current", "appeal-legacy" }));
            Assert.That(encryptor.UnprotectCount, Is.EqualTo(4));
            Assert.That(
                dbContext.Records.AsEnumerable().Any(record =>
                    record.Partition.Contains("consumer-A", StringComparison.Ordinal)),
                Is.False);
        });
    }

    [Test]
    public async Task Duplicate_logical_record_across_rotation_partitions_is_rejected_before_decryption()
    {
        await using var dbContext = Context();
        var encryptor = new TrackingRecordEncryptor();
        var store = new HipRecordStore(dbContext, encryptor);
        var repository = new EfRiskFindingReportRepository(store, dbContext, encryptor);
        var currentHash = Hashing(CurrentKey).Hash("consumer-A");
        var legacyHash = Hashing(LegacyKey).Hash("consumer-A");
        await repository.AddAsync(
            Finding("report-duplicate", "current.example", currentHash, Now),
            CancellationToken.None);
        var legacyCopy = Finding("report-duplicate", "legacy.example", legacyHash, Now);
        await store.SaveAsync(
            "risk-finding-report-owner-v1:" + legacyHash,
            legacyCopy.ReportId,
            legacyCopy,
            CancellationToken.None);
        encryptor.ResetTracking();

        Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await repository.ListByConsumerScopeHashesAsync(
                [currentHash, legacyHash],
                maximumResults: 10,
                CancellationToken.None);
        });
        Assert.That(encryptor.UnprotectCount, Is.Zero);
    }

    private static HipDbContext Context() =>
        new(new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-consumer-history-{Guid.NewGuid():N}")
            .Options);

    private static Sha256PrivacyHashingService Hashing(string key) =>
        new(new PrivacyHashingOptions(key, AllowDevelopmentKey: false));

    private static RiskFindingReport Finding(
        string reportId,
        string domain,
        string consumerScopeHash,
        DateTimeOffset detectedAtUtc) =>
        new(
            reportId,
            SourceClient.BrowserPlugin,
            ReportPlatform.Web,
            TargetType.Url,
            domain,
            $"sha256:{new string('a', 64)}",
            OriginalUrl: null,
            SenderHash: null,
            RiskStatus.HighRisk,
            "Privacy-safe risk summary.",
            detectedAtUtc,
            ReporterTrustLevel.Trusted,
            new PrivacySafeEvidence("test", "Privacy-safe evidence.", new Dictionary<string, string>()),
            "hip-signature-placeholder",
            consumerScopeHash);

    private static AppealRequest Appeal(
        string appealId,
        string submittedByHash,
        DateTimeOffset updatedAtUtc) =>
        new(
            appealId,
            TargetType.Domain,
            "example.com",
            submittedByHash,
            "Privacy-safe appeal reason.",
            AppealStatus.Submitted,
            updatedAtUtc,
            updatedAtUtc,
            ReviewerId: null,
            Decision: "AutomatedFirstPass",
            DecisionReason: "Accepted for review.",
            PrivacySafeEvidence: new Dictionary<string, string>());

    private sealed class TrackingRecordEncryptor : IHipRecordEncryptor
    {
        private const string Prefix = "hip-test-protected:";
        private readonly List<string> unprotectedPayloads = [];

        public int UnprotectCount => unprotectedPayloads.Count;

        public IReadOnlyCollection<string> UnprotectedPayloads => unprotectedPayloads;

        public string Protect(string plaintextJson) =>
            Prefix + Convert.ToBase64String(Encoding.UTF8.GetBytes(plaintextJson));

        public string Unprotect(string storedPayload)
        {
            if (!IsProtectedPayload(storedPayload))
            {
                throw new InvalidOperationException("The test payload was not protected.");
            }

            var plaintext = Encoding.UTF8.GetString(
                Convert.FromBase64String(storedPayload[Prefix.Length..]));
            unprotectedPayloads.Add(plaintext);
            return plaintext;
        }

        public bool IsProtectedPayload(string storedPayload) =>
            storedPayload.StartsWith(Prefix, StringComparison.Ordinal);

        public void ResetTracking() => unprotectedPayloads.Clear();
    }
}
