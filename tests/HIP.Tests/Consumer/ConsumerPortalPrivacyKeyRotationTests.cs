using HIP.Application.Consumer;
using HIP.Application.Reporting;
using HIP.Application.Review;
using HIP.Domain.Reporting;
using HIP.Domain.Review;
using HIP.Domain.Risk;
using HIP.Domain.SelfHealing;

namespace HIP.Tests.Consumer;

/// <summary>
/// Verifies consumer history remains visible during a planned privacy-HMAC rotation.
/// </summary>
public sealed class ConsumerPortalPrivacyKeyRotationTests
{
    private const string CurrentKey = "consumer-current-privacy-key-material";
    private const string LegacyKey = "consumer-legacy-privacy-key-material";
    private static readonly DateTimeOffset Now =
        new(2026, 7, 20, 17, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Scan_report_and_appeal_reads_match_current_and_legacy_consumer_hashes()
    {
        var currentHashing = Hashing(CurrentKey);
        var legacyHashing = Hashing(LegacyKey);
        var rotatedHashing = Hashing(CurrentKey, [LegacyKey]);
        var findings = new InMemoryRiskFindingReportRepository();
        await findings.AddAsync(
            Finding("report-current", "current.example", currentHashing.Hash("consumer-A")),
            CancellationToken.None);
        await findings.AddAsync(
            Finding("report-legacy", "legacy.example", legacyHashing.Hash("consumer-A")),
            CancellationToken.None);
        await findings.AddAsync(
            Finding("report-other", "other.example", legacyHashing.Hash("consumer-B")),
            CancellationToken.None);
        AppealRequest[] appealRecords =
        [
            Appeal("appeal-current", currentHashing.Hash("consumer-A")),
            Appeal("appeal-legacy", legacyHashing.Hash("consumer-A")),
            Appeal("appeal-other", legacyHashing.Hash("consumer-B"))
        ];
        var appealRepository = new InMemoryAppealRepository();
        foreach (var appeal in appealRecords)
        {
            await appealRepository.SaveAsync(appeal, CancellationToken.None);
        }
        var appeals = new StubAppealService(appealRecords);
        var service = new ConsumerPortalService(
            findings,
            appeals,
            rotatedHashing,
            deviceRegistrationService: null!,
            appealRepository: appealRepository);

        var scans = await service.GetScansAsync("consumer-A", CancellationToken.None);
        var reports = await service.GetReportsAsync("consumer-A", CancellationToken.None);
        var visibleAppeals = await service.GetAppealsAsync("consumer-A", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(scans.Select(item => item.Domain), Is.EquivalentTo(new[] { "current.example", "legacy.example" }));
            Assert.That(reports.Select(item => item.ReportId), Is.EquivalentTo(new[] { "report-current", "report-legacy" }));
            Assert.That(visibleAppeals.Select(item => item.AppealId), Is.EquivalentTo(new[] { "appeal-current", "appeal-legacy" }));
        });
    }

    [Test]
    public async Task New_consumer_appeals_write_only_the_current_hash()
    {
        var currentHashing = Hashing(CurrentKey);
        var legacyHashing = Hashing(LegacyKey);
        var appeals = new StubAppealService([]);
        var service = new ConsumerPortalService(
            new InMemoryRiskFindingReportRepository(),
            appeals,
            Hashing(CurrentKey, [LegacyKey]),
            deviceRegistrationService: null!,
            appealRepository: new InMemoryAppealRepository());

        var result = await service.SubmitAppealAsync(
            "consumer-A",
            new ConsumerAppealSubmissionRequest(
                TargetType.Domain,
                "example.com",
                "Please review the current trust evidence.",
                new Dictionary<string, string>()),
            CancellationToken.None);
        var stored = appeals.Get(result.AppealId)!;

        Assert.Multiple(() =>
        {
            Assert.That(result.Accepted, Is.True);
            Assert.That(stored.SubmittedByHash, Is.EqualTo(currentHashing.Hash("consumer-A")));
            Assert.That(stored.SubmittedByHash, Is.Not.EqualTo(legacyHashing.Hash("consumer-A")));
        });
    }

    [Test]
    public async Task Consumer_appeal_rejects_unbounded_evidence_before_persistence()
    {
        var appeals = new StubAppealService([]);
        var service = new ConsumerPortalService(
            new InMemoryRiskFindingReportRepository(),
            appeals,
            Hashing(CurrentKey),
            deviceRegistrationService: null!,
            appealRepository: new InMemoryAppealRepository());
        var evidence = Enumerable.Range(0, 9).ToDictionary(
            index => $"fact-{index}",
            index => $"summary-{index}");

        var result = await service.SubmitAppealAsync(
            "consumer-A",
            new ConsumerAppealSubmissionRequest(
                TargetType.Domain,
                "example.com",
                "Please review the current trust evidence.",
                evidence),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Accepted, Is.False);
            Assert.That(result.Message, Does.Contain("Privacy-safe evidence"));
            Assert.That(appeals.List(), Is.Empty);
        });
    }

    private static Sha256PrivacyHashingService Hashing(
        string currentKey,
        IReadOnlyCollection<string>? legacyKeys = null) =>
        new(new PrivacyHashingOptions(
            currentKey,
            AllowDevelopmentKey: false,
            LegacyKeys: legacyKeys));

    private static RiskFindingReport Finding(string reportId, string domain, string consumerScopeHash) =>
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
            Now,
            ReporterTrustLevel.Trusted,
            new PrivacySafeEvidence("test", "Privacy-safe evidence.", new Dictionary<string, string>()),
            "hip-signature-placeholder",
            consumerScopeHash);

    private static AppealRequest Appeal(string appealId, string submittedByHash) =>
        new(
            appealId,
            TargetType.Domain,
            "example.com",
            submittedByHash,
            "Privacy-safe appeal reason.",
            AppealStatus.Submitted,
            Now,
            Now,
            ReviewerId: null,
            Decision: "AutomatedFirstPass",
            DecisionReason: "Accepted for review.",
            PrivacySafeEvidence: new Dictionary<string, string>());

    private sealed class StubAppealService(IEnumerable<AppealRequest> seed) : IAppealService
    {
        private readonly Dictionary<string, AppealRequest> appeals = seed.ToDictionary(
            appeal => appeal.AppealId,
            StringComparer.Ordinal);

        public AppealRequest Submit(AppealRequest appeal)
        {
            var stored = appeal with
            {
                AppealId = string.IsNullOrWhiteSpace(appeal.AppealId)
                    ? $"appeal-{Guid.NewGuid():N}"
                    : appeal.AppealId
            };
            appeals.Add(stored.AppealId, stored);
            return stored;
        }

        public IReadOnlyCollection<AppealRequest> List() => appeals.Values.ToArray();

        public AppealRequest? Get(string appealId) => appeals.GetValueOrDefault(appealId);

        public AppealRequest Approve(string appealId, string reviewerId, string reason) =>
            throw new NotSupportedException();

        public AppealRequest Reject(string appealId, string reviewerId, string reason) =>
            throw new NotSupportedException();

        public AppealRequest RequestMoreInfo(string appealId, string reviewerId, string reason) =>
            throw new NotSupportedException();
    }
}
