using System.Text.Json;
using HIP.Application.Reporting;
using HIP.Application.Reputation;
using HIP.Application.Review;
using HIP.Application.Rules;
using HIP.Domain.Audit;
using HIP.Domain.Reporting;
using HIP.Domain.Reputation;
using HIP.Domain.Review;
using HIP.Domain.Risk;
using HIP.Domain.Rules;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using NUnit.Framework;
using FindingReporterTrustLevel = HIP.Domain.SelfHealing.ReporterTrustLevel;

namespace HIP.Tests.Persistence;

[TestFixture]
public sealed class PersistenceRepositoryTests
{
    [Test]
    public async Task DbContextCanBeCreated()
    {
        await using var database = await CreateDatabaseAsync();

        Assert.That(await database.Context.Database.CanConnectAsync(), Is.True);
    }

    [Test]
    public async Task ReputationProfileCanBeSavedAndRetrieved()
    {
        await using var database = await CreateDatabaseAsync();
        IReputationProfileRepository repository = new EfReputationProfileRepository(new HipRecordStore(database.Context));
        var profile = new ReputationProfile(
            "rep-domain-example",
            ReputationSubjectType.Domain,
            "example.com",
            82,
            RiskStatus.Trusted,
            2,
            0,
            1,
            DateTimeOffset.UtcNow,
            ["Strong domain history"]);

        await repository.SaveAsync(profile, CancellationToken.None);

        var retrieved = await repository.GetAsync(ReputationSubjectType.Domain, "example.com", CancellationToken.None);
        Assert.That(retrieved, Is.Not.Null);
        Assert.That(retrieved!.CurrentScore, Is.EqualTo(82));
        Assert.That(retrieved.Status, Is.EqualTo(RiskStatus.Trusted));
    }

    [Test]
    public async Task RuleCanBeSavedAndRetrieved()
    {
        await using var database = await CreateDatabaseAsync();
        IRuleRepository repository = new EfRuleRepository(new HipRecordStore(database.Context));
        var rule = CreateRule("persisted-rule");

        await repository.SaveAsync(rule, CancellationToken.None);

        var rules = await repository.ListAsync(CancellationToken.None);
        Assert.That(rules.Single().RuleId, Is.EqualTo("persisted-rule"));
        Assert.That(rules.Single().Conditions.Single().Field, Is.EqualTo("domain.ageDays"));
    }

    [Test]
    public async Task ReviewItemCanBeSavedAndRetrieved()
    {
        await using var database = await CreateDatabaseAsync();
        IReviewQueueRepository repository = new EfReviewQueueRepository(new HipRecordStore(database.Context));
        var reviewItem = CreateReviewItem("review-1");

        await repository.SaveAsync(reviewItem, CancellationToken.None);

        var retrieved = await repository.GetAsync("review-1", CancellationToken.None);
        Assert.That(retrieved, Is.Not.Null);
        Assert.That(retrieved!.Title, Is.EqualTo("Review suspicious domain"));
    }

    [Test]
    public async Task AuditLogCanBeSavedAndRetrieved()
    {
        await using var database = await CreateDatabaseAsync();
        IAuditLogRepository repository = new EfAuditLogRepository(new HipRecordStore(database.Context));
        var entry = new AuditLogEntry(
            "audit-1",
            "admin",
            "Review item approved",
            TargetType.Domain,
            "example.com",
            "Approved after privacy-safe review.",
            DateTimeOffset.UtcNow,
            new Dictionary<string, string> { ["reviewItemId"] = "review-1" },
            AuditSeverity.Medium);

        await repository.SaveAsync(entry, CancellationToken.None);

        var entries = await repository.ListAsync(CancellationToken.None);
        Assert.That(entries.Single().AuditLogId, Is.EqualTo("audit-1"));
        Assert.That(entries.Single().Metadata["reviewItemId"], Is.EqualTo("review-1"));
    }

    [Test]
    public async Task RiskFindingCanBeSavedAndRetrieved()
    {
        await using var database = await CreateDatabaseAsync();
        IRiskFindingReportRepository repository = new EfRiskFindingReportRepository(new HipRecordStore(database.Context));
        var report = CreateRiskFinding("risk-1");

        await repository.AddAsync(report, CancellationToken.None);

        var reports = await repository.ListAsync(CancellationToken.None);
        Assert.That(reports.Single().ReportId, Is.EqualTo("risk-1"));
        Assert.That(reports.Single().Domain, Is.EqualTo("suspicious.example"));
    }

    [Test]
    public async Task DatabaseDoesNotRequirePrivateChatLogs()
    {
        await using var database = await CreateDatabaseAsync();
        IRiskFindingReportRepository repository = new EfRiskFindingReportRepository(new HipRecordStore(database.Context));
        var report = CreateRiskFinding("privacy-safe-report") with
        {
            OriginalUrl = null,
            PrivacySafeEvidence = new PrivacySafeEvidence(
                "SecondLifeLink",
                "Obfuscated URL pattern detected.",
                new Dictionary<string, string>
                {
                    ["matchedPattern"] = "hxxp-dot-link",
                    ["senderHash"] = "sender-hash-only"
                })
        };

        await repository.AddAsync(report, CancellationToken.None);

        var retrieved = (await repository.ListAsync(CancellationToken.None)).Single();
        Assert.That(retrieved.OriginalUrl, Is.Null);
        Assert.That(retrieved.PrivacySafeEvidence.ContainsPrivateContent, Is.False);
        Assert.That(retrieved.PrivacySafeEvidence.Facts.ContainsKey("privateChatLog"), Is.False);
    }

    [Test]
    public async Task RepositoryInterfacesStillWork()
    {
        await using var database = await CreateDatabaseAsync();
        IReputationEventRepository eventRepository = new EfReputationEventRepository(new HipRecordStore(database.Context));
        var reputationEvent = new ReputationEvent(
            "event-1",
            ReputationSubjectType.Domain,
            "example.com",
            ReputationEventType.SuspiciousReport,
            ReputationEventSeverity.Medium,
            -8,
            HIP.Domain.Reputation.ReporterTrustLevel.Trusted,
            "Trusted reporter flagged suspicious redirects.",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddDays(90),
            IsConfirmed: false,
            IsAccidental: false);

        await eventRepository.AddAsync(reputationEvent, CancellationToken.None);

        var events = await eventRepository.ListAsync(ReputationSubjectType.Domain, "example.com", CancellationToken.None);
        Assert.That(events.Single().EventId, Is.EqualTo("event-1"));
    }

    /// <summary>
    /// Verifies browser/banner feedback is persisted with only privacy-safe fields for later scoring and review signals.
    /// </summary>
    [Test]
    public async Task WeightedFeedbackCanBeSavedAndRetrieved()
    {
        await using var database = await CreateDatabaseAsync();
        IWeightedFeedbackRepository repository = new EfWeightedFeedbackRepository(new HipRecordStore(database.Context));
        var submittedAtUtc = DateTimeOffset.UtcNow;
        var feedback = new WeightedFeedbackSubmission(
            "feedback.example",
            HipFeedbackType.LooksSuspicious,
            HipFeedbackSource.BrowserPluginBanner,
            HIP.Domain.Reputation.ReporterTrustLevel.Anonymous,
            submittedAtUtc,
            PageUrlHash: "sha256:page",
            ReporterHash: "sha256:reporter",
            PluginVersion: "0.1.0-dev",
            HipFeedbackReasonCode.ScamOrPhishing);

        await repository.SaveAsync(feedback, CancellationToken.None);

        var retrieved = await repository.ListRecentAsync("feedback.example", submittedAtUtc.AddMinutes(-1), CancellationToken.None);
        Assert.Multiple(() =>
        {
            Assert.That(retrieved, Has.Count.EqualTo(1));
            Assert.That(retrieved.Single().Domain, Is.EqualTo("feedback.example"));
            Assert.That(retrieved.Single().PageUrlHash, Is.EqualTo("sha256:page"));
            Assert.That(retrieved.Single().ReasonCode, Is.EqualTo(HipFeedbackReasonCode.ScamOrPhishing));
        });
    }

    private static TrustRule CreateRule(string ruleId) =>
        new(
            ruleId,
            "New domain with shortener",
            "Flags shortened links that resolve to young domains.",
            Enabled: true,
            RuleMode.Watch,
            RuleSeverity.HighRisk,
            [new RuleCondition("domain.ageDays", RuleOperator.LessThan, JsonSerializer.SerializeToElement(30))],
            [
                new RuleAction(RuleActionType.SetRiskLevel, JsonSerializer.SerializeToElement("HighRisk")),
                new RuleAction(RuleActionType.RouteToSafetyPage, JsonSerializer.SerializeToElement(true))
            ],
            RequiresApproval: true,
            SimulationRequired: true,
            CreatedBy: "persistence-test",
            CreatedReason: "Repository serialization test",
            ApprovalStatus.Pending,
            ConfidenceScore: 72,
            Version: 1);

    private static ReviewItem CreateReviewItem(string id) =>
        new(
            id,
            ReviewType.SuspiciousFinding,
            TargetType.Domain,
            "example.com",
            "Review suspicious domain",
            "Privacy-safe finding needs review.",
            RiskStatus.HighRisk,
            ReviewStatus.Open,
            ReviewPriority.High,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            "system",
            AssignedTo: null,
            Source: "persistence-test",
            EvidenceSummary: "Repeated risky URL hash reports.",
            new Dictionary<string, string> { ["urlHash"] = "abc123" },
            RecommendedAction: "Review domain reputation",
            Decision: null,
            DecisionReason: null);

    private static RiskFindingReport CreateRiskFinding(string id) =>
        new(
            id,
            SourceClient.BrowserPlugin,
            ReportPlatform.Web,
            TargetType.Url,
            "suspicious.example",
            "url-hash-123",
            "https://suspicious.example/path",
            SenderHash: null,
            RiskStatus.HighRisk,
            "Shortened URL resolves to a suspicious domain.",
            DateTimeOffset.UtcNow,
            FindingReporterTrustLevel.Trusted,
            new PrivacySafeEvidence(
                "LinkMetadata",
                "Shortener and young domain signals only.",
                new Dictionary<string, string> { ["usesShortener"] = "true" }),
            "hip-signature-placeholder");

    private static async Task<TestDatabase> CreateDatabaseAsync()
    {
        var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseSqlite(connection)
            .Options;
        var context = new HipDbContext(options);
        await context.Database.EnsureCreatedAsync();

        return new TestDatabase(connection, context);
    }

    private sealed class TestDatabase(SqliteConnection connection, HipDbContext context) : IAsyncDisposable
    {
        public HipDbContext Context { get; } = context;

        public async ValueTask DisposeAsync()
        {
            await Context.DisposeAsync();
            await connection.DisposeAsync();
        }
    }
}
