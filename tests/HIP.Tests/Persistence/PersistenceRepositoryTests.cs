using System.Text.Json;
using System.Text.Json.Serialization;
using HIP.Application.Browser;
using HIP.Application.Reporting;
using HIP.Application.Reputation;
using HIP.Application.Review;
using HIP.Application.Rules;
using HIP.Application.Scalability;
using HIP.Domain.Audit;
using HIP.Domain.Reporting;
using HIP.Domain.Reputation;
using HIP.Domain.Review;
using HIP.Domain.Risk;
using HIP.Domain.Rules;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.Extensions.DependencyInjection;
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

    /// <summary>
    /// Verifies repository payloads are encrypted before they reach the generic JSON record table.
    /// </summary>
    [Test]
    public async Task RecordStoreEncryptsJsonPayloadAtRest()
    {
        await using var database = await CreateDatabaseAsync();
        IReputationProfileRepository repository = new EfReputationProfileRepository(new HipRecordStore(database.Context));
        var profile = new ReputationProfile(
            "rep-domain-encrypted",
            ReputationSubjectType.Domain,
            "encrypted.example",
            74,
            RiskStatus.ProbablySafe,
            1,
            0,
            0,
            DateTimeOffset.UtcNow,
            ["Encrypted storage test reason"]);

        await repository.SaveAsync(profile, CancellationToken.None);

        var rawJson = database.Context.Records.Single().Json;
        Assert.Multiple(() =>
        {
            Assert.That(rawJson, Does.Contain("hip-record-envelope"));
            Assert.That(rawJson, Does.Contain("AES-256-GCM"));
            Assert.That(rawJson, Does.Not.Contain("encrypted.example"));
            Assert.That(rawJson, Does.Not.Contain("Encrypted storage test reason"));
        });
    }

    /// <summary>
    /// Verifies encrypted record storage remains backward compatible with old plaintext development rows.
    /// </summary>
    [Test]
    public async Task RecordStoreCanReadLegacyPlaintextRows()
    {
        await using var database = await CreateDatabaseAsync();
        var profile = new ReputationProfile(
            "rep-domain-legacy",
            ReputationSubjectType.Domain,
            "legacy.example",
            63,
            RiskStatus.ProbablySafe,
            1,
            0,
            0,
            DateTimeOffset.UtcNow,
            ["Legacy plaintext row"]);
        database.Context.Records.Add(new HipDbRecord
        {
            Partition = "reputation-profile",
            Id = "domain:legacy.example",
            Json = JsonSerializer.Serialize(profile, JsonOptions),
            CreatedAtUtc = DateTimeOffset.UtcNow,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        });
        await database.Context.SaveChangesAsync();
        IReputationProfileRepository repository = new EfReputationProfileRepository(new HipRecordStore(database.Context));

        var retrieved = await repository.GetAsync(ReputationSubjectType.Domain, "legacy.example", CancellationToken.None);

        Assert.That(retrieved?.CurrentScore, Is.EqualTo(63));
    }

    /// <summary>
    /// Verifies production startup refuses unsafe EnsureCreated database setup when migrations are absent.
    /// </summary>
    [Test]
    public void DatabaseInitializerRequiresMigrationsOutsideDevelopment()
    {
        var services = new ServiceCollection();
        services.AddDbContext<HipDbContext>(options => options.UseSqlite("DataSource=:memory:"));
        using var provider = services.BuildServiceProvider();

        var exception = Assert.ThrowsAsync<InvalidOperationException>(() =>
            HipDatabaseInitializer.EnsureCreatedAsync(provider, isLocalDevelopment: false));

        Assert.That(exception?.Message, Does.Contain("migrations are required"));
    }

    /// <summary>
    /// Verifies local development startup evolves an existing non-empty database with the typed hot-path tables.
    /// </summary>
    [Test]
    public async Task DatabaseInitializerAddsHotPathTablesToExistingDevelopmentDatabase()
    {
        await using var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText =
                """
                CREATE TABLE hip_records (
                    Partition TEXT NOT NULL,
                    Id TEXT NOT NULL,
                    Json TEXT NOT NULL,
                    CreatedAtUtc TEXT NOT NULL,
                    UpdatedAtUtc TEXT NOT NULL,
                    CONSTRAINT PK_hip_records PRIMARY KEY (Partition, Id)
                );
                """;
            await command.ExecuteNonQueryAsync();
        }

        var services = new ServiceCollection();
        services.AddDbContext<HipDbContext>(options => options.UseSqlite(connection));
        using var provider = services.BuildServiceProvider();

        await HipDatabaseInitializer.EnsureCreatedAsync(provider, isLocalDevelopment: true);

        Assert.Multiple(() =>
        {
            Assert.That(SqliteTableExists(connection, "hip_browser_scan_results"), Is.True);
            Assert.That(SqliteTableExists(connection, "hip_dashboard_scan_aggregates"), Is.True);
        });
    }

    /// <summary>
    /// Verifies local development startup also repairs an existing database that is missing the generic encrypted table.
    /// </summary>
    [Test]
    public async Task DatabaseInitializerAddsGenericRecordTableToExistingDevelopmentDatabase()
    {
        await using var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();
        await using (var command = connection.CreateCommand())
        {
            // This marker table makes the database non-empty, matching the local failure mode where EnsureCreated
            // refuses to create the EF model but HIP still needs its missing development tables added safely.
            command.CommandText =
                """
                CREATE TABLE existing_local_marker (
                    Id TEXT NOT NULL CONSTRAINT PK_existing_local_marker PRIMARY KEY
                );
                """;
            await command.ExecuteNonQueryAsync();
        }

        var services = new ServiceCollection();
        services.AddDbContext<HipDbContext>(options => options.UseSqlite(connection));
        using var provider = services.BuildServiceProvider();

        await HipDatabaseInitializer.EnsureCreatedAsync(provider, isLocalDevelopment: true);

        Assert.Multiple(() =>
        {
            Assert.That(SqliteTableExists(connection, "hip_records"), Is.True);
            Assert.That(SqliteTableExists(connection, "hip_browser_scan_results"), Is.True);
            Assert.That(SqliteTableExists(connection, "hip_dashboard_scan_aggregates"), Is.True);
        });
    }

    /// <summary>
    /// Verifies the development encryption key cannot be used when production safety is requested.
    /// </summary>
    [Test]
    public void RecordEncryptorRejectsDevelopmentKeyOutsideDevelopment()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new DevelopmentHipRecordEncryptor(new HipRecordEncryptionOptions(AllowDevelopmentKey: false)));

        Assert.That(exception?.Message, Does.Contain("Record encryption key"));
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

    /// <summary>
    /// Verifies review workflow services persist through repositories instead of process-local service state.
    /// </summary>
    [Test]
    public async Task ReviewWorkflowServicesPersistAcrossServiceInstances()
    {
        await using var database = await CreateDatabaseAsync();
        var store = new HipRecordStore(database.Context);
        var auditRepository = new EfAuditLogRepository(store);
        var reviewRepository = new EfReviewQueueRepository(store);
        var appealRepository = new EfAppealRepository(store);
        var overrideRepository = new EfReputationOverrideRequestRepository(store);
        var auditService = new AuditLogService(auditRepository);
        var reviewWriter = new ReviewQueueService(new ReviewItemValidator(), reviewRepository, auditService);
        var reviewReader = new ReviewQueueService(new ReviewItemValidator(), reviewRepository, auditService);
        var appealWriter = new AppealService(new AppealRequestValidator(), appealRepository, auditService);
        var appealReader = new AppealService(new AppealRequestValidator(), appealRepository, auditService);
        var overrideWriter = new ReputationOverrideService(new ReputationOverrideRequestValidator(), overrideRepository, auditService);
        var overrideReader = new ReputationOverrideService(new ReputationOverrideRequestValidator(), overrideRepository, auditService);

        var createdReview = reviewWriter.Create(CreateReviewItem(string.Empty));
        var assignedReview = reviewReader.Assign(createdReview.ReviewItemId, "admin-1", "admin-actor");
        var submittedAppeal = appealWriter.Submit(new AppealRequest(
            string.Empty,
            TargetType.Domain,
            "appeal.example",
            "submitter-hash",
            "The warning appears to be a false positive.",
            AppealStatus.Submitted,
            default,
            default,
            ReviewerId: null,
            Decision: null,
            DecisionReason: null,
            new Dictionary<string, string> { ["urlHash"] = "hash-only" }));
        var approvedAppeal = appealReader.Approve(submittedAppeal.AppealId, "admin-2", "Evidence is clean.");
        var overrideRequest = overrideWriter.Request(new ReputationOverrideRequest(
            string.Empty,
            TargetType.Domain,
            "override.example",
            CurrentScore: 45,
            RequestedScore: 70,
            "Manual review confirmed clean behavior.",
            "admin-3",
            OverrideRequestStatus.Pending,
            RequiredApprovalCount: 0,
            [],
            default,
            default));
        var approvedOverride = overrideReader.Approve(overrideRequest.OverrideRequestId, "admin-4", "Second review agrees.");

        var auditEntries = await auditRepository.ListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(assignedReview.AssignedTo, Is.EqualTo("admin-1"));
            Assert.That(reviewReader.Get(createdReview.ReviewItemId)?.Status, Is.EqualTo(ReviewStatus.InReview));
            Assert.That(appealReader.Get(submittedAppeal.AppealId)?.Status, Is.EqualTo(AppealStatus.Approved));
            Assert.That(approvedAppeal.Decision, Is.EqualTo("Approved"));
            Assert.That(overrideReader.List().Single().Status, Is.EqualTo(OverrideRequestStatus.Approved));
            Assert.That(approvedOverride.Approvals, Has.Count.EqualTo(1));
            Assert.That(auditEntries.Select(entry => entry.Action), Does.Contain("Review item assigned"));
            Assert.That(auditEntries.Select(entry => entry.Action), Does.Contain("Appeal approved"));
            Assert.That(auditEntries.Select(entry => entry.Action), Does.Contain("Reputation override approved"));
        });
    }

    /// <summary>
    /// Verifies scan runtime state uses durable adapters for cache, queue, dedupe, and dashboard aggregates.
    /// </summary>
    [Test]
    public async Task ScanRuntimeStateStoresPersistThroughEfAdapters()
    {
        await using var database = await CreateDatabaseAsync();
        var store = new HipRecordStore(database.Context);
        var cache = new EfScanResultCache(store);
        var queue = new EfScanIngestionQueue(store);
        var dedupe = new EfScanResultDedupeService(store);
        var aggregateStore = new EfDashboardScanAggregateStore(database.Context, store);
        var scan = CreateStoredScan("runtime.example", "Dangerous");
        var request = new ScanIngestionRequest(
            "scan-request-1",
            "runtime.example",
            scan.PageUrlHash,
            scan.PrivacySafeMetadata["signalHash"],
            "BrowserPlugin",
            "0.1.0-dev",
            DateTimeOffset.UtcNow,
            ScanProcessingPath.SlowPath);
        var dedupeKey = new ScanDedupeKey(request.Domain, request.UrlHash, request.SignalHash);

        await cache.StoreAsync(scan, TimeSpan.FromMinutes(15), CancellationToken.None);
        await queue.EnqueueAsync(request, CancellationToken.None);
        var firstDedupe = await dedupe.TryAcceptAsync(dedupeKey, TimeSpan.FromMinutes(5), CancellationToken.None);
        var secondDedupe = await dedupe.TryAcceptAsync(dedupeKey, TimeSpan.FromMinutes(5), CancellationToken.None);
        await aggregateStore.UpdateAsync(scan, CancellationToken.None);

        var freshCache = await new EfScanResultCache(store).GetFreshAsync("runtime.example", CancellationToken.None);
        var batch = await new EfScanIngestionQueue(store).DequeueBatchAsync(10, CancellationToken.None);
        var emptyBatch = await queue.DequeueBatchAsync(10, CancellationToken.None);
        var aggregate = await new EfDashboardScanAggregateStore(database.Context, store).GetAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(freshCache?.Result.Domain, Is.EqualTo("runtime.example"));
            Assert.That(batch.Single(), Is.EqualTo(request));
            Assert.That(emptyBatch, Is.Empty);
            Assert.That(firstDedupe, Is.True);
            Assert.That(secondDedupe, Is.False);
            Assert.That(aggregate.TotalScans, Is.EqualTo(1));
            Assert.That(aggregate.Dangerous, Is.EqualTo(1));
        });
    }

    /// <summary>
    /// Verifies new browser scan saves use the typed hot-path scan table instead of forcing dashboards through
    /// encrypted generic record scans.
    /// </summary>
    [Test]
    public async Task BrowserScanResultPersistsToTypedHotPathTable()
    {
        await using var database = await CreateDatabaseAsync();
        var repository = new EfBrowserScanResultRepository(database.Context, new HipRecordStore(database.Context));
        var scan = CreateStoredScan("typed.example", "MostlyTrusted") with
        {
            PrivacySafeMetadata = new Dictionary<string, string>
            {
                ["signalHash"] = "sha256:" + new string('2', 64),
                ["pluginVersion"] = "0.1.9-dev"
            }
        };

        await repository.SaveAsync(scan, CancellationToken.None);

        var entity = await database.Context.BrowserScanResults.SingleAsync();
        var latest = await repository.GetLatestByDomainAsync("typed.example", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(entity.Domain, Is.EqualTo("typed.example"));
            Assert.That(entity.PluginVersion, Is.EqualTo("0.1.9-dev"));
            Assert.That(entity.ReasonsJson, Does.Contain("Privacy-safe stored scan summary."));
            Assert.That(database.Context.Records.Count(), Is.EqualTo(0));
            Assert.That(latest?.Domain, Is.EqualTo("typed.example"));
            Assert.That(latest?.Status, Is.EqualTo("MostlyTrusted"));
        });
    }

    /// <summary>
    /// Verifies typed scan storage keeps raw private page details out of the hot table.
    /// </summary>
    [Test]
    public async Task BrowserScanResultTypedTableStoresOnlyPrivacySafeFields()
    {
        await using var database = await CreateDatabaseAsync();
        var repository = new EfBrowserScanResultRepository(database.Context, new HipRecordStore(database.Context));
        var scan = CreateStoredScan("privacy-hot-path.example", "Unknown") with
        {
            PageUrlHash = "sha256:" + new string('3', 64),
            StoredPageUrl = null,
            PrivacySafeMetadata = new Dictionary<string, string>
            {
                ["signalHash"] = "sha256:" + new string('4', 64),
                ["hasLoginForm"] = "true"
            }
        };

        await repository.SaveAsync(scan, CancellationToken.None);

        var entity = await database.Context.BrowserScanResults.SingleAsync();
        var storedMaterial = string.Join(
            "|",
            entity.Domain,
            entity.PageUrlHash,
            entity.StoredPageUrl,
            entity.PrivacySafeMetadataJson,
            entity.ReasonsJson);

        Assert.Multiple(() =>
        {
            Assert.That(entity.StoredPageUrl, Is.Null);
            Assert.That(storedMaterial, Does.Not.Contain("password"));
            Assert.That(storedMaterial, Does.Not.Contain("formValue"));
            Assert.That(storedMaterial, Does.Not.Contain("page body"));
            Assert.That(storedMaterial, Does.Not.Contain("https://privacy-hot-path.example/private"));
        });
    }

    /// <summary>
    /// Verifies recent scan reads are served from typed rows in newest-first order.
    /// </summary>
    [Test]
    public async Task BrowserScanResultRecentReadsUseTypedRowsNewestFirst()
    {
        await using var database = await CreateDatabaseAsync();
        var repository = new EfBrowserScanResultRepository(database.Context, new HipRecordStore(database.Context));
        var older = CreateStoredScan("older.example", "Trusted") with { LastCheckedUtc = DateTimeOffset.UtcNow.AddMinutes(-10) };
        var newer = CreateStoredScan("newer.example", "Dangerous") with { LastCheckedUtc = DateTimeOffset.UtcNow };

        await repository.SaveAsync(older, CancellationToken.None);
        await repository.SaveAsync(newer, CancellationToken.None);

        var recent = await repository.ListRecentAsync(1, CancellationToken.None);

        Assert.That(recent.Single().Domain, Is.EqualTo("newer.example"));
    }

    /// <summary>
    /// Verifies public lookup does not fail when a local database has typed scan tables but is missing legacy fallback storage.
    /// </summary>
    [Test]
    public async Task BrowserScanResultLookupTreatsMissingLegacyRecordTableAsNoLegacyData()
    {
        await using var database = await CreateDatabaseAsync();
        await database.Context.Database.ExecuteSqlRawAsync("DROP TABLE hip_records;");
        var repository = new EfBrowserScanResultRepository(database.Context, new HipRecordStore(database.Context));

        var latest = await repository.GetLatestByDomainAsync("missing-legacy.example", CancellationToken.None);

        Assert.That(latest, Is.Null);
    }

    /// <summary>
    /// Verifies dashboard scan counters persist into the typed aggregate projection table.
    /// </summary>
    [Test]
    public async Task DashboardScanAggregatePersistsToTypedProjectionTable()
    {
        await using var database = await CreateDatabaseAsync();
        var aggregateStore = new EfDashboardScanAggregateStore(database.Context, new HipRecordStore(database.Context));

        await aggregateStore.UpdateAsync(CreateStoredScan("aggregate-hot-path.example", "Dangerous"), CancellationToken.None);

        var typedAggregate = await database.Context.DashboardScanAggregates.SingleAsync();
        var aggregate = await aggregateStore.GetAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(typedAggregate.Id, Is.EqualTo("current"));
            Assert.That(typedAggregate.TotalScans, Is.EqualTo(1));
            Assert.That(typedAggregate.Dangerous, Is.EqualTo(1));
            Assert.That(database.Context.Records.Count(record => record.Partition == "dashboard-scan-aggregate"), Is.EqualTo(0));
            Assert.That(aggregate.TotalScans, Is.EqualTo(1));
        });
    }

    /// <summary>
    /// Verifies concurrent scan requests can update the single dashboard aggregate without duplicate-key failures.
    /// </summary>
    [Test]
    public async Task DashboardScanAggregateHandlesConcurrentUpdates()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"hip-concurrent-{Guid.NewGuid():N}.db");
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseSqlite($"Data Source={databasePath};Pooling=False")
            .Options;

        try
        {
            await using (var setupContext = new HipDbContext(options))
            {
                await setupContext.Database.EnsureCreatedAsync();
            }

            var scans = Enumerable.Range(0, 12)
                .Select(index => CreateStoredScan($"concurrent-{index}.example", index % 2 == 0 ? "Dangerous" : "Trusted"))
                .ToArray();

            await Task.WhenAll(scans.Select(async scan =>
            {
                await using var context = new HipDbContext(options);
                var aggregateStore = new EfDashboardScanAggregateStore(context, new HipRecordStore(context));
                await aggregateStore.UpdateAsync(scan, CancellationToken.None);
            }));

            await using var verifyContext = new HipDbContext(options);
            var aggregate = await new EfDashboardScanAggregateStore(verifyContext, new HipRecordStore(verifyContext)).GetAsync(CancellationToken.None);

            Assert.Multiple(() =>
            {
                Assert.That(aggregate.TotalScans, Is.EqualTo(12));
                Assert.That(aggregate.Trusted, Is.EqualTo(6));
                Assert.That(aggregate.Dangerous, Is.EqualTo(6));
            });
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(databasePath))
            {
                try
                {
                    File.Delete(databasePath);
                }
                catch (IOException)
                {
                    // Windows can briefly hold SQLite file handles after concurrent contexts dispose; cleanup must not hide test behavior.
                }
            }
        }
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

    private static BrowserScanResultRecord CreateStoredScan(string domain, string status) =>
        new(
            $"browser-scan:{domain}:test",
            domain,
            "sha256:" + new string('f', 64),
            null,
            "BrowserPlugin",
            status == "Dangerous" ? 8 : 88,
            status,
            status,
            ["Privacy-safe stored scan summary."],
            5,
            status == "Dangerous" ? 1 : 0,
            status == "Dangerous" ? 1 : 0,
            status == "Dangerous" ? 1 : 0,
            DateTimeOffset.UtcNow,
            status == "Dangerous" ? "Block" : "Allow",
            new Dictionary<string, string>
            {
                ["signalHash"] = "sha256:" + new string('1', 64)
            });

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

    /// <summary>
    /// Checks whether a table exists in a SQLite test database without touching application data.
    /// </summary>
    /// <param name="connection">Open SQLite connection.</param>
    /// <param name="tableName">Table name to look up.</param>
    /// <returns>True when SQLite reports the table exists.</returns>
    private static bool SqliteTableExists(SqliteConnection connection, string tableName)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = $tableName;";
        command.Parameters.AddWithValue("$tableName", tableName);
        return Convert.ToInt32(command.ExecuteScalar()) == 1;
    }

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() }
    };

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
