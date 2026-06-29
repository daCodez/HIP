namespace HIP.Tests.Infrastructure;

/// <summary>
/// Verifies normal HIP runtime registration cannot silently fall back to volatile in-memory data stores.
/// </summary>
public sealed class RuntimeDataSourceTests
{
    /// <summary>
    /// Ensures live-data repositories are supplied by HIP.Infrastructure, not by application-layer in-memory defaults.
    /// </summary>
    [Test]
    public void Application_runtime_registration_does_not_register_in_memory_live_data_repositories()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.Application", "DependencyInjection.cs"));

        var forbiddenRegistrations = new[]
        {
            "IReputationEventRepository, InMemoryReputationEventRepository",
            "IReputationProfileRepository, InMemoryReputationProfileRepository",
            "IWeightedFeedbackRepository, InMemoryWeightedFeedbackRepository",
            "IRiskFindingReportRepository, InMemoryRiskFindingReportRepository",
            "IHipIdentityRepository, InMemoryHipIdentityRepository",
            "IBrowserScanResultRepository, InMemoryBrowserScanResultRepository",
            "IAdminSiteSafetyRuleRepository, InMemoryAdminSiteSafetyRuleRepository",
            "IAdminReviewQueueRepository, InMemoryAdminReviewQueueRepository",
            "IRuleRepository, InMemoryRuleRepository",
            "IRuleSimulationResultRepository, InMemoryRuleSimulationResultRepository",
            "IGeneratedRuleCandidateRepository, InMemoryGeneratedRuleCandidateRepository",
            "IOutboxEventRepository, InMemoryOutboxEventRepository",
            "IInboxEventRepository, InMemoryInboxEventRepository",
            "IScanResultCache, InMemoryScanResultCache",
            "IScanIngestionQueue, InMemoryScanIngestionQueue",
            "IScanResultDedupeService, InMemoryScanResultDedupeService",
            "IDashboardScanAggregateStore, InMemoryDashboardScanAggregateStore",
            "IDuplicateSubmissionGuard, InMemoryDuplicateSubmissionGuard",
            "ISetupCodeLicenseService, InMemorySetupCodeLicenseService",
            "IExternalSiteEvidenceCache, InMemoryExternalSiteEvidenceCache",
            "IExternalSiteEvidenceSettingsStore, InMemoryExternalSiteEvidenceSettingsStore",
            "IExternalProviderResiliencePolicy, InMemoryExternalProviderResiliencePolicy",
            "ISandboxLinkScanQueue, InMemorySandboxLinkScanQueue"
        };

        Assert.Multiple(() =>
        {
            foreach (var registration in forbiddenRegistrations)
            {
                Assert.That(source, Does.Not.Contain(registration), $"{registration} must stay test-only or be supplied by infrastructure.");
            }
        });
    }

    /// <summary>
    /// Ensures runtime review workflows are not backed by process-local dictionaries or singleton service lifetimes.
    /// </summary>
    [Test]
    public void Review_workflow_runtime_services_are_repository_backed()
    {
        var root = RepositoryRoot();
        var dependencyInjection = File.ReadAllText(Path.Combine(root, "src", "HIP.Application", "DependencyInjection.cs"));
        var reviewServiceSources = new[]
        {
            Path.Combine(root, "src", "HIP.Application", "Review", "AuditLogService.cs"),
            Path.Combine(root, "src", "HIP.Application", "Review", "ReviewQueueService.cs"),
            Path.Combine(root, "src", "HIP.Application", "Review", "AppealService.cs"),
            Path.Combine(root, "src", "HIP.Application", "Review", "ReputationOverrideService.cs")
        };

        Assert.Multiple(() =>
        {
            Assert.That(dependencyInjection, Does.Not.Contain("AddSingleton<IAuditLogService, AuditLogService>"));
            Assert.That(dependencyInjection, Does.Not.Contain("AddSingleton<IReviewQueueService, ReviewQueueService>"));
            Assert.That(dependencyInjection, Does.Not.Contain("AddSingleton<IAppealService, AppealService>"));
            Assert.That(dependencyInjection, Does.Not.Contain("AddSingleton<IReputationOverrideService, ReputationOverrideService>"));

            foreach (var sourcePath in reviewServiceSources)
            {
                var source = File.ReadAllText(sourcePath);
                Assert.That(source, Does.Not.Contain("private readonly Dictionary<string,"), $"{Path.GetFileName(sourcePath)} must not own process-local workflow state.");
                Assert.That(source, Does.Not.Contain("private readonly ConcurrentDictionary<string,"), $"{Path.GetFileName(sourcePath)} must not own process-local workflow state.");
            }
        });
    }

    /// <summary>
    /// Ensures browser scan services do not hide in-memory cache/aggregate defaults in normal application code.
    /// </summary>
    [Test]
    public void Browser_scan_service_requires_explicit_scalability_adapters()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.Application", "Browser", "BrowserScanResultService.cs"));

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Not.Contain("new InMemoryScanResultCache()"));
            Assert.That(source, Does.Not.Contain("new InMemoryDashboardScanAggregateStore()"));
        });
    }

    /// <summary>
    /// Ensures the README no longer tells developers HIP is foundation-only or misnames the product.
    /// </summary>
    [Test]
    public void Readme_describes_current_live_data_runtime_without_foundation_only_language()
    {
        var readme = File.ReadAllText(Path.Combine(RepositoryRoot(), "README.md"));

        Assert.Multiple(() =>
        {
            Assert.That(readme, Does.Contain("HIP stands for Human Identity Protocol."));
            Assert.That(readme, Does.Not.Contain("Human Interactive Protocol"));
            Assert.That(readme, Does.Not.Contain("foundation only"));
            Assert.That(readme, Does.Contain("PostgreSQL"));
            Assert.That(readme, Does.Contain("live"));
        });
    }

    /// <summary>
    /// Resolves the repository root from the test output folder.
    /// </summary>
    /// <returns>Absolute repository root path.</returns>
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
}
