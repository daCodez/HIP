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
            "IInboxEventRepository, InMemoryInboxEventRepository"
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
