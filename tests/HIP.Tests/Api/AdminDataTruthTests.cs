namespace HIP.Tests.Api;

/// <summary>
/// Guards admin operational surfaces against claims that are not backed by live evidence.
/// </summary>
public sealed class AdminDataTruthTests
{
    [Test]
    public void Admin_navigation_does_not_publish_hard_coded_queue_counts()
    {
        var source = ReadWorkspaceFile("src", "HIP.Web", "Components", "Layout", "ControlCenterNav.razor");

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Not.Contain("class=\"count\">5"));
            Assert.That(source, Does.Not.Contain("class=\"count\">12"));
            Assert.That(source, Does.Not.Contain("class=\"count\""));
        });
    }

    [Test]
    public void Message_shield_marks_unconnected_message_ingestion_as_unavailable()
    {
        var source = ReadWorkspaceFile("src", "HIP.Web", "Components", "Pages", "AdminMessageShield.razor");

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Not.Contain("<strong>0</strong><span>Messages Scanned"));
            Assert.That(source, Does.Contain("Message ingestion unavailable"));
            Assert.That(source, Does.Contain("card.IsPlaceholder"));
        });
    }

    [Test]
    public void Platform_page_calls_browser_state_evidence_not_connectivity()
    {
        var source = ReadWorkspaceFile("src", "HIP.Web", "Components", "Pages", "AdminPlatformConnections.razor");

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Not.Contain("Connected Client Type"));
            Assert.That(source, Does.Contain("Client Types With Evidence"));
            Assert.That(source, Does.Contain("Evidence received"));
            Assert.That(source, Does.Contain("Waiting for data"));
        });
    }

    [Test]
    public void Dashboard_displays_snapshot_source_and_dependency_availability()
    {
        var source = ReadWorkspaceFile("src", "HIP.Web", "Components", "Pages", "AdminDashboard.razor");

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Contain("GeneratedAtUtc"));
            Assert.That(source, Does.Contain("DataSource"));
            Assert.That(source, Does.Contain("UnavailableSourceCount"));
            Assert.That(source, Does.Contain("source(s) unavailable"));
        });
    }

    [Test]
    public void Dashboard_displays_client_observed_score_without_claiming_authoritative_protection()
    {
        var source = ReadWorkspaceFile("src", "HIP.Web", "Components", "Pages", "AdminDashboard.razor");

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Contain("ClientObservedScore"));
            Assert.That(source, Does.Contain("Client-observed score"));
            Assert.That(source, Does.Contain("not authoritative"));
            Assert.That(source, Does.Contain("not included in authoritative Trusted, Caution, or Risk percentages"));
        });
    }

    [Test]
    public void Score_overview_selects_live_cards_by_contract_key_and_explains_client_telemetry()
    {
        var source = ReadWorkspaceFile("src", "HIP.Web", "Components", "Pages", "AdminReputationOverview.razor");

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Contain("trustedResults"));
            Assert.That(source, Does.Contain("clientTelemetryObservations"));
            Assert.That(source, Does.Contain("privacy-safe client observations stored"));
            Assert.That(source, Does.Not.Contain("preferredLabels"));
            Assert.That(source, Does.Contain("card.IsPlaceholder ? \"—\" : card.Value"));
        });
    }

    [Test]
    public void Dashboard_consumer_pages_do_not_render_unavailable_cards_as_zero()
    {
        var pages = new[]
        {
            "AdminFeedbackLoop.razor",
            "AdminMessageShield.razor",
            "AdminPlatformConnections.razor",
            "AdminReportsPage.razor",
            "AdminReputationSignals.razor",
            "AdminSenderProfiles.razor"
        };

        foreach (var page in pages)
        {
            var source = ReadWorkspaceFile("src", "HIP.Web", "Components", "Pages", page);
            Assert.That(source, Does.Contain("card.IsPlaceholder"), page);
        }
    }

    [Test]
    public void Every_admin_page_is_present_in_the_data_truth_inventory()
    {
        var inventory = ReadWorkspaceFile("docs", "admin-data-truth.md");
        var pagesDirectory = WorkspacePath("src", "HIP.Web", "Components", "Pages");
        var adminPages = Directory.GetFiles(pagesDirectory, "Admin*.razor")
            .Select(Path.GetFileName)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.That(adminPages, Is.Not.Empty);
        foreach (var page in adminPages)
        {
            Assert.That(inventory, Does.Contain($"`{page}`"), page);
        }
    }

    private static string ReadWorkspaceFile(params string[] segments)
        => File.ReadAllText(WorkspacePath(segments));

    private static string WorkspacePath(params string[] segments)
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine([directory.FullName, .. segments]);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException($"Could not locate {string.Join('/', segments)}.");
    }
}
