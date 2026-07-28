using System.Runtime.CompilerServices;

namespace HIP.Tests.Api;

/// <summary>
/// Guards admin operational surfaces against claims that are not backed by live evidence.
/// </summary>
public sealed class AdminDataTruthTests
{
    private static readonly string SourceDirectory = Path.GetDirectoryName(SourceFilePath())!;

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
            Assert.That(source, Does.Contain("ClientTrustedPercent"));
            Assert.That(source, Does.Contain("ClientCautionPercent"));
            Assert.That(source, Does.Contain("ClientRiskPercent"));
            Assert.That(source, Does.Contain("Client-observed distribution"));
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
            "AdminMessageShield.razor",
            "AdminPlatformConnections.razor",
            "AdminReportsPage.razor",
            "AdminReputationSignals.razor"
        };

        foreach (var page in pages)
        {
            var source = ReadWorkspaceFile("src", "HIP.Web", "Components", "Pages", page);
            Assert.That(source, Does.Contain("card.IsPlaceholder"), page);
        }
    }

    [Test]
    public void Reports_page_refreshes_live_data_without_overlapping_scoped_reads()
    {
        var source = ReadWorkspaceFile("src", "HIP.Web", "Components", "Pages", "AdminReportsPage.razor");

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Contain("@implements IAsyncDisposable"));
            Assert.That(source, Does.Contain("PeriodicTimer(RefreshInterval)"));
            Assert.That(source, Does.Contain("await RefreshSummaryAsync();"));
            Assert.That(source, Does.Contain("await _refreshLoop;"));
            Assert.That(source, Does.Contain("StateHasChanged();"));
            Assert.That(source, Does.Contain("The last complete snapshot remains visible."));
            Assert.That(source, Does.Not.Contain("Task.WhenAll"));
        });
    }

    [Test]
    public void Feedback_loop_uses_stored_privacy_safe_feedback_records()
    {
        var source = ReadWorkspaceFile("src", "HIP.Web", "Components", "Pages", "AdminFeedbackLoop.razor");

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Contain("IAdminFeedbackService"));
            Assert.That(source, Does.Contain("GetOverviewAsync"));
            Assert.That(source, Does.Contain("GetDomainAsync"));
            Assert.That(source, Does.Contain("Reporter identifiers, page hashes, raw URLs, page text, and form data are not shown"));
            Assert.That(source, Does.Not.Contain("IAdminDashboardService"));
            Assert.That(source, Does.Not.Contain("card.IsPlaceholder"));
        });
    }

    [Test]
    public void Sender_profiles_uses_the_stored_sender_profile_service()
    {
        var source = ReadWorkspaceFile("src", "HIP.Web", "Components", "Pages", "AdminSenderProfiles.razor");

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Contain("IAdminSenderProfileService"));
            Assert.That(source, Does.Contain("No sender profiles yet"));
            Assert.That(source, Does.Contain("Reputation Timeline"));
            Assert.That(source, Does.Not.Contain("Sender profiles not connected"));
            Assert.That(source, Does.Not.Contain("No sender repository yet"));
        });
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
        foreach (var startPath in new[]
        {
            SourceDirectory,
            Directory.GetCurrentDirectory(),
            TestContext.CurrentContext.WorkDirectory,
            TestContext.CurrentContext.TestDirectory
        }.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var directory = new DirectoryInfo(startPath);
            while (directory is not null)
            {
                var candidate = Path.Combine([directory.FullName, .. segments]);
                if (File.Exists(candidate) || Directory.Exists(candidate))
                {
                    return candidate;
                }

                directory = directory.Parent;
            }
        }

        throw new FileNotFoundException($"Could not locate {string.Join('/', segments)}.");
    }

    private static string SourceFilePath([CallerFilePath] string sourceFilePath = "") => sourceFilePath;
}
