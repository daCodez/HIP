namespace HIP.Tests.Consumer;

public sealed class ConsumerAppealsPageTests
{
    [Test]
    public void Page_exposes_owner_bound_privacy_safe_submission_and_status()
    {
        var root = FindRepositoryRoot();
        var page = File.ReadAllText(Path.Combine(
            root,
            "src",
            "HIP.Web",
            "Components",
            "Pages",
            "ConsumerAppeals.razor"));
        var styles = File.ReadAllText(Path.Combine(
            root,
            "src",
            "HIP.Web",
            "Components",
            "Pages",
            "ConsumerAppeals.razor.css"));

        Assert.Multiple(() =>
        {
            Assert.That(page, Does.Contain("Submit an appeal"));
            Assert.That(page, Does.Contain("Do not include passwords, private messages, form values, tokens, or personal evidence."));
            Assert.That(page, Does.Contain("HipConsumerPageAccess.ExecuteAuthorizedAsync"));
            Assert.That(page, Does.Contain("ConsumerPortalService.SubmitAppealAsync"));
            Assert.That(page, Does.Contain("maxlength=\"512\""));
            Assert.That(page, Does.Contain("maxlength=\"1000\""));
            Assert.That(page, Does.Contain("Only appeals bound to this consumer account are shown."));
            Assert.That(page, Does.Not.Contain("ReviewerId"));
            Assert.That(styles, Does.Contain("@media (max-width: 44rem)"));
            Assert.That(styles, Does.Contain("@media (prefers-reduced-motion: reduce)"));
        });
    }

    private static string FindRepositoryRoot(
        [System.Runtime.CompilerServices.CallerFilePath] string sourceFilePath = "")
    {
        var current = new DirectoryInfo(Path.GetDirectoryName(sourceFilePath)!);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "HIP.slnx")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate the HIP repository root.");
    }
}
