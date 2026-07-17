using System.Text.RegularExpressions;

namespace HIP.Tests.Infrastructure;

public sealed partial class CiSecurityBaselineTests
{
    [Test]
    public void Ci_workflow_enforces_build_test_browser_and_security_gates()
    {
        var root = RepositoryRoot();
        var workflowPath = Path.Combine(root, ".github", "workflows", "ci.yml");
        Assert.That(File.Exists(workflowPath), Is.True, "The HIP CI workflow must exist.");

        var workflow = File.ReadAllText(workflowPath).ReplaceLineEndings("\n");
        var usesLines = workflow
            .Split('\n')
            .Select(line => line.Trim())
            .Where(line => line.StartsWith("- uses:", StringComparison.Ordinal))
            .ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(workflow, Does.Contain("pull_request:"));
            Assert.That(workflow, Does.Contain("push:"));
            Assert.That(workflow, Does.Not.Contain("pull_request_target:"));
            Assert.That(workflow, Does.Contain("permissions:\n  contents: read"));
            Assert.That(workflow, Does.Not.Contain("write-all"));
            Assert.That(workflow, Does.Contain("fetch-depth: 0"));
            Assert.That(workflow, Does.Contain("gitleaks/gitleaks-action@"));
            Assert.That(workflow, Does.Contain("GITLEAKS_ENABLE_COMMENTS: false"));
            Assert.That(workflow, Does.Contain("dotnet restore HIP.slnx"));
            Assert.That(workflow, Does.Contain("--vulnerable --include-transitive --format json"));
            Assert.That(workflow, Does.Contain("dotnet build HIP.slnx"));
            Assert.That(workflow, Does.Contain("dotnet test HIP.slnx"));
            Assert.That(workflow, Does.Contain("node --check"));
            Assert.That(workflow, Does.Contain("run: npm test"));
            Assert.That(usesLines, Is.Not.Empty);
            Assert.That(usesLines, Is.All.Match(ActionPinPattern()));
        });
    }

    [GeneratedRegex(@"^- uses: [A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}(?:\s+#.*)?$")]
    private static partial Regex ActionPinPattern();

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
