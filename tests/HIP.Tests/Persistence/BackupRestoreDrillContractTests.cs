namespace HIP.Tests.Persistence;

public sealed class BackupRestoreDrillContractTests
{
    [Test]
    public void Drill_is_non_overwriting_checksum_verified_and_excludes_secret_key_material()
    {
        var root = FindRepositoryRoot();
        var script = File.ReadAllText(Path.Combine(root, "eng", "Invoke-HipBackupRestoreDrill.ps1"));
        var runbook = File.ReadAllText(Path.Combine(root, "docs", "backup-restore-drill.md"));

        Assert.Multiple(() =>
        {
            Assert.That(script, Does.Contain("_restore_drill_"));
            Assert.That(script, Does.Contain("The restore database must never equal the source database"));
            Assert.That(script, Does.Contain("Get-FileHash"));
            Assert.That(script, Does.Contain("containsSecretKeyMaterial = $false"));
            Assert.That(script, Does.Contain("--exit-on-error"));
            Assert.That(script, Does.Not.Contain("dropdb"));
            Assert.That(runbook, Does.Contain("never deletes it"));
            Assert.That(runbook, Does.Contain("do not constitute a completed production restore drill"));
        });
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "HIP.slnx"))) return current.FullName;
            current = current.Parent;
        }
        throw new DirectoryNotFoundException("Could not locate HIP.slnx from the test output directory.");
    }
}
