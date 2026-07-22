extern alias SandboxWorkerAlias;

using System.Text;
using HIP.Application.SiteSafety;
using SandboxWorkerAlias::HIP.SandboxWorker;

namespace HIP.Tests.SiteSafety;

public sealed class SandboxContainerIsolationTests
{
    private const string PinnedImage = "registry.example/hip/sandbox@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    [Test]
    public void Launch_plan_enforces_container_resource_network_and_filesystem_restrictions()
    {
        var plan = SandboxContainerLaunchPlanBuilder.Build(LeasedJob(), new SandboxContainerIsolationOptions(PinnedImage));
        var arguments = string.Join(' ', plan.Arguments);

        Assert.Multiple(() =>
        {
            Assert.That(plan.FileName, Is.EqualTo("docker"));
            Assert.That(arguments, Does.Contain("--network none"));
            Assert.That(arguments, Does.Contain("--read-only"));
            Assert.That(arguments, Does.Contain("noexec,nosuid,nodev"));
            Assert.That(arguments, Does.Contain("--cap-drop ALL"));
            Assert.That(arguments, Does.Contain("no-new-privileges=true"));
            Assert.That(arguments, Does.Contain("--pids-limit 32"));
            Assert.That(arguments, Does.Contain("--cpus 0.5"));
            Assert.That(arguments, Does.Contain("--memory 256m --memory-swap 256m"));
            Assert.That(arguments, Does.Contain("--user 65532:65532"));
            Assert.That(arguments, Does.Contain("--log-driver none"));
        });
    }

    [Test]
    public void Launch_plan_excludes_raw_target_hash_lease_and_source_identifiers()
    {
        var job = LeasedJob() with { RawTargetUrl = "https://private.example/path?token=secret" };
        var plan = SandboxContainerLaunchPlanBuilder.Build(job, new SandboxContainerIsolationOptions(PinnedImage));
        var arguments = string.Join(' ', plan.Arguments);

        Assert.Multiple(() =>
        {
            Assert.That(arguments, Does.Not.Contain("private.example"));
            Assert.That(arguments, Does.Not.Contain(job.TargetUrlHash));
            Assert.That(arguments, Does.Not.Contain(job.LeaseToken));
            Assert.That(arguments, Does.Not.Contain(job.SourceScanId));
        });
    }

    [TestCase("hip/sandbox:latest")]
    [TestCase("")]
    [TestCase("hip/sandbox@sha256:abc")]
    public void Unpinned_or_invalid_image_fails_closed(string image)
    {
        Assert.Throws<InvalidOperationException>(() =>
            SandboxContainerLaunchPlanBuilder.Build(LeasedJob(), new SandboxContainerIsolationOptions(image)));
    }

    [Test]
    public void Output_buffer_enforces_exact_byte_limit()
    {
        var buffer = new SandboxOutputBuffer(1024);
        buffer.Append(Encoding.UTF8.GetBytes(new string('a', 1500)));

        Assert.Multiple(() =>
        {
            Assert.That(buffer.ToArray(), Has.Length.EqualTo(1024));
            Assert.That(buffer.Truncated, Is.True);
        });
    }

    private static SandboxLinkScanRequest LeasedJob() => new(
        "sandbox-link-test",
        "risky.example",
        "sha256:private-hash",
        null,
        SandboxLinkScanReason.RiskyPageStatus,
        "scan-private",
        SiteSafetyScanStatus.HighRisk,
        DateTimeOffset.UtcNow)
    {
        Status = SandboxLinkScanJobStatus.Processing,
        AttemptCount = 1,
        LeaseToken = "sandbox-lease:private",
        LeaseOwner = "worker",
        LeaseExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(1),
        Version = 2
    };
}
