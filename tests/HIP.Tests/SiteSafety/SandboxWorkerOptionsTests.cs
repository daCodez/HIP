extern alias SandboxWorkerAlias;

using SandboxWorkerAlias::HIP.SandboxWorker;

namespace HIP.Tests.SiteSafety;

/// <summary>
/// Verifies the sandbox worker rejects unsafe local-dev settings before it starts.
/// </summary>
public sealed class SandboxWorkerOptionsTests
{
    /// <summary>
    /// Confirms the default worker settings are intentionally conservative and valid.
    /// </summary>
    [Test]
    public void Default_options_are_valid()
    {
        var options = new SandboxWorkerOptions();

        Assert.That(SandboxWorkerOptions.Validate(options), Is.EqualTo(true));
        Assert.That(options.ExecuteBrowserSandbox, Is.EqualTo(false));
    }

    /// <summary>
    /// Confirms .NET options binding can dynamically create the options object at startup.
    /// </summary>
    [Test]
    public void Options_can_be_created_by_configuration_binder()
    {
        var options = Activator.CreateInstance<SandboxWorkerOptions>();

        Assert.That(options, Is.Not.Null);
        Assert.That(SandboxWorkerOptions.Validate(options), Is.EqualTo(true));
    }

    /// <summary>
    /// Confirms a huge batch is rejected so one worker cannot grab too much queue work at once.
    /// </summary>
    [Test]
    public void Oversized_batch_is_rejected()
    {
        var options = new SandboxWorkerOptions(BatchSize: 500);

        Assert.That(SandboxWorkerOptions.Validate(options), Is.EqualTo(false));
    }

    /// <summary>
    /// Confirms a tiny idle delay is rejected so a bad setting cannot create a CPU-burning loop.
    /// </summary>
    [Test]
    public void Tiny_idle_delay_is_rejected()
    {
        var options = new SandboxWorkerOptions(IdleDelayMilliseconds: 1);

        Assert.That(SandboxWorkerOptions.Validate(options), Is.EqualTo(false));
    }

    /// <summary>
    /// Confirms future browser execution is still bounded by a short maximum runtime.
    /// </summary>
    [Test]
    public void Long_execution_timeout_is_rejected()
    {
        var options = new SandboxWorkerOptions(MaxExecutionSeconds: 600);

        Assert.That(SandboxWorkerOptions.Validate(options), Is.EqualTo(false));
    }
}
