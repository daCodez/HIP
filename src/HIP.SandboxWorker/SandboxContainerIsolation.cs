using System.Text.RegularExpressions;
using HIP.Application.SiteSafety;

namespace HIP.SandboxWorker;

/// <summary>Fail-closed resource and filesystem policy for a disposable browser sandbox container.</summary>
public sealed record SandboxContainerIsolationOptions(
    string Image,
    decimal CpuLimit = 0.5m,
    int MemoryMegabytes = 256,
    int ProcessLimit = 32,
    int TemporaryFileMegabytes = 16,
    int MaximumOutputBytes = 65536,
    int MaximumExecutionSeconds = 30)
{
    private static readonly Regex DigestImage = new(
        @"^[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static bool Validate(SandboxContainerIsolationOptions options) =>
        options is not null &&
        DigestImage.IsMatch(options.Image ?? string.Empty) &&
        options.CpuLimit is >= 0.1m and <= 2m &&
        options.MemoryMegabytes is >= 64 and <= 1024 &&
        options.ProcessLimit is >= 8 and <= 128 &&
        options.TemporaryFileMegabytes is >= 1 and <= 64 &&
        options.MaximumOutputBytes is >= 1024 and <= 262144 &&
        options.MaximumExecutionSeconds is >= 1 and <= 120;
}

/// <summary>A shell-free Docker launch description for one privacy-safe sandbox job.</summary>
public sealed record SandboxContainerLaunchPlan(
    string FileName,
    IReadOnlyList<string> Arguments,
    TimeSpan Timeout,
    int MaximumOutputBytes);

/// <summary>Builds a locked-down disposable-container launch without raw URLs or secrets in arguments.</summary>
public static class SandboxContainerLaunchPlanBuilder
{
    public static SandboxContainerLaunchPlan Build(SandboxLinkScanRequest job, SandboxContainerIsolationOptions options)
    {
        ArgumentNullException.ThrowIfNull(job);
        if (!SandboxContainerIsolationOptions.Validate(options))
        {
            throw new InvalidOperationException("Sandbox container isolation options are unsafe or incomplete.");
        }

        if (job.Status != SandboxLinkScanJobStatus.Processing || string.IsNullOrWhiteSpace(job.LeaseToken))
        {
            throw new InvalidOperationException("Only a currently leased sandbox job can be launched.");
        }

        var memory = $"{options.MemoryMegabytes}m";
        var arguments = new[]
        {
            "run", "--rm",
            "--network", "none",
            "--read-only",
            "--tmpfs", $"/tmp:rw,noexec,nosuid,nodev,size={options.TemporaryFileMegabytes}m",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges=true",
            "--pids-limit", options.ProcessLimit.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--cpus", options.CpuLimit.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--memory", memory,
            "--memory-swap", memory,
            "--user", "65532:65532",
            "--log-driver", "none",
            "--env", $"HIP_SANDBOX_JOB_ID={job.RequestId}",
            options.Image
        };

        return new SandboxContainerLaunchPlan(
            "docker",
            arguments,
            TimeSpan.FromSeconds(options.MaximumExecutionSeconds),
            options.MaximumOutputBytes);
    }
}

/// <summary>Accumulates UTF-8 process output under an exact byte ceiling.</summary>
public sealed class SandboxOutputBuffer(int maximumBytes)
{
    private readonly MemoryStream output = maximumBytes is >= 1 and <= 262144
        ? new MemoryStream(Math.Min(maximumBytes, 4096))
        : throw new ArgumentOutOfRangeException(nameof(maximumBytes));

    public bool Truncated { get; private set; }

    public void Append(ReadOnlySpan<byte> value)
    {
        var remaining = maximumBytes - checked((int)output.Length);
        if (remaining <= 0)
        {
            Truncated = value.Length > 0 || Truncated;
            return;
        }

        var accepted = Math.Min(remaining, value.Length);
        output.Write(value[..accepted]);
        Truncated |= accepted < value.Length;
    }

    public byte[] ToArray() => output.ToArray();
}
