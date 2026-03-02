using System.Diagnostics;

var projectRoot = "/home/jarvis_bot/.openclaw/workspace/HIP";
var selectedScript = Environment.GetEnvironmentVariable("HIP_APPHOST_SCRIPT");
if (string.IsNullOrWhiteSpace(selectedScript) && args.Length > 0)
{
    selectedScript = args[0];
}

var scriptFileName = string.IsNullOrWhiteSpace(selectedScript) ? "apphost.cs" : selectedScript;
var apphostScript = Path.IsPathRooted(scriptFileName)
    ? scriptFileName
    : Path.Combine(projectRoot, scriptFileName);
var aspireBin = "/home/jarvis_bot/.dotnet/tools/aspire";

if (!File.Exists(apphostScript))
{
    Console.Error.WriteLine($"AppHost script not found: {apphostScript}");
    return 1;
}

Console.WriteLine($"Using AppHost script: {apphostScript}");

if (!File.Exists(aspireBin))
{
    Console.Error.WriteLine($"Aspire CLI not found: {aspireBin}");
    Console.Error.WriteLine("Install with: dotnet tool install -g aspire.cli");
    return 1;
}

// Precheck: stop stale manually-run service processes that can hold fixed ports.
var cleanup = new ProcessStartInfo
{
    FileName = "/bin/bash",
    WorkingDirectory = projectRoot,
    RedirectStandardOutput = true,
    RedirectStandardError = true,
    UseShellExecute = false
};
cleanup.ArgumentList.Add("-lc");
cleanup.ArgumentList.Add("pkill -f 'dotnet run --project HIP.ApiService' || true; pkill -f 'dotnet run --project HIP.Web' || true; pkill -f '/HIP.ApiService/bin/Debug/net10.0/HIP.ApiService' || true; pkill -f '/HIP.Web/bin/Debug/net10.0/HIP.Web' || true");
using (var c = Process.Start(cleanup))
{
    if (c is not null) await c.WaitForExitAsync();
}

var psi = new ProcessStartInfo
{
    FileName = aspireBin,
    WorkingDirectory = projectRoot,
    RedirectStandardInput = false,
    RedirectStandardOutput = true,
    RedirectStandardError = true,
    UseShellExecute = false
};

psi.ArgumentList.Add("run");
psi.ArgumentList.Add("--project");
psi.ArgumentList.Add(apphostScript);
// Keep interactive run semantics so the apphost remains running until Ctrl+C.
// (non-interactive mode can auto-stop in some environments)

psi.Environment["PATH"] = Environment.GetEnvironmentVariable("PATH") + ":/home/jarvis_bot/.dotnet/tools";

using var proc = Process.Start(psi);
if (proc is null)
{
    Console.Error.WriteLine("Failed to start Aspire CLI process.");
    return 1;
}

static bool IsNoisyDevCertLine(string line)
{
    var checks = new[]
    {
        "Dotnet-dev-certs",
        "WslWindowsTrustSucceeded",
        "Developer certificates may not be fully trusted",
        "Trusting the HTTPS development certificate",
        "none of them is trusted",
        "aka.ms/dev-certs-trust"
    };

    return checks.Any(line.Contains);
}

var outTask = Task.Run(async () =>
{
    while (await proc.StandardOutput.ReadLineAsync() is { } line)
    {
        if (!IsNoisyDevCertLine(line))
        {
            Console.WriteLine(line);
        }
    }
});

var errTask = Task.Run(async () =>
{
    while (await proc.StandardError.ReadLineAsync() is { } line)
    {
        if (!IsNoisyDevCertLine(line))
        {
            Console.Error.WriteLine(line);
        }
    }
});

await Task.WhenAll(proc.WaitForExitAsync(), outTask, errTask);
return proc.ExitCode;
