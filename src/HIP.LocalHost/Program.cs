using System.Diagnostics;

namespace HIP.LocalHost;

/// <summary>
/// Starts the HIP API and Web projects directly for local development without Aspire or Docker.
/// </summary>
/// <remarks>
/// This runner is intentionally small: it gives developers a reliable local path when Aspire's DCP
/// cannot access Docker Desktop. It does not replace Aspire for container orchestration or telemetry.
/// </remarks>
internal static class Program
{
    private static readonly Uri ApiHealthUri = new("http://localhost:5099/alive");
    private static readonly Uri WebHealthUri = new("http://localhost:5123/alive");

    /// <summary>
    /// Starts both HIP local services and keeps them alive until the user cancels the process.
    /// </summary>
    /// <param name="args">Command-line arguments. They are currently ignored to keep startup deterministic.</param>
    /// <returns>Zero when services shut down cleanly; non-zero when startup fails.</returns>
    public static async Task<int> Main(string[] args)
    {
        using var cancellation = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        };

        var repositoryRoot = ResolveRepositoryRoot();
        var api = StartService(
            "hip-api",
            repositoryRoot,
            "src/HIP.ApiService/HIP.ApiService.csproj",
            "http://localhost:5099");
        var web = StartService(
            "hip-web",
            repositoryRoot,
            "src/HIP.Web/HIP.Web.csproj",
            "http://localhost:5123");

        try
        {
            await WaitForHealthAsync("hip-api", ApiHealthUri, api, cancellation.Token);
            await WaitForHealthAsync("hip-web", WebHealthUri, web, cancellation.Token);

            Console.WriteLine();
            Console.WriteLine("HIP local services are running without Aspire/Docker.");
            Console.WriteLine("API: http://localhost:5099");
            Console.WriteLine("Web/Admin: http://localhost:5123");
            Console.WriteLine("Press Ctrl+C to stop both services.");
            Console.WriteLine();

            await WaitForExitOrCancellationAsync([api, web], cancellation.Token);
            return 0;
        }
        catch (OperationCanceledException)
        {
            return 0;
        }
        finally
        {
            StopService(api);
            StopService(web);
        }
    }

    /// <summary>
    /// Resolves the repository root from the runner's current working directory.
    /// </summary>
    /// <returns>Absolute repository root path.</returns>
    /// <exception cref="DirectoryNotFoundException">Thrown when the runner is launched outside the HIP repository.</exception>
    private static string ResolveRepositoryRoot()
    {
        var directory = new DirectoryInfo(Environment.CurrentDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "HIP.slnx")) &&
                Directory.Exists(Path.Combine(directory.FullName, "src")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate the HIP repository root. Start HIP.LocalHost from inside the repository.");
    }

    /// <summary>
    /// Starts a HIP service from its already-built assembly on a fixed localhost HTTP endpoint.
    /// </summary>
    /// <param name="name">Display name used in console logs.</param>
    /// <param name="repositoryRoot">Repository root used to resolve project output paths.</param>
    /// <param name="projectPath">Project path relative to the repository root.</param>
    /// <param name="url">HTTP URL the child service should bind to.</param>
    /// <returns>The started child process.</returns>
    /// <remarks>
    /// The runner intentionally avoids child <c>dotnet run</c> because that can trigger NuGet restore/build probes
    /// during startup. Local startup should be boring: build once, then launch the compiled API and Web DLLs.
    /// </remarks>
    private static Process StartService(string name, string repositoryRoot, string projectPath, string url)
    {
        var projectDirectory = Path.GetFullPath(Path.GetDirectoryName(Path.Combine(repositoryRoot, projectPath)) ?? repositoryRoot);
        var projectName = Path.GetFileNameWithoutExtension(projectPath);
        var assemblyPath = Path.Combine(projectDirectory, "bin", "Debug", "net10.0", $"{projectName}.dll");
        if (!File.Exists(assemblyPath))
        {
            throw new FileNotFoundException(
                $"The built service assembly was not found for {name}. Run 'dotnet build HIP.slnx' before starting HIP.LocalHost.",
                assemblyPath);
        }

        var startInfo = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = projectDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        startInfo.ArgumentList.Add(assemblyPath);
        startInfo.ArgumentList.Add("--urls");
        startInfo.ArgumentList.Add(url);
        startInfo.Environment["ASPNETCORE_ENVIRONMENT"] = "Development";
        startInfo.Environment["DOTNET_ENVIRONMENT"] = "Development";

        var process = Process.Start(startInfo) ?? throw new InvalidOperationException($"Failed to start {name}.");
        _ = PipeOutputAsync(name, process.StandardOutput);
        _ = PipeOutputAsync(name, process.StandardError);
        return process;
    }

    /// <summary>
    /// Prefixes child process output so local startup failures show which service produced them.
    /// </summary>
    /// <param name="name">Service name prefix.</param>
    /// <param name="reader">Child output stream.</param>
    /// <returns>A task that completes when the stream closes.</returns>
    private static async Task PipeOutputAsync(string name, StreamReader reader)
    {
        while (await reader.ReadLineAsync() is { } line)
        {
            Console.WriteLine($"[{name}] {line}");
        }
    }

    /// <summary>
    /// Waits for a service health endpoint so the runner reports readiness only after ASP.NET Core is listening.
    /// </summary>
    /// <param name="name">Service name used in startup errors.</param>
    /// <param name="healthUri">Health endpoint URI.</param>
    /// <param name="process">Child service process.</param>
    /// <param name="cancellationToken">Token used to cancel startup waiting.</param>
    /// <returns>A task that completes when the health endpoint returns a success response.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the service exits before becoming healthy.</exception>
    /// <exception cref="TimeoutException">Thrown when the service does not become healthy in time.</exception>
    private static async Task WaitForHealthAsync(string name, Uri healthUri, Process process, CancellationToken cancellationToken)
    {
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
        var deadline = DateTimeOffset.UtcNow.AddSeconds(90);

        while (DateTimeOffset.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (process.HasExited)
            {
                throw new InvalidOperationException($"{name} exited before it became healthy. Exit code: {process.ExitCode}.");
            }

            try
            {
                using var response = await client.GetAsync(healthUri, cancellationToken);
                if (response.IsSuccessStatusCode)
                {
                    return;
                }
            }
            catch (HttpRequestException)
            {
                // Service is still starting. Keep polling without treating transient connection failures as fatal.
            }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                // Health endpoint did not respond within the short probe timeout. Retry until the overall deadline.
            }

            await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
        }

        throw new TimeoutException($"{name} did not become healthy at {healthUri} within 90 seconds.");
    }

    /// <summary>
    /// Keeps the runner alive until any service exits or the user cancels the process.
    /// </summary>
    /// <param name="processes">Started HIP service processes.</param>
    /// <param name="cancellationToken">Token used to stop the wait loop.</param>
    /// <returns>A task that completes when a child exits or cancellation is requested.</returns>
    /// <exception cref="InvalidOperationException">Thrown when one child exits while the runner is active.</exception>
    private static async Task WaitForExitOrCancellationAsync(IReadOnlyCollection<Process> processes, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var exited = processes.FirstOrDefault(process => process.HasExited);
            if (exited is not null)
            {
                throw new InvalidOperationException($"A HIP local service exited unexpectedly. Process id: {exited.Id}. Exit code: {exited.ExitCode}.");
            }

            await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
        }
    }

    /// <summary>
    /// Stops a child service and its process tree so local runs do not leave stale localhost listeners behind.
    /// </summary>
    /// <param name="process">Child service process.</param>
    private static void StopService(Process process)
    {
        if (process.HasExited)
        {
            return;
        }

        try
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit(TimeSpan.FromSeconds(10));
        }
        catch (InvalidOperationException)
        {
            // Process exited between the HasExited check and Kill call.
        }
    }
}
