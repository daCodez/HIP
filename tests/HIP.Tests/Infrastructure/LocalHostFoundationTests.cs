namespace HIP.Tests.Infrastructure;

/// <summary>
/// Verifies the Docker-free local development runner remains available for machines where Aspire cannot access Docker.
/// </summary>
public sealed class LocalHostFoundationTests
{
    /// <summary>
    /// Confirms the solution includes the Docker-free runner project so Visual Studio can select it as a startup project.
    /// </summary>
    [Test]
    public void Solution_includes_localhost_runner_project()
    {
        var solution = File.ReadAllText(Path.Combine(RepositoryRoot(), "HIP.slnx"));

        Assert.That(solution, Does.Contain("src/HIP.LocalHost/HIP.LocalHost.csproj"));
    }

    /// <summary>
    /// Confirms the runner starts the expected localhost ports used by the browser extension and manual testing docs.
    /// </summary>
    [Test]
    public void Localhost_runner_uses_expected_api_and_web_ports()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "HIP.LocalHost", "Program.cs"));

        Assert.That(source, Does.Contain("http://localhost:5099"));
        Assert.That(source, Does.Contain("http://localhost:5123"));
        Assert.That(source, Does.Contain("bin\", \"Debug\", \"net10.0"));
        Assert.That(source, Does.Contain("Run 'dotnet build HIP.slnx' before starting HIP.LocalHost."));
        Assert.That(source, Does.Not.Contain("startInfo.ArgumentList.Add(\"run\")"));
    }

    /// <summary>
    /// Confirms local documentation explains when to use the runner instead of Aspire.
    /// </summary>
    [Test]
    public void Local_development_docs_explain_docker_free_runner()
    {
        var docs = File.ReadAllText(Path.Combine(RepositoryRoot(), "docs", "local-development.md"));

        Assert.That(docs, Does.Contain("Docker-free local runner"));
        Assert.That(docs, Does.Contain("dotnet run --project src/HIP.LocalHost/HIP.LocalHost.csproj"));
        Assert.That(docs, Does.Contain("docker info"));
    }

    /// <summary>
    /// Resolves the repository root from the test output folder.
    /// </summary>
    /// <returns>Absolute repository root path.</returns>
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
