namespace HIP.Security.Tests;

public class BoundaryDependencyTests
{
    [Test]
    public void ApiProject_ShouldNotReferenceSimulatorProject()
    {
        var projectFile = Path.GetFullPath(Path.Combine(TestContext.CurrentContext.TestDirectory, "../../../../HIP.Security.Api/HIP.Security.Api.csproj"));
        var content = File.ReadAllText(projectFile);

        Assert.That(content, Does.Not.Contain("HIP.Security.Simulator"));
    }

    [Test]
    public void CliProject_ShouldNotReferenceSimulatorProject()
    {
        var projectFile = Path.GetFullPath(Path.Combine(TestContext.CurrentContext.TestDirectory, "../../../../HIP.Security.Cli/HIP.Security.Cli.csproj"));
        var content = File.ReadAllText(projectFile);

        Assert.That(content, Does.Not.Contain("HIP.Security.Simulator"));
    }
}
