using System.Net;
using HIP.Tests.Infrastructure;

namespace HIP.Tests.Api;

/// <summary>Protects the interactive browser runtime from being omitted during publication.</summary>
public sealed class BlazorRuntimeAssetTests
{
    [Test]
    public async Task Blazor_browser_runtime_is_served_as_javascript()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        using var response = await client.GetAsync("/_framework/blazor.web.js");
        var content = await response.Content.ReadAsByteArrayAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(response.Content.Headers.ContentType?.MediaType, Does.Contain("javascript"));
            Assert.That(content.Length, Is.GreaterThan(10_000));
        });
    }

    [Test]
    public void Web_project_forces_net10_browser_assets_into_publish_output()
    {
        var project = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "HIP.Web.csproj"));

        Assert.That(project, Does.Contain("<RequiresAspNetWebAssets>true</RequiresAspNetWebAssets>"));
    }

    private static string WorkspaceFile(params string[] segments)
    {
        var directory = new DirectoryInfo(Path.GetDirectoryName(SourceFilePath())!);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
        {
            directory = directory.Parent;
        }

        Assert.That(directory, Is.Not.Null, "Unable to locate the HIP repository root.");
        return Path.Combine([directory!.FullName, .. segments]);
    }

    private static string SourceFilePath(
        [System.Runtime.CompilerServices.CallerFilePath] string sourceFilePath = "") =>
        sourceFilePath;
}
