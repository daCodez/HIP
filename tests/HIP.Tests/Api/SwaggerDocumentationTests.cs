extern alias ApiServiceAlias;

using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests.Api;

/// <summary>
/// Verifies the standalone HIP API service exposes useful Swagger documentation for local developers.
/// </summary>
[TestFixture]
public sealed class SwaggerDocumentationTests
{
    /// <summary>
    /// Confirms the generated Swagger document includes HIP-specific descriptions, privacy guidance, and grouped endpoint metadata.
    /// </summary>
    [Test]
    public async Task Swagger_document_includes_api_purpose_privacy_guidance_and_endpoint_groups()
    {
        await using var factory = new WebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/swagger/v1/swagger.json");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        var root = document.RootElement;
        var info = root.GetProperty("info");

        Assert.That(info.GetProperty("title").GetString(), Is.EqualTo("HIP API"));
        Assert.That(info.GetProperty("description").GetString(), Does.Contain("Privacy baseline"));
        Assert.That(info.GetProperty("description").GetString(), Does.Contain("must not receive page text"));

        var paths = root.GetProperty("paths");
        Assert.That(paths.TryGetProperty("/api/v1/browser/score-site", out var scoreSitePath), Is.True);
        Assert.That(paths.TryGetProperty("/api/v1/site-safety/scan", out var siteSafetyPath), Is.True);

        var scoreSitePost = scoreSitePath.GetProperty("post");
        Assert.That(scoreSitePost.GetProperty("summary").GetString(), Is.EqualTo("Scores the current browser tab domain."));
        Assert.That(scoreSitePost.GetProperty("description").GetString(), Does.Contain("must not include page text"));
        Assert.That(scoreSitePost.GetProperty("tags")[0].GetString(), Is.EqualTo("Browser Plugin"));

        var siteSafetyPost = siteSafetyPath.GetProperty("post");
        Assert.That(siteSafetyPost.GetProperty("summary").GetString(), Is.EqualTo("Runs a privacy-safe site safety scan from browser-observed signals."));
        Assert.That(siteSafetyPost.GetProperty("tags")[0].GetString(), Is.EqualTo("Site Safety"));
    }
}
