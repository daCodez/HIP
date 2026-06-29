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
        await using var factory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/swagger/v1/swagger.json");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        var root = document.RootElement;
        var info = root.GetProperty("info");

        Assert.That(info.GetProperty("title").GetString(), Is.EqualTo("HIP API"));
        Assert.That(info.GetProperty("description").GetString(), Does.Contain("Privacy baseline"));
        Assert.That(info.GetProperty("description").GetString(), Does.Contain("must not receive page text"));
        Assert.That(info.GetProperty("description").GetString(), Does.Contain("Domain trust, page trust, content risk, and final HIP score are separate concepts."));

        var paths = root.GetProperty("paths");
        Assert.That(paths.TryGetProperty("/api/v1/browser/score-site", out var scoreSitePath), Is.True);
        Assert.That(paths.TryGetProperty("/api/v1/browser/scan-results", out var saveScanPath), Is.True);
        Assert.That(paths.TryGetProperty("/api/v1/site-safety/scan", out var siteSafetyPath), Is.True);

        var scoreSitePost = scoreSitePath.GetProperty("post");
        Assert.That(scoreSitePost.GetProperty("summary").GetString(), Is.EqualTo("Scores the current browser tab domain."));
        Assert.That(scoreSitePost.GetProperty("description").GetString(), Does.Contain("Expected caller"));
        Assert.That(scoreSitePost.GetProperty("description").GetString(), Does.Contain("Failure behavior"));
        Assert.That(scoreSitePost.GetProperty("tags")[0].GetString(), Is.EqualTo("Browser Plugin"));

        var saveScanPost = saveScanPath.GetProperty("post");
        Assert.That(saveScanPost.GetProperty("description").GetString(), Does.Contain("Stored fields"));
        Assert.That(saveScanPost.GetProperty("description").GetString(), Does.Contain("Not stored"));
        Assert.That(saveScanPost.GetProperty("description").GetString(), Does.Contain("Downstream use"));

        var siteSafetyPost = siteSafetyPath.GetProperty("post");
        Assert.That(siteSafetyPost.GetProperty("summary").GetString(), Is.EqualTo("Runs a privacy-safe site safety scan from browser-observed signals."));
        Assert.That(siteSafetyPost.GetProperty("description").GetString(), Does.Contain("Expected flow"));
        Assert.That(siteSafetyPost.GetProperty("description").GetString(), Does.Contain("Request may include"));
        Assert.That(siteSafetyPost.GetProperty("description").GetString(), Does.Contain("Status guidance"));
        Assert.That(siteSafetyPost.GetProperty("tags")[0].GetString(), Is.EqualTo("Site Safety"));

        var responseSchemaReference = siteSafetyPost
            .GetProperty("responses")
            .GetProperty("200")
            .GetProperty("content")
            .GetProperty("application/json")
            .GetProperty("schema")
            .GetProperty("$ref")
            .GetString();

        Assert.That(responseSchemaReference, Is.EqualTo("#/components/schemas/SiteSafetyScanApiResponse"));
    }
}
