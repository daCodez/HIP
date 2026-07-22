extern alias ApiServiceAlias;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HIP.Application.Browser;
using HIP.Domain.Risk;
using NUnit.Framework;

namespace HIP.Tests.Security;

/// <summary>
/// Proves unauthenticated browser scan summaries cannot become authoritative public trust evidence.
/// </summary>
[TestFixture]
[NonParallelizable]
public sealed class AnonymousBrowserScanTrustBoundaryTests
{
    /// <summary>
    /// HIP.Web does not let an anonymous caller forge server provenance or drive public lookup.
    /// </summary>
    [Test]
    public Task Web_anonymous_browser_scan_cannot_forge_authoritative_provenance_or_drive_public_lookup() =>
        AssertAnonymousSubmissionIsUntrustedAsync<Program>("web", "/api/v1/public/lookup");

    /// <summary>
    /// HIP.ApiService does not let an anonymous caller forge server provenance or drive public lookup.
    /// </summary>
    [Test]
    public Task Api_service_anonymous_browser_scan_cannot_forge_authoritative_provenance_or_drive_public_lookup() =>
        AssertAnonymousSubmissionIsUntrustedAsync<ApiServiceAlias::ApiServiceProgram>("api", "/api/v1/public/lookup/domain");

    private static async Task AssertAnonymousSubmissionIsUntrustedAsync<TProgram>(string host, string lookupRoutePrefix)
        where TProgram : class
    {
        await using var factory = new HipWebApplicationFactory<TProgram>();
        using var client = factory.CreateClient();
        var domain = $"anonymous-poison-{host}-{Guid.NewGuid():N}.example";
        var receivedAfterUtc = DateTimeOffset.UtcNow.AddSeconds(-1);
        var request = new BrowserScanResultSaveRequest(
            domain,
            $"https://{domain}/login",
            0,
            "Dangerous",
            "Dangerous",
            ["Caller-controlled dangerous classification."],
            1,
            1,
            1,
            1,
            "RouteToSafetyPage",
            new Dictionary<string, string>
            {
                ["submissionTrust"] = "server-authoritative"
            },
            ScannedAtUtc: DateTimeOffset.UtcNow.AddYears(1));

        using var submitted = await client.PostAsJsonAsync("/api/v1/browser/scan-results", request);
        using var stored = await client.GetAsync($"/api/v1/browser/scan-results/{domain}");
        using var lookup = await client.GetAsync($"{lookupRoutePrefix}/{domain}");

        Assert.Multiple(() =>
        {
            Assert.That(submitted.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(stored.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(lookup.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        });

        using var storedJson = await JsonDocument.ParseAsync(await stored.Content.ReadAsStreamAsync());
        using var lookupJson = await JsonDocument.ParseAsync(await lookup.Content.ReadAsStreamAsync());
        var storedAtUtc = storedJson.RootElement.GetProperty("lastCheckedUtc").GetDateTimeOffset();
        var statusElement = lookupJson.RootElement.GetProperty("status");
        var status = statusElement.ValueKind == JsonValueKind.String
            ? statusElement.GetString()
            : ((RiskStatus)statusElement.GetInt32()).ToString();
        Assert.Multiple(() =>
        {
            Assert.That(
                storedJson.RootElement.GetProperty("privacySafeMetadata").GetProperty("submissionTrust").GetString(),
                Is.EqualTo("untrusted-client"));
            Assert.That(storedAtUtc, Is.GreaterThanOrEqualTo(receivedAfterUtc));
            Assert.That(storedAtUtc, Is.LessThanOrEqualTo(DateTimeOffset.UtcNow));
            Assert.That(lookupJson.RootElement.GetProperty("dataSource").GetString(), Is.EqualTo("NoStoredData"));
            Assert.That(status, Is.EqualTo(nameof(RiskStatus.LimitedTrustData)));
            Assert.That(lookupJson.RootElement.GetProperty("recommendedAction").GetString(), Is.EqualTo("ShowCaution"));
        });
    }
}
