using System.Net;

namespace HIP.Tests.Api;

[TestFixture]
[NonParallelizable]
public sealed class PublicBadgeCorsTests
{
    [Test]
    public async Task Web_badge_verification_allows_cross_origin_embed_preflight()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Options, "/api/v1/badge/verify");
        request.Headers.Add("Origin", "https://zerotoherobudgeting.com");
        request.Headers.Add("Access-Control-Request-Method", "POST");
        request.Headers.Add("Access-Control-Request-Headers", "content-type");

        using var response = await client.SendAsync(request);

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NoContent));
            Assert.That(response.Headers.GetValues("Access-Control-Allow-Origin"), Does.Contain("*"));
            Assert.That(response.Headers.GetValues("Access-Control-Allow-Methods"), Has.Some.Contains("POST"));
        });
    }
}
