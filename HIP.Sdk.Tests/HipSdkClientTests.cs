using System.Net;
using System.Net.Http;
using System.Text;
using HIP.Sdk;

namespace HIP.Sdk.Tests;

public sealed class HipSdkClientTests
{
    [Test]
    public async Task GetStatusAsync_ReturnsPayload()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""
            {
              "serviceName": "HIP.ApiService",
              "assemblyVersion": "1.0.0",
              "utcTimestamp": "2026-02-27T00:00:00Z"
            }
            """, Encoding.UTF8, "application/json")
        });

        using var httpClient = new HttpClient(handler) { BaseAddress = new Uri("http://localhost") };
        var sdk = new HipSdkClient(httpClient);

        var result = await sdk.GetStatusAsync();

        Assert.That(result.ServiceName, Is.EqualTo("HIP.ApiService"));
        Assert.That(result.AssemblyVersion, Is.EqualTo("1.0.0"));
    }

    [Test]
    public async Task GetIdentityAsync_404_ReturnsNull()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        using var httpClient = new HttpClient(handler) { BaseAddress = new Uri("http://localhost") };
        var sdk = new HipSdkClient(httpClient);

        var result = await sdk.GetIdentityAsync("missing-id");

        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task GetReputationAsync_ReturnsPayload()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""
            {
              "identityId": "hip-system",
              "score": 100,
              "utcTimestamp": "2026-02-27T00:00:00Z"
            }
            """, Encoding.UTF8, "application/json")
        });

        using var httpClient = new HttpClient(handler) { BaseAddress = new Uri("http://localhost") };
        var sdk = new HipSdkClient(httpClient);

        var result = await sdk.GetReputationAsync("hip-system");

        Assert.That(result, Is.Not.Null);
        Assert.That(result!.IdentityId, Is.EqualTo("hip-system"));
        Assert.That(result.Score, Is.EqualTo(100));
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(handler(request));
    }
}
