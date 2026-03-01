using System.Net;
using System.Text;
using HIP.Audit.Models;
using HIP.Sdk;

namespace HIP.Sdk.Tests;

public sealed class HipSdkAdminClientTests
{
    [Test]
    public async Task GetAuditEventsAsync_ReturnsPayload_AndBuildsQuery()
    {
        HttpRequestMessage? captured = null;
        var handler = new StubHandler(req =>
        {
            captured = req;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """
                    [
                      {
                        "id":"evt-1",
                        "createdAtUtc":"2026-03-01T00:00:00Z",
                        "eventType":"jarvis.token.issue",
                        "subject":"hip-system",
                        "source":"api",
                        "detail":"ok",
                        "category":"token",
                        "outcome":"success",
                        "reasonCode":"ok",
                        "route":"/api/jarvis/token/issue",
                        "correlationId":"abc",
                        "latencyMs":1.0
                      }
                    ]
                    """,
                    Encoding.UTF8,
                    "application/json")
            };
        });

        using var httpClient = new HttpClient(handler) { BaseAddress = new Uri("http://localhost") };
        var sdk = new HipSdkAdminClient(httpClient);

        var result = await sdk.GetAuditEventsAsync(new AuditQuery(Take: 10, EventType: "jarvis.token.issue"), identityId: "hip-system");

        Assert.That(result, Is.Not.Empty);
        Assert.That(result[0].EventType, Is.EqualTo("jarvis.token.issue"));
        Assert.That(captured, Is.Not.Null);
        Assert.That(captured!.RequestUri!.Query, Does.Contain("take=10"));
        Assert.That(captured.RequestUri!.Query, Does.Contain("eventType=jarvis.token.issue"));
        Assert.That(captured.RequestUri!.Query, Does.Contain("identityId=hip-system"));
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(handler(request));
    }
}
