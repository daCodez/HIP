using System.Net;
using System.Text;
using HIP.Application.Dns;
using HIP.Infrastructure.AuthoritativeDns;

namespace HIP.Tests.Dns;

/// <summary>Focused protocol tests for HIP's private PowerDNS API adapter.</summary>
public sealed class PowerDnsAuthoritativePublisherTests
{
    [Test]
    public async Task New_zone_is_dnssec_enabled_rectified_and_returns_public_ds_records()
    {
        var handler = new SequenceHandler(
            Response(HttpStatusCode.NotFound, "{}"),
            Response(HttpStatusCode.Created, "{}"),
            Response(HttpStatusCode.NoContent, string.Empty),
            Response(HttpStatusCode.OK, "{}"),
            Response(HttpStatusCode.OK, "[{\"active\":true,\"ds\":[\"12345 13 2 ABCDEF\"]}]"));
        var options = new PowerDnsAuthoritativeOptions(
            true,
            new Uri("http://powerdns:8081/api/v1/"),
            new string('k', 40),
            ["ns1.guardwithhip.com.", "ns2.guardwithhip.com."]);
        var publisher = new PowerDnsAuthoritativePublisher(new HttpClient(handler), options);

        var publication = await publisher.PublishAsync(
            "example.com",
            [new AuthoritativeDnsRecord("example.com.", AuthoritativeDnsRecordType.A, "203.0.113.10", 300)],
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(publication.DsRecords, Is.EqualTo(new[] { "12345 13 2 ABCDEF" }));
            Assert.That(handler.Requests, Has.Count.EqualTo(5));
            Assert.That(handler.Requests[1].Body, Does.Contain("\"dnssec\":true"));
            Assert.That(handler.Requests[1].Body, Does.Contain("\"api_rectify\":true"));
            Assert.That(handler.Requests[2].Method, Is.EqualTo(HttpMethod.Patch));
            Assert.That(handler.Requests[3].Path, Does.EndWith("/rectify"));
            Assert.That(handler.Requests.All(request => request.ApiKey == new string('k', 40)), Is.True);
        });
    }

    [Test]
    public void Provider_error_does_not_expose_response_body_or_api_key()
    {
        var secret = new string('s', 40);
        var handler = new SequenceHandler(Response(HttpStatusCode.InternalServerError, "private provider diagnostic"));
        var publisher = new PowerDnsAuthoritativePublisher(
            new HttpClient(handler),
            new PowerDnsAuthoritativeOptions(
                true,
                new Uri("http://powerdns:8081/api/v1/"),
                secret,
                ["ns1.guardwithhip.com.", "ns2.guardwithhip.com."]));

        var exception = Assert.ThrowsAsync<InvalidOperationException>(async () => await publisher.PublishAsync(
                "example.com",
                [new AuthoritativeDnsRecord("example.com.", AuthoritativeDnsRecordType.A, "203.0.113.10", 300)],
                CancellationToken.None));

        Assert.Multiple(() =>
        {
            Assert.That(exception!.Message, Does.Not.Contain("private provider diagnostic"));
            Assert.That(exception.Message, Does.Not.Contain(secret));
        });
    }

    private static HttpResponseMessage Response(HttpStatusCode statusCode, string body) =>
        new(statusCode)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };

    private sealed class SequenceHandler(params HttpResponseMessage[] responses) : HttpMessageHandler
    {
        private readonly Queue<HttpResponseMessage> queue = new(responses);
        public List<CapturedRequest> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests.Add(new CapturedRequest(
                request.Method,
                request.RequestUri!.AbsolutePath,
                request.Headers.GetValues("X-API-Key").Single(),
                request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken)));
            return queue.Dequeue();
        }
    }

    private sealed record CapturedRequest(HttpMethod Method, string Path, string ApiKey, string Body);
}
