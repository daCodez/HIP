extern alias ApiServiceAlias;

using System.Net;
using System.Net.Http.Headers;
using HIP.Application.Dns;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HIP.Tests.Api;

/// <summary>Verifies RFC 8484 DNS wire-format GET and POST behavior.</summary>
[TestFixture]
public sealed class HipDnsWireApiServiceTests
{
    private static readonly byte[] Rfc8484ExampleQuery = Convert.FromHexString(
        "00000100000100000000000003777777076578616d706c6503636f6d0000010001");

    /// <summary>Confirms GET accepts the RFC base64url dns parameter and returns DNS wire format.</summary>
    [Test]
    public async Task Wire_get_returns_dns_message_and_public_safe_hip_headers()
    {
        await using var baseFactory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        await using var factory = WithDnsProvider(baseFactory);
        using var client = factory.CreateClient();
        var dns = Convert.ToBase64String(Rfc8484ExampleQuery).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var request = new HttpRequestMessage(HttpMethod.Get, $"/dns-query?dns={dns}");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));
        var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsByteArrayAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(response.Content.Headers.ContentType?.MediaType, Is.EqualTo("application/dns-message"));
            Assert.That(body[2] & 0x80, Is.EqualTo(0x80));
            Assert.That(body[3] & 0x20, Is.EqualTo(0x20));
            Assert.That(body[7], Is.EqualTo(1));
            Assert.That(response.Headers.GetValues("X-HIP-Status").Single(), Is.Not.Empty);
            Assert.That(response.Headers.GetValues("X-HIP-DNSSEC-Status").Single(), Is.EqualTo("secure"));
            Assert.That(response.Headers.GetValues("X-HIP-Authoritative").Single(), Is.EqualTo("false"));
            Assert.That(response.Headers.CacheControl?.MaxAge, Is.EqualTo(TimeSpan.FromSeconds(30)));
        });
    }

    /// <summary>Confirms POST accepts an application/dns-message body and returns the same wire contract.</summary>
    [Test]
    public async Task Wire_post_returns_dns_message()
    {
        await using var baseFactory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        await using var factory = WithDnsProvider(baseFactory);
        using var client = factory.CreateClient();
        using var content = new ByteArrayContent(Rfc8484ExampleQuery);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");

        var response = await client.PostAsync("/dns-query", content);
        var body = await response.Content.ReadAsByteArrayAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(response.Content.Headers.ContentType?.MediaType, Is.EqualTo("application/dns-message"));
            Assert.That(body[2] & 0x80, Is.EqualTo(0x80));
            Assert.That(body[7], Is.EqualTo(1));
        });
    }

    /// <summary>Confirms unsupported DNS types use an HTTP-success DNS NOTIMP response.</summary>
    [Test]
    public async Task Wire_get_returns_dns_error_for_unsupported_type()
    {
        await using var factory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        using var client = factory.CreateClient();
        var query = Rfc8484ExampleQuery.ToArray();
        query[^3] = 15;
        var dns = Convert.ToBase64String(query).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var response = await client.GetAsync($"/dns-query?dns={dns}");
        var body = await response.Content.ReadAsByteArrayAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(body[3] & 0x0F, Is.EqualTo(4));
        });
    }

    /// <summary>Confirms POST rejects non-DNS media types at the HTTP boundary.</summary>
    [Test]
    public async Task Wire_post_rejects_wrong_content_type()
    {
        await using var factory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        using var client = factory.CreateClient();
        using var content = new ByteArrayContent(Rfc8484ExampleQuery);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

        var response = await client.PostAsync("/dns-query", content);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.UnsupportedMediaType));
    }

    private static Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<ApiServiceAlias::ApiServiceProgram>
        WithDnsProvider(HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram> baseFactory) =>
        baseFactory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.RemoveAll<IDnsLookupProvider>();
            services.AddSingleton<IDnsLookupProvider, StubDnsLookupProvider>();
        }));

    private sealed class StubDnsLookupProvider : IDnsLookupProvider
    {
        public string Name => "test-provider";

        public Task<DnsProviderLookupResult> LookupAsync(
            string domain,
            DnsLookupRecordType recordType,
            CancellationToken cancellationToken) =>
            Task.FromResult(new DnsProviderLookupResult(
                0,
                false,
                true,
                DnssecValidationStatus.Secure,
                [new DnsLookupAnswer($"{domain}.", recordType, 30, "192.0.2.20")]));
    }
}
