extern alias ApiServiceAlias;

using System.Net;
using System.Text.Json;
using HIP.Application.Dns;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HIP.Tests.Api;

/// <summary>Verifies the bounded JSON DoH contract exposed by HIP.ApiService.</summary>
[TestFixture]
public sealed class HipAwareDnsApiServiceTests
{
    /// <summary>Confirms a public A query returns standard DNS fields plus the HIP extension.</summary>
    [Test]
    public async Task Dns_query_returns_dns_json_and_hip_trust_extension()
    {
        await using var baseFactory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        await using var factory = baseFactory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.RemoveAll<IDnsLookupProvider>();
            services.AddSingleton<IDnsLookupProvider, StubDnsLookupProvider>();
        }));
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/dns-query?name=example.com&type=A");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(response.Content.Headers.ContentType?.MediaType, Is.EqualTo("application/dns-json"));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.Multiple(() =>
        {
            Assert.That(json.RootElement.GetProperty("Status").GetInt32(), Is.EqualTo(0));
            Assert.That(json.RootElement.GetProperty("AD").GetBoolean(), Is.True);
            Assert.That(json.RootElement.GetProperty("dnssec").GetProperty("status").GetString(), Is.EqualTo("secure"));
            Assert.That(json.RootElement.GetProperty("Question")[0].GetProperty("type").GetInt32(), Is.EqualTo(1));
            Assert.That(json.RootElement.GetProperty("Answer")[0].GetProperty("data").GetString(), Is.EqualTo("192.0.2.20"));
            Assert.That(json.RootElement.GetProperty("hip").GetProperty("domain").GetString(), Is.EqualTo("example.com"));
        });
    }

    /// <summary>Confirms unsupported query types fail without reaching a recursive provider.</summary>
    [Test]
    public async Task Dns_query_rejects_unsupported_record_type()
    {
        await using var factory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/dns-query?name=example.com&type=MX");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

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
