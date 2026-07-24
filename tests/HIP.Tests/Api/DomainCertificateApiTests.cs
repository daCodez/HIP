extern alias ApiServiceAlias;

using System.Net;
using System.Text.Json;
using HIP.Application.Certificates;
using HIP.Domain.Certificates;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HIP.Tests.Api;

[TestFixture]
[NonParallelizable]
public sealed class DomainCertificateApiTests
{
    [Test]
    public async Task Web_host_exposes_verified_public_certificate_without_private_owner_data()
    {
        await using var rootFactory = new HipWebApplicationFactory<Program>();
        await using var factory = Configure(rootFactory, Found());
        using var client = factory.CreateClient();

        await AssertVerifiedResponseAsync(client);
    }

    [Test]
    public async Task Api_service_exposes_the_same_verified_public_certificate_contract()
    {
        await using var rootFactory =
            new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        await using var factory = Configure(rootFactory, Found());
        using var client = factory.CreateClient();

        await AssertVerifiedResponseAsync(client);
    }

    [Test]
    public async Task Missing_certificate_is_not_cached()
    {
        await using var rootFactory = new HipWebApplicationFactory<Program>();
        await using var factory = Configure(
            rootFactory,
            new PublicDomainCertificateLookupResult(
                PublicDomainCertificateLookupStatus.NotFound));
        using var client = factory.CreateClient();

        using var response = await client.GetAsync(
            "/api/v1/public/certificates/hip-domain-cert-missing");

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
            Assert.That(response.Headers.CacheControl?.NoStore, Is.True);
        });
    }

    private static async Task AssertVerifiedResponseAsync(HttpClient client)
    {
        using var response = await client.GetAsync(
            "/api/v1/public/certificates/hip-domain-cert-0001");
        var body = await response.Content.ReadAsStringAsync();
        using var json = JsonDocument.Parse(body);

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(response.Headers.CacheControl?.Public, Is.True);
            Assert.That(response.Headers.CacheControl?.MaxAge, Is.EqualTo(TimeSpan.FromSeconds(60)));
            Assert.That(json.RootElement.GetProperty("schemaVersion").GetString(),
                Is.EqualTo(PublicDomainCertificateService.SchemaVersion));
            Assert.That(json.RootElement.GetProperty("isActive").GetBoolean(), Is.True);
            Assert.That(
                json.RootElement.GetProperty("signedCertificate")
                    .GetProperty("payload")
                    .GetProperty("domain")
                    .GetString(),
                Is.EqualTo("example.com"));
            Assert.That(body, Does.Not.Contain("owner-1"));
            Assert.That(body, Does.Not.Contain("actor-1"));
            Assert.That(body, Does.Not.Contain("enrollment-1"));
        });
    }

    private static PublicDomainCertificateLookupResult Found()
    {
        var certificate = Certificates.CertificateTestData.SignedCertificate();
        return new PublicDomainCertificateLookupResult(
            PublicDomainCertificateLookupStatus.Found,
            new PublicDomainCertificateResponse(
                PublicDomainCertificateService.SchemaVersion,
                certificate,
                DomainCertificateStatus.Active,
                PublicDomainCertificateSignatureStatus.Verified,
                PublicDomainCertificateValidityStatus.Current,
                true,
                Certificates.CertificateTestData.Now,
                certificate.Payload.RevocationStatusUrl,
                certificate.Payload.PublicCertificateUrl));
    }

    private static WebApplicationFactory<TProgram> Configure<TProgram>(
        WebApplicationFactory<TProgram> factory,
        PublicDomainCertificateLookupResult result)
        where TProgram : class =>
        factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.RemoveAll<IPublicDomainCertificateService>();
            services.AddSingleton<IPublicDomainCertificateService>(
                new StubPublicCertificateService(result));
        }));

    private sealed class StubPublicCertificateService(PublicDomainCertificateLookupResult result)
        : IPublicDomainCertificateService
    {
        public Task<PublicDomainCertificateLookupResult> GetByIdAsync(
            string certificateId,
            CancellationToken cancellationToken) =>
            Task.FromResult(result);
    }
}
