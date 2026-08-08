using System.Net;
using System.Text;
using HIP.Application.Identity;
using HIP.Domain.Identity;
using HIP.Infrastructure.Identity;

namespace HIP.Tests.Infrastructure;

/// <summary>Locks the privacy and network boundary for HTML ownership evidence.</summary>
public sealed class SafeHtmlDomainVerificationEvidenceProviderTests
{
    [Test]
    public async Task Html_file_uses_fixed_https_path_and_matches_only_the_active_token()
    {
        var factory = new CapturingHandlerFactory("hip-verification=active-token", "text/plain");
        var provider = Provider(factory);

        var result = await provider.CheckAsync("example.com", VerificationMethod.HtmlFile, "active-token", default);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainVerificationCheckStatus.Verified));
            Assert.That(factory.RequestUri?.AbsoluteUri, Is.EqualTo("https://example.com/hip-verification.txt"));
            Assert.That(result.Message, Does.Not.Contain("active-token"));
        });
    }

    [Test]
    public async Task Meta_tag_accepts_attribute_order_without_retaining_page_content()
    {
        const string html = "<html><head><meta content='meta-token' name='hip-verification'></head></html>";
        var factory = new CapturingHandlerFactory(html, "text/html");
        var provider = Provider(factory);

        var result = await provider.CheckAsync("example.com", VerificationMethod.MetaTag, "meta-token", default);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainVerificationCheckStatus.Verified));
            Assert.That(factory.RequestUri?.AbsoluteUri, Is.EqualTo("https://example.com/"));
            Assert.That(result.Message, Does.Not.Contain(html));
        });
    }

    [Test]
    public async Task Wrong_token_is_invalid_and_never_echoed()
    {
        var provider = Provider(new CapturingHandlerFactory("hip-verification=wrong-token", "text/plain"));

        var result = await provider.CheckAsync("example.com", VerificationMethod.HtmlFile, "private-token", default);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainVerificationCheckStatus.Invalid));
            Assert.That(result.Message, Does.Not.Contain("private-token"));
            Assert.That(result.Message, Does.Not.Contain("wrong-token"));
        });
    }

    [Test]
    public async Task Private_resolution_is_rejected_before_http()
    {
        var factory = new CapturingHandlerFactory("hip-verification=token", "text/plain");
        var provider = new SafeHtmlDomainVerificationEvidenceProvider(
            new WellKnownHipDocumentFetchOptions(TimeSpan.FromSeconds(5), 4096),
            new StubAddressResolver([IPAddress.Loopback]),
            factory);

        var result = await provider.CheckAsync("example.com", VerificationMethod.HtmlFile, "token", default);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainVerificationCheckStatus.PendingVerification));
            Assert.That(factory.CreateCount, Is.Zero);
        });
    }

    private static SafeHtmlDomainVerificationEvidenceProvider Provider(CapturingHandlerFactory factory) => new(
        new WellKnownHipDocumentFetchOptions(TimeSpan.FromSeconds(5), 4096),
        new StubAddressResolver([IPAddress.Parse("8.8.8.8")]),
        factory);

    private sealed class StubAddressResolver(IReadOnlyCollection<IPAddress> addresses) : IWellKnownHostAddressResolver
    {
        public Task<IReadOnlyCollection<IPAddress>> ResolveAsync(string domain, CancellationToken cancellationToken) =>
            Task.FromResult(addresses);
    }

    private sealed class CapturingHandlerFactory(string body, string contentType) : IWellKnownHttpMessageHandlerFactory
    {
        public int CreateCount { get; private set; }
        public Uri? RequestUri { get; private set; }

        public HttpMessageHandler Create(IReadOnlyCollection<IPAddress> approvedAddresses, TimeSpan connectTimeout)
        {
            CreateCount++;
            return new StubHandler(request =>
            {
                RequestUri = request.RequestUri;
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(body, Encoding.UTF8, contentType)
                };
            });
        }
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(response(request));
    }
}
