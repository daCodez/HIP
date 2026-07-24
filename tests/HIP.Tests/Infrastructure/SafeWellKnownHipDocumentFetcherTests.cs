using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using HIP.Domain.Identity;
using HIP.Infrastructure.Identity;

namespace HIP.Tests.Infrastructure;

/// <summary>Locks the network-address boundary used by well-known verification.</summary>
public sealed class SafeWellKnownHipDocumentFetcherTests
{
    [TestCase("0.0.0.0")]
    [TestCase("192.0.0.1")]
    [TestCase("192.0.2.1")]
    [TestCase("192.88.99.1")]
    [TestCase("198.18.0.1")]
    [TestCase("198.51.100.1")]
    [TestCase("127.0.0.1")]
    [TestCase("10.0.0.1")]
    [TestCase("100.64.0.1")]
    [TestCase("169.254.1.1")]
    [TestCase("203.0.113.1")]
    [TestCase("240.0.0.1")]
    [TestCase("::")]
    [TestCase("64:ff9b::a00:1")]
    [TestCase("2001::1")]
    [TestCase("2001:db8::1")]
    [TestCase("2002:a00:1::")]
    [TestCase("3fff::1")]
    [TestCase("172.16.0.1")]
    [TestCase("192.168.0.1")]
    [TestCase("224.0.0.1")]
    [TestCase("::1")]
    [TestCase("fe80::1")]
    [TestCase("fc00::1")]
    [TestCase("::ffff:127.0.0.1")]
    public void Private_or_special_addresses_are_rejected(string value)
    {
        Assert.That(SafeWellKnownHipDocumentFetcher.IsPublicAddress(IPAddress.Parse(value)), Is.False);
    }

    [TestCase("8.8.8.8")]
    [TestCase("1.1.1.1")]
    [TestCase("2606:4700:4700::1111")]
    public void Public_unicast_addresses_are_allowed(string value)
    {
        Assert.That(SafeWellKnownHipDocumentFetcher.IsPublicAddress(IPAddress.Parse(value)), Is.True);
    }

    [Test]
    public void Fetch_limits_are_bounded()
    {
        Assert.Multiple(() =>
        {
            Assert.That(
                () => new WellKnownHipDocumentFetchOptions(TimeSpan.FromMilliseconds(500), 4096).Validate(),
                Throws.TypeOf<ArgumentOutOfRangeException>());
            Assert.That(
                () => new WellKnownHipDocumentFetchOptions(TimeSpan.FromSeconds(5), 512).Validate(),
                Throws.TypeOf<ArgumentOutOfRangeException>());
            Assert.That(
                () => new WellKnownHipDocumentFetchOptions(TimeSpan.FromSeconds(5), 4096).Validate(),
                Throws.Nothing);
        });
    }

    [Test]
    public async Task Private_or_mixed_resolution_is_rejected_before_an_http_handler_is_created()
    {
        var factory = new CapturingHandlerFactory(_ => JsonResponse("{}"));
        var fetcher = Fetcher(
            [IPAddress.Parse("8.8.8.8"), IPAddress.Loopback],
            factory);

        var result = await fetcher.FetchAsync("example.com", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.Null);
            Assert.That(factory.CreateCount, Is.Zero);
        });
    }

    [Test]
    public async Task Fetch_uses_only_the_fixed_https_path_and_pins_the_prevalidated_addresses()
    {
        var approvedAddress = IPAddress.Parse("8.8.8.8");
        var factory = new CapturingHandlerFactory(_ => JsonResponse(DocumentJson("example.com")));
        var fetcher = Fetcher([approvedAddress], factory);

        var result = await fetcher.FetchAsync("example.com", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result?.Domain, Is.EqualTo("example.com"));
            Assert.That(factory.ApprovedAddresses, Is.EqualTo(new[] { approvedAddress }));
            Assert.That(factory.Handler.RequestUri?.Scheme, Is.EqualTo(Uri.UriSchemeHttps));
            Assert.That(factory.Handler.RequestUri?.Host, Is.EqualTo("example.com"));
            Assert.That(factory.Handler.RequestUri?.Port, Is.EqualTo(443));
            Assert.That(factory.Handler.RequestUri?.AbsolutePath, Is.EqualTo("/.well-known/hip.json"));
            Assert.That(factory.Handler.RequestUri?.Query, Is.Empty);
            Assert.That(factory.Handler.Authorization, Is.Null);
            Assert.That(factory.Handler.Cookie, Is.Null);
            Assert.That(factory.Handler.SendCount, Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Redirect_response_is_rejected_without_following_the_location()
    {
        var response = new HttpResponseMessage(HttpStatusCode.Redirect)
        {
            Headers = { Location = new Uri("https://attacker.example/private") }
        };
        var factory = new CapturingHandlerFactory(_ => response);
        var fetcher = Fetcher([IPAddress.Parse("8.8.8.8")], factory);

        var result = await fetcher.FetchAsync("example.com", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.Null);
            Assert.That(factory.Handler.SendCount, Is.EqualTo(1));
            Assert.That(factory.Handler.RequestUri?.Host, Is.EqualTo("example.com"));
        });
    }

    [Test]
    public async Task Oversized_chunked_json_response_is_rejected()
    {
        var content = new ByteArrayContent(new byte[1025]);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        content.Headers.ContentLength = null;
        var factory = new CapturingHandlerFactory(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = content
        });
        var fetcher = Fetcher(
            [IPAddress.Parse("8.8.8.8")],
            factory,
            new WellKnownHipDocumentFetchOptions(TimeSpan.FromSeconds(5), 1024));

        var result = await fetcher.FetchAsync("example.com", CancellationToken.None);

        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task Non_json_success_response_is_rejected()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("not-json", Encoding.UTF8, "text/plain")
        };
        var fetcher = Fetcher(
            [IPAddress.Parse("8.8.8.8")],
            new CapturingHandlerFactory(_ => response));

        var result = await fetcher.FetchAsync("example.com", CancellationToken.None);

        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task Malformed_json_success_response_is_rejected_without_throwing()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                "{\"verificationChallenge\":\"must-not-be-echoed\"",
                Encoding.UTF8,
                "application/json")
        };
        var fetcher = Fetcher(
            [IPAddress.Parse("8.8.8.8")],
            new CapturingHandlerFactory(_ => response));

        Assert.That(await fetcher.FetchAsync("example.com", CancellationToken.None), Is.Null);
    }

    [Test]
    public void Production_handler_disables_redirects_cookies_and_decompression()
    {
        using var handler = new PinnedWellKnownHttpMessageHandlerFactory().Create(
            [IPAddress.Parse("8.8.8.8")],
            TimeSpan.FromSeconds(5));
        var sockets = (SocketsHttpHandler)handler;

        Assert.Multiple(() =>
        {
            Assert.That(sockets.AllowAutoRedirect, Is.False);
            Assert.That(sockets.UseCookies, Is.False);
            Assert.That(sockets.AutomaticDecompression, Is.EqualTo(DecompressionMethods.None));
            Assert.That(sockets.UseProxy, Is.False);
        });
    }

    private static SafeWellKnownHipDocumentFetcher Fetcher(
        IReadOnlyCollection<IPAddress> addresses,
        CapturingHandlerFactory factory,
        WellKnownHipDocumentFetchOptions? options = null) =>
        new(options, new StubAddressResolver(addresses), factory);

    private static HttpResponseMessage JsonResponse(string json) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json")
    };

    private static string DocumentJson(string domain) => JsonSerializer.Serialize(
        new HipWellKnownDocument(domain, $"hip:web:{domain}", [], DateTimeOffset.UtcNow),
        new JsonSerializerOptions(JsonSerializerDefaults.Web));

    private sealed class StubAddressResolver(IReadOnlyCollection<IPAddress> addresses)
        : IWellKnownHostAddressResolver
    {
        public Task<IReadOnlyCollection<IPAddress>> ResolveAsync(
            string domain,
            CancellationToken cancellationToken) => Task.FromResult(addresses);
    }

    private sealed class CapturingHandlerFactory(Func<HttpRequestMessage, HttpResponseMessage> responseFactory)
        : IWellKnownHttpMessageHandlerFactory
    {
        public int CreateCount { get; private set; }
        public IReadOnlyCollection<IPAddress> ApprovedAddresses { get; private set; } = [];
        public CapturingHandler Handler { get; } = new(responseFactory);

        public HttpMessageHandler Create(IReadOnlyCollection<IPAddress> approvedAddresses, TimeSpan connectTimeout)
        {
            CreateCount++;
            ApprovedAddresses = approvedAddresses;
            return Handler;
        }
    }

    private sealed class CapturingHandler(Func<HttpRequestMessage, HttpResponseMessage> responseFactory)
        : HttpMessageHandler
    {
        public int SendCount { get; private set; }
        public Uri? RequestUri { get; private set; }
        public AuthenticationHeaderValue? Authorization { get; private set; }
        public string? Cookie { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            SendCount++;
            RequestUri = request.RequestUri;
            Authorization = request.Headers.Authorization;
            Cookie = request.Headers.TryGetValues("Cookie", out var values) ? string.Join(';', values) : null;
            return Task.FromResult(responseFactory(request));
        }
    }
}
