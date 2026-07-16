using System.Net;
using HIP.Web.Security;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

namespace HIP.Tests.Security;

public sealed class LocalDevelopmentRequestGuardTests
{
    [Test]
    public void Local_development_request_requires_loopback_host_and_peer()
    {
        var context = Request("localhost", IPAddress.Loopback);

        var allowed = LocalDevelopmentRequestGuard.IsLocalDevelopmentRequest(
            context.Request,
            Environment(Environments.Development));

        Assert.That(allowed, Is.True);
    }

    [TestCase("203.0.113.10")]
    [TestCase("2001:db8::10")]
    public void Non_loopback_peer_is_rejected_even_with_localhost_host(string remoteAddress)
    {
        var context = Request("localhost", IPAddress.Parse(remoteAddress));

        var allowed = LocalDevelopmentRequestGuard.IsLocalDevelopmentRequest(
            context.Request,
            Environment(Environments.Development));

        Assert.That(allowed, Is.False);
    }

    [Test]
    public void Missing_peer_address_is_rejected()
    {
        var context = Request("localhost", null);

        var allowed = LocalDevelopmentRequestGuard.IsLocalDevelopmentRequest(
            context.Request,
            Environment(Environments.Development));

        Assert.That(allowed, Is.False);
    }

    [TestCase("Forwarded")]
    [TestCase("X-Forwarded-For")]
    [TestCase("X-Real-IP")]
    public void Forwarded_requests_are_rejected(string headerName)
    {
        var context = Request("localhost", IPAddress.Loopback);
        context.Request.Headers[headerName] = "for=127.0.0.1";

        var allowed = LocalDevelopmentRequestGuard.IsLocalDevelopmentRequest(
            context.Request,
            Environment(Environments.Development));

        Assert.That(allowed, Is.False);
    }

    [Test]
    public void Production_request_is_rejected_even_when_fully_loopback()
    {
        var context = Request("localhost", IPAddress.Loopback);

        var allowed = LocalDevelopmentRequestGuard.IsLocalDevelopmentRequest(
            context.Request,
            Environment(Environments.Production));

        Assert.That(allowed, Is.False);
    }

    private static DefaultHttpContext Request(string host, IPAddress? remoteAddress)
    {
        var context = new DefaultHttpContext();
        context.Request.Host = new HostString(host);
        context.Connection.RemoteIpAddress = remoteAddress;
        return context;
    }

    private static IWebHostEnvironment Environment(string name) => new TestWebHostEnvironment
    {
        EnvironmentName = name
    };

    private sealed class TestWebHostEnvironment : IWebHostEnvironment
    {
        public string ApplicationName { get; set; } = "HIP.Tests";
        public IFileProvider WebRootFileProvider { get; set; } = new NullFileProvider();
        public string WebRootPath { get; set; } = string.Empty;
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ContentRootPath { get; set; } = string.Empty;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
