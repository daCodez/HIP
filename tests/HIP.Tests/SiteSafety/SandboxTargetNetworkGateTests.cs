extern alias SandboxWorkerAlias;

using System.Net;
using SandboxWorkerAlias::HIP.SandboxWorker;

namespace HIP.Tests.SiteSafety;

public sealed class SandboxTargetNetworkGateTests
{
    [TestCase("127.0.0.1")]
    [TestCase("10.0.0.8")]
    [TestCase("169.254.169.254")]
    [TestCase("192.168.1.10")]
    [TestCase("100.64.0.1")]
    [TestCase("198.18.0.1")]
    [TestCase("198.51.100.1")]
    [TestCase("203.0.113.1")]
    [TestCase("::1")]
    [TestCase("fc00::1")]
    [TestCase("2001:db8::1")]
    public void Private_reserved_or_metadata_resolution_is_rejected(string address)
    {
        var gate = new SandboxTargetNetworkGate(new StubResolver(IPAddress.Parse(address)));

        Assert.ThrowsAsync<InvalidOperationException>(() => gate.AuthorizeInitialAsync("https://target.example/path", CancellationToken.None));
    }

    [Test]
    public async Task Connected_address_must_match_the_pre_resolved_public_set()
    {
        var gate = new SandboxTargetNetworkGate(new StubResolver(IPAddress.Parse("93.184.216.34")));
        var target = await gate.AuthorizeInitialAsync("https://target.example/path", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(SandboxTargetNetworkGate.IsConnectedAddressAuthorized(target, IPAddress.Parse("93.184.216.34")), Is.True);
            Assert.That(SandboxTargetNetworkGate.IsConnectedAddressAuthorized(target, IPAddress.Parse("93.184.216.35")), Is.False);
            Assert.That(SandboxTargetNetworkGate.IsConnectedAddressAuthorized(target, IPAddress.Loopback), Is.False);
        });
    }

    [Test]
    public async Task Redirects_are_re_resolved_and_bounded()
    {
        var resolver = new RoutingResolver(new Dictionary<string, IPAddress>
        {
            ["first.example"] = IPAddress.Parse("93.184.216.34"),
            ["second.example"] = IPAddress.Parse("93.184.216.35")
        });
        var gate = new SandboxTargetNetworkGate(resolver);
        var target = await gate.AuthorizeInitialAsync("https://first.example/start", CancellationToken.None);
        target = await gate.AuthorizeRedirectAsync(target, "https://second.example/next", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(target.Url.Host, Is.EqualTo("second.example"));
            Assert.That(target.RedirectCount, Is.EqualTo(1));
            Assert.That(resolver.ResolvedHosts, Is.EqualTo(new[] { "first.example", "second.example" }));
        });
    }

    [TestCase("file:///etc/passwd")]
    [TestCase("https://user:pass@example.com/")]
    [TestCase("https://example.com/path#fragment")]
    [TestCase("https://example.com:8443/")]
    public void Unsafe_url_shapes_are_rejected(string url)
    {
        var gate = new SandboxTargetNetworkGate(new StubResolver(IPAddress.Parse("93.184.216.34")));
        Assert.ThrowsAsync<InvalidOperationException>(() => gate.AuthorizeInitialAsync(url, CancellationToken.None));
    }

    private sealed class StubResolver(params IPAddress[] addresses) : ISandboxDnsResolver
    {
        public Task<IReadOnlyCollection<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyCollection<IPAddress>>(addresses);
    }

    private sealed class RoutingResolver(IReadOnlyDictionary<string, IPAddress> routes) : ISandboxDnsResolver
    {
        public List<string> ResolvedHosts { get; } = [];

        public Task<IReadOnlyCollection<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken)
        {
            ResolvedHosts.Add(host);
            return Task.FromResult<IReadOnlyCollection<IPAddress>>([routes[host]]);
        }
    }
}
