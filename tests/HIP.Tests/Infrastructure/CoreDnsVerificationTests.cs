using HIP.Application.Identity;
using HIP.Domain.Identity;
using HIP.Infrastructure.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace HIP.Tests.Infrastructure;

/// <summary>Locks the executable CoreDNS fixture and optionally exercises its live DNS wire behavior.</summary>
public sealed class CoreDnsVerificationTests
{
    [Test]
    public void Zone_fixture_contains_all_required_verification_scenarios()
    {
        var root = RepositoryRoot();
        var zone = File.ReadAllText(Path.Combine(root, "eng", "coredns", "hip.test.zone"));
        var corefile = File.ReadAllText(Path.Combine(root, "eng", "coredns", "Corefile"));
        var harness = File.ReadAllText(Path.Combine(root, "eng", "Test-HipCoreDns.ps1"));

        Assert.Multiple(() =>
        {
            Assert.That(corefile, Does.Contain("file /zones/hip.test.zone test"));
            Assert.That(zone, Does.Contain("_hip.good 60 IN TXT \"hip-site-verification=good-token\""));
            Assert.That(zone, Does.Contain("_hip.bad 60 IN TXT \"hip-site-verification=wrong-token\""));
            Assert.That(zone.Split("_hip.multi 60 IN TXT", StringSplitOptions.None), Has.Length.EqualTo(4));
            Assert.That(zone, Does.Contain("_hip.segmented 60 IN TXT \"hip-site-\" \"verification=segmented-token\""));
            Assert.That(zone, Does.Contain("_hip.xn--bcher-kva 60 IN TXT \"hip-site-verification=punycode-token\""));
            Assert.That(harness, Does.Contain("Category=CoreDnsLive"));
            Assert.That(harness, Does.Contain("finally"));
        });
    }

    [TestCase("good.test", "good-token", DomainVerificationCheckStatus.Verified)]
    [TestCase("bad.test", "good-token", DomainVerificationCheckStatus.Invalid)]
    [TestCase("missing.test", "good-token", DomainVerificationCheckStatus.NotConfigured)]
    [TestCase("multi.test", "multi-token", DomainVerificationCheckStatus.Verified)]
    [TestCase("segmented.test", "segmented-token", DomainVerificationCheckStatus.Verified)]
    [TestCase("bücher.test", "punycode-token", DomainVerificationCheckStatus.Verified)]
    [Category("CoreDnsLive")]
    public async Task Live_coredns_fixture_returns_expected_domain_control_status(
        string domain,
        string token,
        DomainVerificationCheckStatus expected)
    {
        var endpoint = LiveEndpointOrIgnore();
        var resolver = new DnsClientTxtRecordResolver(
            Options.Create(new DnsVerificationOptions
            {
                NameServerHost = endpoint.Host,
                NameServerPort = endpoint.Port,
                TimeoutMilliseconds = 1500,
                UseTcpOnly = true
            }),
            NullLogger<DnsClientTxtRecordResolver>.Instance);
        var service = new DnsDomainVerificationService(
            resolver,
            new InMemoryDomainVerificationRequestRepository(),
            NullLogger<DnsDomainVerificationService>.Instance);

        var result = await service.CheckDnsTxtAsync(domain, token, CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(expected));
    }

    private static (string Host, int Port) LiveEndpointOrIgnore()
    {
        var host = Environment.GetEnvironmentVariable("HIP_TEST_COREDNS_HOST");
        var portText = Environment.GetEnvironmentVariable("HIP_TEST_COREDNS_PORT");
        var port = 0;
        if (string.IsNullOrWhiteSpace(host) || !int.TryParse(portText, out port))
        {
            Assert.Ignore("Run eng/Test-HipCoreDns.ps1 to activate the live CoreDNS integration cases.");
        }

        return (host!, port);
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new DirectoryNotFoundException("HIP repository root was not found.");
    }

    private sealed class InMemoryDomainVerificationRequestRepository : IDomainVerificationRequestRepository
    {
        private readonly Dictionary<string, DomainVerificationRequest> records = [];
        public Task<bool> TryCreateAsync(DomainVerificationRequest request, CancellationToken cancellationToken) =>
            Task.FromResult(records.TryAdd(Key(request), request));
        public Task<bool> TryUpdateAsync(DomainVerificationRequest expected, DomainVerificationRequest updated, CancellationToken cancellationToken) =>
            Task.FromResult(false);
        public Task<DomainVerificationRequest> SaveAsync(DomainVerificationRequest request, CancellationToken cancellationToken) =>
            Task.FromResult(request);
        public Task<DomainVerificationRequest?> GetAsync(string domain, VerificationMethod method, CancellationToken cancellationToken) =>
            Task.FromResult<DomainVerificationRequest?>(null);
        private static string Key(DomainVerificationRequest request) => $"{request.Method}:{request.Domain}";
    }
}
