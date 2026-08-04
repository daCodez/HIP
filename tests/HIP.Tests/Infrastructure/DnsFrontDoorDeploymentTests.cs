namespace HIP.Tests.Infrastructure;

public sealed class DnsFrontDoorDeploymentTests
{
    [Test]
    public void Dns_front_door_is_private_bounded_and_privacy_preserving()
    {
        var root = RepositoryRoot();
        var compose = File.ReadAllText(Path.Combine(root, "deploy", "vps", "compose.private-staging.yml"));
        var dockerfile = File.ReadAllText(Path.Combine(root, "deploy", "dnsdist", "Dockerfile"));
        var configuration = File.ReadAllText(Path.Combine(root, "deploy", "dnsdist", "dnsdist.conf"));
        var operationalCheck = File.ReadAllText(Path.Combine(root, "deploy", "vps", "check-dns-frontdoor.sh"));
        var serviceStart = compose.IndexOf("  dnsdist:", StringComparison.Ordinal);
        var serviceEnd = compose.IndexOf("\n  keycloak:", serviceStart, StringComparison.Ordinal);
        var service = compose[serviceStart..serviceEnd];

        Assert.Multiple(() =>
        {
            Assert.That(dockerfile, Does.Match(@"FROM powerdns/dnsdist-21:2\.1\.0@sha256:[a-f0-9]{64}"));
            Assert.That(dockerfile, Does.Contain("USER 953:953"));
            Assert.That(dockerfile, Does.Contain("dig @127.0.0.1 -p 5353 . SOA +dnssec"));
            Assert.That(service, Does.Not.Contain("\n    ports:"));
            Assert.That(service, Does.Contain("read_only: true"));
            Assert.That(service, Does.Contain("cap_drop: [ALL]"));
            Assert.That(service, Does.Contain("networks: [backend]"));
            Assert.That(service, Does.Not.Contain("egress"));
            Assert.That(compose, Does.Contain("DnsVerification__NameServerHost: dnsdist"));
            Assert.That(compose, Does.Contain("dnsdist: { condition: service_healthy }"));
            Assert.That(configuration, Does.Contain("setRingBuffersOptions({recordQueries=false, recordResponses=false})"));
            Assert.That(configuration, Does.Contain("setSecurityPollSuffix(\"\")"));
            Assert.That(configuration, Does.Contain("MaxQPSIPRule(250)"));
            Assert.That(configuration, Does.Contain("setMaxUDPOutstanding(4096)"));
            Assert.That(configuration, Does.Contain("setMaxTCPConnectionsPerClient(20)"));
            Assert.That(configuration, Does.Contain("setMaxTCPQueuedConnections(512)"));
            Assert.That(configuration, Does.Contain("newPacketCache(50000"));
            Assert.That(configuration, Does.Contain("getAddressInfo(\"unbound\", refreshBackend)"));
            Assert.That(configuration, Does.Contain("activeBackendAddress"));
            Assert.That(configuration, Does.Contain("rmServer(activeBackend)"));
            Assert.That(configuration, Does.Not.Contain("webserver("));
            Assert.That(configuration, Does.Not.Contain("controlSocket("));
            Assert.That(operationalCheck, Does.Contain("unexpectedly has a published host port"));
            Assert.That(operationalCheck, Does.Contain("dnssec-failed.org"));
            Assert.That(operationalCheck, Does.Contain("status: SERVFAIL"));
        });
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate repository root.");
    }
}
