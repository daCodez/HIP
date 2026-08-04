namespace HIP.Tests.Infrastructure;

/// <summary>Verifies the authoritative DNS service remains isolated until registrar delegation is ready.</summary>
public sealed class AuthoritativeDnsDeploymentTests
{
    [Test]
    public void PowerDns_is_hardened_private_non_recursive_and_connected_only_to_admin_web()
    {
        var root = FindRepositoryRoot();
        var compose = File.ReadAllText(Path.Combine(root, "deploy", "vps", "compose.private-staging.yml"));
        var production = File.ReadAllText(Path.Combine(root, "deploy", "vps", "compose.production.override.yml"));
        var configuration = File.ReadAllText(Path.Combine(root, "deploy", "powerdns", "pdns.conf"));
        var entrypoint = File.ReadAllText(Path.Combine(root, "deploy", "powerdns", "entrypoint.sh"));

        Assert.Multiple(() =>
        {
            Assert.That(compose, Does.Contain("image: guardwithhip/powerdns:${HIP_RELEASE_REVISION"));
            Assert.That(compose, Does.Contain("read_only: true"));
            Assert.That(compose, Does.Contain("cap_drop: [ALL]"));
            Assert.That(compose, Does.Contain("powerdns-data:/var/lib/powerdns"));
            Assert.That(compose, Does.Contain("AuthoritativeDns__ApiBaseUrl: http://powerdns:8081/api/v1/"));
            Assert.That(production, Does.Not.Contain(":53:5300"));
            Assert.That(configuration, Does.Contain("disable-axfr=yes"));
            Assert.That(configuration, Does.Contain("allow-dnsupdate-from="));
            Assert.That(configuration, Does.Contain("log-dns-queries=no"));
            Assert.That(configuration, Does.Contain("default-api-rectify=yes"));
            Assert.That(entrypoint, Does.Not.Contain("echo \"$HIP_POWERDNS_API_KEY\""));
        });
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (current is not null && !File.Exists(Path.Combine(current.FullName, "HIP.sln")))
        {
            current = current.Parent;
        }

        return current?.FullName ?? throw new DirectoryNotFoundException("HIP repository root was not found.");
    }
}
