namespace HIP.Tests.Infrastructure;

/// <summary>Locks the production DNS-over-TLS listener and certificate renewal boundaries.</summary>
public sealed class DnsOverTlsDeploymentTests
{
    [Test]
    public void Production_DNS_over_TLS_is_encrypted_bounded_and_renewable()
    {
        var root = RepositoryRoot();
        var compose = File.ReadAllText(Path.Combine(root, "deploy", "vps", "compose.private-staging.yml"));
        var production = File.ReadAllText(Path.Combine(root, "deploy", "vps", "compose.production.override.yml"));
        var configuration = File.ReadAllText(Path.Combine(root, "deploy", "dnsdist", "dnsdist-dot.conf"));
        var sync = File.ReadAllText(Path.Combine(root, "deploy", "vps", "sync-dnsdist-certificate.sh"));
        var check = File.ReadAllText(Path.Combine(root, "deploy", "vps", "check-dns-over-tls.sh"));
        var caddy = File.ReadAllText(Path.Combine(root, "deploy", "vps", "Caddyfile.production"));

        Assert.Multiple(() =>
        {
            Assert.That(compose, Does.Contain("HIP_DNS_HOST: ${HIP_DNS_HOST:?HIP_DNS_HOST is required}"));
            Assert.That(production, Does.Contain(":853:853/tcp"));
            Assert.That(production, Does.Not.Contain(":53:53"));
            Assert.That(production, Does.Contain("dnsdist-dot.conf:/etc/dnsdist/conf.d/10-dot.conf:ro"));
            Assert.That(production, Does.Contain("HIP_DNSDIST_TLS_PATH"));
            Assert.That(production, Does.Contain("networks: [backend, dns-public]"));
            Assert.That(configuration, Does.Contain("addTLSLocal("));
            Assert.That(configuration, Does.Contain("minTLSVersion=\"tls1.2\""));
            Assert.That(configuration, Does.Contain("numberOfStoredSessions=0"));
            Assert.That(configuration, Does.Contain("maxConcurrentTCPConnections=512"));
            Assert.That(configuration, Does.Contain("MaxQPSIPRule(50"));
            Assert.That(configuration, Does.Contain("MaxQPSRule(5000)"));
            Assert.That(configuration, Does.Contain("reloadAllCertificates()"));
            Assert.That(configuration, Does.Not.Contain("webserver("));
            Assert.That(configuration, Does.Not.Contain("controlSocket("));
            Assert.That(sync, Does.Contain("openssl x509 -in"));
            Assert.That(sync, Does.Contain("openssl pkey -in"));
            Assert.That(sync, Does.Contain("cmp -s"));
            Assert.That(sync, Does.Contain("install -o 953 -g 953"));
            Assert.That(check, Does.Contain("+tls-hostname=\"$host\""));
            Assert.That(check, Does.Contain("Verify return code: 0 (ok)"));
            Assert.That(caddy, Does.Contain("{$HIP_DNS_HOST}"));
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
