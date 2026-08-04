namespace HIP.Tests.Infrastructure;

/// <summary>Locks the production DNS-over-HTTPS routing and privacy boundaries.</summary>
public sealed class DnsOverHttpsDeploymentTests
{
    [Test]
    public void Production_DNS_over_HTTPS_is_standard_bounded_and_credential_free()
    {
        var root = RepositoryRoot();
        var caddy = File.ReadAllText(Path.Combine(root, "deploy", "vps", "Caddyfile.production"));
        var check = File.ReadAllText(Path.Combine(root, "deploy", "vps", "check-dns-over-https.sh"));
        var api = File.ReadAllText(Path.Combine(root, "src", "HIP.ApiService", "Program.cs"));
        var options = File.ReadAllText(Path.Combine(root, "src", "HIP.Application", "Performance", "HipPerformanceOptions.cs"));

        Assert.Multiple(() =>
        {
            Assert.That(caddy, Does.Contain("handle /dns-query"));
            Assert.That(caddy, Does.Contain("reverse_proxy api:8080"));
            Assert.That(caddy, Does.Contain("header_up -Authorization"));
            Assert.That(caddy, Does.Contain("header_up -Cookie"));
            Assert.That(caddy, Does.Contain("header_up -X-HIP-API-Key"));
            Assert.That(caddy, Does.Contain("header_up -X-HIP-Instance-Id"));
            Assert.That(check, Does.Contain("+https=/dns-query"));
            Assert.That(check, Does.Contain("+https-get"));
            Assert.That(check, Does.Contain("HTTP/2-POST"));
            Assert.That(check, Does.Contain("HTTP/2-GET"));
            Assert.That(check, Does.Contain("dnssec-failed.org"));
            Assert.That(api, Does.Contain("PublicDnsPolicy"));
            Assert.That(api, Does.Contain("CreateClientIpFixedWindowPartition"));
            Assert.That(api, Does.Contain("RejectionStatusCode = StatusCodes.Status429TooManyRequests"));
            Assert.That(options, Does.Contain("PublicDnsRequestsPerMinute"));
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
