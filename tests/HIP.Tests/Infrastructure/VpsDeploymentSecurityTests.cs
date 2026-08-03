namespace HIP.Tests.Infrastructure;

/// <summary>Prevents the reviewable VPS release path from drifting back to Development or floating images.</summary>
public sealed class VpsDeploymentSecurityTests
{
    [Test]
    public void Public_host_recovers_portal_paths_to_their_application_subdomains()
    {
        var root = RepositoryRoot();
        var caddySources = new[]
        {
            File.ReadAllText(Path.Combine(root, "deploy", "vps", "Caddyfile")),
            File.ReadAllText(Path.Combine(root, "deploy", "vps", "Caddyfile.production"))
        };

        Assert.Multiple(() =>
        {
            foreach (var caddySource in caddySources)
            {
                Assert.That(caddySource, Does.Contain("@legacyConsumerPortal path_regexp legacyConsumerPortal ^/consumer(?:/(.*))?$"));
                Assert.That(
                    caddySource,
                    Does.Contain("redir @legacyConsumerPortal https://{$HIP_CONSUMER_HOST}/{re.legacyConsumerPortal.1} 302"));
                Assert.That(caddySource, Does.Contain("@legacyAdminPortal path_regexp legacyAdminPortal ^/admin(?:/(.*))?$"));
                Assert.That(
                    caddySource,
                    Does.Contain("redir @legacyAdminPortal https://{$HIP_ADMIN_HOST}/{re.legacyAdminPortal.1} 302"));
                Assert.That(
                    Occurrences(caddySource, "redir @legacyConsumerPortal https://{$HIP_CONSUMER_HOST}/{re.legacyConsumerPortal.1} 302"),
                    Is.EqualTo(4));
                Assert.That(
                    Occurrences(caddySource, "redir @legacyAdminPortal https://{$HIP_ADMIN_HOST}/{re.legacyAdminPortal.1} 302"),
                    Is.EqualTo(4));
                Assert.That(
                    Occurrences(caddySource, "redir @publicExperience https://{$HIP_PUBLIC_HOST}{uri} 302"),
                    Is.EqualTo(3));
                Assert.That(Occurrences(caddySource, "path /platform /how /how-it-works /verify /verification /dev /developers"), Is.EqualTo(3));
                Assert.That(caddySource, Does.Contain("rewrite @consumerUi /consumer{uri}"));
                Assert.That(caddySource, Does.Contain("rewrite @adminUi /admin{uri}"));
            }
        });
    }

    [Test]
    public void Production_override_removes_public_development_runtime_boundaries()
    {
        var root = RepositoryRoot();
        var overrideSource = File.ReadAllText(Path.Combine(
            root,
            "deploy",
            "vps",
            "compose.production.override.yml"));
        var stagingComposeSource = File.ReadAllText(Path.Combine(
            root,
            "deploy",
            "vps",
            "compose.private-staging.yml"));
        var caddySource = File.ReadAllText(Path.Combine(
            root,
            "deploy",
            "vps",
            "Caddyfile.production"));
        var stagingCaddySource = File.ReadAllText(Path.Combine(
            root,
            "deploy",
            "vps",
            "Caddyfile"));

        Assert.Multiple(() =>
        {
            Assert.That(overrideSource, Does.Contain("ASPNETCORE_ENVIRONMENT: Production"));
            Assert.That(overrideSource, Does.Contain("DOTNET_ENVIRONMENT: Production"));
            Assert.That(overrideSource, Does.Contain("HipDevelopmentProxy__Enabled: \"false\""));
            Assert.That(overrideSource, Does.Contain("env_file: !reset []"));
            Assert.That(overrideSource, Does.Contain("HipSessionProtection__CertificatePath:"));
            Assert.That(overrideSource, Does.Contain("HipAuthentication__Authority:"));
            Assert.That(
                Occurrences(overrideSource, "HipManagedSigning__Required: \"true\""),
                Is.EqualTo(3));
            Assert.That(overrideSource, Does.Contain("HIP_SIGNING_ISSUER_ID is required"));
            Assert.That(overrideSource, Does.Contain("HIP_SIGNING_KEY_ID is required"));
            Assert.That(Occurrences(overrideSource, "HipManagedSigning__Provider: SoftHsm"), Is.EqualTo(3));
            Assert.That(Occurrences(overrideSource, "hip-softhsm-user-pin:ro"), Is.EqualTo(3));
            Assert.That(Occurrences(overrideSource, "HipManagedSigning__SoftHsm__ProvisionKeyIfMissing: \"true\""), Is.EqualTo(3));
            Assert.That(Occurrences(stagingComposeSource, "HipManagedSigning__Provider: SoftHsm"), Is.EqualTo(3));
            Assert.That(Occurrences(stagingComposeSource, "hip-softhsm-user-pin:ro"), Is.EqualTo(3));
            Assert.That(Occurrences(stagingComposeSource, "HipManagedSigning__Required: \"true\""), Is.EqualTo(1));
            var provisionScript = File.ReadAllText(Path.Combine(root, "deploy", "vps", "provision-softhsm.sh"));
            Assert.That(provisionScript, Does.Contain("--user 1654:1654"));
            Assert.That(provisionScript, Does.Not.Contain("--user 0:0"));
            Assert.That(caddySource, Does.Not.Contain(
                "header_up X-HIP-Trusted-Staging-Proxy "));
            Assert.That(caddySource, Does.Not.Contain("@publicRoot path /"));
            Assert.That(caddySource, Does.Not.Contain("redir @publicRoot /lookup 302"));
            Assert.That(stagingCaddySource, Does.Not.Contain("@publicRoot path /"));
            Assert.That(stagingCaddySource, Does.Not.Contain("redir @publicRoot /lookup 302"));
        });
    }

    [Test]
    public void Public_proxy_uses_reliable_http_protocols_until_quic_is_operational()
    {
        var root = RepositoryRoot();
        var caddySources = new[]
        {
            File.ReadAllText(Path.Combine(root, "deploy", "vps", "Caddyfile")),
            File.ReadAllText(Path.Combine(root, "deploy", "vps", "Caddyfile.production"))
        };

        Assert.Multiple(() =>
        {
            foreach (var caddySource in caddySources)
            {
                Assert.That(
                    caddySource,
                    Does.Match(@"^\{\r?\n    servers \{\r?\n        protocols h1 h2\r?\n    \}\r?\n\}"));
                Assert.That(caddySource, Does.Not.Contain("protocols h1 h2 h3"));
            }
        });
    }

    [Test]
    public void Vps_external_images_are_digest_pinned_and_HIP_builds_are_revision_tagged()
    {
        var root = RepositoryRoot();
        var compose = File.ReadAllText(Path.Combine(
            root,
            "deploy",
            "vps",
            "compose.private-staging.yml"));
        var dockerfiles = new[]
        {
            Path.Combine(root, "deploy", "keycloak", "Dockerfile"),
            Path.Combine(root, "src", "HIP.ApiService", "Dockerfile"),
            Path.Combine(root, "src", "HIP.Web", "Dockerfile"),
            Path.Combine(root, "src", "HIP.SandboxWorker", "Dockerfile")
        };
        var sandboxWorkerDockerfile = File.ReadAllText(dockerfiles[^1]);

        Assert.Multiple(() =>
        {
            Assert.That(compose, Does.Contain(
                "image: guardwithhip/identity:${HIP_RELEASE_REVISION:?HIP_RELEASE_REVISION is required}"));
            Assert.That(compose, Does.Contain(
                "image: guardwithhip/api:${HIP_RELEASE_REVISION:?HIP_RELEASE_REVISION is required}"));
            Assert.That(compose, Does.Contain(
                "image: guardwithhip/admin-web:${HIP_RELEASE_REVISION:?HIP_RELEASE_REVISION is required}"));
            Assert.That(compose, Does.Contain(
                "image: guardwithhip/consumer-web:${HIP_RELEASE_REVISION:?HIP_RELEASE_REVISION is required}"));
            Assert.That(compose, Does.Contain(
                "image: guardwithhip/sandbox-worker:${HIP_RELEASE_REVISION:?HIP_RELEASE_REVISION is required}"));
            Assert.That(
                compose,
                Does.Not.Match(@"(?m)^\s+image:\s+(?!guardwithhip/)[^\r\n@]+\r?$"),
                "Every third-party image must be pinned by digest.");
            Assert.That(compose, Does.Contain(
                "HIP_RELEASE_REVISION: ${HIP_RELEASE_REVISION:?HIP_RELEASE_REVISION is required}"));
            Assert.That(compose, Does.Contain(
                "HIP_RELEASE_VERSION: ${HIP_RELEASE_VERSION:?HIP_RELEASE_VERSION is required}"));
            Assert.That(
                sandboxWorkerDockerfile,
                Does.Match(@"(?m)^FROM mcr\.microsoft\.com/dotnet/aspnet:10\.0@sha256:[a-f0-9]{64} AS runtime$"));
            Assert.That(sandboxWorkerDockerfile, Does.Contain("libgssapi-krb5-2"));
            foreach (var dockerfilePath in dockerfiles)
            {
                var dockerfile = File.ReadAllText(dockerfilePath);
                Assert.That(
                    dockerfile,
                    Does.Not.Match(@"(?m)^FROM\s+(?:mcr\.microsoft\.com|quay\.io)/[^\s@]+\s"),
                    dockerfilePath);
                Assert.That(dockerfile, Does.Contain("org.opencontainers.image.revision"), dockerfilePath);
                Assert.That(dockerfile, Does.Contain("org.opencontainers.image.version"), dockerfilePath);
            }

            foreach (var dockerfilePath in dockerfiles.Skip(1).Take(2))
            {
                var dockerfile = File.ReadAllText(dockerfilePath);
                Assert.That(dockerfile, Does.Match(@"ARG OPENSSL_REVISION=[a-f0-9]{40}"), dockerfilePath);
                Assert.That(dockerfile, Does.Match(@"ARG SOFTHSM_REVISION=[a-f0-9]{40}"), dockerfilePath);
                Assert.That(dockerfile, Does.Contain("grep -q '^#define WITH_ML_DSA' config.h"), dockerfilePath);
            }
        });
    }

    private static int Occurrences(string value, string fragment)
    {
        var count = 0;
        var index = 0;
        while ((index = value.IndexOf(fragment, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += fragment.Length;
        }

        return count;
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
