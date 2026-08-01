namespace HIP.Tests.Infrastructure;

/// <summary>Prevents the reviewable VPS release path from drifting back to Development or floating images.</summary>
public sealed class VpsDeploymentSecurityTests
{
    [Test]
    public void Production_override_removes_public_development_runtime_boundaries()
    {
        var root = RepositoryRoot();
        var overrideSource = File.ReadAllText(Path.Combine(
            root,
            "deploy",
            "vps",
            "compose.production.override.yml"));
        var caddySource = File.ReadAllText(Path.Combine(
            root,
            "deploy",
            "vps",
            "Caddyfile.production"));

        Assert.Multiple(() =>
        {
            Assert.That(overrideSource, Does.Contain("ASPNETCORE_ENVIRONMENT: Production"));
            Assert.That(overrideSource, Does.Contain("DOTNET_ENVIRONMENT: Production"));
            Assert.That(overrideSource, Does.Contain("HipDevelopmentProxy__Enabled: \"false\""));
            Assert.That(overrideSource, Does.Contain("env_file: !reset []"));
            Assert.That(overrideSource, Does.Contain("HipSessionProtection__CertificatePath:"));
            Assert.That(overrideSource, Does.Contain("HipAuthentication__Authority:"));
            Assert.That(caddySource, Does.Not.Contain(
                "header_up X-HIP-Trusted-Staging-Proxy "));
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
