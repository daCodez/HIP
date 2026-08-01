using HIP.Application;
using HIP.Application.Protocol;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Tests.Protocol;

public sealed class HipManagedSigningReadinessTests
{
    [Test]
    public async Task Disabled_gate_does_not_resolve_signing_services()
    {
        await using var provider = new ServiceCollection().BuildServiceProvider();

        await HipManagedSigningReadiness.ValidateAsync(
            provider,
            new HipManagedSigningReadinessOptions());
    }

    [Test]
    public void Required_gate_rejects_the_unavailable_default_signer()
    {
        var services = new ServiceCollection();
        services.AddHipApplication(allowDevelopmentCryptoProvider: false);
        using var provider = services.BuildServiceProvider();

        var exception = Assert.ThrowsAsync<InvalidOperationException>(() =>
            HipManagedSigningReadiness.ValidateAsync(
                provider,
                new HipManagedSigningReadinessOptions
                {
                    Required = true,
                    ExpectedIssuerId = "hip:production:certificate-authority",
                    ExpectedKeyId = "production-key-1",
                    ExpectedAlgorithm = MlDsa65SignatureProvider.Algorithm
                }));

        Assert.That(exception!.Message, Does.Contain("no managed-custody signer"));
    }

    [Test]
    public void Required_gate_rejects_non_v1_algorithm_before_resolving_signer()
    {
        using var provider = new ServiceCollection().BuildServiceProvider();

        var exception = Assert.ThrowsAsync<InvalidOperationException>(() =>
            HipManagedSigningReadiness.ValidateAsync(
                provider,
                new HipManagedSigningReadinessOptions
                {
                    Required = true,
                    ExpectedIssuerId = "hip:production:certificate-authority",
                    ExpectedKeyId = "production-key-1",
                    ExpectedAlgorithm = "development-ecdsa-p256"
                }));

        Assert.That(exception!.Message, Does.Contain(MlDsa65SignatureProvider.Algorithm));
    }

    [Test]
    public void Both_public_hosts_validate_managed_signing_before_accepting_traffic()
    {
        var root = RepositoryRoot();
        var apiProgram = File.ReadAllText(Path.Combine(root, "src", "HIP.ApiService", "Program.cs"));
        var webProgram = File.ReadAllText(Path.Combine(root, "src", "HIP.Web", "Program.cs"));

        Assert.Multiple(() =>
        {
            Assert.That(apiProgram, Does.Contain("HipManagedSigningReadiness.ValidateAsync"));
            Assert.That(webProgram, Does.Contain("HipManagedSigningReadiness.ValidateAsync"));
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
