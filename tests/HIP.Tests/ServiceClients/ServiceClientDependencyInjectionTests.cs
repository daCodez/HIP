using HIP.Application;
using HIP.Application.ServiceClients;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Tests.ServiceClients;

/// <summary>Verifies the production application registration surface for service-client lifecycle services.</summary>
public sealed class ServiceClientDependencyInjectionTests
{
    [Test]
    public void AddHipApplication_registers_service_client_cryptography_and_lifecycle_with_safe_lifetimes()
    {
        var services = new ServiceCollection();

        services.AddHipApplication();

        Assert.Multiple(() =>
        {
            AssertDescriptor<IServiceClientCredentialGenerator, CryptographicServiceClientCredentialGenerator>(
                services,
                ServiceLifetime.Singleton);
            AssertDescriptor<IServiceClientSecretProtector, Pbkdf2ServiceClientSecretProtector>(
                services,
                ServiceLifetime.Singleton);
            AssertDescriptor<ServiceClientOwnerScopeDerivation, ServiceClientOwnerScopeDerivation>(
                services,
                ServiceLifetime.Singleton);
            AssertDescriptor<ServiceClientLifecycleService, ServiceClientLifecycleService>(
                services,
                ServiceLifetime.Scoped);
            AssertDescriptor<IServiceClientLifecycleService, RateLimitedServiceClientLifecycleService>(
                services,
                ServiceLifetime.Scoped);
            AssertDescriptor<IServiceClientManagementMutationLimiter, UnavailableServiceClientManagementMutationLimiter>(
                services,
                ServiceLifetime.Singleton);
        });
    }

    private static void AssertDescriptor<TService, TImplementation>(
        IServiceCollection services,
        ServiceLifetime lifetime)
    {
        var descriptor = services.Single(candidate => candidate.ServiceType == typeof(TService));
        Assert.That(descriptor.ImplementationType, Is.EqualTo(typeof(TImplementation)));
        Assert.That(descriptor.Lifetime, Is.EqualTo(lifetime));
    }
}
