using HIP.Application.Administration;
using HIP.Application.Reporting;
using HIP.Application.SecondLife;
using HIP.Domain.Audit;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HIP.Tests;

/// <summary>
/// Supplies the non-policy collaborators required when a focused test registers HIP's complete authorization handler set.
/// Production hosts resolve these boundaries from the application and infrastructure registrations instead.
/// </summary>
internal static class HipAuthorizationTestServices
{
    public static IServiceCollection AddHipAuthorizationTestDependencies(this IServiceCollection services)
    {
        services.TryAddSingleton<IAdminAccessRepository, EmptyAdminAccessRepository>();
        services.TryAddSingleton<ISetupCodeLicenseService, InMemorySetupCodeLicenseService>();
        services.TryAddSingleton<IHudDeviceCredentialService>(new HudDeviceCredentialService(
            new PrivacyHashingOptions("test-only-HUD-authorization-key", AllowDevelopmentKey: true)));
        return services;
    }

    private sealed class EmptyAdminAccessRepository : IAdminAccessRepository
    {
        public Task<AdminAccessDirectory?> GetAsync(CancellationToken cancellationToken) =>
            Task.FromResult<AdminAccessDirectory?>(null);

        public Task<bool> TrySaveAsync(
            AdminAccessDirectory directory,
            long expectedVersion,
            AuditLogEntry auditEntry,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException("Focused authorization tests do not mutate administrator access.");
    }
}
