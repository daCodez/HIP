namespace HIP.Web.Security;

using Microsoft.Extensions.DependencyInjection.Extensions;

/// <summary>
/// Registers the selected administrator authentication provider behind HIP's stable contract.
/// </summary>
public static class HipAdminAuthenticationServiceExtensions
{
    /// <summary>
    /// Adds one authentication provider implementation for the administrator login flow.
    /// </summary>
    public static IServiceCollection AddHipAdminAuthenticationProvider<TProvider>(this IServiceCollection services)
        where TProvider : class, IHipAdminAuthenticationProvider
    {
        ArgumentNullException.ThrowIfNull(services);
        services.RemoveAll<IHipAdminAuthenticationProvider>();
        services.AddSingleton<IHipAdminAuthenticationProvider, TProvider>();
        return services;
    }
}
