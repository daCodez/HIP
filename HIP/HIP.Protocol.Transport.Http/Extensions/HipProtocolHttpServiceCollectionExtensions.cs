using HIP.Protocol.Transport.Http.Mapping;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Protocol.Transport.Http.Extensions;

public static class HipProtocolHttpServiceCollectionExtensions
{
    /// <summary>
    /// Registers HTTP transport mapping components for HIP protocol.
    /// </summary>
    public static IServiceCollection AddHipProtocolHttp(this IServiceCollection services)
    {
        services.AddSingleton<IHipHttpEnvelopeMapper, HipHttpEnvelopeMapper>();
        return services;
    }
}
