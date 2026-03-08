using HIP.Protocol.Security.Abstractions;
using HIP.Protocol.Security.Extensions;
using HIP.Simulator.Core.Interfaces;
using HIP.Simulator.Core.Services;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Simulator.Core.Extensions;

public static class SimulatorServiceCollectionExtensions
{
    public static IServiceCollection AddHipSimulatorCore(this IServiceCollection services)
    {
        services.AddHipProtocolCore(
            configureOptions: options =>
            {
                options.AllowedClockSkewSeconds = 300;
                options.ReplayWindowSeconds = 600;
            },
            configureKeys: keys =>
            {
                var sender = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
                var verifier = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
                keys.Add(new HipSigningKey("key-sender", "ECDSA_P256_SHA256", sender));
                keys.Add(new HipSigningKey("hip-http-verifier", "ECDSA_P256_SHA256", verifier));
            });

        services.AddSingleton<IClock, SystemClock>();
        services.AddSingleton<IScenarioLoader, JsonScenarioLoader>();
        services.AddSingleton<IScenarioValidator, ScenarioValidator>();
        services.AddSingleton<IEventGenerator, EventGenerator>();
        services.AddSingleton<IEventInjector, InMemoryEventInjector>();
        services.AddSingleton<IPolicyEvaluator, HipPolicyEvaluatorAdapter>();
        services.AddSingleton<ICoverageAnalyzer, CoverageAnalyzer>();
        services.AddSingleton<IPolicySuggester, PolicySuggester>();
        services.AddSingleton<IReportWriter, JsonReportWriter>();
        services.AddSingleton<IReportWriter, HtmlReportWriter>();
        services.AddSingleton<IReportWriter, MarkdownSuggestionReportWriter>();
        services.AddSingleton<ISimulationExecutionTarget, ApplicationExecutionTarget>();
        services.AddSingleton<ISimulationExecutionTarget, ProtocolExecutionTarget>();
        services.AddSingleton<ISimulationRunner, SimulationRunner>();
        return services;
    }
}
