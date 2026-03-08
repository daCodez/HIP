using HIP.Protocol.Canonicalization;
using HIP.Protocol.Security.Abstractions;
using HIP.Protocol.Security.Options;
using HIP.Protocol.Security.Services;
using HIP.Protocol.Validation;
using HIP.Protocol.Versioning;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Protocol.Security.Extensions;

public static class HipProtocolSecurityServiceCollectionExtensions
{
    /// <summary>
    /// Registers HIP protocol core services with secure, low-latency defaults.
    /// Caller must provide key material via <paramref name="configureKeys"/>.
    /// </summary>
    public static IServiceCollection AddHipProtocolCore(
        this IServiceCollection services,
        Action<HipSecurityOptions>? configureOptions,
        Action<ICollection<HipSigningKey>> configureKeys)
    {
        var options = new HipSecurityOptions();
        configureOptions?.Invoke(options);
        services.AddSingleton(options);

        var keys = new List<HipSigningKey>();
        configureKeys(keys);

        services.AddSingleton<IHipVersionPolicy>(_ => new HipVersionPolicy(["1.0"]));
        services.AddSingleton<IHipCanonicalSerializer, HipCanonicalSerializer>();
        services.AddSingleton<IHipPayloadHasher, Sha256PayloadHasher>();

        services.AddSingleton<IHipEnvelopeValidator, HipEnvelopeValidator>();
        services.AddSingleton<IHipReceiptValidator, HipReceiptValidator>();

        services.AddSingleton<IHipReplayGuard, InMemoryReplayGuard>();
        services.AddSingleton<IHipTimestampPolicy, HipTimestampPolicy>();
        services.AddSingleton<InMemoryRevocationChecker>();
        services.AddSingleton<IHipRevocationChecker>(sp => sp.GetRequiredService<InMemoryRevocationChecker>());
        services.AddSingleton<IHipKeyLifecycleValidator, HipKeyLifecycleValidator>();

        services.AddSingleton<IHipKeyStore>(_ => new InMemoryHipKeyStore(keys));
        services.AddSingleton<IHipAlgorithmProvider, EcdsaP256AlgorithmProvider>();
        services.AddSingleton<IHipAlgorithmProvider, Ed25519AlgorithmProvider>();

        services.AddSingleton<AlgorithmRouterSigner>();
        services.AddSingleton<IHipSigner>(sp => sp.GetRequiredService<AlgorithmRouterSigner>());
        services.AddSingleton<IHipSignatureVerifier>(sp => sp.GetRequiredService<AlgorithmRouterSigner>());
        services.AddSingleton<IHipKeyResolver>(sp => sp.GetRequiredService<AlgorithmRouterSigner>());

        services.AddSingleton<HipEnvelopeSecurityService>();
        services.AddSingleton<HipReceiptSecurityService>();
        services.AddSingleton<HipChallengeService>();
        services.AddSingleton<HipProtectedMessageProcessor>();

        return services;
    }
}
