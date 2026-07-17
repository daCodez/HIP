namespace HIP.Application.Protocol;

/// <summary>Fail-closed provider selector for HIP signing and verification operations.</summary>
public sealed class HipSignatureProviderFactory : IHipSignatureProviderFactory
{
    private const SignatureProviderOperations KnownOperations =
        SignatureProviderOperations.Sign | SignatureProviderOperations.Verify;
    private readonly IReadOnlyDictionary<string, IHipSignatureProvider> providers;

    /// <summary>Creates a factory from the signature providers registered for the current host.</summary>
    public HipSignatureProviderFactory(IEnumerable<IHipSignatureProvider> providers)
    {
        ArgumentNullException.ThrowIfNull(providers);
        var registered = new Dictionary<string, IHipSignatureProvider>(StringComparer.Ordinal);
        foreach (var provider in providers)
        {
            ArgumentNullException.ThrowIfNull(provider);
            var capabilities = provider.Capabilities ??
                throw new InvalidOperationException("A HIP signature provider did not declare capabilities.");
            ArgumentException.ThrowIfNullOrWhiteSpace(capabilities.Algorithm);
            if (!Enum.IsDefined(capabilities.AlgorithmFamily))
            {
                throw new InvalidOperationException(
                    $"HIP signature provider '{capabilities.Algorithm}' declared an invalid algorithm family.");
            }

            if ((capabilities.SupportedOperations & ~KnownOperations) != 0)
            {
                throw new InvalidOperationException(
                    $"HIP signature provider '{capabilities.Algorithm}' declared unknown operations.");
            }

            if (!registered.TryAdd(capabilities.Algorithm, provider))
            {
                throw new InvalidOperationException(
                    $"Multiple HIP signature providers registered algorithm '{capabilities.Algorithm}'.");
            }
        }

        this.providers = registered;
    }

    /// <inheritdoc />
    public IHipSignatureProvider GetRequiredProvider(
        string algorithm,
        SignatureProviderOperations requiredOperations,
        SignatureProviderRuntimePolicy policy)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithm);
        ArgumentNullException.ThrowIfNull(policy);
        if (requiredOperations == SignatureProviderOperations.None ||
            (requiredOperations & ~KnownOperations) != 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(requiredOperations), requiredOperations,
                "At least one known HIP signature operation is required.");
        }

        if (!policy.Allows(algorithm))
        {
            throw new InvalidOperationException(
                $"HIP signature algorithm '{algorithm}' is disallowed by runtime policy.");
        }

        if (!providers.TryGetValue(algorithm, out var provider))
        {
            throw new NotSupportedException(
                $"No HIP signature provider is registered for algorithm '{algorithm}'.");
        }

        var capabilities = provider.Capabilities;
        if (!capabilities.IsAvailable)
        {
            throw new InvalidOperationException(
                $"HIP signature provider '{algorithm}' is unavailable in the current runtime.");
        }

        if (policy.Environment == SignatureProviderRuntimeEnvironment.Production &&
            capabilities.IsDevelopmentOnly)
        {
            throw new InvalidOperationException(
                $"HIP signature provider '{algorithm}' is development-only and cannot be selected in production.");
        }

        if ((capabilities.SupportedOperations & requiredOperations) != requiredOperations)
        {
            throw new InvalidOperationException(
                $"HIP signature provider '{algorithm}' does not support the required operations '{requiredOperations}'.");
        }

        return provider;
    }
}
