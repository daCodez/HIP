using HIP.Application.Identity;
using HIP.Domain.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Application.Protocol;

/// <summary>Production launch contract for HIP's externally managed signing authority.</summary>
public sealed class HipManagedSigningReadinessOptions
{
    public const string SectionName = "HipManagedSigning";

    public bool Required { get; init; }

    public string ExpectedIssuerId { get; init; } = string.Empty;

    public string ExpectedKeyId { get; init; } = string.Empty;

    public string ExpectedAlgorithm { get; init; } = MlDsa65SignatureProvider.Algorithm;
}

/// <summary>
/// Fails startup when a V1 deployment requires signing but managed custody,
/// authorization, provider support, or durable public lifecycle state is absent.
/// Providers may additionally prove signing with a fixed non-document challenge; private key material is never requested.
/// </summary>
public static class HipManagedSigningReadiness
{
    public static async Task ValidateAsync(
        IServiceProvider services,
        HipManagedSigningReadinessOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);
        if (!options.Required)
        {
            return;
        }

        var expected = new HipTrustReceiptAuthorizedSigner(
            options.ExpectedIssuerId,
            options.ExpectedKeyId);
        if (!string.Equals(
                options.ExpectedAlgorithm,
                MlDsa65SignatureProvider.Algorithm,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"HIP V1 managed signing requires {MlDsa65SignatureProvider.Algorithm}.");
        }

        using var scope = services.CreateScope();
        var signer = scope.ServiceProvider.GetRequiredService<IManagedTrustReceiptSigner>();
        if (signer is UnavailableManagedTrustReceiptSigner)
        {
            throw new InvalidOperationException(
                "HIP V1 managed signing is required, but no managed-custody signer is registered.");
        }

        var signingKey = await signer.GetSigningKeyAsync(cancellationToken).ConfigureAwait(false);
        if (!string.Equals(signingKey.IssuerId, expected.IssuerId, StringComparison.Ordinal) ||
            !string.Equals(signingKey.KeyId, expected.KeyId, StringComparison.Ordinal) ||
            !string.Equals(signingKey.Algorithm, options.ExpectedAlgorithm, StringComparison.Ordinal) ||
            signingKey.AlgorithmFamily != SignatureAlgorithmFamily.PostQuantum)
        {
            throw new InvalidOperationException(
                "The managed signer metadata does not match the explicitly configured HIP V1 issuer, key, and algorithm.");
        }

        var issuerPolicy = scope.ServiceProvider.GetRequiredService<HipTrustReceiptIssuerPolicy>();
        if (!issuerPolicy.IsAuthorized(signingKey.IssuerId, signingKey.KeyId))
        {
            throw new InvalidOperationException(
                "The configured managed signer is not explicitly authorized to issue HIP trust documents.");
        }

        var runtimePolicy = scope.ServiceProvider.GetRequiredService<SignatureProviderRuntimePolicy>();
        if (runtimePolicy.Environment != SignatureProviderRuntimeEnvironment.Production)
        {
            throw new InvalidOperationException("HIP V1 managed signing requires the production provider policy.");
        }

        var providerFactory = scope.ServiceProvider.GetRequiredService<IHipSignatureProviderFactory>();
        _ = providerFactory.GetRequiredProvider(
            signingKey.Algorithm,
            SignatureProviderOperations.Verify,
            runtimePolicy);

        var lifecycle = scope.ServiceProvider.GetRequiredService<ISigningKeyLifecycleService>();
        var durableKey = await lifecycle.GetRequiredSigningKeyAsync(
                signingKey.IssuerId,
                signingKey.KeyId,
                cancellationToken)
            .ConfigureAwait(false);
        if (!durableKey.CanCreateSignature ||
            !string.Equals(durableKey.Algorithm, signingKey.Algorithm, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The managed signing key is not active in HIP's durable public key lifecycle state.");
        }

        if (signer is IManagedSigningReadinessProbe signingProbe)
        {
            await signingProbe.ValidateSigningAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}
