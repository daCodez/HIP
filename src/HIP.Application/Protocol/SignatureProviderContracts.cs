using HIP.Domain.Identity;

namespace HIP.Application.Protocol;

/// <summary>Signature operations a HIP provider can expose.</summary>
[Flags]
public enum SignatureProviderOperations
{
    None = 0,
    Sign = 1,
    Verify = 2
}

/// <summary>Declares provider mechanics without asserting that signed content is safe or reputable.</summary>
/// <param name="Algorithm">Exact protocol algorithm identifier handled by the provider.</param>
/// <param name="AlgorithmFamily">Cryptographic family declared by the provider.</param>
/// <param name="SupportedOperations">Operations currently exposed by the provider.</param>
/// <param name="IsAvailable">Whether the runtime can currently use the provider.</param>
/// <param name="IsDevelopmentOnly">Whether runtime policy must restrict the provider to development.</param>
public sealed record SignatureProviderCapabilities(
    string Algorithm,
    SignatureAlgorithmFamily AlgorithmFamily,
    SignatureProviderOperations SupportedOperations,
    bool IsAvailable,
    bool IsDevelopmentOnly)
{
    /// <summary>Provider selection proves no safety or reputation property; HIP evaluates those separately.</summary>
    public bool EstablishesSafetyOrReputation => false;
}

/// <summary>Cryptographically agile signing and verification boundary used by HIP protocol operations.</summary>
public interface IHipSignatureProvider
{
    /// <summary>Gets the provider's declared, runtime-testable capabilities.</summary>
    SignatureProviderCapabilities Capabilities { get; }

    /// <summary>Signs a content hash using provider-specific private key material.</summary>
    string SignHash(string contentHash, string privateKey);

    /// <summary>Verifies a content-hash signature using provider-specific public key material.</summary>
    bool VerifySignature(string contentHash, string signatureValue, string publicKey);
}

/// <summary>Runtime boundary applied in addition to an explicit algorithm request.</summary>
public enum SignatureProviderRuntimeEnvironment
{
    Development,
    Production
}

/// <summary>Immutable runtime policy that allowlists exact signature algorithms.</summary>
public sealed class SignatureProviderRuntimePolicy
{
    private readonly HashSet<string> allowedAlgorithms;

    private SignatureProviderRuntimePolicy(
        SignatureProviderRuntimeEnvironment environment,
        IEnumerable<string> allowedAlgorithms)
    {
        Environment = environment;
        this.allowedAlgorithms = new HashSet<string>(StringComparer.Ordinal);
        foreach (var algorithm in allowedAlgorithms ?? throw new ArgumentNullException(nameof(allowedAlgorithms)))
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(algorithm);
            this.allowedAlgorithms.Add(algorithm);
        }
    }

    /// <summary>Gets the runtime environment enforced by this policy.</summary>
    public SignatureProviderRuntimeEnvironment Environment { get; }

    /// <summary>Creates an explicit development allowlist.</summary>
    public static SignatureProviderRuntimePolicy ForDevelopment(params string[] allowedAlgorithms) =>
        new(SignatureProviderRuntimeEnvironment.Development, allowedAlgorithms);

    /// <summary>Creates an explicit production allowlist. Development-only providers remain prohibited.</summary>
    public static SignatureProviderRuntimePolicy ForProduction(params string[] allowedAlgorithms) =>
        new(SignatureProviderRuntimeEnvironment.Production, allowedAlgorithms);

    /// <summary>Returns whether the exact protocol algorithm identifier is allowlisted.</summary>
    public bool Allows(string algorithm) => allowedAlgorithms.Contains(algorithm);
}

/// <summary>Selects a provider only when its algorithm, runtime policy, availability, and capabilities all match.</summary>
public interface IHipSignatureProviderFactory
{
    /// <summary>Returns the explicitly requested provider or fails closed without fallback.</summary>
    IHipSignatureProvider GetRequiredProvider(
        string algorithm,
        SignatureProviderOperations requiredOperations,
        SignatureProviderRuntimePolicy policy);
}
