using HIP.Application.Protocol;

namespace HIP.Application.Identity;

/// <summary>Legacy identity-crypto boundary retained while identity services migrate to algorithm-specific providers.</summary>
public interface IHipCryptoProvider : IHipSignatureProvider
{
    /// <summary>Generates provider-specific identity key material.</summary>
    HipKeyPair GenerateKeyPair();

    /// <summary>Produces the development content hash used by current identity flows.</summary>
    string HashContent(string content);
}
