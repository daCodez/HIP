using System.Security.Cryptography;
using System.Text;
using HIP.Application.Identity;
using HIP.Application.Protocol;

namespace HIP.Infrastructure.Protocol;

/// <summary>Creates per-identity ML-DSA-65 keys inside SoftHSM without exporting private material.</summary>
internal sealed class SoftHsmManagedIdentityKeyProvider(ISoftHsmPkcs11Client softHsm)
    : IManagedIdentityKeyProvider
{
    private readonly ISoftHsmPkcs11Client token = softHsm;

    public async Task<HipManagedIdentityKey> GetOrCreateAsync(
        string identityId,
        string keyId,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identityId);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        cancellationToken.ThrowIfCancellationRequested();

        var label = KeyLabel(identityId.Trim(), keyId.Trim());
        var key = await token.GetOrCreateSigningKeyAsync(label, cancellationToken).ConfigureAwait(false);
        return new HipManagedIdentityKey(key.PublicKeyPem, MlDsa65SignatureProvider.Algorithm);
    }

    internal static string KeyLabel(string identityId, string keyId)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes($"{identityId}\n{keyId}"));
        return $"hip-identity-{Convert.ToHexString(digest).ToLowerInvariant()[..32]}";
    }
}
