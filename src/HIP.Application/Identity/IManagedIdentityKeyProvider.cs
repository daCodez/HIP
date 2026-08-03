namespace HIP.Application.Identity;

/// <summary>Public portion of a provider-managed identity key whose private material never leaves custody.</summary>
public sealed record HipManagedIdentityKey(string PublicKey, string Algorithm);

/// <summary>Creates or recovers identity keys through the selected production custody provider.</summary>
public interface IManagedIdentityKeyProvider
{
    /// <summary>Gets the stable provider-managed key for one HIP identity and lifecycle key identifier.</summary>
    Task<HipManagedIdentityKey> GetOrCreateAsync(
        string identityId,
        string keyId,
        CancellationToken cancellationToken);
}
