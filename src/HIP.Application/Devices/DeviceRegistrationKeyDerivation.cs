using System.Security.Cryptography;
using System.Text;
using HIP.Application.Reporting;

namespace HIP.Application.Devices;

/// <summary>Derives exact, domain-separated HMAC scopes without normalizing authenticated consumer identifiers.</summary>
public sealed class DeviceRegistrationKeyDerivation
{
    private static readonly byte[] OwnerDomain = "HIP\0device-registration\0owner\0v1\0"u8.ToArray();
    private readonly IReadOnlyList<byte[]> keys;

    public DeviceRegistrationKeyDerivation(PrivacyHashingOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var legacyKeys = options.LegacyKeys?.ToArray() ?? [];
        if (legacyKeys.Length > PrivacyHashingOptions.MaximumLegacyKeyCount)
        {
            throw new InvalidOperationException(
                $"HIP device-registration hashing supports at most {PrivacyHashingOptions.MaximumLegacyKeyCount} legacy keys.");
        }

        var uniqueKeys = new HashSet<string>(StringComparer.Ordinal);
        var resolvedKeys = new List<byte[]>(PrivacyHashingOptions.MaximumKeyCount);
        AddKey(options.SecretKey, options.AllowDevelopmentKey, uniqueKeys, resolvedKeys);
        foreach (var legacyKey in legacyKeys)
        {
            AddKey(legacyKey, options.AllowDevelopmentKey, uniqueKeys, resolvedKeys);
        }

        keys = Array.AsReadOnly(resolvedKeys.ToArray());
    }

    /// <summary>Returns the current owner partition used by new registrations.</summary>
    public string OwnerScopeId(string ownerId) => OwnerScopeId(ownerId, keys[0]);

    /// <summary>Returns the current owner partition followed by unique legacy partitions used for rotation reads.</summary>
    public IReadOnlyList<string> OwnerScopeIds(string ownerId)
    {
        ArgumentNullException.ThrowIfNull(ownerId);
        return Array.AsReadOnly(keys.Select(candidate => OwnerScopeId(ownerId, candidate)).ToArray());
    }

    private static string OwnerScopeId(string ownerId, byte[] candidateKey)
    {
        ArgumentNullException.ThrowIfNull(ownerId);
        var ownerBytes = Encoding.UTF8.GetBytes(ownerId);
        var input = new byte[OwnerDomain.Length + ownerBytes.Length];
        OwnerDomain.CopyTo(input, 0);
        ownerBytes.CopyTo(input, OwnerDomain.Length);
        var digest = HMACSHA256.HashData(candidateKey, input);
        return $"owner-hmac-sha256-v1:{Convert.ToHexString(digest).ToLowerInvariant()}";
    }

    private static void AddKey(
        string? candidate,
        bool allowDevelopmentKey,
        ISet<string> uniqueKeys,
        ICollection<byte[]> resolvedKeys)
    {
        if (string.IsNullOrWhiteSpace(candidate) ||
            (!allowDevelopmentKey &&
             string.Equals(
                 candidate,
                 Sha256PrivacyHashingService.DevelopmentOnlyKey,
                 StringComparison.Ordinal)))
        {
            throw new InvalidOperationException(
                "HIP device-registration hashing requires configured non-development key material.");
        }

        if (uniqueKeys.Add(candidate))
        {
            resolvedKeys.Add(Encoding.UTF8.GetBytes(candidate));
        }
    }
}
