using System.Text;
using HIP.Application.Reporting;

namespace HIP.Infrastructure.Security;

/// <summary>Builds a bounded current-first HMAC key ring for distributed service-client limiters.</summary>
internal static class ServiceClientLimiterPrivacyKeyRing
{
    /// <summary>
    /// Returns the current key followed by exact, deduplicated legacy keys. Omitting legacy keys intentionally
    /// provides the emergency option to stop overlap with an older key immediately.
    /// </summary>
    public static IReadOnlyList<byte[]> Resolve(PrivacyHashingOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var legacyKeys = options.LegacyKeys ?? [];
        if (legacyKeys.Count > PrivacyHashingOptions.MaximumLegacyKeyCount)
        {
            throw new InvalidOperationException(
                $"Service-client limiting supports at most {PrivacyHashingOptions.MaximumLegacyKeyCount} legacy privacy keys.");
        }

        var uniqueKeys = new HashSet<string>(StringComparer.Ordinal);
        var resolvedKeys = new List<byte[]>(PrivacyHashingOptions.MaximumKeyCount);
        AddKey(options.SecretKey, options.AllowDevelopmentKey, uniqueKeys, resolvedKeys);
        foreach (var legacyKey in legacyKeys)
        {
            AddKey(legacyKey, options.AllowDevelopmentKey, uniqueKeys, resolvedKeys);
        }

        return Array.AsReadOnly(resolvedKeys.ToArray());
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
                "Service-client limiting requires configured privacy HMAC key material.");
        }

        if (uniqueKeys.Add(candidate))
        {
            resolvedKeys.Add(Encoding.UTF8.GetBytes(candidate));
        }
    }
}
