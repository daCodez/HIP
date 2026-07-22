using System.Security.Cryptography;
using System.Text;
using HIP.Application.Reporting;

namespace HIP.Application.SecondLife;

/// <summary>
/// Issues and validates bearer credentials bound to one activated Second Life HUD device.
/// </summary>
public interface IHudDeviceCredentialService
{
    /// <summary>Issues an opaque credential bound to one license/device activation.</summary>
    string Issue(string licenseId, string deviceId);

    /// <summary>
    /// Validates a supplied credential for the requested device and returns its bound license ID.
    /// </summary>
    /// <param name="deviceId">Device ID from the authorized request resource.</param>
    /// <param name="credential">Opaque credential returned by activation.</param>
    /// <returns>The bound license ID when validation succeeds; otherwise null.</returns>
    string? ValidateAndGetLicenseId(string deviceId, string? credential);
}

/// <summary>
/// Uses a domain-separated HMAC so credentials need not be stored and device IDs are never authorization by themselves.
/// </summary>
public sealed class HudDeviceCredentialService : IHudDeviceCredentialService
{
    private const string CredentialDomain = "hip:hud-device-credential:v2:";
    private const string CredentialVersion = "v2";
    private readonly IReadOnlyList<byte[]> keyBytes;

    /// <summary>Creates a current-first, bounded HUD credential key ring.</summary>
    public HudDeviceCredentialService(PrivacyHashingOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var legacyKeys = options.LegacyKeys?.ToArray() ?? [];
        if (legacyKeys.Length > PrivacyHashingOptions.MaximumLegacyKeyCount)
        {
            throw new InvalidOperationException(
                $"HIP HUD credential validation supports at most {PrivacyHashingOptions.MaximumLegacyKeyCount} legacy keys.");
        }

        var uniqueKeys = new HashSet<string>(StringComparer.Ordinal);
        var resolvedKeys = new List<byte[]>(PrivacyHashingOptions.MaximumKeyCount);
        AddKey(options.SecretKey, options.AllowDevelopmentKey, uniqueKeys, resolvedKeys);
        foreach (var legacyKey in legacyKeys)
        {
            AddKey(legacyKey, options.AllowDevelopmentKey, uniqueKeys, resolvedKeys);
        }

        keyBytes = Array.AsReadOnly(resolvedKeys.ToArray());
    }

    /// <inheritdoc />
    public string Issue(string licenseId, string deviceId)
    {
        var normalizedLicenseId = NormalizeLicenseId(licenseId);
        var normalizedDeviceId = NormalizeDeviceId(deviceId);
        var mac = ComputeMac(keyBytes[0], normalizedLicenseId, normalizedDeviceId);
        return $"{CredentialVersion}.{normalizedLicenseId}.{mac}";
    }

    /// <inheritdoc />
    public string? ValidateAndGetLicenseId(string deviceId, string? credential)
    {
        if (string.IsNullOrWhiteSpace(credential) || credential.Length > 256)
        {
            return null;
        }

        try
        {
            var parts = credential.Split('.', StringSplitOptions.None);
            if (parts.Length != 3 ||
                !string.Equals(parts[0], CredentialVersion, StringComparison.Ordinal) ||
                parts[2].Length != 64)
            {
                return null;
            }

            var normalizedLicenseId = NormalizeLicenseId(parts[1]);
            var normalizedDeviceId = NormalizeDeviceId(deviceId);
            var suppliedMac = Convert.FromHexString(parts[2]);
            var matched = 0;
            foreach (var candidateKey in keyBytes)
            {
                var expectedMac = Convert.FromHexString(ComputeMac(
                    candidateKey,
                    normalizedLicenseId,
                    normalizedDeviceId));
                matched |= CryptographicOperations.FixedTimeEquals(expectedMac, suppliedMac) ? 1 : 0;
            }

            return matched != 0
                ? normalizedLicenseId
                : null;
        }
        catch (ArgumentException)
        {
            return null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static string ComputeMac(byte[] key, string normalizedLicenseId, string normalizedDeviceId)
    {
        var input = Encoding.UTF8.GetBytes(
            $"{CredentialDomain}{normalizedLicenseId.Length}:{normalizedLicenseId}:{normalizedDeviceId}");
        return Convert.ToHexString(HMACSHA256.HashData(key, input)).ToLowerInvariant();
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
                "HIP HUD credential hashing requires configured non-development key material.");
        }

        if (uniqueKeys.Add(candidate))
        {
            resolvedKeys.Add(Encoding.UTF8.GetBytes(candidate));
        }
    }

    private static string NormalizeLicenseId(string licenseId)
    {
        if (string.IsNullOrWhiteSpace(licenseId) ||
            licenseId.Length > 128 ||
            licenseId.Any(character => !char.IsAsciiLetterOrDigit(character) && character != '-'))
        {
            throw new ArgumentException("HUD license ID is invalid.", nameof(licenseId));
        }

        return licenseId.Trim().ToLowerInvariant();
    }

    private static string NormalizeDeviceId(string deviceId)
    {
        var normalized = deviceId?.Trim();
        if (string.IsNullOrWhiteSpace(normalized) || normalized.Length > 128)
        {
            throw new ArgumentException("HUD device ID must contain 1 to 128 characters.", nameof(deviceId));
        }

        return normalized.ToLowerInvariant();
    }
}
