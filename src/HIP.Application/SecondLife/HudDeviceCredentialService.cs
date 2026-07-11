using System.Security.Cryptography;
using System.Text;
using HIP.Application.Reporting;

namespace HIP.Application.SecondLife;

/// <summary>
/// Issues and validates bearer credentials bound to one activated Second Life HUD device.
/// </summary>
public interface IHudDeviceCredentialService
{
    /// <summary>Issues the deterministic credential returned only to the activated HUD.</summary>
    string Issue(string deviceId);

    /// <summary>Validates a supplied credential for the requested device using constant-time comparison.</summary>
    bool IsValid(string deviceId, string? credential);
}

/// <summary>
/// Uses a domain-separated HMAC so credentials need not be stored and device IDs are never authorization by themselves.
/// </summary>
public sealed class HudDeviceCredentialService(PrivacyHashingOptions options) : IHudDeviceCredentialService
{
    private const string CredentialDomain = "hip:hud-device-credential:v1:";
    private readonly byte[] keyBytes = Encoding.UTF8.GetBytes(options.SecretKey);

    /// <inheritdoc />
    public string Issue(string deviceId)
    {
        var normalizedDeviceId = NormalizeDeviceId(deviceId);
        using var hmac = new HMACSHA256(keyBytes);
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(CredentialDomain + normalizedDeviceId)))
            .ToLowerInvariant();
    }

    /// <inheritdoc />
    public bool IsValid(string deviceId, string? credential)
    {
        if (string.IsNullOrWhiteSpace(credential) || credential.Length != 64)
        {
            return false;
        }

        try
        {
            var expected = Convert.FromHexString(Issue(deviceId));
            var supplied = Convert.FromHexString(credential);
            return CryptographicOperations.FixedTimeEquals(expected, supplied);
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static string NormalizeDeviceId(string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId) || deviceId.Length > 128)
        {
            throw new ArgumentException("HUD device ID must contain 1 to 128 characters.", nameof(deviceId));
        }

        return deviceId.Trim().ToLowerInvariant();
    }
}
