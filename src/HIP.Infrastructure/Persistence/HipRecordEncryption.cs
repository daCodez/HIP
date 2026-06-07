using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HIP.Infrastructure.Persistence;

/// <summary>
/// Configuration for HIP JSON record encryption.
/// </summary>
/// <param name="Key">Configuration-backed encryption key. Production must supply a strong non-demo value.</param>
/// <param name="AllowDevelopmentKey">Whether the built-in development key may be used.</param>
public sealed record HipRecordEncryptionOptions(
    string Key = DevelopmentHipRecordEncryptor.DevelopmentOnlyKey,
    bool AllowDevelopmentKey = true);

/// <summary>
/// Encrypts and decrypts JSON payloads stored in HIP's generic record table.
/// </summary>
public interface IHipRecordEncryptor
{
    /// <summary>
    /// Encrypts a serialized record payload for database storage.
    /// </summary>
    /// <param name="plaintextJson">Plain JSON produced by HIP serializers.</param>
    /// <returns>Encrypted JSON envelope with version metadata.</returns>
    string Protect(string plaintextJson);

    /// <summary>
    /// Decrypts an encrypted envelope or returns legacy plaintext JSON unchanged.
    /// </summary>
    /// <param name="storedPayload">Payload from the database record column.</param>
    /// <returns>Plain JSON for deserialization.</returns>
    string Unprotect(string storedPayload);
}

/// <summary>
/// AES-GCM record encryptor for HIP's development SQLite persistence foundation.
/// </summary>
/// <remarks>
/// This encrypts the record JSON before storage and keeps a versioned envelope so future key rotation can be added.
/// It also reads old plaintext development records to preserve compatibility during the transition.
/// </remarks>
public sealed class DevelopmentHipRecordEncryptor : IHipRecordEncryptor
{
    /// <summary>
    /// Development-only fallback encryption key. Production hosts must override this through configuration.
    /// </summary>
    public const string DevelopmentOnlyKey = "HIP-DEV-ONLY-RECORD-ENCRYPTION-KEY-CHANGE-BEFORE-PRODUCTION";

    private const string EnvelopeMarker = "hip-record-envelope";
    private readonly byte[] keyBytes;

    /// <summary>
    /// Creates an AES-GCM record encryptor and refuses demo keys when the host disables them.
    /// </summary>
    /// <param name="options">Encryption options supplied by the host.</param>
    /// <exception cref="InvalidOperationException">Thrown when a demo key is used outside local Development.</exception>
    public DevelopmentHipRecordEncryptor(HipRecordEncryptionOptions? options = null)
    {
        var resolved = options ?? new HipRecordEncryptionOptions();
        if (!resolved.AllowDevelopmentKey && IsDevelopmentKey(resolved.Key))
        {
            throw new InvalidOperationException("HIP Record encryption key requires a non-default key outside local Development.");
        }

        keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(resolved.Key));
    }

    /// <inheritdoc />
    public string Protect(string plaintextJson)
    {
        ArgumentNullException.ThrowIfNull(plaintextJson);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plaintext = Encoding.UTF8.GetBytes(plaintextJson);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];

        using var aes = new AesGcm(keyBytes, tag.Length);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        return JsonSerializer.Serialize(new HipEncryptedRecordEnvelope(
            EnvelopeMarker,
            Version: 1,
            Algorithm: "AES-256-GCM",
            KeyId: "configured-v1",
            Nonce: Convert.ToBase64String(nonce),
            Ciphertext: Convert.ToBase64String(ciphertext),
            Tag: Convert.ToBase64String(tag)));
    }

    /// <inheritdoc />
    public string Unprotect(string storedPayload)
    {
        ArgumentNullException.ThrowIfNull(storedPayload);
        if (!LooksLikeEnvelope(storedPayload))
        {
            return storedPayload;
        }

        var envelope = JsonSerializer.Deserialize<HipEncryptedRecordEnvelope>(storedPayload)
            ?? throw new InvalidOperationException("HIP encrypted record envelope could not be read.");
        if (envelope.Type != EnvelopeMarker || envelope.Version != 1 || envelope.Algorithm != "AES-256-GCM")
        {
            throw new InvalidOperationException("HIP encrypted record envelope version is not supported.");
        }

        var nonce = Convert.FromBase64String(envelope.Nonce);
        var ciphertext = Convert.FromBase64String(envelope.Ciphertext);
        var tag = Convert.FromBase64String(envelope.Tag);
        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(keyBytes, tag.Length);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return Encoding.UTF8.GetString(plaintext);
    }

    /// <summary>
    /// Checks whether a stored string is a HIP encryption envelope without logging or parsing decrypted content.
    /// </summary>
    /// <param name="storedPayload">Stored database value.</param>
    /// <returns>True when the payload appears to be an encrypted HIP envelope.</returns>
    private static bool LooksLikeEnvelope(string storedPayload) =>
        storedPayload.Contains(EnvelopeMarker, StringComparison.Ordinal);

    /// <summary>
    /// Checks whether the configured key is the built-in demo key.
    /// </summary>
    /// <param name="key">Configured key.</param>
    /// <returns>True when the key is missing or the demo key.</returns>
    private static bool IsDevelopmentKey(string? key) =>
        string.IsNullOrWhiteSpace(key) ||
        key.Equals(DevelopmentOnlyKey, StringComparison.Ordinal);

    /// <summary>
    /// Versioned encrypted record envelope stored inside the existing JSON column.
    /// </summary>
    /// <param name="Type">Envelope marker.</param>
    /// <param name="Version">Envelope version for future key rotation support.</param>
    /// <param name="Algorithm">Encryption algorithm.</param>
    /// <param name="KeyId">Configuration key identifier.</param>
    /// <param name="Nonce">Base64 AES-GCM nonce.</param>
    /// <param name="Ciphertext">Base64 encrypted JSON.</param>
    /// <param name="Tag">Base64 authentication tag.</param>
    private sealed record HipEncryptedRecordEnvelope(
        string Type,
        int Version,
        string Algorithm,
        string KeyId,
        string Nonce,
        string Ciphertext,
        string Tag);
}
