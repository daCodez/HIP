using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace HIP.Agent.Worker;

public sealed class FileEncryptedCredentialStore(IOptions<AgentOptions> options, ILogger<FileEncryptedCredentialStore> logger) : IAgentCredentialStore
{
    private readonly AgentOptions _options = options.Value;

    public async Task<AgentCredential?> LoadAsync(CancellationToken cancellationToken)
    {
        var path = ResolvePath();
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            var cipherText = await File.ReadAllTextAsync(path, cancellationToken);
            var payload = Decrypt(cipherText);
            return JsonSerializer.Deserialize<AgentCredential>(payload);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to load agent credentials from {Path}", path);
            return null;
        }
    }

    public async Task SaveAsync(AgentCredential credential, CancellationToken cancellationToken)
    {
        var path = ResolvePath();
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var json = JsonSerializer.Serialize(credential, new JsonSerializerOptions { WriteIndented = true });
        var cipherText = Encrypt(json);
        await File.WriteAllTextAsync(path, cipherText, cancellationToken);
    }

    private string ResolvePath()
        => string.IsNullOrWhiteSpace(_options.CredentialStorePath)
            ? Path.Combine(AppContext.BaseDirectory, "agent-credentials.enc")
            : _options.CredentialStorePath;

    private static string Encrypt(string plain)
    {
        // TODO(security): replace this placeholder key derivation with OS keychain-backed key material
        // (DPAPI on Windows, Keychain on macOS, libsecret/keyring on Linux).
        // Current implementation is best-effort obfuscation for scaffold purposes.
        using var aes = Aes.Create();
        aes.Key = DeriveKey();
        aes.GenerateIV();

        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        var plainBytes = Encoding.UTF8.GetBytes(plain);
        var encrypted = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

        var payload = new EncryptedPayload(Convert.ToBase64String(aes.IV), Convert.ToBase64String(encrypted));
        return JsonSerializer.Serialize(payload);
    }

    private static string Decrypt(string cipher)
    {
        var payload = JsonSerializer.Deserialize<EncryptedPayload>(cipher)
            ?? throw new InvalidOperationException("Credential file format is invalid.");

        using var aes = Aes.Create();
        aes.Key = DeriveKey();
        aes.IV = Convert.FromBase64String(payload.IV);

        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        var encryptedBytes = Convert.FromBase64String(payload.Data);
        var plain = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
        return Encoding.UTF8.GetString(plain);
    }

    private static byte[] DeriveKey()
    {
        var entropy = $"{Environment.MachineName}:{Environment.UserName}:{Environment.OSVersion}";
        return SHA256.HashData(Encoding.UTF8.GetBytes(entropy));
    }

    private sealed record EncryptedPayload(string IV, string Data);
}
