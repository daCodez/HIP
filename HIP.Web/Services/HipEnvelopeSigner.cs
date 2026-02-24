using System.Security.Cryptography;
using System.Text;

namespace HIP.Web.Services;

public sealed class HipEnvelopeSigner
{
    public HipEnvelope Build(string identityId, string keyId, string method, string pathAndQuery, string body)
    {
        var msgId = Guid.NewGuid().ToString("n");
        var nonce = Guid.NewGuid().ToString("n");
        var issuedAt = DateTimeOffset.UtcNow;
        var expiresAt = issuedAt.AddMinutes(2);
        var bodyHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body ?? string.Empty))).ToLowerInvariant();

        var payload = $"{msgId}|{identityId}|{keyId}|{issuedAt.ToUnixTimeSeconds()}|{expiresAt.ToUnixTimeSeconds()}|{nonce}|{method.ToUpperInvariant()}|{pathAndQuery}|{bodyHash}";
        var privateKeyPath = $"/home/jarvis_bot/.openclaw/keys/private/{keyId}.key";

        var pem = File.ReadAllText(privateKeyPath);
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(pem);

        var signature = ecdsa.SignData(Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256);
        return new HipEnvelope(msgId, nonce, issuedAt, expiresAt, Convert.ToBase64String(signature));
    }
}

public sealed record HipEnvelope(string MessageId, string Nonce, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc, string SignatureBase64);
