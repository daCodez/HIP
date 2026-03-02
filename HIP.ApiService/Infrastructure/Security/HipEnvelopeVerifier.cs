using System.Security.Cryptography;
using System.Text;
using HIP.ApiService.Application.Abstractions;
using HIP.ApiService;
using Microsoft.Extensions.Options;

namespace HIP.ApiService.Infrastructure.Security;

/// <summary>
/// Executes the operation for this public API member.
/// </summary>
/// <returns>The operation result.</returns>
public sealed class HipEnvelopeVerifier(
    IOptions<CryptoProviderOptions> cryptoOptions,
    IReplayProtectionService replayProtection) : IHipEnvelopeVerifier
{
    private static readonly TimeSpan MaxFutureSkew = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="httpContext">The httpContext value used by this operation.</param>
    /// <param name="cancellationToken">The cancellationToken value used by this operation.</param>
    /// <returns>The operation result.</returns>
    public async Task<HipEnvelopeVerificationResult> VerifyIfRequiredAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        var origin = httpContext.Request.Headers["x-hip-origin"].ToString();
        if (!string.Equals(origin, "bff", StringComparison.OrdinalIgnoreCase))
        {
            return new HipEnvelopeVerificationResult(true, StatusCodes.Status200OK, "policy.notRequired", "signature not required");
        }

        var identityId = httpContext.Request.Headers["x-hip-identity"].ToString();
        var keyId = httpContext.Request.Headers["x-hip-key-id"].ToString();
        var msgId = httpContext.Request.Headers["x-hip-msg-id"].ToString();
        var nonce = httpContext.Request.Headers["x-hip-nonce"].ToString();
        var issuedAtRaw = httpContext.Request.Headers["x-hip-issued-at"].ToString();
        var expiresAtRaw = httpContext.Request.Headers["x-hip-expires-at"].ToString();
        var signatureBase64 = httpContext.Request.Headers["x-hip-signature"].ToString();

        if (new[] { identityId, keyId, msgId, nonce, issuedAtRaw, expiresAtRaw, signatureBase64 }.Any(string.IsNullOrWhiteSpace))
        {
            return new HipEnvelopeVerificationResult(false, StatusCodes.Status401Unauthorized, "policy.invalidEnvelope", "missing required signature headers");
        }

        if (!long.TryParse(issuedAtRaw, out var issuedUnix) || !long.TryParse(expiresAtRaw, out var expiresUnix))
        {
            return new HipEnvelopeVerificationResult(false, StatusCodes.Status401Unauthorized, "policy.invalidEnvelope", "invalid timestamp headers");
        }

        var now = DateTimeOffset.UtcNow;
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(issuedUnix);
        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(expiresUnix);
        if (expiresAt <= issuedAt)
        {
            return new HipEnvelopeVerificationResult(false, StatusCodes.Status401Unauthorized, "policy.invalidEnvelope", "invalid envelope lifetime");
        }

        if (expiresAt < now || issuedAt > now.Add(MaxFutureSkew))
        {
            return new HipEnvelopeVerificationResult(false, StatusCodes.Status401Unauthorized, "policy.envelopeExpired", "envelope expired or issued in future");
        }

        var publicStore = cryptoOptions.Value.PublicKeyStorePath;
        if (string.IsNullOrWhiteSpace(publicStore))
        {
            return new HipEnvelopeVerificationResult(false, StatusCodes.Status500InternalServerError, "policy.misconfigured", "public key store not configured");
        }

        var publicPath = Path.Combine(publicStore, $"{keyId}.pub");
        if (!File.Exists(publicPath))
        {
            return new HipEnvelopeVerificationResult(false, StatusCodes.Status401Unauthorized, "policy.invalidKey", "public key not found");
        }

        var body = string.Empty;
        if (httpContext.Request.ContentLength is > 0)
        {
            httpContext.Request.EnableBuffering();
            using var reader = new StreamReader(httpContext.Request.Body, Encoding.UTF8, leaveOpen: true);
            body = await reader.ReadToEndAsync(cancellationToken);
            httpContext.Request.Body.Position = 0;
        }

        var bodyHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body))).ToLowerInvariant();
        var pathAndQuery = $"{httpContext.Request.Path}{httpContext.Request.QueryString}";
        var payload = $"{msgId}|{identityId}|{keyId}|{issuedUnix}|{expiresUnix}|{nonce}|{httpContext.Request.Method.ToUpperInvariant()}|{pathAndQuery}|{bodyHash}";

        try
        {
            var pem = await File.ReadAllTextAsync(publicPath, cancellationToken);
            var signature = Convert.FromBase64String(signatureBase64);
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(pem);
            var valid = ecdsa.VerifyData(Encoding.UTF8.GetBytes(payload), signature, HashAlgorithmName.SHA256);
            if (!valid)
            {
                return new HipEnvelopeVerificationResult(false, StatusCodes.Status401Unauthorized, "policy.invalidSignature", "invalid envelope signature");
            }

            if (!await replayProtection.TryConsumeAsync($"env:{msgId}", identityId, cancellationToken))
            {
                return new HipEnvelopeVerificationResult(false, StatusCodes.Status409Conflict, "policy.replayDetected", "envelope replay detected");
            }

            return new HipEnvelopeVerificationResult(true, StatusCodes.Status200OK, "policy.signatureValid", "ok");
        }
        catch
        {
            return new HipEnvelopeVerificationResult(false, StatusCodes.Status401Unauthorized, "policy.invalidSignature", "signature parse/verify failed");
        }
    }
}
