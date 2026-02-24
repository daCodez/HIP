using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HIP.ApiService.Application.Abstractions;

namespace HIP.ApiService.Infrastructure.Security;

public sealed class InMemoryJarvisTokenService(IKeyRotationPolicy keyPolicy) : IJarvisTokenService
{
    private static readonly TimeSpan AccessTtl = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan RefreshTtl = TimeSpan.FromHours(12);

    private readonly ConcurrentDictionary<string, RefreshRecord> _refreshByHash = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _consumedProofJti = new();

    public TokenIssueResult Issue(TokenIssueRequest request)
    {
        var key = keyPolicy.Current();
        var now = DateTimeOffset.UtcNow;
        var accessExpiry = now.Add(AccessTtl);
        var refreshExpiry = now.Add(RefreshTtl);

        var claims = new AccessClaims(
            Sub: request.IdentityId,
            Aud: request.Audience,
            Did: request.DeviceId,
            Kid: key.KeyId,
            Ver: key.Version,
            Exp: accessExpiry.ToUnixTimeSeconds(),
            Jti: Guid.NewGuid().ToString("n"));

        var accessToken = SignClaims(claims, key.Secret);
        var refreshToken = $"rtk_{Guid.NewGuid():N}";
        _refreshByHash[Hash(refreshToken)] = new RefreshRecord(request.IdentityId, request.Audience, request.DeviceId, key.KeyId, key.Version, refreshExpiry);

        return new TokenIssueResult(accessToken, accessExpiry, refreshToken, refreshExpiry, key.KeyId, key.Version, request.Audience, request.DeviceId);
    }

    public TokenValidationResult Validate(TokenValidationRequest request)
    {
        if (!TryParseAndVerify<AccessClaims>(request.AccessToken, out var claims, out var reason))
        {
            return new TokenValidationResult(false, reason, null, null, null, null);
        }

        if (claims!.Ver < keyPolicy.MinAcceptedVersion)
        {
            return new TokenValidationResult(false, "soft_revoked", claims.Sub, DateTimeOffset.FromUnixTimeSeconds(claims.Exp), claims.Kid, claims.Ver);
        }

        if (!string.IsNullOrWhiteSpace(request.Audience) && !string.Equals(request.Audience, claims.Aud, StringComparison.Ordinal))
        {
            return new TokenValidationResult(false, "audience_mismatch", claims.Sub, DateTimeOffset.FromUnixTimeSeconds(claims.Exp), claims.Kid, claims.Ver);
        }

        if (!string.IsNullOrWhiteSpace(request.DeviceId) && !string.Equals(request.DeviceId, claims.Did, StringComparison.Ordinal))
        {
            return new TokenValidationResult(false, "device_mismatch", claims.Sub, DateTimeOffset.FromUnixTimeSeconds(claims.Exp), claims.Kid, claims.Ver);
        }

        if (claims.Exp <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
        {
            return new TokenValidationResult(false, "expired", claims.Sub, DateTimeOffset.FromUnixTimeSeconds(claims.Exp), claims.Kid, claims.Ver);
        }

        return new TokenValidationResult(true, "ok", claims.Sub, DateTimeOffset.FromUnixTimeSeconds(claims.Exp), claims.Kid, claims.Ver);
    }

    public TokenRefreshResult Refresh(TokenRefreshRequest request)
    {
        var hash = Hash(request.RefreshToken);
        if (!_refreshByHash.TryRemove(hash, out var record))
        {
            return new TokenRefreshResult(false, "refresh_not_found", null);
        }

        if (record.ExpiresAtUtc <= DateTimeOffset.UtcNow)
        {
            return new TokenRefreshResult(false, "refresh_expired", null);
        }

        var tokenSet = Issue(new TokenIssueRequest(record.IdentityId, record.Audience, record.DeviceId));
        return new TokenRefreshResult(true, "ok", tokenSet);
    }

    public TokenRevokeResult Revoke(TokenRevokeRequest request)
    {
        var revokedRefresh = 0;

        if (!string.IsNullOrWhiteSpace(request.RefreshToken) && _refreshByHash.TryRemove(Hash(request.RefreshToken), out _))
        {
            revokedRefresh++;
        }

        if (!string.IsNullOrWhiteSpace(request.IdentityId))
        {
            foreach (var item in _refreshByHash.Where(x => x.Value.IdentityId == request.IdentityId).ToList())
            {
                if (_refreshByHash.TryRemove(item.Key, out _))
                {
                    revokedRefresh++;
                }
            }
        }

        var revokedAccess = 0;
        if (!string.IsNullOrWhiteSpace(request.AccessToken) && TryParseAndVerify<AccessClaims>(request.AccessToken, out var claims, out _))
        {
            keyPolicy.Rotate(emergency: true);
            revokedAccess = 1;
        }

        var total = revokedAccess + revokedRefresh;
        return total > 0
            ? new TokenRevokeResult(true, "revoked", revokedAccess, revokedRefresh)
            : new TokenRevokeResult(false, "not_found", 0, 0);
    }

    public ProofTokenIssueResult IssueProofToken(ProofTokenIssueRequest request)
    {
        var ttl = request.Ttl ?? TimeSpan.FromMinutes(1);
        if (ttl <= TimeSpan.Zero || ttl > TimeSpan.FromMinutes(5))
        {
            return new ProofTokenIssueResult(false, "invalid_ttl", null, null);
        }

        var key = keyPolicy.Current();
        var exp = DateTimeOffset.UtcNow.Add(ttl);
        var claims = new ProofClaims(request.IdentityId, request.Audience, request.DeviceId, request.Action, key.KeyId, key.Version, exp.ToUnixTimeSeconds(), Guid.NewGuid().ToString("n"));
        var token = SignClaims(claims, key.Secret);
        return new ProofTokenIssueResult(true, "ok", token, exp);
    }

    public ProofTokenConsumeResult ConsumeProofToken(ProofTokenConsumeRequest request)
    {
        if (!TryParseAndVerify(request.ProofToken, out ProofClaims? claims, out var reason))
        {
            return new ProofTokenConsumeResult(false, reason, null);
        }

        if (claims!.Ver < keyPolicy.MinAcceptedVersion)
        {
            return new ProofTokenConsumeResult(false, "soft_revoked", claims.Sub);
        }

        if (claims.Exp <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
        {
            return new ProofTokenConsumeResult(false, "expired", claims.Sub);
        }

        if (!string.Equals(claims.Act, request.ExpectedAction, StringComparison.Ordinal))
        {
            return new ProofTokenConsumeResult(false, "action_mismatch", claims.Sub);
        }

        if (!string.IsNullOrWhiteSpace(request.Audience) && !string.Equals(request.Audience, claims.Aud, StringComparison.Ordinal))
        {
            return new ProofTokenConsumeResult(false, "audience_mismatch", claims.Sub);
        }

        if (!string.IsNullOrWhiteSpace(request.DeviceId) && !string.Equals(request.DeviceId, claims.Did, StringComparison.Ordinal))
        {
            return new ProofTokenConsumeResult(false, "device_mismatch", claims.Sub);
        }

        SweepConsumedProofs();
        if (!_consumedProofJti.TryAdd(claims.Jti, DateTimeOffset.FromUnixTimeSeconds(claims.Exp)))
        {
            return new ProofTokenConsumeResult(false, "already_used", claims.Sub);
        }

        return new ProofTokenConsumeResult(true, "ok", claims.Sub);
    }

    private void SweepConsumedProofs()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var item in _consumedProofJti)
        {
            if (item.Value <= now)
            {
                _consumedProofJti.TryRemove(item.Key, out _);
            }
        }
    }

    private static string Hash(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes);
    }

    private static string SignClaims<T>(T claims, byte[] key)
    {
        var payloadJson = JsonSerializer.Serialize(claims);
        var payload = Encoding.UTF8.GetBytes(payloadJson);
        using var hmac = new HMACSHA256(key);
        var sig = hmac.ComputeHash(payload);
        return $"v1.{Convert.ToBase64String(payload)}.{Convert.ToBase64String(sig)}";
    }

    private bool TryParseAndVerify<T>(string token, out T? claims, out string reason)
    {
        claims = default;
        reason = "invalid_token";

        var parts = token.Split('.', 3);
        if (parts.Length != 3 || parts[0] != "v1") return false;

        try
        {
            var payload = Convert.FromBase64String(parts[1]);
            var signature = Convert.FromBase64String(parts[2]);
            claims = JsonSerializer.Deserialize<T>(payload);
            if (claims is null)
            {
                reason = "invalid_payload";
                return false;
            }

            var kid = claims switch
            {
                AccessClaims ac => ac.Kid,
                ProofClaims pc => pc.Kid,
                _ => null
            };

            if (string.IsNullOrWhiteSpace(kid) || !keyPolicy.TryGet(kid, out var keyMaterial))
            {
                reason = "unknown_key";
                return false;
            }

            using var hmac = new HMACSHA256(keyMaterial.Secret);
            var expected = hmac.ComputeHash(payload);
            if (!CryptographicOperations.FixedTimeEquals(expected, signature))
            {
                reason = "bad_signature";
                return false;
            }

            reason = "ok";
            return true;
        }
        catch
        {
            reason = "invalid_token";
            return false;
        }
    }

    private sealed record RefreshRecord(string IdentityId, string Audience, string? DeviceId, string KeyId, int Version, DateTimeOffset ExpiresAtUtc);
    private sealed record AccessClaims(string Sub, string Aud, string? Did, string Kid, int Ver, long Exp, string Jti);
    private sealed record ProofClaims(string Sub, string Aud, string? Did, string Act, string Kid, int Ver, long Exp, string Jti);
}
