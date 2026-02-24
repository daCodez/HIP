using System.Collections.Concurrent;
using HIP.ApiService.Application.Abstractions;

namespace HIP.ApiService.Infrastructure.Security;

public sealed class InMemoryJarvisTokenService : IJarvisTokenService
{
    private static readonly TimeSpan AccessTtl = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan RefreshTtl = TimeSpan.FromHours(12);

    private readonly ConcurrentDictionary<string, (string IdentityId, DateTimeOffset ExpiresAtUtc)> _access = new();
    private readonly ConcurrentDictionary<string, (string IdentityId, DateTimeOffset ExpiresAtUtc)> _refresh = new();

    public TokenIssueResult Issue(string identityId)
    {
        var now = DateTimeOffset.UtcNow;
        var accessToken = $"atk_{Guid.NewGuid():N}";
        var refreshToken = $"rtk_{Guid.NewGuid():N}";

        var accessExpiry = now.Add(AccessTtl);
        var refreshExpiry = now.Add(RefreshTtl);

        _access[accessToken] = (identityId, accessExpiry);
        _refresh[refreshToken] = (identityId, refreshExpiry);

        return new TokenIssueResult(accessToken, accessExpiry, refreshToken, refreshExpiry);
    }

    public TokenValidationResult Validate(string token)
    {
        if (!_access.TryGetValue(token, out var item))
        {
            return new TokenValidationResult(false, "not_found", null, null);
        }

        if (item.ExpiresAtUtc <= DateTimeOffset.UtcNow)
        {
            _access.TryRemove(token, out _);
            return new TokenValidationResult(false, "expired", item.IdentityId, item.ExpiresAtUtc);
        }

        return new TokenValidationResult(true, "ok", item.IdentityId, item.ExpiresAtUtc);
    }

    public TokenRefreshResult Refresh(string refreshToken)
    {
        if (!_refresh.TryGetValue(refreshToken, out var item))
        {
            return new TokenRefreshResult(false, "refresh_not_found", null);
        }

        if (item.ExpiresAtUtc <= DateTimeOffset.UtcNow)
        {
            _refresh.TryRemove(refreshToken, out _);
            return new TokenRefreshResult(false, "refresh_expired", null);
        }

        _refresh.TryRemove(refreshToken, out _);
        var newSet = Issue(item.IdentityId);
        return new TokenRefreshResult(true, "ok", newSet);
    }

    public TokenRevokeResult Revoke(TokenRevokeRequest request)
    {
        if (request is null)
        {
            return new TokenRevokeResult(false, "invalid_request", 0, 0);
        }

        var revokedAccess = 0;
        var revokedRefresh = 0;

        if (!string.IsNullOrWhiteSpace(request.AccessToken) && _access.TryRemove(request.AccessToken, out _))
        {
            revokedAccess++;
        }

        if (!string.IsNullOrWhiteSpace(request.RefreshToken) && _refresh.TryRemove(request.RefreshToken, out _))
        {
            revokedRefresh++;
        }

        if (!string.IsNullOrWhiteSpace(request.IdentityId))
        {
            foreach (var item in _access.Where(x => x.Value.IdentityId == request.IdentityId).ToList())
            {
                if (_access.TryRemove(item.Key, out _))
                {
                    revokedAccess++;
                }
            }

            foreach (var item in _refresh.Where(x => x.Value.IdentityId == request.IdentityId).ToList())
            {
                if (_refresh.TryRemove(item.Key, out _))
                {
                    revokedRefresh++;
                }
            }
        }

        var total = revokedAccess + revokedRefresh;
        return total > 0
            ? new TokenRevokeResult(true, "revoked", revokedAccess, revokedRefresh)
            : new TokenRevokeResult(false, "not_found", 0, 0);
    }
}
