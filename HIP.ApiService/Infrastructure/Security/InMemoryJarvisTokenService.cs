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
}
