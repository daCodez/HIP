namespace HIP.ApiService.Application.Abstractions;

public interface IJarvisTokenService
{
    TokenIssueResult Issue(string identityId);
    TokenValidationResult Validate(string token);
    TokenRefreshResult Refresh(string refreshToken);
}

public sealed record TokenIssueResult(string AccessToken, DateTimeOffset AccessExpiresAtUtc, string RefreshToken, DateTimeOffset RefreshExpiresAtUtc);
public sealed record TokenValidationResult(bool IsValid, string Reason, string? IdentityId, DateTimeOffset? ExpiresAtUtc);
public sealed record TokenRefreshResult(bool Success, string Reason, TokenIssueResult? TokenSet);
