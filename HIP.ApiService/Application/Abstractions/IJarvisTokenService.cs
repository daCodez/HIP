namespace HIP.ApiService.Application.Abstractions;

public interface IJarvisTokenService
{
    TokenIssueResult Issue(TokenIssueRequest request);
    TokenValidationResult Validate(TokenValidationRequest request);
    TokenRefreshResult Refresh(TokenRefreshRequest request);
    TokenRevokeResult Revoke(TokenRevokeRequest request);
    ProofTokenIssueResult IssueProofToken(ProofTokenIssueRequest request);
    ProofTokenConsumeResult ConsumeProofToken(ProofTokenConsumeRequest request);
}

public sealed record TokenIssueRequest(string IdentityId, string Audience, string? DeviceId);
public sealed record TokenValidationRequest(string AccessToken, string? Audience, string? DeviceId);
public sealed record TokenRefreshRequest(string RefreshToken);
public sealed record TokenRevokeRequest(string? AccessToken, string? RefreshToken, string? IdentityId);

public sealed record TokenIssueResult(
    string AccessToken,
    DateTimeOffset AccessExpiresAtUtc,
    string RefreshToken,
    DateTimeOffset RefreshExpiresAtUtc,
    string KeyId,
    int KeyVersion,
    string Audience,
    string? DeviceId);

public sealed record TokenValidationResult(bool IsValid, string Reason, string? IdentityId, DateTimeOffset? ExpiresAtUtc, string? KeyId, int? KeyVersion);
public sealed record TokenRefreshResult(bool Success, string Reason, TokenIssueResult? TokenSet);
public sealed record TokenRevokeResult(bool Success, string Reason, int RevokedAccessCount, int RevokedRefreshCount);

public sealed record ProofTokenIssueRequest(string IdentityId, string Audience, string? DeviceId, string Action, TimeSpan? Ttl = null);
public sealed record ProofTokenConsumeRequest(string ProofToken, string ExpectedAction, string? Audience, string? DeviceId);
public sealed record ProofTokenIssueResult(bool Success, string Reason, string? ProofToken, DateTimeOffset? ExpiresAtUtc);
public sealed record ProofTokenConsumeResult(bool Success, string Reason, string? IdentityId);
