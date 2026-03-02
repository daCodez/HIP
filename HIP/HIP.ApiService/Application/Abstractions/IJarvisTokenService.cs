namespace HIP.ApiService.Application.Abstractions;

/// <summary>
/// Issues, validates, refreshes, revokes, and consumes Jarvis access/proof tokens.
/// </summary>
public interface IJarvisTokenService
{
    /// <summary>Issues a new access/refresh token pair.</summary>
    Task<TokenIssueResult> IssueAsync(TokenIssueRequest request, CancellationToken cancellationToken);

    /// <summary>Validates an access token for audience/device constraints.</summary>
    Task<TokenValidationResult> ValidateAsync(TokenValidationRequest request, CancellationToken cancellationToken);

    /// <summary>Refreshes token set using a refresh token.</summary>
    Task<TokenRefreshResult> RefreshAsync(TokenRefreshRequest request, CancellationToken cancellationToken);

    /// <summary>Revokes access and/or refresh tokens.</summary>
    Task<TokenRevokeResult> RevokeAsync(TokenRevokeRequest request, CancellationToken cancellationToken);

    /// <summary>Issues a one-time proof token for a specific action.</summary>
    Task<ProofTokenIssueResult> IssueProofTokenAsync(ProofTokenIssueRequest request, CancellationToken cancellationToken);

    /// <summary>Consumes and validates a proof token.</summary>
    Task<ProofTokenConsumeResult> ConsumeProofTokenAsync(ProofTokenConsumeRequest request, CancellationToken cancellationToken);
}

/// <summary>Input contract for token issuance.</summary>
public sealed record TokenIssueRequest(string IdentityId, string Audience, string? DeviceId);

/// <summary>Input contract for token validation.</summary>
public sealed record TokenValidationRequest(string AccessToken, string? Audience, string? DeviceId);

/// <summary>Input contract for token refresh.</summary>
public sealed record TokenRefreshRequest(string RefreshToken);

/// <summary>Input contract for token revocation.</summary>
public sealed record TokenRevokeRequest(string? AccessToken, string? RefreshToken, string? IdentityId);

/// <summary>Successful token issuance payload.</summary>
public sealed record TokenIssueResult(
    string AccessToken,
    DateTimeOffset AccessExpiresAtUtc,
    string RefreshToken,
    DateTimeOffset RefreshExpiresAtUtc,
    string KeyId,
    int KeyVersion,
    string Audience,
    string? DeviceId);

/// <summary>Token validation outcome payload.</summary>
public sealed record TokenValidationResult(bool IsValid, string Reason, string? IdentityId, DateTimeOffset? ExpiresAtUtc, string? KeyId, int? KeyVersion);

/// <summary>Token refresh outcome payload.</summary>
public sealed record TokenRefreshResult(bool Success, string Reason, TokenIssueResult? TokenSet);

/// <summary>Token revoke outcome payload.</summary>
public sealed record TokenRevokeResult(bool Success, string Reason, int RevokedAccessCount, int RevokedRefreshCount);

/// <summary>Input contract for proof-token issuance.</summary>
public sealed record ProofTokenIssueRequest(string IdentityId, string Audience, string? DeviceId, string Action, TimeSpan? Ttl = null);

/// <summary>Input contract for proof-token consumption.</summary>
public sealed record ProofTokenConsumeRequest(string ProofToken, string ExpectedAction, string? Audience, string? DeviceId);

/// <summary>Proof-token issuance outcome payload.</summary>
public sealed record ProofTokenIssueResult(bool Success, string Reason, string? ProofToken, DateTimeOffset? ExpiresAtUtc);

/// <summary>Proof-token consumption outcome payload.</summary>
public sealed record ProofTokenConsumeResult(bool Success, string Reason, string? IdentityId);
