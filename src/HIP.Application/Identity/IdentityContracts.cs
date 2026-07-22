using HIP.Domain.Identity;

namespace HIP.Application.Identity;

public sealed record IdentityRegistrationRequest(
    IdentitySubjectType IdentityType,
    string DisplayName,
    string ReputationTargetId);

public sealed record IdentityRegistrationResponse(
    HipIdentity Identity,
    string? DevelopmentPrivateKey,
    string Warning);

/// <summary>
/// Requests development-only signing. A missing key identifier selects the documented initial development key.
/// </summary>
public sealed record SignContentRequest(
    string IdentityId,
    string ContentHash,
    string DevelopmentPrivateKey,
    DateTimeOffset? ExpiresAtUtc,
    string? KeyId = null);

/// <summary>
/// Requests development-only verification with managed-key lifecycle enforcement.
/// </summary>
/// <param name="TrustedSignedAtUtc">Authenticated signing time from a trusted envelope or stored HIP signature; never untrusted request metadata.</param>
public sealed record VerifySignatureRequest(
    string IdentityId,
    string ContentHash,
    string SignatureValue,
    string? KeyId = null,
    DateTimeOffset? TrustedSignedAtUtc = null);

public sealed record WebsiteIdentityRegistrationRequest(
    string Domain,
    string DisplayName,
    VerificationMethod VerificationMethod);

public sealed record WebsiteIdentityRegistrationResponse(
    WebsiteIdentity WebsiteIdentity,
    DomainVerificationRequest VerificationRequest,
    string? DevelopmentPrivateKey,
    string Warning);

public sealed record WebsiteVerificationRequest(
    string Domain,
    VerificationMethod Method,
    string Token);

/// <summary>
/// Result of retrying a stored domain-verification challenge without exposing its token.
/// </summary>
public sealed record DomainVerificationRetryResult(
    DomainVerificationRequest Request,
    DomainVerificationCheckResult Check);

/// <summary>
/// Reason supplied by an authorized owner when revoking domain verification.
/// </summary>
public sealed record DomainVerificationRevokeRequest(string Reason);

/// <summary>
/// Requests signing through the managed legacy signature facade.
/// </summary>
/// <param name="KeyId">Required managed key identifier. Null remains source-compatible but fails clearly at runtime.</param>
public sealed record HipSignatureRequest(
    string IdentityId,
    string ContentHash,
    string DevelopmentPrivateKey,
    DateTimeOffset? ExpiresAtUtc,
    string? KeyId = null);

/// <summary>
/// Requests public verification against immutable managed key history.
/// </summary>
/// <param name="KeyId">Required immutable managed key identifier. Null remains source-compatible but fails clearly at runtime.</param>
/// <param name="TrustedSignedAtUtc">Authenticated signing time from a trusted envelope or stored HIP signature; never untrusted request metadata.</param>
public sealed record HipSignatureVerificationRequest(
    string IdentityId,
    string ContentHash,
    string SignatureValue,
    string? SignerReputationStatus,
    string? KeyId = null,
    DateTimeOffset? TrustedSignedAtUtc = null);
