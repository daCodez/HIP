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

public sealed record SignContentRequest(
    string IdentityId,
    string ContentHash,
    string DevelopmentPrivateKey,
    DateTimeOffset? ExpiresAtUtc);

public sealed record VerifySignatureRequest(
    string IdentityId,
    string ContentHash,
    string SignatureValue);

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

public sealed record HipSignatureRequest(
    string IdentityId,
    string ContentHash,
    string DevelopmentPrivateKey,
    DateTimeOffset? ExpiresAtUtc);

public sealed record HipSignatureVerificationRequest(
    string IdentityId,
    string ContentHash,
    string SignatureValue,
    string? SignerReputationStatus);
