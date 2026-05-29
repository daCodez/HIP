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
