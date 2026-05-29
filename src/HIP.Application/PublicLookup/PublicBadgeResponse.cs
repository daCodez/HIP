using HIP.Domain.Risk;

namespace HIP.Application.PublicLookup;

public sealed record PublicBadgeResponse(
    string Domain,
    int Score,
    RiskStatus Status,
    bool VerifiedDomain,
    DateTimeOffset LastCheckedUtc,
    string PublicLookupUrl,
    string BadgeText,
    string BadgeVariant,
    string IdentityVerificationStatus,
    bool? SignatureValid,
    string? ResponseSignature);
