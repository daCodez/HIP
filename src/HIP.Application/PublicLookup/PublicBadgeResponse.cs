using HIP.Domain.Risk;

namespace HIP.Application.PublicLookup;

public sealed record PublicBadgeResponse(
    string Domain,
    int Score,
    RiskStatus Status,
    bool VerifiedDomain,
    DateTimeOffset LastCheckedUtc,
    string LookupUrl,
    string PublicLookupUrl,
    string BadgeText,
    string BadgeVariant,
    string IdentityVerificationStatus,
    bool? SignatureValid,
    string VerifiedMeaning,
    string? ResponseSignature);
