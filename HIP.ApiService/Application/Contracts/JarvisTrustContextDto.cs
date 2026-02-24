namespace HIP.ApiService.Application.Contracts;

public sealed record JarvisTrustContextDto(
    string IdentityId,
    bool IdentityExists,
    int ReputationScore,
    string TrustLevel,
    bool CanUseSensitiveTools,
    string MemoryRoute);
