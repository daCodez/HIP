namespace HIP.ApiService.Application.Contracts;

/// <summary>
/// Trust-context payload consumed by Jarvis-facing workflows.
/// </summary>
/// <param name="IdentityId">Identity id represented by this context.</param>
/// <param name="IdentityExists">Whether the identity exists in storage.</param>
/// <param name="ReputationScore">Current reputation score for the identity.</param>
/// <param name="TrustLevel">Derived trust-level label.</param>
/// <param name="CanUseSensitiveTools">Whether sensitive tool usage is allowed.</param>
/// <param name="MemoryRoute">Suggested memory route/policy label.</param>
public sealed record JarvisTrustContextDto(
    string IdentityId,
    bool IdentityExists,
    int ReputationScore,
    string TrustLevel,
    bool CanUseSensitiveTools,
    string MemoryRoute);
