namespace HIP.Domain.Identity;

public sealed record HipIdentity(
    string IdentityId,
    IdentitySubjectType IdentityType,
    string DisplayName,
    string PublicKey,
    string KeyAlgorithm,
    VerificationStatus VerificationStatus,
    DateTimeOffset CreatedAtUtc,
    string ReputationTargetId)
{
    public bool UsesQuantumResistantSigning =>
        KeyAlgorithm.Contains("PQ", StringComparison.OrdinalIgnoreCase) ||
        KeyAlgorithm.Contains("Dilithium", StringComparison.OrdinalIgnoreCase);
}
