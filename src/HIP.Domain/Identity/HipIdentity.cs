namespace HIP.Domain.Identity;

public sealed record HipIdentity(
    string Id,
    IdentitySubjectType SubjectType,
    string DisplayName,
    string PublicKeyId,
    SignatureAlgorithmFamily AlgorithmFamily)
{
    public bool UsesQuantumResistantSigning => AlgorithmFamily == SignatureAlgorithmFamily.PostQuantum;
}
