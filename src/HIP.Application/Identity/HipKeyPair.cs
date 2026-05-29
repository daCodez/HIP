namespace HIP.Application.Identity;

public sealed record HipKeyPair(
    string PublicKey,
    string PrivateKey,
    string Algorithm,
    bool IsProductionSafe);
