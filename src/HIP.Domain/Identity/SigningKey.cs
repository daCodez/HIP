namespace HIP.Domain.Identity;

public sealed record SigningKey(
    string KeyId,
    string Algorithm,
    string PublicKey);
