namespace HIP.ApiService;

public sealed class CryptoProviderOptions
{
    public const string SectionName = "HIP:Crypto";

    public string Provider { get; init; } = "Placeholder";
    public string? PublicKeyStorePath { get; init; }
    public string? PrivateKeyStorePath { get; init; }
}
