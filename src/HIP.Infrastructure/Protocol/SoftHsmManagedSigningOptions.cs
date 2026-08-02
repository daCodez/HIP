namespace HIP.Infrastructure.Protocol;

/// <summary>Configuration for HIP's software-backed PKCS #11 signing provider.</summary>
public sealed class SoftHsmManagedSigningOptions
{
    public const string ProviderName = "SoftHsm";

    public string LibraryPath { get; init; } = string.Empty;

    public string TokenLabel { get; init; } = string.Empty;

    public string UserPinFilePath { get; init; } = string.Empty;

    public string KeyLabel { get; init; } = string.Empty;

    public string ProvisioningLockFilePath { get; init; } = string.Empty;

    public bool ProvisionKeyIfMissing { get; init; }

    internal string? Validate()
    {
        if (!Path.IsPathFullyQualified(LibraryPath))
        {
            return "SoftHSM library path must be absolute.";
        }

        if (!Path.IsPathFullyQualified(UserPinFilePath))
        {
            return "SoftHSM user PIN file path must be absolute.";
        }

        if (string.IsNullOrWhiteSpace(TokenLabel) || TokenLabel.Trim().Length > 32)
        {
            return "SoftHSM token label must contain between 1 and 32 characters.";
        }

        if (string.IsNullOrWhiteSpace(KeyLabel) || KeyLabel.Trim().Length > 64)
        {
            return "SoftHSM key label must contain between 1 and 64 characters.";
        }

        if (ProvisionKeyIfMissing && !Path.IsPathFullyQualified(ProvisioningLockFilePath))
        {
            return "SoftHSM provisioning lock path must be absolute when automatic key creation is enabled.";
        }

        return null;
    }
}
