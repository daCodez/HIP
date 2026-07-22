using Microsoft.Extensions.Options;

namespace HIP.Web.Security;

/// <summary>
/// Configures the shared, certificate-protected ASP.NET Core Data Protection key ring used by HIP Web sessions.
/// </summary>
/// <remarks>
/// The certificate password is a secret and must be supplied by an environment variable, secret store, or another
/// protected configuration provider. It must never be committed to an appsettings file or written to logs.
/// </remarks>
public sealed class HipSessionProtectionOptions
{
    public const string SectionName = "HipSessionProtection";
    public const int MaxApplicationNameLength = 64;
    public const int MaxPathLength = 4096;
    public const int MaxCertificatePasswordLength = 4096;

    /// <summary>Gets or sets the absolute shared directory that stores the encrypted key ring.</summary>
    public string KeyRingDirectoryPath { get; set; } = string.Empty;

    /// <summary>Gets or sets the absolute path to a PKCS#12 certificate containing a private key.</summary>
    public string CertificatePath { get; set; } = string.Empty;

    /// <summary>Gets or sets the PKCS#12 password supplied by protected configuration.</summary>
    public string CertificatePassword { get; set; } = string.Empty;

    /// <summary>Gets or sets the stable Data Protection application discriminator shared by HIP Web replicas.</summary>
    public string ApplicationName { get; set; } = "HIP.Web";
}

/// <summary>Fails production startup closed when durable encrypted session protection is not configured safely.</summary>
public sealed class HipSessionProtectionOptionsValidator(IHostEnvironment hostEnvironment)
    : IValidateOptions<HipSessionProtectionOptions>
{
    private readonly IHostEnvironment environment =
        hostEnvironment ?? throw new ArgumentNullException(nameof(hostEnvironment));

    public ValidateOptionsResult Validate(string? name, HipSessionProtectionOptions options)
    {
        if (environment.IsDevelopment())
        {
            return ValidateOptionsResult.Success;
        }

        if (options is null)
        {
            return ValidateOptionsResult.Fail("HIP production session-protection options are required.");
        }

        var failures = new List<string>();
        if (!IsSafeAbsolutePath(options.KeyRingDirectoryPath, requirePkcs12: false))
        {
            failures.Add("HIP session key-ring directory must be a non-root absolute path without traversal.");
        }

        if (!IsSafeAbsolutePath(options.CertificatePath, requirePkcs12: true))
        {
            failures.Add("HIP session certificate must be an absolute PKCS#12 path without traversal.");
        }

        if (string.IsNullOrWhiteSpace(options.CertificatePassword) ||
            options.CertificatePassword.Length > HipSessionProtectionOptions.MaxCertificatePasswordLength)
        {
            failures.Add("HIP session certificate password must be supplied by protected configuration.");
        }

        if (!IsSafeApplicationName(options.ApplicationName))
        {
            failures.Add("HIP session application name must be a bounded protocol token.");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }

    private static bool IsSafeAbsolutePath(string? value, bool requirePkcs12)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > HipSessionProtectionOptions.MaxPathLength ||
            !Path.IsPathFullyQualified(value) ||
            ContainsTraversal(value))
        {
            return false;
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(value);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }

        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrWhiteSpace(root) ||
            string.Equals(
                fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
        {
            return false;
        }

        if (!requirePkcs12)
        {
            return true;
        }

        var extension = Path.GetExtension(fullPath);
        return string.Equals(extension, ".pfx", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(extension, ".p12", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsTraversal(string value) => value
        .Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries)
        .Any(segment => string.Equals(segment, "..", StringComparison.Ordinal));

    private static bool IsSafeApplicationName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > HipSessionProtectionOptions.MaxApplicationNameLength)
        {
            return false;
        }

        return value[0] is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' &&
               value[^1] is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' &&
               value.All(character =>
                   character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-' or '_');
    }
}
