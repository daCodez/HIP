using HIP.Web.Security;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace HIP.Tests.Security;

/// <summary>
/// Verifies production session-protection settings fail closed without reading keys or certificates.
/// </summary>
public sealed class HipSessionProtectionOptionsValidatorTests
{
    [Test]
    public void Defaults_use_a_stable_bounded_application_name()
    {
        var options = new HipSessionProtectionOptions();

        Assert.That(options.ApplicationName, Is.EqualTo("HIP.Web"));
    }

    [Test]
    public void Valid_production_configuration_succeeds_without_loading_files()
    {
        var options = ValidOptions();

        var result = Validate(options, Environments.Production);

        Assert.That(result.Succeeded, Is.True);
    }

    [Test]
    public void Development_does_not_require_production_session_protection_settings()
    {
        var result = Validate(new HipSessionProtectionOptions(), Environments.Development);

        Assert.That(result.Succeeded, Is.True);
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("   ")]
    [TestCase("relative/session-keys")]
    public void Missing_or_relative_key_ring_directory_fails(string? keyRingDirectory)
    {
        var options = ValidOptions();
        options.KeyRingDirectoryPath = keyRingDirectory ?? string.Empty;

        Assert.That(Validate(options).Failed, Is.True);
    }

    [Test]
    public void Root_only_key_ring_directory_fails()
    {
        var options = ValidOptions();
        options.KeyRingDirectoryPath = Path.GetPathRoot(Path.GetTempPath())!;

        Assert.That(Validate(options).Failed, Is.True);
    }

    [TestCase("../session-keys")]
    [TestCase("safe/../session-keys")]
    public void Traversal_in_key_ring_directory_fails(string unsafeSuffix)
    {
        var options = ValidOptions();
        options.KeyRingDirectoryPath = Path.Combine(Path.GetTempPath(), unsafeSuffix);

        Assert.That(Validate(options).Failed, Is.True);
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("   ")]
    [TestCase("relative/session-protection.pfx")]
    public void Missing_or_relative_certificate_path_fails(string? certificatePath)
    {
        var options = ValidOptions();
        options.CertificatePath = certificatePath ?? string.Empty;

        Assert.That(Validate(options).Failed, Is.True);
    }

    [Test]
    public void Root_only_certificate_path_fails()
    {
        var options = ValidOptions();
        options.CertificatePath = Path.GetPathRoot(Path.GetTempPath())!;

        Assert.That(Validate(options).Failed, Is.True);
    }

    [TestCase("session-protection.pem")]
    [TestCase("session-protection.crt")]
    [TestCase("session-protection")]
    public void Non_pkcs12_certificate_path_fails(string fileName)
    {
        var options = ValidOptions();
        options.CertificatePath = Path.Combine(Path.GetTempPath(), "hip", "certificates", fileName);

        Assert.That(Validate(options).Failed, Is.True);
    }

    [Test]
    public void Traversal_in_certificate_path_fails()
    {
        var options = ValidOptions();
        options.CertificatePath = Path.Combine(Path.GetTempPath(), "hip", "..", "session-protection.pfx");

        Assert.That(Validate(options).Failed, Is.True);
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("   ")]
    public void Missing_certificate_password_fails(string? certificatePassword)
    {
        var options = ValidOptions();
        options.CertificatePassword = certificatePassword ?? string.Empty;

        Assert.That(Validate(options).Failed, Is.True);
    }

    [TestCase("")]
    [TestCase("   ")]
    [TestCase("HIP Web")]
    [TestCase("HIP/Web")]
    [TestCase(".HIP")]
    [TestCase("HIP.")]
    public void Blank_or_unsafe_application_name_fails(string applicationName)
    {
        var options = ValidOptions();
        options.ApplicationName = applicationName;

        Assert.That(Validate(options).Failed, Is.True);
    }

    [Test]
    public void Oversized_application_name_fails()
    {
        var options = ValidOptions();
        options.ApplicationName = new string('a', HipSessionProtectionOptions.MaxApplicationNameLength + 1);

        Assert.That(Validate(options).Failed, Is.True);
    }

    [Test]
    public void Failure_messages_do_not_echo_paths_or_passwords()
    {
        const string sensitiveMarker = "do-not-disclose-session-secret";
        var options = new HipSessionProtectionOptions
        {
            KeyRingDirectoryPath = sensitiveMarker,
            CertificatePath = sensitiveMarker,
            CertificatePassword = sensitiveMarker,
            ApplicationName = "HIP Web"
        };

        var result = Validate(options);
        var failures = string.Join(" ", result.Failures ?? []);

        Assert.Multiple(() =>
        {
            Assert.That(result.Failed, Is.True);
            Assert.That(failures, Does.Not.Contain(sensitiveMarker));
            Assert.That(failures, Does.Not.Contain(options.CertificatePassword));
        });
    }

    private static HipSessionProtectionOptions ValidOptions() => new()
    {
        KeyRingDirectoryPath = Path.Combine(Path.GetTempPath(), "hip", "session-keys"),
        CertificatePath = Path.Combine(Path.GetTempPath(), "hip", "certificates", "session-protection.pfx"),
        CertificatePassword = "test-placeholder-from-secret-provider",
        ApplicationName = "HIP.Web"
    };

    private static ValidateOptionsResult Validate(
        HipSessionProtectionOptions options,
        string environmentName = "Production") =>
        new HipSessionProtectionOptionsValidator(new TestHostEnvironment(environmentName))
            .Validate(Options.DefaultName, options);

    private sealed class TestHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;

        public string ApplicationName { get; set; } = "HIP.Tests";

        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;

        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
