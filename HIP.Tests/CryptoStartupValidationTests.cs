using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class CryptoStartupValidationTests
{
    [Test]
    public void Startup_WithEcdsaAndMissingDirectories_ThrowsInvalidOperationException()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"hip-startup-test-{Guid.NewGuid():n}");
        var missingPrivateDir = Path.Combine(tempRoot, "missing-private");
        var missingPublicDir = Path.Combine(tempRoot, "missing-public");

        using var app = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment("Development");
                builder.UseSetting("HIP:Crypto:Provider", "ECDsa");
                builder.UseSetting("HIP:Crypto:PrivateKeyStorePath", missingPrivateDir);
                builder.UseSetting("HIP:Crypto:PublicKeyStorePath", missingPublicDir);
            });

        var ex = Assert.Throws<InvalidOperationException>(() =>
        {
            using var _ = app.CreateClient();
        });

        Assert.That(ex, Is.Not.Null);
        Assert.That(ex!.Message, Does.Contain("PrivateKeyStorePath"));
        Assert.That(ex.Message, Does.Contain("does not exist"));
    }

    [Test]
    public void Startup_NonDevelopmentWithUnsecuredTransport_ThrowsInvalidOperationException()
    {
        var previous = Environment.GetEnvironmentVariable("ASPIRE_ALLOW_UNSECURED_TRANSPORT");
        Environment.SetEnvironmentVariable("ASPIRE_ALLOW_UNSECURED_TRANSPORT", "true");

        try
        {
            using var app = new WebApplicationFactory<Program>()
                .WithWebHostBuilder(builder =>
                {
                    builder.UseEnvironment("Production");
                    builder.UseSetting("HIP:Crypto:Provider", "Placeholder");
                });

            var ex = Assert.Throws<InvalidOperationException>(() =>
            {
                using var _ = app.CreateClient();
            });

            Assert.That(ex, Is.Not.Null);
            Assert.That(ex!.Message, Does.Contain("ASPIRE_ALLOW_UNSECURED_TRANSPORT must be disabled outside Development"));
        }
        finally
        {
            Environment.SetEnvironmentVariable("ASPIRE_ALLOW_UNSECURED_TRANSPORT", previous);
        }
    }

    [Test]
    public void Startup_DevelopmentWithUnsecuredTransport_DoesNotThrow()
    {
        var previous = Environment.GetEnvironmentVariable("ASPIRE_ALLOW_UNSECURED_TRANSPORT");
        Environment.SetEnvironmentVariable("ASPIRE_ALLOW_UNSECURED_TRANSPORT", "true");

        try
        {
            using var app = new WebApplicationFactory<Program>()
                .WithWebHostBuilder(builder =>
                {
                    builder.UseEnvironment("Development");
                    builder.UseSetting("HIP:Crypto:Provider", "Placeholder");
                });

            Assert.DoesNotThrow(() =>
            {
                using var _ = app.CreateClient();
            });
        }
        finally
        {
            Environment.SetEnvironmentVariable("ASPIRE_ALLOW_UNSECURED_TRANSPORT", previous);
        }
    }
}
