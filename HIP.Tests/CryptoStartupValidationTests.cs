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
}
