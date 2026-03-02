using System.Net;
using System.Net.Http.Json;
using HIP.ApiService.Infrastructure.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class CryptoConfigEndpointTests
{
    [Test]
    public async Task CryptoConfig_InDevelopment_ReturnsResolvedKeyPathsAndExistenceFlags()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"hip-crypto-test-{Guid.NewGuid():n}");
        var privateDir = Path.Combine(tempRoot, "private");
        var publicDir = Path.Combine(tempRoot, "public");
        Directory.CreateDirectory(privateDir);
        Directory.CreateDirectory(publicDir);

        var keyId = "hip-system";
        var privateKeyPath = Path.Combine(privateDir, $"{keyId}.key");
        var publicKeyPath = Path.Combine(publicDir, $"{keyId}.pub");
        await File.WriteAllTextAsync(privateKeyPath, "PRIVATE-PEM-STUB");
        await File.WriteAllTextAsync(publicKeyPath, "PUBLIC-PEM-STUB");

        try
        {
            await using var app = new WebApplicationFactory<Program>()
                .WithWebHostBuilder(builder =>
                {
                    builder.UseEnvironment("Development");
                    builder.UseSetting("HIP:Crypto:Provider", "ECDsa");
                    builder.UseSetting("HIP:Crypto:PrivateKeyStorePath", privateDir);
                    builder.UseSetting("HIP:Crypto:PublicKeyStorePath", publicDir);
                });

            using (var scope = app.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<HipDbContext>();
                var rec = await db.ReputationSignals.FindAsync("hip-system");
                if (rec is not null)
                {
                    rec.AcceptanceRatio = 1;
                    rec.FeedbackScore = 1;
                    rec.DaysActive = 365;
                    rec.AbuseReports = 0;
                    rec.AuthFailures = 0;
                    rec.SpamFlags = 0;
                    await db.SaveChangesAsync();
                }
            }

            using var client = app.CreateClient();

            var response = await client.GetAsync($"/api/admin/crypto-config?keyId={keyId}");
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

            var result = await response.Content.ReadFromJsonAsync<CryptoConfigResponse>();
            Assert.That(result, Is.Not.Null);
            Assert.That(result!.Provider, Is.EqualTo("ECDsa"));
            Assert.That(result.KeyId, Is.EqualTo(keyId));
            Assert.That(result.PrivateKeyPath, Is.EqualTo(privateKeyPath));
            Assert.That(result.PublicKeyPath, Is.EqualTo(publicKeyPath));
            Assert.That(result.PrivateKeyExists, Is.True);
            Assert.That(result.PublicKeyExists, Is.True);
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                Directory.Delete(tempRoot, recursive: true);
            }
        }
    }

    private sealed record CryptoConfigResponse(
        string Provider,
        string? PrivateKeyStorePath,
        string? PublicKeyStorePath,
        string KeyId,
        string? PrivateKeyPath,
        string? PublicKeyPath,
        bool PrivateKeyExists,
        bool PublicKeyExists);
}
