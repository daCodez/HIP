using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using HIP.ApiService.Application.Contracts;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class AbuseSimulationTests
{
    [Test]
    [Category("Stress")]
    public async Task StatusBurst_TriggersRateLimit429Responses()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        const int totalRequests = 170;
        var tasks = Enumerable.Range(0, totalRequests)
            .Select(_ => client.GetAsync("/api/status"));

        var responses = await Task.WhenAll(tasks);

        var tooMany = responses.Count(r => r.StatusCode == HttpStatusCode.TooManyRequests);
        Assert.That(tooMany, Is.GreaterThan(0), "Expected at least one 429 under burst load.");
    }

    [Test]
    [Category("Stress")]
    public async Task VerifyBurst_WithMalformedSignatures_ReturnsInvalidFormatWithoutCrashing()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"hip-abuse-test-{Guid.NewGuid():n}");
        var privateDir = Path.Combine(tempRoot, "private");
        var publicDir = Path.Combine(tempRoot, "public");
        Directory.CreateDirectory(privateDir);
        Directory.CreateDirectory(publicDir);

        var keyId = "hip-system";
        using (var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            await File.WriteAllTextAsync(Path.Combine(privateDir, $"{keyId}.key"), ecdsa.ExportECPrivateKeyPem());
            await File.WriteAllTextAsync(Path.Combine(publicDir, $"{keyId}.pub"), ecdsa.ExportSubjectPublicKeyInfoPem());
        }

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

            using var client = app.CreateClient();

            var payload = new SignedMessageDto(
                Id: Guid.NewGuid().ToString("n"),
                From: "hip-system",
                To: "target",
                Body: "abuse-sim",
                SignatureBase64: "!!!", // malformed on purpose
                KeyId: keyId,
                CreatedAtUtc: DateTimeOffset.UtcNow);

            const int attempts = 40;
            var tasks = Enumerable.Range(0, attempts)
                .Select(_ => client.PostAsJsonAsync("/api/messages/verify", payload));

            var responses = await Task.WhenAll(tasks);
            Assert.That(responses.All(r => r.StatusCode == HttpStatusCode.OK), Is.True);

            var resultTasks = responses.Select(r => r.Content.ReadFromJsonAsync<VerifyMessageResultDto>());
            var results = await Task.WhenAll(resultTasks);

            Assert.That(results.All(x => x is not null), Is.True);
            Assert.That(results.All(x => x!.IsValid == false), Is.True);
            Assert.That(results.All(x => x!.Reason == "invalid_format"), Is.True);
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                Directory.Delete(tempRoot, recursive: true);
            }
        }
    }
}
