using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using HIP.ApiService.Application.Contracts;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class MessageVerificationEndpointTests
{
    [Test]
    public async Task VerifySignedMessage_DefaultProvider_ReturnsProviderNotEnabled()
    {
        await using var app = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment("Production");
            });
        using var client = app.CreateClient();

        var payload = new SignedMessageDto(
            Id: Guid.NewGuid().ToString("n"),
            From: "hip-system",
            To: "target",
            Body: "hello",
            SignatureBase64: Convert.ToBase64String(new byte[64]));

        var response = await client.PostAsJsonAsync("/api/messages/verify", payload);
        var result = await response.Content.ReadFromJsonAsync<VerifyMessageResultDto>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.IsValid, Is.EqualTo(false));
        Assert.That(result.Reason, Is.EqualTo("provider_not_enabled"));
    }

    [Test]
    public async Task SignAndVerify_WithKeyRotationKeyId_WorksWithVersionedKeyFiles()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"hip-verify-test-{Guid.NewGuid():n}");
        var privateDir = Path.Combine(tempRoot, "private");
        var publicDir = Path.Combine(tempRoot, "public");
        Directory.CreateDirectory(privateDir);
        Directory.CreateDirectory(publicDir);

        var keyId = "hip-system-v2";
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

            var signRequest = new SignMessageRequestDto(
                From: "hip-system",
                To: "target",
                Body: "hello rotated key",
                KeyId: keyId);

            var signResponse = await client.PostAsJsonAsync("/api/messages/sign", signRequest);
            var signed = await signResponse.Content.ReadFromJsonAsync<SignMessageResultDto>();

            Assert.That(signResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(signed, Is.Not.Null);
            Assert.That(signed!.Success, Is.True);
            Assert.That(signed.Message, Is.Not.Null);
            Assert.That(signed.Message!.KeyId, Is.EqualTo(keyId));

            var verifyResponse = await client.PostAsJsonAsync("/api/messages/verify", signed.Message);
            var verify = await verifyResponse.Content.ReadFromJsonAsync<VerifyMessageResultDto>();

            Assert.That(verifyResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(verify, Is.Not.Null);
            Assert.That(verify!.IsValid, Is.True);
            Assert.That(verify.Reason, Is.EqualTo("ok"));

            var replayResponse = await client.PostAsJsonAsync("/api/messages/verify", signed.Message);
            var replay = await replayResponse.Content.ReadFromJsonAsync<VerifyMessageResultDto>();

            Assert.That(replayResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(replay, Is.Not.Null);
            Assert.That(replay!.IsValid, Is.False);
            Assert.That(replay.Reason, Is.EqualTo("replay_detected"));
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
