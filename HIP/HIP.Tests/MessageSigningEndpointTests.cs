using System.Net;
using System.Net.Http.Json;
using HIP.ApiService.Application.Contracts;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class MessageSigningEndpointTests
{
    [Test]
    public async Task SignMessage_DefaultProvider_ReturnsProviderNotEnabled()
    {
        await using var app = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment("Production");
            });
        using var client = app.CreateClient();

        var payload = new SignMessageRequestDto(
            From: "hip-system",
            To: "target",
            Body: "hello");

        var response = await client.PostAsJsonAsync("/api/messages/sign", payload);
        var result = await response.Content.ReadFromJsonAsync<SignMessageResultDto>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.Success, Is.EqualTo(false));
        Assert.That(result.Reason, Is.EqualTo("provider_not_enabled"));
        Assert.That(result.Message, Is.Null);
    }

    [Test]
    public async Task SignMessage_WithEcdsaAndMissingPrivateKey_ReturnsPrivateKeyNotFound()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"hip-sign-test-{Guid.NewGuid():n}");
        var privateDir = Path.Combine(tempRoot, "private");
        var publicDir = Path.Combine(tempRoot, "public");
        Directory.CreateDirectory(privateDir);
        Directory.CreateDirectory(publicDir);

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
            var payload = new SignMessageRequestDto(
                From: "hip-system",
                To: "target",
                Body: "hello");

            var response = await client.PostAsJsonAsync("/api/messages/sign", payload);
            var result = await response.Content.ReadFromJsonAsync<SignMessageResultDto>();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(result, Is.Not.Null);
            Assert.That(result!.Success, Is.False);
            Assert.That(result.Reason, Is.EqualTo("private_key_not_found"));
            Assert.That(result.Message, Is.Null);
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
