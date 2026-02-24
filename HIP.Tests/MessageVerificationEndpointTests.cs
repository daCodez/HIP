using System.Net;
using System.Net.Http.Json;
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
}
