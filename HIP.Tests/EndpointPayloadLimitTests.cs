using System.Net;
using System.Net.Http.Json;
using HIP.ApiService.Application.Contracts;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class EndpointPayloadLimitTests
{
    private sealed record PayloadTooLargeErrorDto(string Code, string Reason);

    [Test]
    public async Task SignMessage_RejectsPayloadOverEndpointLimit_WithStandard413Body()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var oversizedBody = new string('x', 150 * 1024);
        var request = new SignMessageRequestDto("alice", "bob", oversizedBody);

        using var response = await client.PostAsJsonAsync("/api/messages/sign", request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.RequestEntityTooLarge));

        var payload = await response.Content.ReadFromJsonAsync<PayloadTooLargeErrorDto>();
        Assert.That(payload, Is.Not.Null);
        Assert.That(payload!.Code, Is.EqualTo("payload.tooLarge"));
        Assert.That(payload.Reason, Is.EqualTo("request payload exceeds configured endpoint limit"));
    }

    [Test]
    public async Task JarvisPolicyEvaluate_RejectsPayloadOverEndpointLimit_WithStandard413Body()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var oversizedText = new string('y', 300 * 1024);
        var request = new JarvisPolicyEvaluationRequestDto(
            IdentityId: "hip-system",
            UserText: oversizedText,
            ContextNote: null,
            ToolName: null,
            RiskLevel: "medium");

        using var response = await client.PostAsJsonAsync("/api/jarvis/policy/evaluate", request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.RequestEntityTooLarge));

        var payload = await response.Content.ReadFromJsonAsync<PayloadTooLargeErrorDto>();
        Assert.That(payload, Is.Not.Null);
        Assert.That(payload!.Code, Is.EqualTo("payload.tooLarge"));
        Assert.That(payload.Reason, Is.EqualTo("request payload exceeds configured endpoint limit"));
    }
}
