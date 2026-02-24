using System.Net;
using System.Net.Http.Json;
using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Application.Contracts;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class JarvisTokenEndpointTests
{
    [Test]
    public async Task TokenIssueValidateRefresh_RoundTripWorks()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var issueResponse = await client.PostAsJsonAsync("/api/jarvis/token/issue", new JarvisTokenIssueRequestDto("hip-system", "jarvis-runtime", "device-1"));
        var issue = await issueResponse.Content.ReadFromJsonAsync<TokenIssueResult>();

        Assert.That(issueResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(issue, Is.Not.Null);
        Assert.That(issue!.AccessToken, Does.StartWith("v1."));
        Assert.That(issue.RefreshToken, Does.StartWith("rtk_"));
        Assert.That(issue.Audience, Is.EqualTo("jarvis-runtime"));
        Assert.That(issue.DeviceId, Is.EqualTo("device-1"));
        Assert.That(issue.KeyId, Does.StartWith("jarvis-k"));

        var validateResponse = await client.PostAsJsonAsync("/api/jarvis/token/validate", new JarvisTokenValidateRequestDto(issue.AccessToken, "jarvis-runtime", "device-1"));
        var validate = await validateResponse.Content.ReadFromJsonAsync<TokenValidationResult>();

        Assert.That(validateResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(validate, Is.Not.Null);
        Assert.That(validate!.IsValid, Is.True);

        var refreshResponse = await client.PostAsJsonAsync("/api/jarvis/token/refresh", new JarvisTokenRefreshRequestDto(issue.RefreshToken));
        var refresh = await refreshResponse.Content.ReadFromJsonAsync<TokenRefreshResult>();

        Assert.That(refreshResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(refresh, Is.Not.Null);
        Assert.That(refresh!.Success, Is.True);
        Assert.That(refresh.TokenSet, Is.Not.Null);
        Assert.That(refresh.TokenSet!.AccessToken, Is.Not.EqualTo(issue.AccessToken));

        var revokeResponse = await client.PostAsJsonAsync("/api/jarvis/token/revoke", new JarvisTokenRevokeRequestDto(
            AccessToken: refresh.TokenSet.AccessToken,
            RefreshToken: refresh.TokenSet.RefreshToken,
            IdentityId: null));
        var revoke = await revokeResponse.Content.ReadFromJsonAsync<TokenRevokeResult>();

        Assert.That(revokeResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(revoke, Is.Not.Null);
        Assert.That(revoke!.Success, Is.True);
        Assert.That(revoke.RevokedAccessCount, Is.GreaterThanOrEqualTo(1));
        Assert.That(revoke.RevokedRefreshCount, Is.GreaterThanOrEqualTo(1));

        var validateRevoked = await client.PostAsJsonAsync("/api/jarvis/token/validate", new JarvisTokenValidateRequestDto(refresh.TokenSet.AccessToken, "jarvis-runtime", "device-1"));
        var validateRevokedPayload = await validateRevoked.Content.ReadFromJsonAsync<TokenValidationResult>();

        Assert.That(validateRevoked.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(validateRevokedPayload, Is.Not.Null);
        Assert.That(validateRevokedPayload!.IsValid, Is.False);
        Assert.That(validateRevokedPayload.Reason, Is.EqualTo("soft_revoked"));
    }

    [Test]
    public async Task ProofToken_ConsumesOnce_ThenRejectsReuse()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var issueResponse = await client.PostAsJsonAsync("/api/jarvis/proof/issue", new JarvisProofTokenIssueRequestDto(
            IdentityId: "hip-system",
            Audience: "jarvis-runtime",
            DeviceId: "device-1",
            Action: "tool:camera",
            TtlSeconds: 60));

        var issue = await issueResponse.Content.ReadFromJsonAsync<ProofTokenIssueResult>();
        Assert.That(issueResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(issue, Is.Not.Null);
        Assert.That(issue!.Success, Is.True);
        Assert.That(issue.ProofToken, Is.Not.Null);

        var consumeResponse = await client.PostAsJsonAsync("/api/jarvis/proof/consume", new JarvisProofTokenConsumeRequestDto(
            issue.ProofToken!, "tool:camera", "jarvis-runtime", "device-1"));
        var consume = await consumeResponse.Content.ReadFromJsonAsync<ProofTokenConsumeResult>();

        Assert.That(consumeResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(consume, Is.Not.Null);
        Assert.That(consume!.Success, Is.True);

        var replayConsumeResponse = await client.PostAsJsonAsync("/api/jarvis/proof/consume", new JarvisProofTokenConsumeRequestDto(
            issue.ProofToken!, "tool:camera", "jarvis-runtime", "device-1"));
        var replayConsume = await replayConsumeResponse.Content.ReadFromJsonAsync<ProofTokenConsumeResult>();

        Assert.That(replayConsumeResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(replayConsume, Is.Not.Null);
        Assert.That(replayConsume!.Success, Is.False);
        Assert.That(replayConsume.Reason, Is.EqualTo("already_used"));
    }
}
