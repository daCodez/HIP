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

        var issueResponse = await client.PostAsJsonAsync("/api/jarvis/token/issue", new JarvisTokenIssueRequestDto("hip-system"));
        var issue = await issueResponse.Content.ReadFromJsonAsync<TokenIssueResult>();

        Assert.That(issueResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(issue, Is.Not.Null);
        Assert.That(issue!.AccessToken, Does.StartWith("atk_"));
        Assert.That(issue.RefreshToken, Does.StartWith("rtk_"));

        var validateResponse = await client.PostAsJsonAsync("/api/jarvis/token/validate", new JarvisTokenValidateRequestDto(issue.AccessToken));
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
    }
}
