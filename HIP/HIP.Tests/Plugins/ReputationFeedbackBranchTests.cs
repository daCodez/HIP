using System.Net;
using System.Net.Http.Json;
using HIP.ApiService.Infrastructure.Plugins;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests.Plugins;

public sealed class ReputationFeedbackBranchTests
{
    [Test]
    public async Task FeedbackPlugin_DuplicateSubmission_ReturnsConflict()
    {
        const string key = "HIP__Plugins__Enabled__0";
        var original = Environment.GetEnvironmentVariable(key);
        Environment.SetEnvironmentVariable(key, "core.reputation.feedback");

        try
        {
            await using var app = new WebApplicationFactory<Program>();
            using var client = app.CreateClient();

            var req = new ReputationFeedbackPlugin.ReputationFeedbackRequest("dup-user", "suspicious", "email", "dup");
            var first = await client.PostAsJsonAsync("/api/plugins/reputation/feedback", req);
            var second = await client.PostAsJsonAsync("/api/plugins/reputation/feedback", req);

            Assert.That(first.StatusCode, Is.EqualTo(HttpStatusCode.Accepted));
            Assert.That(second.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
        }
        finally
        {
            Environment.SetEnvironmentVariable(key, original);
        }
    }

    [Test]
    public async Task FeedbackPlugin_RateLimit_Returns429()
    {
        const string enabledKey = "HIP__Plugins__Enabled__0";
        const string maxKey = "HIP__ReputationFeedback__MaxPerReporterPerMinute";
        var originalEnabled = Environment.GetEnvironmentVariable(enabledKey);
        var originalMax = Environment.GetEnvironmentVariable(maxKey);
        Environment.SetEnvironmentVariable(enabledKey, "core.reputation.feedback");
        Environment.SetEnvironmentVariable(maxKey, "1");

        try
        {
            await using var app = new WebApplicationFactory<Program>();
            using var client = app.CreateClient();

            var first = await client.PostAsJsonAsync("/api/plugins/reputation/feedback",
                new ReputationFeedbackPlugin.ReputationFeedbackRequest("rl-user-a", "legit", "api", null));
            var second = await client.PostAsJsonAsync("/api/plugins/reputation/feedback",
                new ReputationFeedbackPlugin.ReputationFeedbackRequest("rl-user-b", "legit", "api", null));

            Assert.That(first.StatusCode, Is.EqualTo(HttpStatusCode.Accepted));
            Assert.That(second.StatusCode, Is.EqualTo(HttpStatusCode.TooManyRequests));
        }
        finally
        {
            Environment.SetEnvironmentVariable(enabledKey, originalEnabled);
            Environment.SetEnvironmentVariable(maxKey, originalMax);
        }
    }
    [TestCase("legit", HttpStatusCode.Accepted)]
    [TestCase("suspicious", HttpStatusCode.Accepted)]
    [TestCase("malicious", HttpStatusCode.Accepted)]
    [TestCase("unknown", HttpStatusCode.BadRequest)]
    public async Task FeedbackPlugin_CoversFeedbackBranches(string feedback, HttpStatusCode expected)
    {
        const string key = "HIP__Plugins__Enabled__0";
        var original = Environment.GetEnvironmentVariable(key);
        Environment.SetEnvironmentVariable(key, "core.reputation.feedback");

        try
        {
            await using var app = new WebApplicationFactory<Program>();
            using var client = app.CreateClient();

            var response = await client.PostAsJsonAsync("/api/plugins/reputation/feedback",
                new ReputationFeedbackPlugin.ReputationFeedbackRequest("branch-user", feedback, "tests", "branch-coverage"));

            Assert.That(response.StatusCode, Is.EqualTo(expected));
        }
        finally
        {
            Environment.SetEnvironmentVariable(key, original);
        }
    }

    [Test]
    public async Task FeedbackPlugin_MissingIdentity_ReturnsBadRequest()
    {
        const string key = "HIP__Plugins__Enabled__0";
        var original = Environment.GetEnvironmentVariable(key);
        Environment.SetEnvironmentVariable(key, "core.reputation.feedback");

        try
        {
            await using var app = new WebApplicationFactory<Program>();
            using var client = app.CreateClient();

            var response = await client.PostAsJsonAsync("/api/plugins/reputation/feedback",
                new ReputationFeedbackPlugin.ReputationFeedbackRequest("", "legit"));

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        }
        finally
        {
            Environment.SetEnvironmentVariable(key, original);
        }
    }
}
