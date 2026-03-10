using System.Net.Http.Json;
using Microsoft.Extensions.Options;

namespace HIP.Agent.Worker;

public sealed class HeartbeatClient(HttpClient httpClient, IOptions<AgentOptions> options, IAgentCredentialStore credentialStore, ILogger<HeartbeatClient> logger)
{
    private readonly AgentOptions _options = options.Value;

    public async Task SendAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_options.BaseUrl))
        {
            logger.LogWarning("Agent:BaseUrl is empty. Skipping heartbeat.");
            return;
        }

        var endpoint = new Uri(new Uri(_options.BaseUrl), _options.HeartbeatPath);
        var credential = await credentialStore.LoadAsync(cancellationToken);
        var token = credential?.BootstrapToken ?? _options.EnrollmentToken;

        var payload = new HeartbeatRequest(
            DeviceId: credential?.DeviceId ?? _options.DeviceId,
            AssignedIdentity: credential?.AssignedIdentity,
            Status: "online",
            TimestampUtc: DateTimeOffset.UtcNow,
            AgentVersion: typeof(HeartbeatClient).Assembly.GetName().Version?.ToString() ?? "0.0.0");

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = JsonContent.Create(payload)
        };

        if (!string.IsNullOrWhiteSpace(token))
        {
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        }

        using var response = await httpClient.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            logger.LogWarning("Heartbeat returned non-success status code: {StatusCode}", (int)response.StatusCode);
            return;
        }

        logger.LogInformation("Heartbeat sent to {Endpoint}", endpoint);
    }
}

public sealed record HeartbeatRequest(
    string DeviceId,
    string? AssignedIdentity,
    string Status,
    DateTimeOffset TimestampUtc,
    string AgentVersion);
