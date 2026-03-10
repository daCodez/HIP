using System.Net.Http.Json;
using Microsoft.Extensions.Options;

namespace HIP.Agent.Worker;

public sealed class EnrollmentClient(HttpClient httpClient, IOptions<AgentOptions> options)
{
    private readonly AgentOptions _options = options.Value;

    public async Task<EnrollmentResponse?> EnrollAsync(string enrollmentToken, CancellationToken cancellationToken)
    {
        var endpoint = new Uri(new Uri(_options.BaseUrl), _options.EnrollmentPath);
        var request = new EnrollmentRequest(_options.DeviceId, _options.DeviceName, enrollmentToken);

        using var response = await httpClient.PostAsJsonAsync(endpoint, request, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        return await response.Content.ReadFromJsonAsync<EnrollmentResponse>(cancellationToken: cancellationToken);
    }
}

public sealed record EnrollmentRequest(string DeviceId, string? DeviceName, string EnrollmentToken);

public sealed record EnrollmentResponse(string DeviceId, string AssignedIdentity, string BootstrapToken, DateTimeOffset IssuedAtUtc);
