using System.Net;
using System.Net.Http.Json;
using HIP.Sdk.Models;

namespace HIP.Sdk;

public sealed class HipSdkClient(HttpClient httpClient) : IHipSdkClient
{
    public async Task<StatusResponse> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        var result = await httpClient.GetFromJsonAsync<StatusResponse>("/api/status", cancellationToken)
            ?? throw new InvalidOperationException("HIP status payload was empty.");

        return result;
    }

    public Task<IdentityDto?> GetIdentityAsync(string id, CancellationToken cancellationToken = default)
        => GetNullableAsync<IdentityDto>($"/api/identity/{Uri.EscapeDataString(id)}", cancellationToken);

    public Task<ReputationDto?> GetReputationAsync(string identityId, CancellationToken cancellationToken = default)
        => GetNullableAsync<ReputationDto>($"/api/reputation/{Uri.EscapeDataString(identityId)}", cancellationToken);

    private async Task<T?> GetNullableAsync<T>(string path, CancellationToken cancellationToken) where T : class
    {
        using var response = await httpClient.GetAsync(path, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<T>(cancellationToken);
    }
}
