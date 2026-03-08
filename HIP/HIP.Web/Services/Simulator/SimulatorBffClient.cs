using System.Net.Http.Json;
using HIP.Simulator.Core.Models;

namespace HIP.Web.Services.Simulator;

public sealed class SimulatorBffClient(IHttpClientFactory httpClientFactory)
{
    private readonly HttpClient _client = httpClientFactory.CreateClient("hip-bff");

    public async Task<IReadOnlyList<string>> GetSuitesAsync(CancellationToken ct = default)
        => await _client.GetFromJsonAsync<string[]>("/bff/simulator/suites", ct) ?? [];

    public async Task<IReadOnlyList<ScenarioListItem>> GetScenariosAsync(string? suite, CancellationToken ct = default)
        => await _client.GetFromJsonAsync<ScenarioListItem[]>($"/bff/simulator/scenarios?suite={Uri.EscapeDataString(suite ?? string.Empty)}", ct) ?? [];

    public async Task<string?> StartRunAsync(string? suite, string? scenarioId, int? seed, string? mode = null, CancellationToken ct = default)
    {
        var response = await _client.PostAsJsonAsync("/bff/simulator/run", new { suite, scenarioId, seed, mode }, ct);
        if (!response.IsSuccessStatusCode) return null;
        var payload = await response.Content.ReadFromJsonAsync<RunAccepted>(cancellationToken: ct);
        return payload?.RunId;
    }

    public async Task<RunStatus?> GetRunAsync(string runId, CancellationToken ct = default)
        => await _client.GetFromJsonAsync<RunStatus>($"/bff/simulator/runs/{Uri.EscapeDataString(runId)}", ct);

    public sealed record ScenarioListItem(string Id, string Name, string Suite);
    public sealed record RunAccepted(string RunId, string Status);
    public async Task<bool> CancelRunAsync(string runId, CancellationToken ct = default)
    {
        var response = await _client.PostAsync($"/bff/simulator/runs/{Uri.EscapeDataString(runId)}/cancel", null, ct);
        return response.IsSuccessStatusCode;
    }

    public async Task<IReadOnlyList<RunHistoryItem>> GetHistoryAsync(CancellationToken ct = default)
        => await _client.GetFromJsonAsync<RunHistoryItem[]>("/bff/simulator/runs", ct) ?? [];

    public sealed record RunStatus(string RunId, string Status, SimulationRunResult? Result);
    public sealed record RunHistoryItem(
        string RunId,
        string Status,
        DateTimeOffset StartedUtc,
        DateTimeOffset? CompletedUtc,
        string? Suite,
        string? ScenarioId,
        string? Mode,
        int? Total,
        int? Passed,
        int? Failed,
        int? EventTypes,
        int? Rules,
        int? Fields,
        int? Uncovered,
        int? Invalid);
}
