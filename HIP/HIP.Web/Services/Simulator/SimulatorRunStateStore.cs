using System.Text.Json;

namespace HIP.Web.Services.Simulator;

public sealed class SimulatorRunStateStore
{
    private readonly string _statePath;
    private readonly Lock _sync = new();

    public SimulatorRunStateStore()
    {
        var root = "/home/jarvis_bot/.openclaw/workspace/HIP/HIP.Simulator.Cli/out";
        Directory.CreateDirectory(root);
        _statePath = Path.Combine(root, "run-history.json");
    }

    public IReadOnlyList<SimulatorRunHistoryItem> Load()
    {
        lock (_sync)
        {
            if (!File.Exists(_statePath)) return [];
            var json = File.ReadAllText(_statePath);
            return JsonSerializer.Deserialize<List<SimulatorRunHistoryItem>>(json) ?? [];
        }
    }

    public void Upsert(SimulatorRunHistoryItem item)
    {
        lock (_sync)
        {
            var items = Load().ToDictionary(x => x.RunId, StringComparer.OrdinalIgnoreCase);
            items[item.RunId] = item;
            File.WriteAllText(_statePath, JsonSerializer.Serialize(items.Values.OrderByDescending(x => x.StartedUtc), new JsonSerializerOptions { WriteIndented = true }));
        }
    }
}

public sealed record SimulatorRunHistoryItem(
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
