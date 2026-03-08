using System.Collections.Concurrent;
using HIP.Simulator.Core.Interfaces;
using HIP.Simulator.Core.Models;

namespace HIP.Admin.Services;

public sealed class SimulatorAdminService(ISimulationRunner runner, IScenarioLoader loader, ICoverageAnalyzer coverageAnalyzer, IWebHostEnvironment env)
{
    private readonly ConcurrentDictionary<string, SimulationRunResult> _results = new();
    private readonly ConcurrentDictionary<string, string> _status = new();
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _cancellations = new();
    private readonly ConcurrentDictionary<string, SimulationProgressUpdate> _progress = new();

    public string ScenarioRoot => Path.Combine(env.ContentRootPath, "..", "HIP.Simulator.Cli", "scenarios");
    public string ReportRoot => Path.Combine(env.ContentRootPath, "..", "HIP.Simulator.Cli", "out", "admin-runs");

    public Task<IReadOnlyList<string>> GetSuitesAsync(CancellationToken ct = default)
        => loader.ListSuitesAsync(ScenarioRoot, ct);

    public async Task<IReadOnlyList<(string Id, string Name, string Suite)>> GetScenariosAsync(string? suite, CancellationToken ct = default)
    {
        var all = await loader.ListScenariosAsync(ScenarioRoot, ct);
        return string.IsNullOrWhiteSpace(suite)
            ? all
            : all.Where(x => x.Suite.Equals(suite, StringComparison.OrdinalIgnoreCase)).ToArray();
    }

    public async Task<string> StartRunAsync(string? suite, string? scenarioId, int? seed, CancellationToken requestCt = default)
    {
        var runId = CreateRun("running", requestCt, out var cts);

        var progress = new Progress<SimulationProgressUpdate>(p => _progress[runId] = p);
        var options = new SimulationRunOptions
        {
            InputFolder = ScenarioRoot,
            ReportFolder = Path.Combine(ReportRoot, runId),
            Suite = string.IsNullOrWhiteSpace(suite) ? null : suite.Trim(),
            ScenarioId = string.IsNullOrWhiteSpace(scenarioId) ? null : scenarioId.Trim(),
            RandomSeed = seed,
            Progress = progress
        };

        _ = Task.Run(async () =>
        {
            try
            {
                var result = await runner.RunAsync(options, cts.Token);
                _results[runId] = result;
                _status[runId] = "completed";
            }
            catch (OperationCanceledException)
            {
                _status[runId] = "cancelled";
            }
            catch
            {
                _status[runId] = "failed";
            }
            finally
            {
                _cancellations.TryRemove(runId, out _);
            }
        }, CancellationToken.None);

        return runId;
    }

    public Task<string> StartCampaignAsync(string profile, int durationSeconds, int waveIntervalSeconds, int? seed, CancellationToken requestCt = default)
    {
        var runId = CreateRun("running-campaign", requestCt, out var cts);

        _ = Task.Run(async () =>
        {
            try
            {
                var suites = ResolveCampaignSuites(profile);
                var scenarioCatalog = new List<Scenario>();
                foreach (var suite in suites)
                {
                    scenarioCatalog.AddRange(await loader.LoadAsync(ScenarioRoot, suite, null, cts.Token));
                }

                var started = DateTimeOffset.UtcNow;
                var wave = 0;
                var scenarioResults = new List<ScenarioResult>();

                while ((DateTimeOffset.UtcNow - started).TotalSeconds < durationSeconds)
                {
                    cts.Token.ThrowIfCancellationRequested();
                    wave++;

                    for (var i = 0; i < suites.Length; i++)
                    {
                        var suite = suites[i];
                        int? suiteSeed = seed.HasValue ? seed.Value + wave + i : null;
                        _progress[runId] = new SimulationProgressUpdate("campaign-wave", wave, Math.Max(1, durationSeconds / Math.Max(1, waveIntervalSeconds)), suite, $"Wave {wave}: running suite '{suite}'");

                        var run = await runner.RunAsync(new SimulationRunOptions
                        {
                            InputFolder = ScenarioRoot,
                            ReportFolder = Path.Combine(ReportRoot, runId, $"wave-{wave}-{suite}"),
                            Suite = suite,
                            RandomSeed = suiteSeed
                        }, cts.Token);

                        scenarioResults.AddRange(run.Scenarios);
                    }

                    await Task.Delay(TimeSpan.FromSeconds(Math.Max(1, waveIntervalSeconds)), cts.Token);
                }

                var coverage = coverageAnalyzer.Analyze(scenarioCatalog, scenarioResults);
                var merged = new SimulationRunResult(
                    TotalScenarios: scenarioResults.Count,
                    Passed: scenarioResults.Count(x => x.Passed),
                    Failed: scenarioResults.Count(x => !x.Passed),
                    Uncovered: scenarioResults.Count(x => !x.IsCovered && x.IsValid),
                    Invalid: scenarioResults.Count(x => !x.IsValid),
                    SuggestedPoliciesGenerated: scenarioResults.Count(x => x.Suggestion is not null),
                    Scenarios: scenarioResults,
                    Coverage: coverage);

                _results[runId] = merged;
                _status[runId] = "completed";
                _progress[runId] = new SimulationProgressUpdate("campaign-complete", scenarioResults.Count, scenarioResults.Count, null, "Campaign completed");
            }
            catch (OperationCanceledException)
            {
                _status[runId] = "cancelled";
            }
            catch
            {
                _status[runId] = "failed";
            }
            finally
            {
                _cancellations.TryRemove(runId, out _);
            }
        }, CancellationToken.None);

        return Task.FromResult(runId);
    }

    public bool Cancel(string runId)
    {
        if (!_cancellations.TryGetValue(runId, out var cts)) return false;
        _status[runId] = "cancelling";
        cts.Cancel();
        return true;
    }

    public (string Status, SimulationRunResult? Result, SimulationProgressUpdate? Progress, ThreatCoverageSummary? ThreatCoverage) GetRun(string runId)
    {
        var status = _status.TryGetValue(runId, out var s) ? s : "not_found";
        _results.TryGetValue(runId, out var result);
        _progress.TryGetValue(runId, out var progress);
        var threatCoverage = result is null ? null : BuildThreatCoverage(result);
        return (status, result, progress, threatCoverage);
    }

    private string CreateRun(string initialStatus, CancellationToken requestCt, out CancellationTokenSource cts)
    {
        var runId = Guid.NewGuid().ToString("N");
        _status[runId] = initialStatus;
        cts = CancellationTokenSource.CreateLinkedTokenSource(requestCt);
        _cancellations[runId] = cts;
        return runId;
    }

    private static string[] ResolveCampaignSuites(string profile)
        => profile.Trim().ToLowerInvariant() switch
        {
            "aggressive" => ["authentication", "token", "messaging", "session", "reputation", "device", "uncovered"],
            "stealth" => ["authentication", "session", "reputation", "uncovered"],
            "insider" => ["session", "reputation", "uncovered", "invalid"],
            _ => ["authentication", "token", "messaging", "reputation", "session"]
        };

    private ThreatCoverageSummary BuildThreatCoverage(SimulationRunResult result)
    {
        var catalog = LoadThreatCatalog();
        if (catalog.Count == 0)
        {
            return new ThreatCoverageSummary(0, 0, 0, 0, 0, [], []);
        }

        var covered = new List<ThreatCatalogItem>();
        var partial = new List<ThreatCatalogItem>();
        var uncovered = new List<ThreatCatalogItem>();

        foreach (var item in catalog)
        {
            var threatScenarios = result.Scenarios.Where(s => item.ScenarioIds.Contains(s.ScenarioId, StringComparer.OrdinalIgnoreCase)).ToList();
            if (threatScenarios.Count == 0)
            {
                uncovered.Add(item);
                continue;
            }

            var coveredCount = threatScenarios.Count(s => s.IsCovered && s.IsValid);
            if (coveredCount == 0)
            {
                uncovered.Add(item);
            }
            else if (coveredCount < item.ScenarioIds.Count)
            {
                partial.Add(item);
            }
            else
            {
                covered.Add(item);
            }
        }

        var criticalUncovered = uncovered.Count(x => x.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase));
        return new ThreatCoverageSummary(catalog.Count, covered.Count, partial.Count, uncovered.Count, criticalUncovered, uncovered, partial);
    }

    private List<ThreatCatalogItem> LoadThreatCatalog()
    {
        try
        {
            var file = Path.Combine(ScenarioRoot, "threat-catalog.json");
            if (!File.Exists(file)) return [];
            var json = File.ReadAllText(file);
            return System.Text.Json.JsonSerializer.Deserialize<List<ThreatCatalogItem>>(json, new System.Text.Json.JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            }) ?? [];
        }
        catch
        {
            return [];
        }
    }
}
