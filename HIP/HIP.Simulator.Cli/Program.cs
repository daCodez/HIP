using HIP.Simulator.Core.Extensions;
using HIP.Simulator.Core.Interfaces;
using HIP.Simulator.Core.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddLogging();
builder.Services.AddHipSimulatorCore();

using var host = builder.Build();

var cmd = args.FirstOrDefault()?.ToLowerInvariant() ?? "run";
var rest = args.Skip(1).ToArray();

var loader = host.Services.GetRequiredService<IScenarioLoader>();
var validator = host.Services.GetRequiredService<IScenarioValidator>();
var runner = host.Services.GetRequiredService<ISimulationRunner>();

var defaultInput = Path.Combine(AppContext.BaseDirectory, "scenarios");
if (!Directory.Exists(defaultInput))
{
    defaultInput = Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), "scenarios"));
}

switch (cmd)
{
    case "list-suites":
        {
            var suites = await loader.ListSuitesAsync(GetArg("--input") ?? defaultInput);
            foreach (var s in suites) Console.WriteLine(s);
            return;
        }
    case "list-scenarios":
        {
            var scenarios = await loader.ListScenariosAsync(GetArg("--input") ?? defaultInput);
            foreach (var s in scenarios.OrderBy(x => x.Suite).ThenBy(x => x.Id))
            {
                Console.WriteLine($"{s.Suite,-14} {s.Id,-35} {s.Name}");
            }
            return;
        }
    case "validate-scenarios":
        {
            var all = await loader.LoadAsync(GetArg("--input") ?? defaultInput, GetArg("--suite"), GetArg("--scenario"));
            var failed = 0;
            foreach (var s in all)
            {
                var issues = validator.Validate(s);
                if (issues.Count == 0) continue;
                failed++;
                Console.WriteLine($"[INVALID] {s.Id}");
                foreach (var issue in issues) Console.WriteLine($"  - {issue}");
            }

            Console.WriteLine($"Validated {all.Count} scenarios. Invalid: {failed}");
            return;
        }
    case "run":
    default:
        {
            var options = new SimulationRunOptions
            {
                InputFolder = GetArg("--input") ?? defaultInput,
                ReportFolder = GetArg("--report") ?? Path.Combine(Directory.GetCurrentDirectory(), "out"),
                Suite = GetArg("--suite"),
                ScenarioId = GetArg("--scenario"),
                RandomSeed = TryInt(GetArg("--seed")),
                ExecutionModeOverride = ParseExecutionMode(GetArg("--mode"))
            };

            var result = await runner.RunAsync(options);
            Console.WriteLine($"Total scenarios: {result.TotalScenarios}");
            Console.WriteLine($"Passed: {result.Passed}");
            Console.WriteLine($"Failed: {result.Failed}");
            Console.WriteLine($"Uncovered: {result.Uncovered}");
            Console.WriteLine($"Invalid: {result.Invalid}");
            Console.WriteLine($"Suggested policies generated: {result.SuggestedPoliciesGenerated}");
            return;
        }
}

string? GetArg(string key)
{
    var i = Array.IndexOf(rest, key);
    return i >= 0 && i < rest.Length - 1 ? rest[i + 1] : null;
}

static int? TryInt(string? value)
    => int.TryParse(value, out var n) ? n : null;

static SimulationExecutionMode? ParseExecutionMode(string? value)
    => value?.ToLowerInvariant() switch
    {
        "application" => SimulationExecutionMode.Application,
        "protocol" => SimulationExecutionMode.Protocol,
        "hybrid" => SimulationExecutionMode.Hybrid,
        null or "" => null,
        _ => throw new ArgumentException("Unsupported --mode value. Use application|protocol|hybrid")
    };
