using HIP.Security.Application.Campaigns.ReplayCampaign;
using HIP.Security.Application.Campaigns.RunCampaign;
using HIP.Security.Application.Suggestions.GeneratePolicySuggestions;
using HIP.Security.Application.Suggestions.GenerateScenarioSuggestions;
using HIP.Security.Application.DependencyInjection;
using HIP.Security.Infrastructure.DependencyInjection;
using MediatR;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection()
    .AddHipSecurityApplication()
    .AddHipSecurityInfrastructure()
    .BuildServiceProvider();

var mediator = services.GetRequiredService<IMediator>();

if (args.Length == 0)
{
    PrintUsage();
    return 1;
}

var command = args[0].Trim().ToLowerInvariant();
var campaignId = TryReadGuid(args.ElementAtOrDefault(1));

switch (command)
{
    case "run-campaign":
        var runResult = await mediator.Send(new RunCampaignCommand(campaignId));
        Console.WriteLine($"Campaign {runResult.CampaignId} => {runResult.Status} (Executed {runResult.ExecutedCount}/{runResult.ScenarioCount})");
        break;

    case "generate-scenarios":
        var scenarioSuggestions = await mediator.Send(new GenerateScenarioSuggestionsQuery(campaignId));
        foreach (var item in scenarioSuggestions)
        {
            Console.WriteLine($"- {item}");
        }

        break;

    case "suggest-policies":
        var policySuggestions = await mediator.Send(new GeneratePolicySuggestionsQuery(campaignId));
        foreach (var item in policySuggestions)
        {
            Console.WriteLine($"- {item}");
        }

        break;

    case "replay":
        Console.WriteLine(await mediator.Send(new ReplayCampaignCommand(campaignId)));
        break;

    default:
        PrintUsage();
        return 1;
}

return 0;

static Guid TryReadGuid(string? raw) => Guid.TryParse(raw, out var parsed) ? parsed : Guid.NewGuid();

static void PrintUsage()
{
    Console.WriteLine("HIP.Security CLI (Phase 2 scaffold)");
    Console.WriteLine("Commands:");
    Console.WriteLine("  run-campaign [campaignId]");
    Console.WriteLine("  generate-scenarios [campaignId]");
    Console.WriteLine("  suggest-policies [campaignId]");
    Console.WriteLine("  replay [campaignId]");
}
