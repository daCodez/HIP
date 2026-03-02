using HIP.Sdk;
using Microsoft.Extensions.DependencyInjection;

var baseUrl = args.FirstOrDefault() ?? "http://127.0.0.1:5101";
var identityId = args.Skip(1).FirstOrDefault() ?? "hip-system";

var services = new ServiceCollection();
services.AddHipSdkClient(o => o.BaseUrl = baseUrl);

using var provider = services.BuildServiceProvider();
var hip = provider.GetRequiredService<IHipSdkClient>();

Console.WriteLine($"HIP SDK demo → baseUrl={baseUrl}, identity={identityId}");

try
{
    var status = await hip.GetStatusAsync();
    Console.WriteLine($"status: {status.ServiceName} v{status.AssemblyVersion} @ {status.UtcTimestamp:O}");

    var identity = await hip.GetIdentityAsync(identityId);
    if (identity is null)
    {
        Console.WriteLine("identity: not found");
    }
    else
    {
        Console.WriteLine($"identity: id={identity.Id}, keyRef={identity.PublicKeyRef}");
    }

    var reputation = await hip.GetReputationAsync(identityId);
    if (reputation is null)
    {
        Console.WriteLine("reputation: not found");
    }
    else
    {
        Console.WriteLine($"reputation: score={reputation.Score}, at={reputation.UtcTimestamp:O}");
    }
}
catch (HttpRequestException ex)
{
    Console.Error.WriteLine($"HIP API unreachable at {baseUrl}: {ex.Message}");
    Console.Error.WriteLine("Tip: start HIP.ApiService first (dotnet run --project HIP.ApiService).");
    Environment.ExitCode = 2;
}
