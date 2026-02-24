#:sdk Aspire.AppHost.Sdk@13.1.1

var builder = DistributedApplication.CreateBuilder(args);

var apiReplicasRaw = Environment.GetEnvironmentVariable("HIP_API_REPLICAS");
var apiReplicas = int.TryParse(apiReplicasRaw, out var parsedReplicas) && parsedReplicas > 0
    ? parsedReplicas
    : 1;

var api = builder.AddProject("hip-api", "/home/jarvis_bot/.openclaw/workspace/HIP/HIP.ApiService/HIP.ApiService.csproj")
    .WithReplicas(apiReplicas);

builder.AddProject("hip-web", "/home/jarvis_bot/.openclaw/workspace/HIP/HIP.Web/HIP.Web.csproj")
    .WithReference(api)
    .WaitFor(api);

builder.Build().Run();
