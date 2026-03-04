#:sdk Aspire.AppHost.Sdk@13.1.2

var builder = DistributedApplication.CreateBuilder(args);

var apiReplicasRaw = Environment.GetEnvironmentVariable("HIP_API_REPLICAS");
var apiReplicas = int.TryParse(apiReplicasRaw, out var parsedReplicas) && parsedReplicas > 0
    ? parsedReplicas
    : 1;

var api = builder.AddProject("hip-api", "/home/jarvis_bot/.openclaw/workspace/HIP/HIP.ApiService/HIP.ApiService.csproj")
    .WithEnvironment("ASPNETCORE_ENVIRONMENT", "Development")
    .WithHttpEndpoint(name: "http", port: 44985, isProxied: false)
    .WithReplicas(apiReplicas)
    .WithUrlForEndpoint("http", url =>
    {
        url.Url = "https://srv1377835-1.tailb59890.ts.net:8445/swagger/index.html";
        url.DisplayText = "Swagger";
    });

builder.AddProject("hip-web", "/home/jarvis_bot/.openclaw/workspace/HIP/HIP.Web/HIP.Web.csproj")
    .WithHttpEndpoint(name: "http", port: 45727, isProxied: false)
    .WithReference(api)
    .WaitFor(api)
    .WithUrlForEndpoint("http", url =>
    {
        url.Url = "https://srv1377835-1.tailb59890.ts.net:8444";
        url.DisplayText = "HIP.Web";
    });

builder.Build().Run();
