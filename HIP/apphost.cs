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
        url.Url = "https://srv1377835-1.tailb59890.ts.net:8443/swagger";
        url.DisplayText = "HIP.API";
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

builder.AddProject("hip-admin", "/home/jarvis_bot/.openclaw/workspace/HIP/HIP.Admin/HIP.Admin.csproj")
    .WithEnvironment("ASPNETCORE_ENVIRONMENT", "Development")
    .WithHttpEndpoint(name: "admin-http", port: 45728, isProxied: false)
    .WithReference(api)
    .WaitFor(api)
    .WithUrlForEndpoint("admin-http", url =>
    {
        url.Url = "https://srv1377835-1.tailb59890.ts.net:8443/admin";
        url.DisplayText = "HIP.Admin";
    })
    .WithUrls(c =>
    {
        c.Urls.Clear();
        c.Urls.Add(new Aspire.Hosting.ApplicationModel.ResourceUrlAnnotation
        {
            Url = "https://srv1377835-1.tailb59890.ts.net:8443/admin",
            DisplayText = "HIP.Admin"
        });
    });

builder.AddProject("hip-proxy", "/home/jarvis_bot/.openclaw/workspace/HIP/HIP.Proxy/HIP.Proxy.csproj")
    .WithHttpEndpoint(name: "proxy-http", port: 45729, isProxied: false)
    .WithReference(api)
    .WaitFor(api)
    .WithUrlForEndpoint("proxy-http", url =>
    {
        url.Url = "https://srv1377835-1.tailb59890.ts.net:8443";
        url.DisplayText = "HIP.Proxy";
    })
    .WithUrls(c =>
    {
        c.Urls.Clear();
        c.Urls.Add(new Aspire.Hosting.ApplicationModel.ResourceUrlAnnotation
        {
            Url = "https://srv1377835-1.tailb59890.ts.net:8443",
            DisplayText = "HIP.Proxy"
        });
    });

builder.AddProject("hip-simulator-cli", "/home/jarvis_bot/.openclaw/workspace/HIP/HIP.Simulator.Cli/HIP.Simulator.Cli.csproj")
    .WithReference(api)
    .WaitFor(api)
    .WithEnvironment("DOTNET_ENVIRONMENT", "Development")
    .WithArgs("list-suites", "--input", "/home/jarvis_bot/.openclaw/workspace/HIP/HIP.Simulator.Cli/scenarios");

builder.Build().Run();
