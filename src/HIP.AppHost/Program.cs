var builder = DistributedApplication.CreateBuilder(args);

var apiService = builder.AddProject<Projects.HIP_ApiService>("hip-api");

builder.AddProject<Projects.HIP_Web>("hip-web")
    .WithExternalHttpEndpoints()
    .WithReference(apiService)
    .WaitFor(apiService);

builder.Build().Run();
