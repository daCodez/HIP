var builder = DistributedApplication.CreateBuilder(args);

var api = builder.AddProject<Projects.HIP_ApiService>("hip-api");
builder.AddProject<Projects.HIP_Web>("hip-web")
    .WithReference(api)
    .WaitFor(api);

builder.Build().Run();
