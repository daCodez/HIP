var builder = DistributedApplication.CreateBuilder(args);

// Aspire is the authoritative local orchestrator for HIP. The explicit `http`
// launch profiles keep the dashboard URLs stable for the browser plugin and
// local manual testing while avoiding HTTPS-port inference noise.
var postgres = builder.AddPostgres("postgres")
    .WithDataVolume();

var hipDatabase = postgres.AddDatabase("HipDatabase");

var redis = builder.AddRedis("redis")
    .WithDataVolume();

var apiService = builder.AddProject<Projects.HIP_ApiService>("hip-api", launchProfileName: "http")
    .WithExternalHttpEndpoints()
    .WithReference(hipDatabase)
    .WaitFor(hipDatabase)
    .WithReference(redis)
    .WaitFor(redis)
    .WithEnvironment("HipInfrastructure__DatabaseProvider", "PostgreSQL");

builder.AddProject<Projects.HIP_Web>("hip-web", launchProfileName: "http")
    .WithExternalHttpEndpoints()
    .WithReference(apiService)
    .WaitFor(apiService);

builder.Build().Run();
