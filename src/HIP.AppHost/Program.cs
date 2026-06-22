var builder = DistributedApplication.CreateBuilder(args);

// Aspire is the authoritative local orchestrator for HIP. The explicit `http`
// launch profiles keep the dashboard URLs stable for the browser plugin and
// local manual testing while avoiding HTTPS-port inference noise.
//
// These keys are intentionally local-only non-default values. They keep the
// infrastructure production guard active while allowing Aspire-launched local
// services, including workers without launch profiles, to start consistently.
const string LocalRecordEncryptionKey = "hip-local-dev-record-key-32bytes!";
const string LocalPrivacyHashingKey = "hip-local-dev-privacy-key-32bytes";
var enableCoreDns = !string.Equals(builder.Configuration["HIP_ASPIRE_ENABLE_COREDNS"], "false", StringComparison.OrdinalIgnoreCase);
var coreDnsDirectory = Path.GetFullPath(Path.Combine(builder.AppHostDirectory, "..", "..", "eng", "coredns"));
var coreDns = enableCoreDns
    ? builder.AddContainer("hip-coredns", "coredns/coredns", "latest")
        .WithArgs("-conf", "/etc/coredns/Corefile")
        .WithBindMount(Path.Combine(coreDnsDirectory, "Corefile"), "/etc/coredns/Corefile", isReadOnly: true)
        .WithBindMount(Path.Combine(coreDnsDirectory, "hip.test.zone"), "/zones/hip.test.zone", isReadOnly: true)
        // TCP avoids UDP port-mapping surprises on Windows while still exercising real DNS TXT lookups.
        .WithEndpoint(port: 1053, targetPort: 53, scheme: "tcp", name: "dns")
    : null;

var postgres = builder.AddPostgres("postgres")
    .WithDataVolume();

var hipDatabase = postgres.AddDatabase("HipDatabase");

var redis = builder.AddRedis("redis")
    .WithDataVolume();

var apiService = builder.AddProject<Projects.HIP_ApiService>("hip-api", launchProfileName: "http")
    .WithExternalHttpEndpoints()
    // Add the Swagger UI as an Aspire dashboard action so local API discovery is one click.
    .WithUrlForEndpoint("http", _ => new() { Url = "/swagger", DisplayText = "Swagger" })
    .WithReference(hipDatabase)
    .WaitFor(hipDatabase)
    .WithReference(redis)
    .WaitFor(redis)
    .WithEnvironment("DOTNET_ENVIRONMENT", "Development")
    .WithEnvironment("ASPNETCORE_ENVIRONMENT", "Development")
    .WithEnvironment("HipInfrastructure__DatabaseProvider", "PostgreSQL")
    .WithEnvironment("HipSecurity__RecordEncryptionKey", LocalRecordEncryptionKey)
    .WithEnvironment("HipSecurity__PrivacyHashingKey", LocalPrivacyHashingKey);

if (coreDns is not null)
{
    apiService
        .WithEnvironment("DnsVerification__NameServerHost", "127.0.0.1")
        .WithEnvironment("DnsVerification__NameServerPort", "1053")
        .WithEnvironment("DnsVerification__UseTcpOnly", "true")
        .WaitFor(coreDns);
}

builder.AddProject<Projects.HIP_Web>("hip-web", launchProfileName: "http")
    .WithExternalHttpEndpoints()
    // Add the admin shell as an Aspire dashboard action; the base URL remains available separately.
    .WithUrlForEndpoint("http", _ => new() { Url = "/admin", DisplayText = "Admin" })
    .WithReference(hipDatabase)
    .WaitFor(hipDatabase)
    .WithReference(apiService)
    .WaitFor(apiService)
    .WithReference(redis)
    .WaitFor(redis)
    .WithEnvironment("DOTNET_ENVIRONMENT", "Development")
    .WithEnvironment("ASPNETCORE_ENVIRONMENT", "Development")
    .WithEnvironment("HipInfrastructure__DatabaseProvider", "PostgreSQL")
    .WithEnvironment("HipSecurity__RecordEncryptionKey", LocalRecordEncryptionKey)
    .WithEnvironment("HipSecurity__PrivacyHashingKey", LocalPrivacyHashingKey);

builder.AddProject<Projects.HIP_SandboxWorker>("hip-sandbox-worker")
    .WithReference(hipDatabase)
    .WaitFor(hipDatabase)
    .WithReference(redis)
    .WaitFor(redis)
    .WithEnvironment("DOTNET_ENVIRONMENT", "Development")
    .WithEnvironment("HipInfrastructure__DatabaseProvider", "PostgreSQL")
    .WithEnvironment("HipSecurity__RecordEncryptionKey", LocalRecordEncryptionKey)
    .WithEnvironment("HipSecurity__PrivacyHashingKey", LocalPrivacyHashingKey)
    // The worker is registered now so Aspire starts it with the rest of HIP.
    // Browser execution stays disabled until the hardened runner exists.
    .WithEnvironment("SandboxWorker__ExecuteBrowserSandbox", "false");

builder.Build().Run();
