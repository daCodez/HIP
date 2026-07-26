var builder = DistributedApplication.CreateBuilder(args);

// Aspire is the authoritative local orchestrator for HIP. The explicit `http`
// launch profiles keep the dashboard URLs stable for the browser plugin and
// local manual testing while avoiding HTTPS-port inference noise.
//
// Secret parameters are resolved from AppHost user secrets, environment variables,
// or deployment configuration. Aspire marks them secret so their values are not
// published in the application manifest or written to logs.
var recordEncryptionKey = builder.AddParameter("hip-record-encryption-key", secret: true);
var legacyRecordEncryptionKey = builder.AddParameter("hip-legacy-record-encryption-key", secret: true);
var privacyHashingKey = builder.AddParameter("hip-privacy-hashing-key", secret: true);
var legacyPrivacyHashingKey = string.IsNullOrWhiteSpace(
    builder.Configuration["Parameters:hip-legacy-privacy-hashing-key"])
    ? null
    : builder.AddParameter("hip-legacy-privacy-hashing-key", secret: true);
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
    .WithEnvironment("HipSecurity__RecordEncryptionKey", recordEncryptionKey)
    .WithEnvironment("HipSecurity__LegacyRecordEncryptionKeys__0", legacyRecordEncryptionKey)
    .WithEnvironment("HipSecurity__PrivacyHashingKey", privacyHashingKey);

if (legacyPrivacyHashingKey is not null)
{
    apiService.WithEnvironment("HipSecurity__LegacyPrivacyHashingKeys__0", legacyPrivacyHashingKey);
}

if (coreDns is not null)
{
    apiService
        .WithEnvironment("DnsVerification__NameServerHost", "127.0.0.1")
        .WithEnvironment("DnsVerification__NameServerPort", "1053")
        .WithEnvironment("DnsVerification__UseTcpOnly", "true")
        .WaitFor(coreDns);
}

var web = builder.AddProject<Projects.HIP_Web>("hip-web", launchProfileName: "http")
    .WithExternalHttpEndpoints()
    // Keep both authenticated portals discoverable from the Aspire dashboard.
    .WithUrlForEndpoint("http", _ => new() { Url = "/consumer", DisplayText = "Consumer" })
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
    .WithEnvironment("HipSecurity__RecordEncryptionKey", recordEncryptionKey)
    .WithEnvironment("HipSecurity__LegacyRecordEncryptionKeys__0", legacyRecordEncryptionKey)
    .WithEnvironment("HipSecurity__PrivacyHashingKey", privacyHashingKey);

if (legacyPrivacyHashingKey is not null)
{
    web.WithEnvironment("HipSecurity__LegacyPrivacyHashingKeys__0", legacyPrivacyHashingKey);
}

// This one-shot project never starts an HTTP listener and is opt-in in the Aspire dashboard.
// Starting it is the explicit operator confirmation to index pre-HIP-0205 global consumer history.
var ownerIndexBackfill = builder.AddProject<Projects.HIP_Web>("hip-owner-index-backfill", launchProfileName: "maintenance")
    .WithReference(hipDatabase)
    .WaitFor(hipDatabase)
    .WithReference(redis)
    .WaitFor(redis)
    .WithExplicitStart()
    .WithEnvironment("DOTNET_ENVIRONMENT", "Development")
    .WithEnvironment("ASPNETCORE_ENVIRONMENT", "Development")
    .WithEnvironment("HipInfrastructure__DatabaseProvider", "PostgreSQL")
    .WithEnvironment("HipSecurity__RecordEncryptionKey", recordEncryptionKey)
    .WithEnvironment("HipSecurity__LegacyRecordEncryptionKeys__0", legacyRecordEncryptionKey)
    .WithEnvironment("HipSecurity__PrivacyHashingKey", privacyHashingKey);

if (legacyPrivacyHashingKey is not null)
{
    ownerIndexBackfill.WithEnvironment("HipSecurity__LegacyPrivacyHashingKeys__0", legacyPrivacyHashingKey);
}

var sandboxWorker = builder.AddProject<Projects.HIP_SandboxWorker>("hip-sandbox-worker")
    .WithReference(hipDatabase)
    .WaitFor(hipDatabase)
    .WithReference(redis)
    .WaitFor(redis)
    .WithEnvironment("DOTNET_ENVIRONMENT", "Development")
    .WithEnvironment("HipInfrastructure__DatabaseProvider", "PostgreSQL")
    .WithEnvironment("HipSecurity__RecordEncryptionKey", recordEncryptionKey)
    .WithEnvironment("HipSecurity__LegacyRecordEncryptionKeys__0", legacyRecordEncryptionKey)
    .WithEnvironment("HipSecurity__PrivacyHashingKey", privacyHashingKey)
    // The worker is registered now so Aspire starts it with the rest of HIP.
    // Browser execution stays disabled until the hardened runner exists.
    .WithEnvironment("SandboxWorker__ExecuteBrowserSandbox", "false");

if (legacyPrivacyHashingKey is not null)
{
    sandboxWorker.WithEnvironment("HipSecurity__LegacyPrivacyHashingKeys__0", legacyPrivacyHashingKey);
}

builder.Build().Run();
