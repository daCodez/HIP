using HIP.Application;
using HIP.Infrastructure;
using HIP.SandboxWorker;

var builder = Host.CreateApplicationBuilder(args);

// The worker uses the same service defaults as the API and web hosts so Aspire can
// capture logs, traces, and health signals in one local dashboard.
builder.AddServiceDefaults();

builder.Services.AddHipApplication(
    builder.Environment.IsDevelopment(),
    builder.Environment.IsDevelopment() ? "sandbox" : null);
builder.Services.AddHipInfrastructure(builder.Configuration, builder.Environment.IsDevelopment());
builder.Services
    .AddOptions<SandboxWorkerOptions>()
    .Bind(builder.Configuration.GetSection(SandboxWorkerOptions.SectionName))
    .Validate(SandboxWorkerOptions.Validate, "Sandbox worker options must use safe bounded values.")
    .ValidateOnStart();
builder.Services.AddHostedService<SandboxLinkScanWorker>();
builder.Services.AddHostedService<ExternalSiteEvidenceJobWorker>();
builder.Services
    .AddOptions<RiskFindingRetentionWorkerOptions>()
    .Bind(builder.Configuration.GetSection(RiskFindingRetentionWorkerOptions.SectionName))
    .Validate(RiskFindingRetentionWorkerOptions.Validate, "Risk finding retention worker options must use safe bounded values.")
    .ValidateOnStart();
builder.Services.AddHostedService<RiskFindingRetentionWorker>();

await builder.Build().RunAsync();
