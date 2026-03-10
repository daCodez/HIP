using HIP.Agent.Worker;

if (EnrollmentPlaceholderCommand.IsEnrollmentCommand(args))
{
    return await EnrollmentPlaceholderCommand.RunAsync(args);
}

var builder = Host.CreateApplicationBuilder(args);
builder.Configuration.AddJsonFile("appsettings.Local.json", optional: true, reloadOnChange: true);

builder.Services
    .AddOptions<AgentOptions>()
    .Bind(builder.Configuration.GetSection(AgentOptions.SectionName));

builder.Services.AddSingleton<IAgentCredentialStore, FileEncryptedCredentialStore>();
builder.Services.AddHttpClient<EnrollmentClient>();
builder.Services.AddHttpClient<HeartbeatClient>();
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
await host.RunAsync();
return 0;
