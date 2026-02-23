using FluentValidation;
using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Application.Behaviors;
using HIP.ApiService.Infrastructure.Identity;
using HIP.ApiService.Infrastructure.Reputation;
using HIP.ServiceDefaults;
using MediatR;

var builder = WebApplication.CreateBuilder(args);
builder.AddServiceDefaults();

builder.Services.Configure<CryptoProviderOptions>(builder.Configuration.GetSection(CryptoProviderOptions.SectionName)); // validation/security awareness: options bind from env/config only

builder.Services.AddLogging(); // performance awareness: central logging pipeline
builder.Services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(typeof(Program).Assembly));
builder.Services.AddValidatorsFromAssembly(typeof(Program).Assembly);
builder.Services.AddTransient(typeof(IPipelineBehavior<,>), typeof(ValidationBehavior<,>));

builder.Services.AddSingleton<IIdentityService, InMemoryIdentityService>();
builder.Services.AddSingleton<IReputationService, InMemoryReputationService>();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

app.UseExceptionHandler(); // security awareness: prevent leaking internals

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapStatusEndpoints();
app.MapDefaultEndpoints();

app.Run();

public partial class Program { }
