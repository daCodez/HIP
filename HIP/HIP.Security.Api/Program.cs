using System.Threading.RateLimiting;
using HIP.Security.Api.Mappings;
using HIP.Security.Api.Security;
using HIP.Security.Application.DependencyInjection;
using HIP.Security.Infrastructure.DependencyInjection;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddOpenApi();
builder.Services.AddSingleton<IPolicyDtoMapper, PolicyDtoMapper>();
builder.Services
    .AddHipSecurityApplication()
    .AddHipSecurityInfrastructure();

builder.Services
    .AddAuthentication(PlaceholderHeaderAuthenticationHandler.SchemeName)
    .AddScheme<AuthenticationSchemeOptions, PlaceholderHeaderAuthenticationHandler>(
        PlaceholderHeaderAuthenticationHandler.SchemeName,
        _ => { });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(SecurityAuthorizationPolicies.PolicyRead, policy => policy.RequireRole("SecurityReader", "SecurityOperator", "SecurityAdmin"));
    options.AddPolicy(SecurityAuthorizationPolicies.PolicyWrite, policy => policy.RequireRole("SecurityOperator", "SecurityAdmin"));
    options.AddPolicy(SecurityAuthorizationPolicies.PolicyPromote, policy => policy.RequireRole("SecurityAdmin"));
    options.AddPolicy(SecurityAuthorizationPolicies.CampaignExecute, policy => policy.RequireRole("SecurityOperator", "SecurityAdmin"));
});

builder.Services.AddRateLimiter(options =>
{
    options.AddPolicy("policy-write", _ =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: "policy-write",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 20,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));

    options.AddPolicy("policy-promote", _ =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: "policy-promote",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));

    options.AddPolicy("campaign-sensitive", _ =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: "campaign-sensitive",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 30,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.MapControllers();

app.Run();
