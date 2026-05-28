using HIP.Application;
using HIP.Application.PublicLookup;
using HIP.Application.Rules;
using HIP.Application.SelfHealing;
using HIP.Application.Simulation;
using HIP.Domain.Rules;
using HIP.Domain.SelfHealing;
using HIP.Web.Components;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();
builder.Services.AddHipApplication();
builder.Services.AddCors(options =>
{
    options.AddPolicy("PublicHipReadOnly", policy =>
        policy.AllowAnyOrigin()
            .WithMethods("GET")
            .AllowAnyHeader());
});

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();
app.UseCors("PublicHipReadOnly");

app.UseAntiforgery();

var publicApi = app.MapGroup("/api/public");

publicApi.MapGet("/lookup/domain/{domain}", async (
    string domain,
    IPublicDomainLookupService lookupService,
    CancellationToken cancellationToken) =>
{
    try
    {
        return Results.Ok(await lookupService.LookupDomainAsync(domain, cancellationToken));
    }
    catch (ArgumentException ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

publicApi.MapGet("/badge/domain/{domain}", async (
    string domain,
    ITrustBadgeService badgeService,
    CancellationToken cancellationToken) =>
{
    try
    {
        return Results.Ok(await badgeService.GetDomainBadgeAsync(domain, cancellationToken));
    }
    catch (ArgumentException ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

var adminApi = app.MapGroup("/api/admin/rules");

adminApi.MapPost("/simulate", (
    AdminRuleSimulationRequest request,
    IAdminRuleService adminRuleService) =>
{
    try
    {
        var result = adminRuleService.Simulate(request.Rule, request.TestCases);
        return Results.Ok(result);
    }
    catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

var selfHealingApi = app.MapGroup("/api/admin/self-healing");

selfHealingApi.MapPost("/detect-patterns", (
    IReadOnlyCollection<SuspiciousFinding> findings,
    IPatternDetectionService patternDetectionService) =>
{
    try
    {
        return Results.Ok(patternDetectionService.DetectPatterns(findings));
    }
    catch (ArgumentException ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

selfHealingApi.MapPost("/generate-rule", (
    PatternCluster cluster,
    IRuleCandidateGenerator ruleCandidateGenerator) =>
{
    try
    {
        return Results.Ok(ruleCandidateGenerator.Generate(cluster));
    }
    catch (ArgumentException ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

selfHealingApi.MapPost("/analyze-findings", (
    IReadOnlyCollection<SuspiciousFinding> findings,
    ISelfHealingAnalysisService selfHealingAnalysisService) =>
{
    try
    {
        return Results.Ok(selfHealingAnalysisService.Analyze(findings));
    }
    catch (ArgumentException ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.MapDefaultEndpoints();

app.Run();

public sealed record AdminRuleSimulationRequest(
    TrustRule Rule,
    IReadOnlyCollection<RuleSimulationTestCase>? TestCases);
