using HIP.Application;
using HIP.Application.PublicLookup;
using HIP.Application.Reputation;
using HIP.Application.Review;
using HIP.Application.Rules;
using HIP.Application.SelfHealing;
using HIP.Application.Simulation;
using HIP.Domain.Review;
using HIP.Domain.Reputation;
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

publicApi.MapPost("/appeals", (
    AppealRequest appeal,
    IAppealService appealService) =>
{
    try
    {
        return Results.Ok(appealService.Submit(appeal));
    }
    catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

publicApi.MapPost("/feedback", async (
    ReputationFeedbackRequest feedback,
    IReputationService reputationService,
    CancellationToken cancellationToken) =>
{
    try
    {
        return Results.Ok(await reputationService.SubmitFeedbackAsync(feedback, cancellationToken));
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

var reviewApi = app.MapGroup("/api/admin/review");

reviewApi.MapGet("/", (IReviewQueueService reviewQueueService) => Results.Ok(reviewQueueService.List()));

reviewApi.MapGet("/{id}", (string id, IReviewQueueService reviewQueueService) =>
    reviewQueueService.Get(id) is { } item ? Results.Ok(item) : Results.NotFound());

reviewApi.MapPost("/", (ReviewItem item, IReviewQueueService reviewQueueService) =>
{
    try
    {
        return Results.Ok(reviewQueueService.Create(item));
    }
    catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

reviewApi.MapPost("/{id}/approve", (string id, AdminDecisionRequest request, IReviewQueueService reviewQueueService) =>
    Results.Ok(reviewQueueService.Approve(id, request.ActorId, request.Reason)));

reviewApi.MapPost("/{id}/reject", (string id, AdminDecisionRequest request, IReviewQueueService reviewQueueService) =>
    Results.Ok(reviewQueueService.Reject(id, request.ActorId, request.Reason)));

reviewApi.MapPost("/{id}/needs-more-info", (string id, AdminDecisionRequest request, IReviewQueueService reviewQueueService) =>
    Results.Ok(reviewQueueService.RequestMoreInfo(id, request.ActorId, request.Reason)));

reviewApi.MapPost("/{id}/assign", (string id, AdminAssignRequest request, IReviewQueueService reviewQueueService) =>
    Results.Ok(reviewQueueService.Assign(id, request.AssignedTo, request.ActorId)));

var appealApi = app.MapGroup("/api/admin/appeals");

appealApi.MapGet("/", (IAppealService appealService) => Results.Ok(appealService.List()));
appealApi.MapPost("/{id}/approve", (string id, AdminDecisionRequest request, IAppealService appealService) =>
    Results.Ok(appealService.Approve(id, request.ActorId, request.Reason)));
appealApi.MapPost("/{id}/reject", (string id, AdminDecisionRequest request, IAppealService appealService) =>
    Results.Ok(appealService.Reject(id, request.ActorId, request.Reason)));
appealApi.MapPost("/{id}/needs-more-info", (string id, AdminDecisionRequest request, IAppealService appealService) =>
    Results.Ok(appealService.RequestMoreInfo(id, request.ActorId, request.Reason)));

var overrideApi = app.MapGroup("/api/admin/reputation-overrides");

overrideApi.MapGet("/", (IReputationOverrideService reputationOverrideService) => Results.Ok(reputationOverrideService.List()));
overrideApi.MapPost("/", (ReputationOverrideRequest request, IReputationOverrideService reputationOverrideService) =>
{
    try
    {
        return Results.Ok(reputationOverrideService.Request(request));
    }
    catch (Exception ex) when (ex is ArgumentException or FluentValidation.ValidationException)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});
overrideApi.MapPost("/{id}/approve", (string id, AdminDecisionRequest request, IReputationOverrideService reputationOverrideService) =>
    Results.Ok(reputationOverrideService.Approve(id, request.ActorId, request.Reason)));
overrideApi.MapPost("/{id}/reject", (string id, AdminDecisionRequest request, IReputationOverrideService reputationOverrideService) =>
    Results.Ok(reputationOverrideService.Reject(id, request.ActorId, request.Reason)));

app.MapGet("/api/admin/audit-logs", (IAuditLogService auditLogService) => Results.Ok(auditLogService.List()));

var reputationApi = app.MapGroup("/api/admin/reputation");

reputationApi.MapGet("/{targetType}/{targetId}", async (
    ReputationSubjectType targetType,
    string targetId,
    IReputationService reputationService,
    CancellationToken cancellationToken) =>
{
    try
    {
        return Results.Ok(await reputationService.GetProfileAsync(targetType, targetId, cancellationToken));
    }
    catch (ArgumentException ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

reputationApi.MapPost("/events", async (
    ReputationEvent reputationEvent,
    IReputationService reputationService,
    CancellationToken cancellationToken) =>
{
    try
    {
        return Results.Ok(await reputationService.ApplyEventAsync(reputationEvent, cancellationToken));
    }
    catch (ArgumentException ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

reputationApi.MapPost("/{targetType}/{targetId}/recalculate", async (
    ReputationSubjectType targetType,
    string targetId,
    IReputationService reputationService,
    CancellationToken cancellationToken) =>
{
    try
    {
        return Results.Ok(await reputationService.RecalculateAsync(targetType, targetId, cancellationToken));
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

public sealed record AdminDecisionRequest(string ActorId, string Reason);

public sealed record AdminAssignRequest(string ActorId, string AssignedTo);
