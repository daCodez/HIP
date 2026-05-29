using HIP.Application;
using HIP.Application.Consumer;
using HIP.Application.Dashboard;
using HIP.Application.Identity;
using HIP.Application.PublicLookup;
using HIP.Application.Reporting;
using HIP.Application.Reputation;
using HIP.Application.Review;
using HIP.Application.Rules;
using HIP.Application.SelfHealing;
using HIP.Application.SecondLife;
using HIP.Application.Simulation;
using HIP.Domain.Review;
using HIP.Domain.Reporting;
using HIP.Domain.Reputation;
using HIP.Domain.Identity;
using HIP.Domain.Rules;
using HIP.Domain.SelfHealing;
using HIP.Infrastructure;
using HIP.Infrastructure.Persistence;
using HIP.Web;
using HIP.Web.Components;
using HIP.Web.Security;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();
builder.Services.AddHipApplication();
builder.Services.AddHipInfrastructure(builder.Configuration);
builder.Services.AddHipAdminAuthorization();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddCors(options =>
{
    options.AddPolicy("PublicHipReadOnly", policy =>
        policy.AllowAnyOrigin()
            .WithMethods("GET", "POST")
            .AllowAnyHeader());
});

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

var app = builder.Build();

await HipDatabaseInitializer.EnsureCreatedAsync(app.Services);

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
app.UseWhen(
    context => !context.Request.Path.StartsWithSegments("/api"),
    branch => branch.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true));
app.UseHttpsRedirection();
app.UseCors("PublicHipReadOnly");
app.UseAuthentication();
app.UseAuthorization();

app.UseAntiforgery();

MapPublicApis(app.MapGroup(ApiRoutes.Public));
MapSecondLifeHudApis(app.MapGroup(ApiRoutes.SecondLifeHud));
MapRulesApis(app.MapGroup($"{ApiRoutes.Admin}/rules").RequireAuthorization(AdminPolicies.CanManageRules));
MapSelfHealingApis(app.MapGroup($"{ApiRoutes.Admin}/self-healing").RequireAuthorization(AdminPolicies.CanManageRules));
MapReviewApis(app.MapGroup($"{ApiRoutes.Admin}/review").RequireAuthorization(AdminPolicies.CanReviewReports));
MapAppealApis(app.MapGroup($"{ApiRoutes.Admin}/appeals").RequireAuthorization(AdminPolicies.CanReviewReports));
MapReputationOverrideApis(app.MapGroup($"{ApiRoutes.Admin}/reputation-overrides").RequireAuthorization(AdminPolicies.CanApproveOverrides));
MapReputationApis(app.MapGroup($"{ApiRoutes.Admin}/reputation").RequireAuthorization(AdminPolicies.CanViewAdminDashboard));
MapDashboardApis(app.MapGroup($"{ApiRoutes.Admin}/dashboard").RequireAuthorization(AdminPolicies.CanViewAdminDashboard));
MapConsumerApis(app.MapGroup(ApiRoutes.Consumer).RequireAuthorization(ConsumerPolicies.CanUseConsumerPortal));
MapIdentityApis(app.MapGroup(ApiRoutes.Identity));
app.MapGet($"{ApiRoutes.Admin}/audit-logs", (IAuditLogService auditLogService) => Results.Ok(auditLogService.List()))
    .RequireAuthorization(AdminPolicies.CanViewAuditLogs);

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.MapDefaultEndpoints();

app.Run();

static void MapPublicApis(RouteGroupBuilder publicApi)
{
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

    publicApi.MapPost("/risk-findings", async (
        RiskFindingReport report,
        IRiskFindingIngestionService ingestionService,
        CancellationToken cancellationToken) =>
    {
        var response = await ingestionService.IngestAsync(report, cancellationToken);
        return response.Accepted ? Results.Ok(response) : Results.BadRequest(response);
    });
}

static void MapDashboardApis(RouteGroupBuilder dashboardApi)
{
    dashboardApi.MapGet("/summary", async (
        IAdminDashboardService dashboardService,
        CancellationToken cancellationToken) =>
        Results.Ok(await dashboardService.GetSummaryAsync(cancellationToken)));
}

static void MapConsumerApis(RouteGroupBuilder consumerApi)
{
    consumerApi.MapGet("/status", async (
        HttpContext httpContext,
        IConsumerPortalService consumerPortalService,
        CancellationToken cancellationToken) =>
        Results.Ok(await consumerPortalService.GetStatusAsync(ConsumerId(httpContext), cancellationToken)));

    consumerApi.MapGet("/scans", async (
        HttpContext httpContext,
        IConsumerPortalService consumerPortalService,
        CancellationToken cancellationToken) =>
        Results.Ok(await consumerPortalService.GetScansAsync(ConsumerId(httpContext), cancellationToken)));

    consumerApi.MapGet("/reports", async (
        HttpContext httpContext,
        IConsumerPortalService consumerPortalService,
        CancellationToken cancellationToken) =>
        Results.Ok(await consumerPortalService.GetReportsAsync(ConsumerId(httpContext), cancellationToken)));

    consumerApi.MapGet("/appeals", async (
        HttpContext httpContext,
        IConsumerPortalService consumerPortalService,
        CancellationToken cancellationToken) =>
        Results.Ok(await consumerPortalService.GetAppealsAsync(ConsumerId(httpContext), cancellationToken)));

    consumerApi.MapGet("/settings", (
        HttpContext httpContext,
        IConsumerPortalService consumerPortalService) =>
        Results.Ok(consumerPortalService.GetSettings(ConsumerId(httpContext))));

    consumerApi.MapPost("/settings", (
        HttpContext httpContext,
        ConsumerSettings settings,
        IConsumerPortalService consumerPortalService) =>
    {
        var result = consumerPortalService.SaveSettings(ConsumerId(httpContext), settings);
        return result.Saved ? Results.Ok(result) : Results.BadRequest(result);
    });
}

static string ConsumerId(HttpContext httpContext) =>
    httpContext.User.FindFirst("hip_consumer_id")?.Value
    ?? httpContext.User.Identity?.Name
    ?? "development-consumer";

static void MapSecondLifeHudApis(RouteGroupBuilder slHudApi)
{
    slHudApi.MapPost("/activate", (
        SecondLifeHudActivationRequest request,
        ISecondLifeHudService hudService) =>
    {
        var response = hudService.Activate(request);
        return response.Activated ? Results.Ok(response) : Results.BadRequest(response);
    });

    slHudApi.MapPost("/report-finding", async (
        SecondLifeHudFindingReport report,
        ISecondLifeHudService hudService,
        CancellationToken cancellationToken) =>
    {
        var response = await hudService.ReportFindingAsync(report, cancellationToken);
        return response.Accepted ? Results.Ok(response) : Results.BadRequest(response);
    });
}

static void MapRulesApis(RouteGroupBuilder adminApi)
{
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
}

static void MapSelfHealingApis(RouteGroupBuilder selfHealingApi)
{
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
}

static void MapReviewApis(RouteGroupBuilder reviewApi)
{
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
}

static void MapAppealApis(RouteGroupBuilder appealApi)
{
    appealApi.MapGet("/", (IAppealService appealService) => Results.Ok(appealService.List()));
    appealApi.MapPost("/{id}/approve", (string id, AdminDecisionRequest request, IAppealService appealService) =>
        Results.Ok(appealService.Approve(id, request.ActorId, request.Reason)));
    appealApi.MapPost("/{id}/reject", (string id, AdminDecisionRequest request, IAppealService appealService) =>
        Results.Ok(appealService.Reject(id, request.ActorId, request.Reason)));
    appealApi.MapPost("/{id}/needs-more-info", (string id, AdminDecisionRequest request, IAppealService appealService) =>
        Results.Ok(appealService.RequestMoreInfo(id, request.ActorId, request.Reason)));
}

static void MapReputationOverrideApis(RouteGroupBuilder overrideApi)
{
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
}

static void MapReputationApis(RouteGroupBuilder reputationApi)
{
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
}

static void MapIdentityApis(RouteGroupBuilder identityApi)
{
    identityApi.MapPost("/register", async (
        IdentityRegistrationRequest request,
        IHipIdentityService identityService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await identityService.RegisterAsync(request, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    identityApi.MapPost("/domain-verification/start", async (
        DomainVerificationApiRequest request,
        IDomainVerificationService domainVerificationService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await domainVerificationService.StartAsync(request.Domain, request.Method, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    identityApi.MapPost("/domain-verification/verify", async (
        DomainVerificationApiRequest request,
        IDomainVerificationService domainVerificationService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await domainVerificationService.VerifyAsync(request.Domain, request.Method, request.Token ?? string.Empty, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    identityApi.MapPost("/sign", async (
        SignContentRequest request,
        IHipIdentityService identityService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await identityService.SignAsync(request, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });

    identityApi.MapPost("/verify", async (
        VerifySignatureRequest request,
        IHipIdentityService identityService,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await identityService.VerifyAsync(request, cancellationToken));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    });
}

public sealed record AdminRuleSimulationRequest(
    TrustRule Rule,
    IReadOnlyCollection<RuleSimulationTestCase>? TestCases);

public sealed record AdminDecisionRequest(string ActorId, string Reason);

public sealed record AdminAssignRequest(string ActorId, string AssignedTo);

public sealed record DomainVerificationApiRequest(string Domain, VerificationMethod Method, string? Token);

public partial class Program;
