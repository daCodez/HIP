using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Infrastructure.Plugins;
using Microsoft.Extensions.Options;
using System.Text;
using System.Text.Json;

namespace HIP.ApiService.Features.Admin;

/// <summary>
/// Admin endpoints for viewing enforceable policy rules.
/// </summary>
public static class PolicyEndpoints
{
    /// <summary>
    /// Maps admin policy endpoints.
    /// </summary>
    public static IEndpointRouteBuilder MapPolicyEndpoints(this IEndpointRouteBuilder endpoints)
    {
        async Task<IResult> getPolicyRulesHandler(
            HttpContext httpContext,
            PolicyVersionStore store,
            IHipEnvelopeVerifier envelopeVerifier,
            IIdentityService identityService,
            IReputationService reputationService,
            CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null)
            {
                return gate;
            }

            return Results.Ok(store.GetEditableRules().Select(x => new
            {
                ruleId = x.RuleId,
                name = x.Name,
                category = x.Category,
                condition = x.Condition,
                action = x.Action,
                severity = x.Severity,
                enabled = x.Enabled
            }));
        }

        endpoints.MapGet("/api/admin/policy", getPolicyRulesHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetAdminPolicyRules")
            .WithSummary("Get effective admin policy rules")
            .WithDescription("Returns the active baseline security policy rule set for HIP admin surfaces, including category, condition, action, severity, and enabled state.")
            .WithTags("Admin", "Policy")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/v1/admin/policy", getPolicyRulesHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetAdminPolicyRulesV1")
            .WithSummary("Get effective admin policy rules")
            .WithDescription("Versioned alias of admin policy rules endpoint.")
            .WithTags("Admin", "Policy", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        async Task<IResult> getPolicySchemaHandler(
            HttpContext httpContext,
            IWebHostEnvironment env,
            IHipEnvelopeVerifier envelopeVerifier,
            IIdentityService identityService,
            IReputationService reputationService,
            CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null) return gate;

            var path = Path.Combine(env.ContentRootPath, "Policy", "policy-schema.json");
            if (!File.Exists(path)) return Results.NotFound(new { code = "policy.schema.missing" });
            var json = await File.ReadAllTextAsync(path, cancellationToken);
            return Results.Content(json, "application/json", Encoding.UTF8);
        }

        endpoints.MapGet("/api/admin/policy/schema", getPolicySchemaHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetPolicySchema")
            .WithSummary("Get policy JSON schema")
            .WithDescription("Returns the canonical policy JSON schema used for validation and sandbox contract checks.")
            .WithTags("Admin", "Policy")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/v1/admin/policy/schema", getPolicySchemaHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetPolicySchemaV1")
            .WithSummary("Get policy JSON schema")
            .WithDescription("Versioned alias of policy schema endpoint.")
            .WithTags("Admin", "Policy", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status429TooManyRequests);

        async Task<IResult> getStarterPoliciesHandler(
            HttpContext httpContext,
            IWebHostEnvironment env,
            IHipEnvelopeVerifier envelopeVerifier,
            IIdentityService identityService,
            IReputationService reputationService,
            CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null) return gate;

            var path = Path.Combine(env.ContentRootPath, "Policy", "starter-policies.json");
            if (!File.Exists(path)) return Results.NotFound(new { code = "policy.starter.missing" });
            var json = await File.ReadAllTextAsync(path, cancellationToken);
            return Results.Content(json, "application/json", Encoding.UTF8);
        }

        endpoints.MapGet("/api/admin/policy/starter", getStarterPoliciesHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetStarterPolicies")
            .WithSummary("Get starter policy set")
            .WithDescription("Returns the starter policy catalog JSON aligned with HIP policy schema.")
            .WithTags("Admin", "Policy")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/v1/admin/policy/starter", getStarterPoliciesHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetStarterPoliciesV1")
            .WithSummary("Get starter policy set")
            .WithDescription("Versioned alias of starter policy catalog endpoint.")
            .WithTags("Admin", "Policy", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status429TooManyRequests);

        async Task<IResult> getPolicyContextSampleHandler(
            HttpContext httpContext,
            IWebHostEnvironment env,
            IHipEnvelopeVerifier envelopeVerifier,
            IIdentityService identityService,
            IReputationService reputationService,
            CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null) return gate;

            var path = Path.Combine(env.ContentRootPath, "Policy", "policy-context.sample.json");
            if (!File.Exists(path)) return Results.NotFound(new { code = "policy.context.missing" });
            var json = await File.ReadAllTextAsync(path, cancellationToken);
            return Results.Content(json, "application/json", Encoding.UTF8);
        }

        endpoints.MapGet("/api/admin/policy/context-sample", getPolicyContextSampleHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetPolicyContextSample")
            .WithSummary("Get sample policy evaluation context")
            .WithDescription("Returns sample PolicyContext payload for sandbox testing and contract validation.")
            .WithTags("Admin", "Policy")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/v1/admin/policy/context-sample", getPolicyContextSampleHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetPolicyContextSampleV1")
            .WithSummary("Get sample policy evaluation context")
            .WithDescription("Versioned alias of sample policy context endpoint.")
            .WithTags("Admin", "Policy", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status429TooManyRequests);

        async Task<IResult> upsertPolicyRuleHandler(
            HttpContext httpContext,
            JsonElement input,
            PolicyVersionStore store,
            IHipEnvelopeVerifier envelopeVerifier,
            IIdentityService identityService,
            IReputationService reputationService,
            CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null)
            {
                return gate;
            }

            var ruleId = input.TryGetProperty("ruleId", out var idEl) ? idEl.GetString() : null;
            var name = input.TryGetProperty("name", out var nameEl) ? nameEl.GetString() : null;
            if (string.IsNullOrWhiteSpace(ruleId) || string.IsNullOrWhiteSpace(name))
            {
                return Results.BadRequest(new { code = "policy.validation", reason = "ruleId and name are required" });
            }

            var category = input.TryGetProperty("category", out var cEl) ? cEl.GetString() ?? "System" : "System";
            var condition = input.TryGetProperty("condition", out var condEl) ? condEl.GetString() ?? "event matches rule" : "event matches rule";
            var action = input.TryGetProperty("action", out var actEl) ? actEl.GetString() ?? "Warn" : "Warn";
            var severity = input.TryGetProperty("severity", out var sevEl) ? sevEl.GetString() ?? "Medium" : "Medium";
            var enabled = input.TryGetProperty("enabled", out var enEl) ? enEl.ValueKind != JsonValueKind.False : true;
            var actor = input.TryGetProperty("actor", out var actorEl) ? actorEl.GetString() ?? "admin" : "admin";
            var reason = input.TryGetProperty("reason", out var reasonEl) ? reasonEl.GetString() ?? "manual update" : "manual update";

            var allowedCategories = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Login","Device","Session","Messaging","Token","Reputation","Authorization","System","Data","Risk"
            };
            var allowedActions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Challenge","Block","Warn","RateLimit","Alert","Lock","KillSession","Quarantine","Restrict","RequireApproval","AuditAndNotify","RevokeToken","ReduceReputation","Allow"
            };
            var allowedSeverity = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Info","Warning","Medium","High","Critical"
            };

            if (!allowedCategories.Contains(category))
            {
                return Results.BadRequest(new { code = "policy.validation", reason = $"Unsupported category '{category}'" });
            }
            if (!allowedActions.Contains(action))
            {
                return Results.BadRequest(new { code = "policy.validation", reason = $"Unsupported action '{action}'" });
            }
            if (!allowedSeverity.Contains(severity))
            {
                return Results.BadRequest(new { code = "policy.validation", reason = $"Unsupported severity '{severity}'" });
            }
            if (string.IsNullOrWhiteSpace(condition) || condition.Length > 512)
            {
                return Results.BadRequest(new { code = "policy.validation", reason = "Condition is required and must be <= 512 chars" });
            }

            var (_, draftId) = store.UpsertRule(new PolicyRuleEntry(ruleId, name, category, condition, action, severity, enabled), actor, reason);
            return Results.Ok(new { saved = true, ruleId, draftId });
        }

        endpoints.MapPost("/api/admin/policy", upsertPolicyRuleHandler)
            .RequireRateLimiting("read-api")
            .WithName("UpsertAdminPolicyRule")
            .WithSummary("Create or update an admin policy rule")
            .WithDescription("Upserts a policy rule in the in-memory policy store for runtime testing and sandbox evaluation.")
            .WithTags("Admin", "Policy")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/v1/admin/policy", upsertPolicyRuleHandler)
            .RequireRateLimiting("read-api")
            .WithName("UpsertAdminPolicyRuleV1")
            .WithSummary("Create or update an admin policy rule")
            .WithDescription("Versioned alias of admin policy upsert endpoint.")
            .WithTags("Admin", "Policy", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status429TooManyRequests);

        async Task<IResult> getPolicyVersionsHandler(
            HttpContext httpContext,
            PolicyVersionStore store,
            IHipEnvelopeVerifier envelopeVerifier,
            IIdentityService identityService,
            IReputationService reputationService,
            CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null) return gate;

            var versions = store.List().Select(v => new
            {
                versionId = v.VersionId,
                name = v.Name,
                status = v.Status,
                createdUtc = v.CreatedUtc,
                activatedUtc = v.ActivatedUtc,
                actor = v.Actor,
                reason = v.Reason,
                approvedBy = v.ApprovedBy,
                ruleCount = v.Rules.Count
            });

            return Results.Ok(versions);
        }

        endpoints.MapGet("/api/admin/policy/versions", getPolicyVersionsHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetPolicyVersions")
            .WithSummary("List policy pack versions")
            .WithDescription("Returns draft/active/archived policy versions with metadata.")
            .WithTags("Admin", "Policy")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/v1/admin/policy/versions", getPolicyVersionsHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetPolicyVersionsV1")
            .WithSummary("List policy pack versions")
            .WithDescription("Versioned alias of policy version listing endpoint.")
            .WithTags("Admin", "Policy", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        async Task<IResult> createPolicyDraftHandler(
            HttpContext httpContext,
            JsonElement input,
            PolicyVersionStore store,
            IHipEnvelopeVerifier envelopeVerifier,
            IIdentityService identityService,
            IReputationService reputationService,
            CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null) return gate;

            var actor = input.TryGetProperty("actor", out var aEl) ? aEl.GetString() ?? "admin" : "admin";
            var reason = input.TryGetProperty("reason", out var rEl) ? rEl.GetString() ?? "draft requested" : "draft requested";
            var draft = store.CreateDraft(actor, reason);
            return Results.Ok(new { draft.VersionId, draft.Name, draft.Status, draft.CreatedUtc, draft.Actor, draft.Reason, ruleCount = draft.Rules.Count });
        }

        endpoints.MapPost("/api/admin/policy/versions/draft", createPolicyDraftHandler)
            .RequireRateLimiting("read-api")
            .WithName("CreatePolicyDraft")
            .WithSummary("Create policy draft from active version")
            .WithDescription("Creates (or returns existing) draft policy pack for editing and simulation.")
            .WithTags("Admin", "Policy")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/v1/admin/policy/versions/draft", createPolicyDraftHandler)
            .RequireRateLimiting("read-api")
            .WithName("CreatePolicyDraftV1")
            .WithSummary("Create policy draft from active version")
            .WithDescription("Versioned alias of policy draft creation endpoint.")
            .WithTags("Admin", "Policy", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        async Task<IResult> previewPolicyImpactHandler(
            HttpContext httpContext,
            string versionId,
            PolicyVersionStore store,
            IHipEnvelopeVerifier envelopeVerifier,
            IIdentityService identityService,
            IReputationService reputationService,
            CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null) return gate;
            return Results.Ok(store.PreviewImpact(versionId));
        }

        endpoints.MapGet("/api/admin/policy/versions/{versionId}/impact", previewPolicyImpactHandler)
            .RequireRateLimiting("read-api")
            .WithName("PreviewPolicyImpact")
            .WithSummary("Preview policy impact")
            .WithDescription("Shows block/challenge/warn counts and deltas if a version is activated.")
            .WithTags("Admin", "Policy")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/v1/admin/policy/versions/{versionId}/impact", previewPolicyImpactHandler)
            .RequireRateLimiting("read-api")
            .WithName("PreviewPolicyImpactV1")
            .WithSummary("Preview policy impact")
            .WithDescription("Versioned alias of policy impact preview endpoint.")
            .WithTags("Admin", "Policy", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        async Task<IResult> diffPolicyVersionHandler(
            HttpContext httpContext,
            string versionId,
            string? against,
            PolicyVersionStore store,
            IHipEnvelopeVerifier envelopeVerifier,
            IIdentityService identityService,
            IReputationService reputationService,
            CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null) return gate;
            return Results.Ok(store.Diff(versionId, against));
        }

        endpoints.MapGet("/api/admin/policy/versions/{versionId}/diff", diffPolicyVersionHandler)
            .RequireRateLimiting("read-api")
            .WithName("DiffPolicyVersion")
            .WithSummary("Diff policy versions")
            .WithDescription("Compares target policy version against active (or specified) baseline and returns added/removed/changed rules.")
            .WithTags("Admin", "Policy")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/v1/admin/policy/versions/{versionId}/diff", diffPolicyVersionHandler)
            .RequireRateLimiting("read-api")
            .WithName("DiffPolicyVersionV1")
            .WithSummary("Diff policy versions")
            .WithDescription("Versioned alias of policy diff endpoint.")
            .WithTags("Admin", "Policy", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        async Task<IResult> activatePolicyVersionHandler(
            HttpContext httpContext,
            string versionId,
            JsonElement input,
            PolicyVersionStore store,
            IHipEnvelopeVerifier envelopeVerifier,
            IIdentityService identityService,
            IReputationService reputationService,
            CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null) return gate;

            var actor = input.TryGetProperty("actor", out var aEl) ? aEl.GetString() ?? "admin" : "admin";
            var reason = input.TryGetProperty("reason", out var rEl) ? rEl.GetString() ?? "activate" : "activate";
            var approvedBy = input.TryGetProperty("approvedBy", out var apEl) ? apEl.GetString() : null;

            var activated = store.Activate(versionId, actor, reason, approvedBy);
            return Results.Ok(new { activated.VersionId, activated.Status, activated.ActivatedUtc, activated.Actor, activated.Reason, activated.ApprovedBy });
        }

        endpoints.MapPost("/api/admin/policy/versions/{versionId}/activate", activatePolicyVersionHandler)
            .RequireRateLimiting("read-api")
            .WithName("ActivatePolicyVersion")
            .WithSummary("Activate policy version")
            .WithDescription("Promotes a draft/archived version to active and archives previous active version.")
            .WithTags("Admin", "Policy")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/v1/admin/policy/versions/{versionId}/activate", activatePolicyVersionHandler)
            .RequireRateLimiting("read-api")
            .WithName("ActivatePolicyVersionV1")
            .WithSummary("Activate policy version")
            .WithDescription("Versioned alias of policy version activation endpoint.")
            .WithTags("Admin", "Policy", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        async Task<IResult> rollbackPolicyVersionHandler(
            HttpContext httpContext,
            JsonElement input,
            PolicyVersionStore store,
            IHipEnvelopeVerifier envelopeVerifier,
            IIdentityService identityService,
            IReputationService reputationService,
            CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null) return gate;

            var actor = input.TryGetProperty("actor", out var aEl) ? aEl.GetString() ?? "admin" : "admin";
            var reason = input.TryGetProperty("reason", out var rEl) ? rEl.GetString() ?? "rollback" : "rollback";
            var rolled = store.Rollback(actor, reason);
            return Results.Ok(new { rolled.VersionId, rolled.Status, rolled.ActivatedUtc, rolled.Actor, rolled.Reason });
        }

        endpoints.MapPost("/api/admin/policy/versions/rollback", rollbackPolicyVersionHandler)
            .RequireRateLimiting("read-api")
            .WithName("RollbackPolicyVersion")
            .WithSummary("Rollback to previous active policy version")
            .WithDescription("One-click rollback to previously active policy version.")
            .WithTags("Admin", "Policy")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/v1/admin/policy/versions/rollback", rollbackPolicyVersionHandler)
            .RequireRateLimiting("read-api")
            .WithName("RollbackPolicyVersionV1")
            .WithSummary("Rollback to previous active policy version")
            .WithDescription("Versioned alias of policy rollback endpoint.")
            .WithTags("Admin", "Policy", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        async Task<IResult> generatePolicyAiDraftHandler(
            HttpContext httpContext,
            JsonElement input,
            IHipEnvelopeVerifier envelopeVerifier,
            IIdentityService identityService,
            IReputationService reputationService,
            CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null)
            {
                return gate;
            }

            var prompt = input.TryGetProperty("prompt", out var pEl) ? pEl.GetString() ?? string.Empty : string.Empty;
            var lower = prompt.ToLowerInvariant();

            var category = lower.Contains("login") || lower.Contains("mfa") ? "Login"
                : lower.Contains("device") ? "Device"
                : lower.Contains("token") || lower.Contains("replay") ? "Token"
                : lower.Contains("reputation") ? "Reputation"
                : lower.Contains("spam") || lower.Contains("phish") || lower.Contains("message") || lower.Contains("link") ? "Messaging"
                : "System";

            var draft = new
            {
                ruleId = $"AI-{DateTimeOffset.UtcNow:HHmmss}",
                name = string.IsNullOrWhiteSpace(prompt) ? "AI Draft Rule" : prompt.Length > 48 ? prompt[..48] : prompt,
                category,
                condition = category switch
                {
                    "Login" => "mfa == false",
                    "Device" => "deviceTrusted == false",
                    "Token" => "replayDetected == true",
                    "Reputation" => "reputation < 20",
                    "Messaging" => "domainFlagged == true",
                    _ => "event matches risk pattern"
                },
                action = category is "Token" or "Messaging" ? "Block" : "Challenge",
                severity = category is "Token" or "Messaging" ? "Critical" : "Medium",
                tests = new[]
                {
                    "case-1: expected trigger",
                    "case-2: expected no trigger"
                }
            };

            return Results.Ok(draft);
        }

        endpoints.MapPost("/api/admin/policy/ai-draft", generatePolicyAiDraftHandler)
            .RequireRateLimiting("read-api")
            .WithName("GenerateAdminPolicyAIDraft")
            .WithSummary("Generate an AI-style policy draft")
            .WithDescription("Creates a policy rule draft from natural language prompt for review before saving or activation.")
            .WithTags("Admin", "Policy")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/v1/admin/policy/ai-draft", generatePolicyAiDraftHandler)
            .RequireRateLimiting("read-api")
            .WithName("GenerateAdminPolicyAIDraftV1")
            .WithSummary("Generate an AI-style policy draft")
            .WithDescription("Versioned alias of AI policy draft endpoint.")
            .WithTags("Admin", "Policy", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        async Task<IResult> simulatePolicyHandler(
            HttpContext httpContext,
            JsonElement input,
            IHipEnvelopeVerifier envelopeVerifier,
            IIdentityService identityService,
            IReputationService reputationService,
            CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null)
            {
                return gate;
            }

            var triggered = new List<string>();
            var actions = new List<string>();
            var trace = new List<string>();

            var mfaMissing = input.TryGetProperty("mfa", out var mfaEl) && mfaEl.ValueKind == JsonValueKind.False;
            var untrustedDevice = input.TryGetProperty("deviceTrusted", out var deviceEl) && deviceEl.ValueKind == JsonValueKind.False;
            var replayDetected = input.TryGetProperty("replayDetected", out var replayEl) && replayEl.ValueKind == JsonValueKind.True;
            var tokenExpired = input.TryGetProperty("tokenExpired", out var tokenEl) && tokenEl.ValueKind == JsonValueKind.True;
            var domainFlagged = input.TryGetProperty("domainFlagged", out var domainEl) && domainEl.ValueKind == JsonValueKind.True;
            var ipRiskHigh = input.TryGetProperty("ipRisk", out var ipRiskEl) && string.Equals(ipRiskEl.GetString(), "high", StringComparison.OrdinalIgnoreCase);
            var reputationLow = input.TryGetProperty("reputation", out var repEl) && repEl.ValueKind == JsonValueKind.Number && repEl.GetInt32() < 30;
            var reputationVeryLow = input.TryGetProperty("reputation", out var repLowEl) && repLowEl.ValueKind == JsonValueKind.Number && repLowEl.GetInt32() < 10;

            Eval("LoginPolicy.MfaRequired", mfaMissing, "Require MFA", "Require MFA");
            Eval("DevicePolicy.TrustedDevice", untrustedDevice, "Untrusted Device", "Challenge device");
            Eval("TokenPolicy.Replay", replayDetected, "Replay Attempt", "Block token");
            Eval("TokenPolicy.Expiry", tokenExpired, "Token Expired", "Block request");
            Eval("ReputationPolicy.LowScore", reputationLow, "Low Reputation", "Restrict actions");
            Eval("ReputationPolicy.VeryLowScore", reputationVeryLow, "Very Low Reputation", "Quarantine account");
            Eval("MessagingPolicy.PhishingDomain", domainFlagged, "Phishing Domain", "Block message");
            Eval("LoginPolicy.SuspiciousIp", ipRiskHigh, "Suspicious IP", "Send alert");

            var decision = replayDetected || tokenExpired || domainFlagged || reputationVeryLow
                ? "BLOCK"
                : mfaMissing || untrustedDevice
                    ? "CHALLENGE"
                    : reputationLow || ipRiskHigh
                        ? "WARN"
                        : "ALLOW";

            return Results.Ok(new { decision, triggeredRules = triggered, actions, trace });

            void Eval(string key, bool condition, string rule, string action)
            {
                trace.Add($"{(condition ? "✔" : "✘")} {key} → {(condition ? "triggered" : "not triggered")}");
                if (!condition) return;
                triggered.Add(rule);
                actions.Add(action);
            }
        }

        endpoints.MapPost("/api/admin/policy/simulate", simulatePolicyHandler)
            .RequireRateLimiting("read-api")
            .WithName("SimulateAdminPolicy")
            .WithSummary("Simulate policy evaluation for sandbox input")
            .WithDescription("Evaluates an input event payload against baseline HIP policy rules and returns decision, triggered rules, actions, and trace.")
            .WithTags("Admin", "Policy")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/v1/admin/policy/simulate", simulatePolicyHandler)
            .RequireRateLimiting("read-api")
            .WithName("SimulateAdminPolicyV1")
            .WithSummary("Simulate policy evaluation for sandbox input")
            .WithDescription("Versioned alias of policy simulation endpoint.")
            .WithTags("Admin", "Policy", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        return endpoints;
    }
}
