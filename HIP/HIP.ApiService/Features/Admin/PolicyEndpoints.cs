using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Infrastructure.Plugins;
using Microsoft.Extensions.Options;
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
        endpoints.MapGet("/api/admin/policy", async (
                HttpContext httpContext,
                PolicyRuleStore store,
                IHipEnvelopeVerifier envelopeVerifier,
                IIdentityService identityService,
                IReputationService reputationService,
                CancellationToken cancellationToken) =>
            {
                var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
                if (gate is not null)
                {
                    return gate;
                }

                return Results.Ok(store.GetAll().Select(x => new
                {
                    ruleId = x.RuleId,
                    name = x.Name,
                    category = x.Category,
                    condition = x.Condition,
                    action = x.Action,
                    severity = x.Severity,
                    enabled = x.Enabled
                }));
            })
            .RequireRateLimiting("read-api")
            .WithName("GetAdminPolicyRules")
            .WithSummary("Get effective admin policy rules")
            .WithDescription("Returns the active baseline security policy rule set for HIP admin surfaces, including category, condition, action, severity, and enabled state.")
            .WithTags("Admin", "Policy")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/admin/policy", async (
                HttpContext httpContext,
                JsonElement input,
                PolicyRuleStore store,
                IHipEnvelopeVerifier envelopeVerifier,
                IIdentityService identityService,
                IReputationService reputationService,
                CancellationToken cancellationToken) =>
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

                store.Upsert(new PolicyRuleEntry(ruleId, name, category, condition, action, severity, enabled));
                return Results.Ok(new { saved = true, ruleId });
            })
            .RequireRateLimiting("read-api")
            .WithName("UpsertAdminPolicyRule")
            .WithSummary("Create or update an admin policy rule")
            .WithDescription("Upserts a policy rule in the in-memory policy store for runtime testing and sandbox evaluation.")
            .WithTags("Admin", "Policy")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/admin/policy/ai-draft", async (
                HttpContext httpContext,
                JsonElement input,
                IHipEnvelopeVerifier envelopeVerifier,
                IIdentityService identityService,
                IReputationService reputationService,
                CancellationToken cancellationToken) =>
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
            })
            .RequireRateLimiting("read-api")
            .WithName("GenerateAdminPolicyAIDraft")
            .WithSummary("Generate an AI-style policy draft")
            .WithDescription("Creates a policy rule draft from natural language prompt for review before saving or activation.")
            .WithTags("Admin", "Policy")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/admin/policy/simulate", async (
                HttpContext httpContext,
                JsonElement input,
                IHipEnvelopeVerifier envelopeVerifier,
                IIdentityService identityService,
                IReputationService reputationService,
                CancellationToken cancellationToken) =>
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
            })
            .RequireRateLimiting("read-api")
            .WithName("SimulateAdminPolicy")
            .WithSummary("Simulate policy evaluation for sandbox input")
            .WithDescription("Evaluates an input event payload against baseline HIP policy rules and returns decision, triggered rules, actions, and trace.")
            .WithTags("Admin", "Policy")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        return endpoints;
    }
}
