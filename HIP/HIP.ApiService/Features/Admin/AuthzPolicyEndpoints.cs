using HIP.ApiService.Application.Abstractions;
using System.Text.Json;

namespace HIP.ApiService.Features.Admin;

/// <summary>
/// Admin endpoints for authorization-policy management and simulation.
/// </summary>
public static class AuthzPolicyEndpoints
{
    /// <summary>
    /// Maps authorization policy admin endpoints.
    /// </summary>
    /// <param name="endpoints">Endpoint route builder.</param>
    /// <returns>The same route builder for chaining.</returns>
    public static IEndpointRouteBuilder MapAuthzPolicyEndpoints(this IEndpointRouteBuilder endpoints)
    {
        async Task<IResult> getAuthzPoliciesHandler(
            HttpContext httpContext,
            AuthzPolicyStore store,
            IHipEnvelopeVerifier envelopeVerifier,
            IIdentityService identityService,
            IReputationService reputationService,
            CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null) return gate;

            return Results.Ok(store.GetAll().Select(x => new
            {
                ruleId = x.RuleId,
                name = x.Name,
                role = x.Role,
                resource = x.Resource,
                action = x.Action,
                decision = x.Decision,
                enabled = x.Enabled
            }));
        }

        endpoints.MapGet("/api/admin/authz-policies", getAuthzPoliciesHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetAdminAuthzPolicyRules")
            .WithSummary("Get authorization policy rules")
            .WithDescription("Returns role/resource/action authorization policies used for permissions simulation and admin control-plane design.")
            .WithTags("Admin", "Authorization")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/v1/admin/authz-policies", getAuthzPoliciesHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetAdminAuthzPolicyRulesV1")
            .WithSummary("Get authorization policy rules")
            .WithDescription("Versioned alias of authorization policy listing endpoint.")
            .WithTags("Admin", "Authorization", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        async Task<IResult> simulateAuthzHandler(
            HttpContext httpContext,
            JsonElement input,
            AuthzPolicyStore store,
            IHipEnvelopeVerifier envelopeVerifier,
            IIdentityService identityService,
            IReputationService reputationService,
            CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null) return gate;

            var role = input.TryGetProperty("role", out var rEl) ? (rEl.GetString() ?? "Support") : "Support";
            var resource = input.TryGetProperty("resource", out var rsEl) ? (rsEl.GetString() ?? "audit") : "audit";
            var action = input.TryGetProperty("action", out var aEl) ? (aEl.GetString() ?? "read") : "read";

            var triggered = new List<string>();
            var trace = new List<string>();
            string decision = "Deny";

            foreach (var rule in store.GetAll().Where(x => x.Enabled))
            {
                var match = string.Equals(rule.Role, role, StringComparison.OrdinalIgnoreCase)
                            && string.Equals(rule.Resource, resource, StringComparison.OrdinalIgnoreCase)
                            && (string.Equals(rule.Action, action, StringComparison.OrdinalIgnoreCase)
                                || string.Equals(rule.Action, "manage", StringComparison.OrdinalIgnoreCase));

                trace.Add($"{(match ? "✔" : "✘")} {rule.RuleId} ({rule.Name})");
                if (!match) continue;
                triggered.Add(rule.RuleId);
                decision = rule.Decision;
                break;
            }

            return Results.Ok(new
            {
                decision = decision.ToUpperInvariant(),
                triggeredRules = triggered,
                actions = new[] { decision.Equals("Allow", StringComparison.OrdinalIgnoreCase) ? "Grant access" : "Deny access" },
                trace
            });
        }

        endpoints.MapPost("/api/admin/authz/simulate", simulateAuthzHandler)
            .RequireRateLimiting("read-api")
            .WithName("SimulateAdminAuthorization")
            .WithSummary("Simulate authorization decision")
            .WithDescription("Evaluates role/resource/action against authorization policy rules and returns allow/deny decision with trace.")
            .WithTags("Admin", "Authorization")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/v1/admin/authz/simulate", simulateAuthzHandler)
            .RequireRateLimiting("read-api")
            .WithName("SimulateAdminAuthorizationV1")
            .WithSummary("Simulate authorization decision")
            .WithDescription("Versioned alias of authorization simulation endpoint.")
            .WithTags("Admin", "Authorization", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        return endpoints;
    }
}
